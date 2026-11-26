use crate::target::{Location, Mapping, ProbeSpec, ProcessMaps, ResolvedProbe, integer};
use anyhow::{Context, Result, bail, ensure};
use object::{Object, ObjectSegment, ObjectSymbol, SegmentFlags};
use serde_json::{Value, json};
use std::{collections::BTreeMap, fs::File, os::unix::fs::FileExt, str::FromStr};
use yaxpeax_arch::{Decoder, U8Reader};
use yaxpeax_arm::armv8::a64::InstDecoder;

pub const MAX_SITES: usize = debugplz_abi::instruction::MAX_SITES as usize;
pub const MAX_ADDRESSES: usize = debugplz_abi::instruction::MAX_ADDRESSES as usize;
const PAGE_BYTES: u64 = 4096;

#[derive(Clone, Debug)]
enum End {
    Point(ProbeSpec),
    Length(u64),
}

#[derive(Clone, Debug)]
pub struct RangeSpec {
    start: ProbeSpec,
    end: End,
}

impl FromStr for RangeSpec {
    type Err = anyhow::Error;

    fn from_str(input: &str) -> Result<Self> {
        if let Some((start, end)) = input.split_once("..") {
            let start: ProbeSpec = start.parse()?;
            ensure!(!end.is_empty() && !end.contains(".."), "invalid range end");
            let end = if let Some(library) = &start.library {
                if end.starts_with(&format!("{library}+")) {
                    end.parse()?
                } else {
                    format!("{library}+{end}").parse()?
                }
            } else {
                end.parse()?
            };
            return Ok(Self {
                start,
                end: End::Point(end),
            });
        }
        let (start, length) = input
            .rsplit_once(':')
            .context("expected START..END or START:BYTES (for example lib.so+func:0x40)")?;
        let length = integer(length)?;
        ensure!(
            length != 0 && length % 4 == 0,
            "range length must be a positive multiple of 4 bytes"
        );
        Ok(Self {
            start: start.parse()?,
            end: End::Length(length),
        })
    }
}

pub struct Point {
    pub target: usize,
    pub file_offset: u64,
    pub elf_address: u64,
    pub instructions: BTreeMap<u64, Instruction>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Instruction {
    pub word: u32,
    pub assembly: String,
}

pub(super) struct CodePage {
    mapping: Mapping,
    bytes: Vec<u8>,
}

pub struct Plan {
    pub targets: Vec<ResolvedProbe>,
    pub points: Vec<Point>,
    pub(super) pid: u32,
    pub(super) pages: BTreeMap<u64, CodePage>,
}

impl Plan {
    pub fn resolve(maps: &ProcessMaps, specs: &[RangeSpec]) -> Result<Self> {
        ensure!(
            !specs.is_empty(),
            "at least one instruction range is required"
        );
        let mut plan = Self {
            targets: Vec::new(),
            points: Vec::new(),
            pid: maps.pid,
            pages: BTreeMap::new(),
        };
        let memory = File::open(format!("/proc/{}/mem", maps.pid))
            .context("opening target runtime instruction memory")?;
        let mut unique = BTreeMap::new();
        for spec in specs {
            let mut target = maps.resolve(&spec.start)?;
            let mut bytes = vec![0; usize::try_from(target.file.metadata()?.len())?];
            target.file.read_exact_at(&mut bytes, 0)?;
            let elf = object::File::parse(bytes.as_slice())?;
            let length = spec.length(&target, &elf)?;
            let end = checked_end(target.file_offset, length)?;
            ensure!(end <= bytes.len() as u64, "range extends beyond file");
            ensure!(
                elf.segments().any(|s| {
                    let (offset, size) = s.file_range();
                    matches!(s.flags(), SegmentFlags::Elf { p_flags, .. } if p_flags.0 & 1 != 0)
                        && target.file_offset >= offset
                        && end
                            .checked_sub(offset)
                            .is_some_and(|relative| relative <= size)
                }),
                "range must fit one executable file-backed PT_LOAD"
            );
            let runtime = match spec.start.location {
                Location::RuntimeAddress(address) => Some((
                    address,
                    address
                        .checked_add(length)
                        .context("runtime range overflow")?,
                )),
                Location::ElfAddress(_) | Location::Symbol(_, _) => None,
            };
            let identity = (target.mappings[0].device, target.mappings[0].inode);
            target.mappings = maps
                .mappings
                .iter()
                .filter(|m| {
                    m.executable
                        && !m.writable
                        && !m.shared
                        && (m.device, m.inode) == identity
                        && m.offset < end
                        && target.file_offset.saturating_sub(m.offset) < m.end - m.start
                        && runtime.is_none_or(|(start, end)| m.start < end && start < m.end)
                })
                .cloned()
                .collect();
            let target_index = plan.targets.len();
            for offset in (target.file_offset..end).step_by(4) {
                let address = target
                    .elf_address
                    .checked_add(offset - target.file_offset)
                    .context("ELF range address overflow")?;
                let mut instructions = BTreeMap::new();
                for m in &target.mappings {
                    if offset < m.offset || offset - m.offset + 4 > m.end - m.start {
                        continue;
                    }
                    let pc = m.start + offset - m.offset;
                    if runtime.is_none_or(|(start, end)| start <= pc && pc < end) {
                        let page = pc & !(PAGE_BYTES - 1);
                        ensure!(
                            m.start <= page && page + PAGE_BYTES <= m.end,
                            "UXN requires a complete private executable page at {pc:#x}"
                        );
                        let snapshot = match plan.pages.entry(page) {
                            std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
                            std::collections::btree_map::Entry::Vacant(entry) => {
                                let mut bytes = vec![0; usize::try_from(PAGE_BYTES)?];
                                memory.read_exact_at(&mut bytes, page).with_context(|| {
                                    format!("reading runtime code page {page:#x}")
                                })?;
                                check_page(&bytes, page)?;
                                entry.insert(CodePage {
                                    mapping: m.clone(),
                                    bytes,
                                })
                            }
                        };
                        let index = usize::try_from(pc - page)?;
                        let word = u32::from_le_bytes(snapshot.bytes[index..index + 4].try_into()?);
                        let assembly = decode(word).with_context(|| {
                            format!(
                                "runtime PC {pc:#x}, {}+{address:#x} ({word:08x})",
                                target.path.display()
                            )
                        })?;
                        instructions.insert(pc, Instruction { word, assembly });
                    }
                }
                ensure!(
                    !instructions.is_empty(),
                    "instruction {address:#x} has no private read-only executable mapping"
                );
                let key = (identity, offset);
                if let Some(&index) = unique.get(&key) {
                    let old: &mut Point = &mut plan.points[index];
                    old.instructions.extend(instructions);
                } else {
                    ensure!(
                        plan.points.len() < MAX_SITES,
                        "instruction trace exceeds {MAX_SITES} unique sites"
                    );
                    unique.insert(key, plan.points.len());
                    plan.points.push(Point {
                        target: target_index,
                        file_offset: offset,
                        elf_address: address,
                        instructions,
                    });
                }
            }
            plan.targets.push(target);
        }
        ensure!(
            plan.points
                .iter()
                .map(|p| p.instructions.len())
                .sum::<usize>()
                <= MAX_ADDRESSES,
            "instruction trace exceeds {MAX_ADDRESSES} runtime addresses"
        );
        plan.verify_code()?;
        Ok(plan)
    }

    pub fn preview(&self) -> Value {
        json!({"sites": self.points.len(), "instruction_source":"runtime", "instructions": self.points.iter().enumerate().map(|(i, p)| {
            json!({"site":i + 1, "path":self.targets[p.target].path, "file_offset":format!("{:#x}",p.file_offset),
                "elf_address":format!("{:#x}",p.elf_address),
                "instances":p.instructions.iter().map(|(pc, instruction)| json!({
                    "pc":format!("{pc:#x}"), "opcode":format!("{:08x}",instruction.word),
                    "instruction":instruction.assembly})).collect::<Vec<_>>()})
        }).collect::<Vec<_>>()})
    }

    pub fn verify_code(&self) -> Result<()> {
        let maps = ProcessMaps::read(self.pid)?;
        let memory = File::open(format!("/proc/{}/mem", self.pid))
            .context("opening target runtime instruction memory for verification")?;
        let mut bytes = vec![0; usize::try_from(PAGE_BYTES)?];
        for (page, snapshot) in &self.pages {
            ensure!(
                maps.mappings.contains(&snapshot.mapping),
                "runtime code mapping changed during setup at {page:#x}"
            );
            memory
                .read_exact_at(&mut bytes, *page)
                .with_context(|| format!("verifying runtime code page {page:#x}"))?;
            ensure!(
                bytes == snapshot.bytes,
                "runtime code page changed during setup at {page:#x}"
            );
        }
        Ok(())
    }
}

impl RangeSpec {
    fn length(&self, start: &ResolvedProbe, elf: &object::File<'_>) -> Result<u64> {
        match &self.end {
            End::Length(length) => Ok(*length),
            End::Point(end) => {
                ensure!(
                    self.start.library == end.library,
                    "range endpoints must use the same library/address form"
                );
                let (first, last) = match (&self.start.location, &end.location) {
                    (Location::RuntimeAddress(first), Location::RuntimeAddress(last)) => {
                        (*first, *last)
                    }
                    (
                        Location::ElfAddress(_) | Location::Symbol(_, _),
                        Location::ElfAddress(last),
                    ) => (start.elf_address, *last),
                    (
                        Location::ElfAddress(_) | Location::Symbol(_, _),
                        Location::Symbol(name, additional),
                    ) => {
                        let symbol = elf
                            .dynamic_symbols()
                            .chain(elf.symbols())
                            .find(|s| s.is_definition() && s.name().ok() == Some(name.as_str()))
                            .with_context(|| format!("range end symbol {name} not found"))?;
                        (
                            start.elf_address,
                            symbol
                                .address()
                                .checked_add(*additional)
                                .context("range end symbol overflow")?,
                        )
                    }
                    _ => bail!("range endpoints mix ELF and runtime addresses"),
                };
                last.checked_sub(first)
                    .filter(|length| *length != 0)
                    .context("range end must follow start")
            }
        }
    }
}

fn checked_end(start: u64, length: u64) -> Result<u64> {
    ensure!(
        start.is_multiple_of(4) && length != 0 && length.is_multiple_of(4),
        "instruction range must be nonempty and 4-byte aligned"
    );
    ensure!(
        length / 4 <= MAX_SITES as u64,
        "one range exceeds {MAX_SITES} sites"
    );
    start.checked_add(length).context("range overflow")
}

fn check_page(bytes: &[u8], page: u64) -> Result<()> {
    ensure!(
        bytes.len() == usize::try_from(PAGE_BYTES)?,
        "incomplete runtime code page"
    );
    for (index, chunk) in bytes.as_chunks::<4>().0.iter().enumerate() {
        let word = u32::from_le_bytes(*chunk);
        ensure!(
            word & 0x3f80_0000 != 0x0800_0000,
            "exclusive instruction at runtime PC {:#x} shares a trace page; BRK may break its reservation",
            page + u64::try_from(index)? * 4
        );
    }
    Ok(())
}

fn decode(word: u32) -> Result<String> {
    let bytes = word.to_le_bytes();
    let instruction = InstDecoder::default()
        .decode(&mut U8Reader::new(&bytes))
        .context("invalid or unsupported AArch64 instruction")?;
    // Keep conservative preflight checks aligned with the target 5.15 decoder.
    // Kernel registration is authoritative; this does not enable rejected opcodes.
    let rejected = word & 0xffff_0000 == 0 // UDF
        || word & 0xff00_0000 == 0xd400_0000
        || word & 0x3f80_0000 == 0x0800_0000
        || word & 0xfff8_f01f == 0xd500_401f
        || word & 0xfff0_0000 == 0xd510_0000
        || word & 0xfeff_f800 == 0xd61f_0800
        || word & 0xfeff_f800 == 0xd63f_0800
        || word & 0xffff_fbff == 0xd65f_0bff
        || word == 0xd69f_03e0 || word & 0xffff_fbff == 0xd69f_0bff
        || word & 0xffff_ffe0 == 0xd53b_4220 // MRS DAIF
        || word & 0xff00_0000 == 0xd800_0000; // PRFM literal
    ensure!(
        !rejected,
        "instruction rejected by ARM64 uprobe preflight: {instruction}"
    );
    if word & 0xffff_f01f == 0xd503_201f {
        let hint = (word >> 5) & 0x7f;
        ensure!(
            matches!(hint, 0 | 7 | 8 | 10 | 24..=27 | 32 | 34 | 36 | 38),
            "HINT rejected by ARM64 uprobe: {instruction}"
        );
    }
    Ok(instruction.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_lengths_and_inherited_endpoints() {
        assert!(matches!(
            "lib.so+func:0x40".parse::<RangeSpec>().unwrap().end,
            End::Length(64)
        ));
        let spec: RangeSpec = "lib.so+func..end+0x4".parse().unwrap();
        let End::Point(end) = spec.end else {
            panic!("expected endpoint")
        };
        assert_eq!(end.library.as_deref(), Some("lib.so"));
        assert_eq!(end.location, Location::Symbol("end".into(), 4));
        assert!("0x7000..0x7040".parse::<RangeSpec>().is_ok());
        for bad in [
            "lib.so+func",
            "lib.so+func:0",
            "lib.so+func:3",
            "lib.so+func..",
            "lib.so+func..end..other",
        ] {
            assert!(bad.parse::<RangeSpec>().is_err(), "{bad}");
        }
    }

    #[test]
    fn boundaries_and_budgets_are_checked() {
        assert_eq!(checked_end(0x1000, 0x40).unwrap(), 0x1040);
        for (start, length) in [(3, 4), (0, 0), (0, 5), (u64::MAX - 3, 4), (0, 4100)] {
            assert!(checked_end(start, length).is_err());
        }
    }

    #[test]
    fn decodes_branches_and_refuses_exception_and_system_instructions() {
        for word in [
            0x91000400, 0xd65f03c0, 0x14000002, 0x94000002, 0x54000040, 0x10000000, 0x58000000,
            0xd503201f, 0xd503233f, 0xd503245f,
        ] {
            assert!(decode(word).is_ok(), "{word:08x}: {:?}", decode(word));
        }
        for word in [
            0, 0xd4000001, 0xd4200000, 0xd51b4200, 0xc85f7c00, 0xc8007c01, 0xd503203f, 0xd8000000,
            0xd63f091f, 0xd65f0bff, 0xd53b4220,
        ] {
            assert!(decode(word).is_err(), "{word:08x}");
        }
    }

    #[test]
    fn rejects_exclusive_sequence_outside_requested_bytes_on_same_page() {
        let mut bytes = vec![0; 4096];
        bytes[0x80..0x84].copy_from_slice(&0xc85f7c00_u32.to_le_bytes());
        assert!(check_page(&bytes, 0x7000).is_err());
        assert!(check_page(&bytes[..4092], 0x7000).is_err());
        bytes[0x80..0x84].copy_from_slice(&0xd503201f_u32.to_le_bytes());
        assert!(check_page(&bytes, 0x7000).is_ok());
    }

    #[test]
    fn resolves_half_open_elf_and_runtime_ranges_and_deduplicates_aliases() {
        use std::{fs, os::fd::AsRawFd};
        struct MappedCode(*mut libc::c_void);
        impl MappedCode {
            fn new(file: &File, first_word: u32) -> Self {
                // SAFETY: mmap creates one private file-backed page at an OS-chosen
                // address; the file contains the entire page at offset 4096.
                let ptr = unsafe {
                    libc::mmap(
                        std::ptr::null_mut(),
                        4096,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_PRIVATE,
                        file.as_raw_fd(),
                        4096,
                    )
                };
                assert_ne!(ptr, libc::MAP_FAILED);
                let mut bytes = vec![0; 4096];
                for chunk in bytes.as_chunks_mut::<4>().0 {
                    chunk.copy_from_slice(&0xd503201f_u32.to_le_bytes());
                }
                bytes[..4].copy_from_slice(&first_word.to_le_bytes());
                // SAFETY: the new writable mapping owns 4096 bytes and does
                // not alias the source buffer. No test executes its A64 code.
                unsafe {
                    std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr.cast::<u8>(), 4096);
                }
                // SAFETY: ptr is the complete live mapping just allocated.
                let result =
                    unsafe { libc::mprotect(ptr, 4096, libc::PROT_READ | libc::PROT_EXEC) };
                assert_eq!(result, 0);
                Self(ptr)
            }
            fn pc(&self) -> u64 {
                self.0 as u64
            }
        }
        impl Drop for MappedCode {
            fn drop(&mut self) {
                // SAFETY: each guard exclusively owns its full live mapping.
                assert_eq!(unsafe { libc::munmap(self.0, 4096) }, 0);
            }
        }
        let path = std::env::temp_dir().join(format!("debugplz-range-test-{}", std::process::id()));
        let mut bytes = vec![0_u8; 8192];
        bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        for (offset, value) in [
            (16, 3_u16),
            (18, 183),
            (52, 64),
            (54, 56),
            (56, 1),
            (58, 64),
        ] {
            bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
        }
        bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
        bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
        bytes[64..68].copy_from_slice(&1_u32.to_le_bytes());
        bytes[68..72].copy_from_slice(&5_u32.to_le_bytes());
        for (offset, value) in [
            (72, 4096_u64),
            (80, 0x10000),
            (96, 4096),
            (104, 4096),
            (112, 4096),
        ] {
            bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        for chunk in bytes[4096..].as_chunks_mut::<4>().0 {
            chunk.copy_from_slice(&0xd503201f_u32.to_le_bytes());
        }
        bytes[4096..4100].copy_from_slice(&0x74959469_u32.to_le_bytes());
        // File-only exclusive instructions must not reject decrypted live code.
        bytes[4224..4228].copy_from_slice(&0xc85f7c00_u32.to_le_bytes());
        fs::write(&path, bytes).unwrap();
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let a = MappedCode::new(&file, 0xd10243ff);
        let b = MappedCode::new(&file, 0x91000400);
        let maps = ProcessMaps::read(std::process::id()).unwrap();
        let absolute = format!("{:#x}:8", a.pc()).parse().unwrap();
        let numeric = format!("{}+0x10000..0x11000", path.display())
            .parse()
            .unwrap();
        let plan = Plan::resolve(&maps, &[absolute, numeric]).unwrap();
        assert_eq!(plan.points.len(), 1024);
        assert_eq!(plan.points[0].instructions.len(), 2);
        assert_eq!(plan.points[0].instructions[&a.pc()].word, 0xd10243ff);
        assert_eq!(plan.points[0].instructions[&b.pc()].word, 0x91000400);
        assert_eq!(plan.points[0].file_offset, 4096);
        assert_eq!(plan.preview()["instruction_source"], "runtime");
        let spec = format!("{:#x}:8", a.pc()).parse().unwrap();
        let plan = Plan::resolve(&maps, &[spec]).unwrap();
        assert_eq!(plan.points.len(), 2);
        assert_eq!(
            plan.points[0]
                .instructions
                .keys()
                .copied()
                .collect::<Vec<_>>(),
            [a.pc()]
        );
        assert!(
            Plan::resolve(
                &maps,
                &[format!("{:#x}..{:#x}", a.pc(), a.pc() - 4).parse().unwrap()]
            )
            .is_err()
        );
        assert!(Plan::resolve(&maps, &[format!("{:#x}:4100", a.pc()).parse().unwrap()]).is_err());
        plan.verify_code().unwrap();
        file.write_all_at(&0_u32.to_le_bytes(), 4096).unwrap();
        plan.verify_code().unwrap(); // private plaintext survives a file change
        let memory = fs::OpenOptions::new()
            .write(true)
            .open("/proc/self/mem")
            .unwrap();
        memory
            .write_all_at(&0x91000400_u32.to_le_bytes(), a.pc())
            .unwrap();
        assert!(plan.verify_code().is_err());
        let plan = Plan::resolve(&maps, &[format!("{:#x}:8", a.pc()).parse().unwrap()]).unwrap();
        memory
            .write_all_at(&0xc85f7c00_u32.to_le_bytes(), a.pc() + 0x80)
            .unwrap();
        assert!(plan.verify_code().is_err()); // change elsewhere on the page
        assert!(Plan::resolve(&maps, &[format!("{:#x}:8", a.pc()).parse().unwrap()]).is_err());
        memory
            .write_all_at(&0xd503201f_u32.to_le_bytes(), a.pc() + 0x80)
            .unwrap();
        plan.verify_code().unwrap();
        // SAFETY: a owns exactly this page; the guard still owns its unmap.
        assert_eq!(unsafe { libc::mprotect(a.0, 4096, libc::PROT_READ) }, 0);
        assert!(plan.verify_code().is_err());
        fs::remove_file(path).unwrap();
    }
}
