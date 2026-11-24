use crate::target::{Location, ProbeSpec, ProcessMaps, ResolvedProbe, integer};
use anyhow::{Context, Result, bail, ensure};
use object::{Object, ObjectSegment, ObjectSymbol, SegmentFlags};
use serde_json::{Value, json};
use std::{collections::BTreeMap, os::unix::fs::FileExt, str::FromStr};
use yaxpeax_arch::{Decoder, U8Reader};
use yaxpeax_arm::armv8::a64::InstDecoder;

pub const MAX_SITES: usize = 1024;
pub const MAX_ADDRESSES: usize = 4096;
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
    pub word: u32,
    pub assembly: String,
    pub addresses: Vec<u64>,
}

pub struct Plan {
    pub targets: Vec<ResolvedProbe>,
    pub points: Vec<Point>,
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
        };
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
            check_pages(&bytes, target.file_offset, end)?;
            let target_index = plan.targets.len();
            for offset in (target.file_offset..end).step_by(4) {
                let address = target
                    .elf_address
                    .checked_add(offset - target.file_offset)
                    .context("ELF range address overflow")?;
                let word = u32::from_le_bytes(
                    bytes[usize::try_from(offset)?..usize::try_from(offset + 4)?].try_into()?,
                );
                let assembly = decode(word).with_context(|| {
                    format!("{}+{address:#x} ({word:08x})", target.path.display())
                })?;
                let mut addresses = Vec::new();
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
                        addresses.push(pc);
                    }
                }
                ensure!(
                    !addresses.is_empty(),
                    "instruction {address:#x} has no private read-only executable mapping"
                );
                let key = (identity, offset);
                if let Some(&index) = unique.get(&key) {
                    let old: &mut Point = &mut plan.points[index];
                    ensure!(
                        old.word == word,
                        "backing file changed during range resolution"
                    );
                    old.addresses.extend(addresses);
                    old.addresses.sort_unstable();
                    old.addresses.dedup();
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
                        word,
                        assembly,
                        addresses,
                    });
                }
            }
            plan.targets.push(target);
        }
        ensure!(
            plan.points.iter().map(|p| p.addresses.len()).sum::<usize>() <= MAX_ADDRESSES,
            "instruction trace exceeds {MAX_ADDRESSES} runtime addresses"
        );
        Ok(plan)
    }

    pub fn preview(&self) -> Value {
        json!({"sites": self.points.len(), "instructions": self.points.iter().enumerate().map(|(i, p)| {
            json!({"site":i + 1, "path":self.targets[p.target].path, "file_offset":format!("{:#x}",p.file_offset),
                "elf_address":format!("{:#x}",p.elf_address), "opcode":format!("{:08x}",p.word),
                "instruction":p.assembly, "addresses":p.addresses.iter().map(|pc|format!("{pc:#x}")).collect::<Vec<_>>()})
        }).collect::<Vec<_>>()})
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

fn check_pages(bytes: &[u8], start: u64, end: u64) -> Result<()> {
    let first = usize::try_from(start & !(PAGE_BYTES - 1))?;
    let last = usize::try_from(
        end.checked_add(PAGE_BYTES - 1)
            .context("page range overflow")?
            & !(PAGE_BYTES - 1),
    )?
    .min(bytes.len());
    for (index, chunk) in bytes[first..last].as_chunks::<4>().0.iter().enumerate() {
        let word = u32::from_le_bytes(*chunk);
        ensure!(
            word & 0x3f80_0000 != 0x0800_0000,
            "exclusive instruction at file offset {:#x} shares a trace page; BRK may break its reservation",
            first + index * 4
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
        let mut bytes = vec![0; 8192];
        bytes[0x80..0x84].copy_from_slice(&0xc85f7c00_u32.to_le_bytes());
        assert!(check_pages(&bytes, 0x100, 0x110).is_err());
        assert!(check_pages(&bytes, 0x1000, 0x1010).is_ok());
    }

    #[test]
    fn resolves_half_open_elf_and_runtime_ranges_and_deduplicates_aliases() {
        use std::{fs, os::unix::fs::MetadataExt};
        let path = std::env::temp_dir().join(format!("amtracer-range-test-{}", std::process::id()));
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
        fs::write(&path, bytes).unwrap();
        let metadata = fs::metadata(&path).unwrap();
        let mapping = |start: u64| {
            format!(
                "{start:x}-{:x} r-xp 00001000 {:02x}:{:02x} {} {}",
                start + 4096,
                libc::major(metadata.dev()),
                libc::minor(metadata.dev()),
                metadata.ino(),
                path.display()
            )
            .parse()
            .unwrap()
        };
        let maps = ProcessMaps {
            pid: std::process::id(),
            mappings: vec![mapping(0x7000), mapping(0x9000)],
        };
        let absolute = "0x7000..0x7008".parse().unwrap();
        let numeric = format!("{}+0x10000..0x11000", path.display())
            .parse()
            .unwrap();
        let plan = Plan::resolve(&maps, &[absolute, numeric]).unwrap();
        assert_eq!(plan.points.len(), 1024);
        assert_eq!(plan.points[0].addresses, [0x7000, 0x9000]);
        assert_eq!(plan.points[0].file_offset, 4096);
        let plan = Plan::resolve(&maps, &["0x7000:8".parse().unwrap()]).unwrap();
        assert_eq!(plan.points.len(), 2);
        assert_eq!(plan.points[0].addresses, [0x7000]);
        assert!(Plan::resolve(&maps, &["0x7000..0x6ffc".parse().unwrap()]).is_err());
        assert!(Plan::resolve(&maps, &["0x7000:4100".parse().unwrap()]).is_err());
        fs::remove_file(path).unwrap();
    }
}
