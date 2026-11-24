use anyhow::{Context, Result, bail, ensure};
use object::{Object, ObjectSegment, ObjectSymbol, SegmentFlags};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::Read,
    os::unix::{fs::MetadataExt, io::AsRawFd},
    path::{Path, PathBuf},
    str::FromStr,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mapping {
    pub start: u64,
    pub end: u64,
    pub offset: u64,
    pub executable: bool,
    pub writable: bool,
    pub shared: bool,
    pub inode: u64,
    pub device: (u32, u32),
    pub path: PathBuf,
}

impl FromStr for Mapping {
    type Err = anyhow::Error;
    fn from_str(line: &str) -> Result<Self> {
        fn token<'a>(rest: &mut &'a str) -> Result<&'a str> {
            *rest = rest.trim_start();
            let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
            ensure!(end != 0, "missing maps field");
            let value = &rest[..end];
            *rest = &rest[end..];
            Ok(value)
        }
        let mut rest = line;
        let (start, end) = token(&mut rest)?.split_once('-').context("maps range")?;
        let permissions = token(&mut rest)?;
        let offset = u64::from_str_radix(token(&mut rest)?, 16)?;
        let (major, minor) = token(&mut rest)?.split_once(':').context("maps device")?;
        let device = (
            u32::from_str_radix(major, 16)?,
            u32::from_str_radix(minor, 16)?,
        );
        let inode = token(&mut rest)?.parse()?;
        let mapping = Self {
            start: u64::from_str_radix(start, 16)?,
            end: u64::from_str_radix(end, 16)?,
            offset,
            executable: permissions.contains('x'),
            writable: permissions.contains('w'),
            shared: permissions.ends_with('s'),
            inode,
            device,
            path: PathBuf::from(rest.trim_start()),
        };
        ensure!(mapping.start < mapping.end, "empty maps range");
        Ok(mapping)
    }
}

impl Mapping {
    pub fn open_backing_file(&self, pid: u32) -> Result<File> {
        let original = self.path.to_string_lossy();
        let clean = original.strip_suffix(" (deleted)").unwrap_or(&original);
        let paths = [
            PathBuf::from(format!("/proc/{pid}/root{clean}")),
            PathBuf::from(format!(
                "/proc/{pid}/map_files/{:x}-{:x}",
                self.start, self.end
            )),
        ];
        for path in paths {
            if let Ok(file) = File::open(path) {
                let metadata = file.metadata()?;
                if metadata.ino() == self.inode
                    && i64::from(libc::major(metadata.dev())) == i64::from(self.device.0)
                    && i64::from(libc::minor(metadata.dev())) == i64::from(self.device.1)
                {
                    return Ok(file);
                }
            }
        }
        bail!(
            "cannot open original mapped inode for {}",
            self.path.display()
        )
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Location {
    ElfAddress(u64),
    Symbol(String, u64),
    RuntimeAddress(u64),
}
#[derive(Clone, Debug)]
pub struct ProbeSpec {
    pub library: Option<String>,
    pub location: Location,
}

pub fn integer(input: &str) -> Result<u64> {
    Ok(if let Some(hex) = input.strip_prefix("0x") {
        u64::from_str_radix(hex, 16)?
    } else {
        input.parse()?
    })
}

impl FromStr for ProbeSpec {
    type Err = anyhow::Error;
    fn from_str(input: &str) -> Result<Self> {
        if input.starts_with("0x") && !input.contains('+') {
            return Ok(Self {
                library: None,
                location: Location::RuntimeAddress(integer(input)?),
            });
        }
        let (library, point) = input
            .split_once('+')
            .context("expected LIB+OFFSET, LIB+SYMBOL or 0xVA")?;
        ensure!(
            !library.is_empty() && !point.is_empty(),
            "empty library or point"
        );
        let location = if point.starts_with("0x") || point.bytes().all(|b| b.is_ascii_digit()) {
            Location::ElfAddress(integer(point)?)
        } else if let Some((symbol, offset)) = point.rsplit_once('+') {
            ensure!(!symbol.is_empty(), "empty symbol");
            Location::Symbol(symbol.to_owned(), integer(offset)?)
        } else {
            Location::Symbol(point.to_owned(), 0)
        };
        Ok(Self {
            library: Some(library.to_owned()),
            location,
        })
    }
}

pub struct ResolvedProbe {
    pub file: File,
    pub path: PathBuf,
    pub file_offset: u64,
    pub elf_address: u64,
    pub mappings: Vec<Mapping>,
}
impl ResolvedProbe {
    pub fn attach_path(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.file.as_raw_fd()))
    }
}

pub struct ProcessMaps {
    pub pid: u32,
    pub mappings: Vec<Mapping>,
}
impl ProcessMaps {
    pub fn read(pid: u32) -> Result<Self> {
        ensure!(pid != 0 && pid <= i32::MAX as u32, "invalid process ID");
        let text =
            fs::read_to_string(format!("/proc/{pid}/maps")).context("reading target maps")?;
        let mappings = text.lines().map(str::parse).collect::<Result<Vec<_>>>()?;
        Ok(Self { pid, mappings })
    }

    pub fn resolve(&self, spec: &ProbeSpec) -> Result<ResolvedProbe> {
        let mapping = match &spec.location {
            Location::RuntimeAddress(address) => self
                .mappings
                .iter()
                .find(|m| m.start <= *address && *address < m.end && m.executable)
                .context("address is not in an executable file mapping")?,
            Location::ElfAddress(_) | Location::Symbol(_, _) => {
                let name = spec.library.as_deref().context("missing library")?;
                let mut matches = BTreeMap::new();
                for m in self
                    .mappings
                    .iter()
                    .filter(|m| m.executable && m.inode != 0)
                {
                    if m.path == Path::new(name) || m.path.file_name().is_some_and(|n| n == name) {
                        matches.entry((&m.path, m.inode)).or_insert(m);
                    }
                }
                ensure!(
                    matches.len() == 1,
                    "library {name}: {} candidates: {:?}",
                    matches.len(),
                    matches.keys()
                );
                *matches.values().next().context("library not loaded")?
            }
        };
        ensure!(
            mapping.inode != 0 && mapping.path.is_absolute(),
            "anonymous/JIT mapping cannot use standard uprobe"
        );
        let mut file = mapping.open_backing_file(self.pid)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        let elf = object::File::parse(bytes.as_slice())
            .context("parsing mapped ELF (APK entries require APK resolver)")?;
        ensure!(
            elf.architecture() == object::Architecture::Aarch64
                && elf.is_64()
                && elf.is_little_endian(),
            "target must be AArch64 little-endian ELF"
        );
        let file_offset = match &spec.location {
            Location::RuntimeAddress(address) => mapping
                .offset
                .checked_add(address - mapping.start)
                .context("file offset overflow")?,
            Location::ElfAddress(address) => Self::elf_offset(&elf, *address)?,
            Location::Symbol(name, additional) => {
                let symbol = elf
                    .dynamic_symbols()
                    .chain(elf.symbols())
                    .find(|s| s.is_definition() && s.name().ok() == Some(name.as_str()))
                    .context("symbol not found")?;
                let address = symbol
                    .address()
                    .checked_add(*additional)
                    .context("symbol offset overflow")?;
                Self::elf_offset(&elf, address)?
            }
        };
        ensure!(file_offset % 4 == 0, "AArch64 probe must be 4-byte aligned");
        ensure!(
            file_offset
                .checked_add(4)
                .is_some_and(|end| end <= bytes.len() as u64),
            "probe outside file"
        );
        ensure!(
            elf.segments().any(|s| {
                let (offset, size) = s.file_range();
                Self::executable(s.flags())
                    && size >= 4
                    && file_offset >= offset
                    && file_offset - offset <= size - 4
            }),
            "probe outside executable PT_LOAD"
        );
        let mappings: Vec<_> = self
            .mappings
            .iter()
            .filter(|m| {
                m.executable
                    && m.device == mapping.device
                    && m.inode == mapping.inode
                    && file_offset >= m.offset
                    && file_offset - m.offset < m.end - m.start
                    && match spec.location {
                        Location::RuntimeAddress(address) => m.start <= address && address < m.end,
                        Location::ElfAddress(_) | Location::Symbol(_, _) => true,
                    }
            })
            .cloned()
            .collect();
        ensure!(
            !mappings.is_empty(),
            "probe offset is not mapped executable"
        );
        Ok(ResolvedProbe {
            file,
            path: mapping.path.clone(),
            file_offset,
            mappings,
            elf_address: elf
                .segments()
                .filter(|s| Self::executable(s.flags()))
                .find_map(|s| {
                    let (offset, size) = s.file_range();
                    let relative = file_offset.checked_sub(offset)?;
                    (relative < size)
                        .then(|| s.address().checked_add(relative))
                        .flatten()
                })
                .context("no ELF address for probe")?,
        })
    }

    fn executable(flags: SegmentFlags) -> bool {
        matches!(flags, SegmentFlags::Elf { p_flags, .. } if p_flags.0 & 1 != 0)
    }
    fn elf_offset(elf: &object::File<'_>, address: u64) -> Result<u64> {
        for segment in elf.segments().filter(|s| Self::executable(s.flags())) {
            let (offset, size) = segment.file_range();
            if let Some(relative) = address.checked_sub(segment.address()).filter(|r| *r < size) {
                return offset.checked_add(relative).context("ELF offset overflow");
            }
        }
        bail!("ELF virtual address {address:#x} outside executable file-backed segment")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn maps_preserves_spaces_and_offset() {
        let m: Mapping = "7000-9000 r-xp 00003000 08:01 42  /tmp/a  b.so"
            .parse()
            .unwrap();
        assert_eq!(m.path, PathBuf::from("/tmp/a  b.so"));
        assert_eq!(m.offset, 0x3000);
    }
    #[test]
    fn parses_all_locations() {
        assert_eq!(
            "lib.so+0x1234".parse::<ProbeSpec>().unwrap().location,
            Location::ElfAddress(0x1234)
        );
        assert_eq!(
            "lib.so+fn+0x10".parse::<ProbeSpec>().unwrap().location,
            Location::Symbol("fn".into(), 16)
        );
        assert_eq!(
            "0x701234".parse::<ProbeSpec>().unwrap().location,
            Location::RuntimeAddress(0x701234)
        );
        assert!("lib.so+".parse::<ProbeSpec>().is_err());
    }
}
