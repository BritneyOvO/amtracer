use crate::target::{Mapping, ProcessMaps};
use anyhow::{Result, ensure};
use framehop::{
    ExplicitModuleSectionInfo, Module, Unwinder,
    aarch64::{CacheAarch64, PtrAuthMask, UnwindRegsAarch64, UnwinderAarch64},
};
use object::{Object, ObjectSection, ObjectSegment, ObjectSymbol};
use serde_json::{Value, json};
use std::{collections::BTreeMap, io::Read, ops::Range, sync::Arc};

pub struct Snapshot<'a> {
    pub pc: u64,
    pub sp: u64,
    pub fp: u64,
    pub lr: u64,
    pub bytes: &'a [u8],
}
impl Snapshot<'_> {
    fn read(&self, address: u64) -> Result<u64, ()> {
        let offset = usize::try_from(address.checked_sub(self.sp).ok_or(())?).map_err(|_| ())?;
        let end = offset.checked_add(8).ok_or(())?;
        let bytes = self.bytes.get(offset..end).ok_or(())?;
        Ok(u64::from_le_bytes(bytes.try_into().map_err(|_| ())?))
    }
}

struct Symbol {
    address: u64,
    size: u64,
    name: String,
}
struct Image {
    sections: ExplicitModuleSectionInfo<Arc<[u8]>>,
    symbols: Vec<Symbol>,
    loads: Vec<(u64, u64, u64)>,
    build_id: Option<String>,
}
impl Image {
    fn read(mapping: &Mapping, pid: u32) -> Result<Self> {
        let mut bytes = Vec::new();
        mapping.open_backing_file(pid)?.read_to_end(&mut bytes)?;
        let elf = object::File::parse(bytes.as_slice())?;
        ensure!(
            elf.architecture() == object::Architecture::Aarch64 && elf.is_little_endian(),
            "not an ARM64 ELF"
        );
        let range = |name: &str| {
            let section = elf.section_by_name(name)?;
            Some(section.address()..section.address().checked_add(section.size())?)
        };
        let data = |name: &str| -> Result<Option<Arc<[u8]>>> {
            elf.section_by_name(name)
                .map(|s| {
                    s.uncompressed_data()
                        .map(|b| Arc::from(b.into_owned()))
                        .map_err(Into::into)
                })
                .transpose()
        };
        let sections = ExplicitModuleSectionInfo {
            base_svma: 0,
            text_svma: range(".text"),
            text: data(".text")?,
            eh_frame_svma: range(".eh_frame"),
            eh_frame: data(".eh_frame")?,
            eh_frame_hdr_svma: range(".eh_frame_hdr"),
            eh_frame_hdr: data(".eh_frame_hdr")?,
            debug_frame: data(".debug_frame")?,
            got_svma: range(".got"),
            ..Default::default()
        };
        let mut symbols = elf
            .symbols()
            .chain(elf.dynamic_symbols())
            .filter(|s| s.is_definition() && s.kind() == object::SymbolKind::Text)
            .filter_map(|s| {
                Some(Symbol {
                    address: s.address(),
                    size: s.size(),
                    name: s.name().ok()?.to_owned(),
                })
            })
            .collect::<Vec<_>>();
        symbols.sort_by_key(|s| s.address);
        symbols.dedup_by_key(|s| s.address);
        let loads = elf.segments().filter(|s| matches!(s.flags(), object::SegmentFlags::Elf{p_flags,..} if p_flags.0 & 1 != 0))
            .map(|s| {let (offset,size)=s.file_range(); (offset,size,s.address())}).collect();
        let build_id = elf
            .build_id()?
            .map(|id| id.iter().map(|b| format!("{b:02x}")).collect());
        Ok(Self {
            sections,
            symbols,
            loads,
            build_id,
        })
    }

    fn load_bias(&self, mapping: &Mapping) -> Result<u64> {
        let mut biases = self
            .loads
            .iter()
            .filter_map(|&(offset, size, address)| {
                let end = offset.checked_add(size)?;
                if mapping.offset >= end
                    || mapping.offset.checked_add(mapping.end - mapping.start)? <= offset
                {
                    return None;
                }
                u64::try_from(
                    i128::from(mapping.start) + i128::from(offset)
                        - i128::from(mapping.offset)
                        - i128::from(address),
                )
                .ok()
            })
            .collect::<Vec<_>>();
        biases.sort_unstable();
        biases.dedup();
        ensure!(biases.len() == 1, "ambiguous executable PT_LOAD mapping");
        Ok(biases[0])
    }
}

struct LoadedImage {
    range: Range<u64>,
    bias: u64,
    path: String,
    image: Arc<Image>,
}

pub struct NativeUnwinder {
    unwinder: UnwinderAarch64<Arc<[u8]>>,
    cache: CacheAarch64,
    images: Vec<LoadedImage>,
    executable: Vec<Range<u64>>,
    mask: PtrAuthMask,
}
impl NativeUnwinder {
    pub fn new(maps: &ProcessMaps) -> Self {
        let mut unwinder = UnwinderAarch64::new();
        let mut images = Vec::new();
        let mut files = BTreeMap::new();
        let mut executable = maps
            .mappings
            .iter()
            .filter(|m| m.executable)
            .map(|m| m.start..m.end)
            .collect::<Vec<_>>();
        executable.sort_unstable_by_key(|r| r.start);
        for mapping in maps
            .mappings
            .iter()
            .filter(|m| m.executable && m.inode != 0)
        {
            let key = (mapping.device, mapping.inode);
            let image = files
                .entry(key)
                .or_insert_with(|| Image::read(mapping, maps.pid).map(Arc::new));
            let image = match image {
                Ok(image) => image.clone(),
                Err(error) => {
                    eprintln!("unwind: {}: {error:#}", mapping.path.display());
                    continue;
                }
            };
            let bias = match image.load_bias(mapping) {
                Ok(bias) => bias,
                Err(error) => {
                    eprintln!("unwind: {}: {error:#}", mapping.path.display());
                    continue;
                }
            };
            let path = mapping.path.to_string_lossy().into_owned();
            let range = mapping.start..mapping.end;
            unwinder.add_module(Module::new(
                path.clone(),
                range.clone(),
                bias,
                image.sections.clone(),
            ));
            images.push(LoadedImage {
                range,
                bias,
                path,
                image,
            });
        }
        images.sort_unstable_by_key(|img| img.range.start);
        // Derive the address width from this process's executable mappings.
        // Every returned address is also checked against those mappings.
        let highest = executable
            .iter()
            .map(|r| r.end - 1)
            .max()
            .unwrap_or(u64::MAX);
        Self {
            unwinder,
            cache: CacheAarch64::new(),
            images,
            executable,
            mask: PtrAuthMask::from_max_known_address(highest),
        }
    }

    fn is_executable(executable: &[Range<u64>], address: u64) -> bool {
        let after = executable.partition_point(|r| r.start <= address);
        after
            .checked_sub(1)
            .is_some_and(|idx| address < executable[idx].end)
    }

    fn find_image(images: &[LoadedImage], address: u64) -> Option<&LoadedImage> {
        let after = images.partition_point(|img| img.range.start <= address);
        after
            .checked_sub(1)
            .map(|idx| &images[idx])
            .filter(|img| address < img.range.end)
    }

    pub fn unwind(&mut self, snapshot: Snapshot<'_>) -> Value {
        let regs = UnwindRegsAarch64::new_with_ptr_auth_mask(
            self.mask,
            snapshot.lr,
            snapshot.sp,
            snapshot.fp,
        );
        let mut read = |address| snapshot.read(address);
        let mut frames = self
            .unwinder
            .iter_frames(snapshot.pc, regs, &mut self.cache, &mut read);
        let mut output = Vec::new();
        let end = loop {
            if output.len() == 128 {
                break "depth_limit".to_owned();
            }
            match frames.next() {
                Ok(Some(frame)) => {
                    let address = frame.address_for_lookup();
                    if !Self::is_executable(&self.executable, address) {
                        break format!("unmapped_code:{address:#x}");
                    }
                    let mut entry = json!({"pc":format!("{:#x}",frame.address()),"lookup_pc":format!("{address:#x}"),"return_address":frame.is_return_address()});
                    if let Some(module) = Self::find_image(&self.images, address) {
                        let svma = address - module.bias;
                        entry["module"] = json!(module.path.as_str());
                        entry["module_offset"] = json!(format!("{svma:#x}"));
                        entry["build_id"] = json!(module.image.build_id.as_deref());
                        let index = module.image.symbols.partition_point(|s| s.address <= svma);
                        if let Some(symbol) = index
                            .checked_sub(1)
                            .and_then(|i| module.image.symbols.get(i))
                            && (symbol.size == 0 || svma - symbol.address < symbol.size)
                        {
                            entry["symbol"] = json!(symbol.name.as_str());
                            entry["symbol_offset"] = json!(format!("{:#x}", svma - symbol.address));
                        }
                    }
                    output.push(entry);
                }
                Ok(None) => break "complete".to_owned(),
                Err(framehop::Error::CouldNotReadStack(address)) => {
                    break format!("outside_snapshot:{address:#x}");
                }
                Err(error) => break error.to_string(),
            }
        };
        json!({"frames":output,"end":end,"snapshot_bytes":snapshot.bytes.len(),"return_address_mask":format!("{:#x}",self.mask.0)})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn snapshot_never_reads_live_memory() {
        let data = 0x1122334455667788_u64.to_le_bytes();
        let snapshot = Snapshot {
            pc: 0,
            sp: 0x1000,
            fp: 0,
            lr: 0,
            bytes: &data,
        };
        assert_eq!(snapshot.read(0x1000), Ok(0x1122334455667788));
        for address in [0xfff, 0x1001, 0x1008, u64::MAX] {
            assert!(snapshot.read(address).is_err());
        }
    }
    #[test]
    fn load_bias_uses_segment_virtual_address() {
        let mapping: Mapping = "7000-9000 r-xp 00003000 08:01 42 /test.so".parse().unwrap();
        let image = Image {
            sections: Default::default(),
            symbols: Vec::new(),
            loads: vec![(0x3000, 0x2000, 0x5000)],
            build_id: None,
        };
        assert_eq!(image.load_bias(&mapping).unwrap(), 0x2000);
    }
}
