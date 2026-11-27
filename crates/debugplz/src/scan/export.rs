use super::Path as ChainPath;
use crate::target::integer;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Deserializer, Serialize};
use std::{
    collections::BTreeSet,
    fs::File,
    io::{BufReader, BufWriter, Write},
    path::Path,
};

const VERSION: u16 = 1;

fn address<'de, D: Deserializer<'de>>(de: D) -> Result<u64, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Address {
        Number(u64),
        Text(String),
    }
    match Address::deserialize(de)? {
        Address::Number(n) => Ok(n),
        Address::Text(text) => integer(&text).map_err(serde::de::Error::custom),
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Segment {
    pub module: String,
    pub segment: String,
    #[serde(deserialize_with = "address")]
    pub start: u64,
    #[serde(deserialize_with = "address")]
    pub end: u64,
}

impl Segment {
    pub fn select_roots(segments: &[Self], modules: &[String]) -> Result<Vec<Self>> {
        if modules.is_empty() {
            return Ok(segments.to_vec());
        }
        let mut selected = Vec::new();
        for spec in modules {
            let filter = super::live::parse_module_range(spec)?;
            let mut matched = false;
            for segment in segments {
                let name_matches = filter.name.is_none_or(|name| {
                    let base = Path::new(name)
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or(name);
                    segment.module == name || segment.module == base
                });
                if !name_matches {
                    continue;
                }
                let (start, end) = if let Some((lo, hi)) = filter.range {
                    (segment.start.max(lo), segment.end.min(hi))
                } else {
                    (segment.start, segment.end)
                };
                if start < end {
                    matched = true;
                    selected.push(Self {
                        module: segment.module.clone(),
                        segment: segment.segment.clone(),
                        start,
                        end,
                    });
                }
            }
            if !matched {
                if let (None, Some((lo, hi))) = (filter.name, filter.range) {
                    selected.push(Self {
                        module: "[range]".to_owned(),
                        segment: format!("{lo:#x}-{hi:#x}"),
                        start: lo,
                        end: hi,
                    });
                } else {
                    anyhow::bail!("module {spec:?} is missing from the target");
                }
            }
        }
        selected.sort_unstable_by_key(|segment| (segment.start, segment.end));
        selected.dedup_by(|a, b| {
            a.module == b.module && a.segment == b.segment && a.start == b.start && a.end == b.end
        });
        Ok(selected)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Pointer {
    #[serde(deserialize_with = "address")]
    pub address: u64,
    #[serde(deserialize_with = "address")]
    pub value: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Snapshot {
    pub version: u16,
    pub segments: Vec<Segment>,
    pub pointers: Vec<Pointer>,
}

impl Snapshot {
    pub fn read(path: &Path, max_address: u64, width: u64) -> Result<Self> {
        let file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
        let mut snapshot: Self = serde_json::from_reader(BufReader::new(file))
            .with_context(|| format!("parsing {}", path.display()))?;
        ensure!(
            snapshot.version == VERSION,
            "unsupported pointer export version {}",
            snapshot.version
        );
        snapshot
            .segments
            .sort_unstable_by_key(|segment| segment.start);
        let mut end = 0;
        let mut names = BTreeSet::new();
        for segment in &snapshot.segments {
            ensure!(
                !segment.module.is_empty()
                    && !segment.segment.is_empty()
                    && segment.start < segment.end
                    && segment.end - 1 <= max_address,
                "invalid range or name for {}:{}",
                segment.module,
                segment.segment
            );
            ensure!(segment.start >= end, "module segments overlap");
            ensure!(
                names.insert((&segment.module, &segment.segment)),
                "duplicate segment {}:{}",
                segment.module,
                segment.segment
            );
            end = segment.end;
        }
        snapshot
            .pointers
            .sort_unstable_by_key(|p| (p.address, p.value));
        snapshot.pointers.dedup();
        for pair in snapshot.pointers.windows(2) {
            ensure!(
                pair[0].address != pair[1].address,
                "conflicting values for pointer slot {:#x}",
                pair[0].address
            );
        }
        for slot in &snapshot.pointers {
            ensure!(
                slot.address <= max_address - (width - 1) && slot.value <= max_address,
                "pointer at {:#x} does not fit the selected pointer width",
                slot.address
            );
        }
        Ok(snapshot)
    }

    pub fn write(&self, path: &Path) -> Result<()> {
        let file =
            File::create_new(path).with_context(|| format!("creating {}", path.display()))?;
        let mut writer = BufWriter::new(file);
        serde_json::to_writer(&mut writer, self)?;
        writer.write_all(b"\n")?;
        writer.flush()?;
        Ok(())
    }
}

pub(super) struct Results<W> {
    writer: W,
    count: u64,
}

impl<W: Write> Results<W> {
    pub fn new(mut writer: W, bits: u8, segments: &[&Segment]) -> Result<Self> {
        writer.write_all(b"DPTR")?;
        writer.write_all(&VERSION.to_le_bytes())?;
        writer.write_all(&[bits, 0])?;
        writer.write_all(&u32::try_from(segments.len())?.to_le_bytes())?;
        for segment in segments {
            for name in [&segment.module, &segment.segment] {
                writer.write_all(&u32::try_from(name.len())?.to_le_bytes())?;
                writer.write_all(name.as_bytes())?;
            }
        }
        Ok(Self { writer, count: 0 })
    }

    pub fn chain(&mut self, path: &ChainPath, root: usize, root_offset: u64) -> Result<()> {
        self.writer.write_all(&[1])?;
        self.writer.write_all(&path.target.to_le_bytes())?;
        self.writer.write_all(&u32::try_from(root)?.to_le_bytes())?;
        self.writer.write_all(&root_offset.to_le_bytes())?;
        self.writer
            .write_all(&u16::try_from(path.offsets.len())?.to_le_bytes())?;
        for offset in path.offsets.iter().rev() {
            self.writer.write_all(&offset.to_le_bytes())?;
        }
        self.count += 1;
        Ok(())
    }

    pub fn finish(mut self, complete: bool) -> Result<u64> {
        self.writer.write_all(&[0, u8::from(complete)])?;
        self.writer.write_all(&self.count.to_le_bytes())?;
        Ok(self.count)
    }
}
