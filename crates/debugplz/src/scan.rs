mod export;
mod live;
#[cfg(test)]
mod tests;

use crate::target::integer;
use anyhow::{Context, Result, ensure};
use clap::{Args, Subcommand, ValueEnum};
use export::{Pointer, Results, Segment, Snapshot};
use live::{LiveScanConfig, ReaderSpec};
use serde_json::json;
use std::{
    collections::BTreeSet,
    fs::File,
    io::{BufWriter, Write},
    path::PathBuf,
    str::FromStr,
    time::{Duration, Instant},
};

#[derive(Subcommand)]
pub enum Command {
    /// Trace pointer chains from target process memory or a structured debug export.
    Pointer(Options),
}

impl Command {
    pub fn run(self) -> Result<()> {
        match self {
            Self::Pointer(options) => options.run(),
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum Width {
    #[value(name = "32")]
    Bits32,
    #[value(name = "64")]
    Bits64,
}

impl Width {
    fn bits(self) -> u8 {
        match self {
            Self::Bits32 => 32,
            Self::Bits64 => 64,
        }
    }

    fn max_address(self) -> u64 {
        match self {
            Self::Bits32 => u64::from(u32::MAX),
            Self::Bits64 => u64::MAX,
        }
    }
}

#[derive(Clone)]
struct LayerLimit {
    layer: u16,
    offset: u64,
}

impl FromStr for LayerLimit {
    type Err = anyhow::Error;

    fn from_str(input: &str) -> Result<Self> {
        let (layer, offset) = input.split_once(':').context("expected LAYER:OFFSET")?;
        Ok(Self {
            layer: layer.parse().context("invalid layer number")?,
            offset: offset_limit(offset)?,
        })
    }
}

fn offset_limit(input: &str) -> Result<u64> {
    let offset = integer(input)?;
    ensure!(
        i64::try_from(offset).is_ok(),
        "offset limit exceeds i64::MAX"
    );
    Ok(offset)
}

#[derive(Args)]
pub struct Options {
    #[arg(required = true, value_name = "TARGET", value_parser = integer)]
    targets: Vec<u64>,
    /// Target process ID for live memory scanning.
    #[arg(
        short,
        long,
        required_unless_present = "input",
        conflicts_with = "input",
        value_parser = clap::value_parser!(u32).range(1..=2147483647)
    )]
    pid: Option<u32>,
    /// JSON export containing explicit pointer records and module segments.
    #[arg(long, required_unless_present = "pid")]
    input: Option<PathBuf>,
    /// Memory reader for live scans: syscall, pread, or path to a custom .so.
    #[arg(long, default_value = "syscall")]
    reader: ReaderSpec,
    /// Path for the binary chain results.
    #[arg(short, long)]
    output: PathBuf,
    /// Also save the normalized export as JSON.
    #[arg(long)]
    norm: Option<PathBuf>,
    #[arg(long, value_enum, default_value = "64")]
    bits: Width,
    /// Maximum dereferences per chain.
    #[arg(long, default_value_t = 4, value_parser = clap::value_parser!(u16).range(0..=256))]
    depth: u16,
    #[arg(long, default_value = "0x400", value_parser = offset_limit)]
    max_offset: u64,
    /// Restrict chain roots to these module names or ranges (e.g. libfoo.so, libfoo.so:0x1000-0x2000).
    #[arg(long, value_delimiter = ',')]
    modules: Vec<String>,
    /// Override the offset limit by layer, counting from the target.
    #[arg(long, value_delimiter = ',', value_name = "LAYER:OFFSET")]
    layer_limits: Vec<LayerLimit>,
    /// Stop the search after the given number of milliseconds.
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
    budget_ms: Option<u64>,
    /// Try shorter offsets first within each layer.
    #[arg(long)]
    auto_offset: bool,
    /// Accept 4-byte-aligned pointer slots at either pointer width.
    #[arg(long)]
    align4: bool,
    /// Step by 4 bytes across adjacent readable page boundaries when scanning 64-bit pointers.
    #[arg(long)]
    cross_page_step4: bool,
    /// Allow offsets below zero.
    #[arg(long)]
    negative_offsets: bool,
    /// Query /proc/PID/pagemap to skip unpopulated pages before reading memory.
    #[arg(long, alias = "page-table-query")]
    pagemap: bool,
    /// Also attempt to read restricted (non-readable / guard) VMA regions.
    #[arg(long, alias = "read-restricted")]
    restricted: bool,
}

impl Options {
    fn limits(&self) -> Result<Vec<u64>> {
        let mut limits = vec![self.max_offset; usize::from(self.depth)];
        let mut layers = BTreeSet::new();
        for rule in &self.layer_limits {
            ensure!(
                (1..=self.depth).contains(&rule.layer) && layers.insert(rule.layer),
                "layer {} must be unique and within 1..={}",
                rule.layer,
                self.depth
            );
            limits[usize::from(rule.layer - 1)] = rule.offset;
        }
        Ok(limits)
    }

    fn run(self) -> Result<()> {
        let limits = self.limits()?;
        let targets = self.targets.iter().copied().collect::<BTreeSet<_>>();
        let max_address = self.bits.max_address();
        ensure!(
            targets.iter().all(|&target| target <= max_address),
            "target does not fit the selected pointer width"
        );
        let width = u64::from(self.bits.bits() / 8);
        let alignment = if self.align4 || self.cross_page_step4 {
            4
        } else {
            width
        };
        let max_limit = limits.iter().copied().max().unwrap_or(self.max_offset);
        let mut snapshot = if let Some(input) = &self.input {
            Snapshot::read(input, max_address, width)?
        } else {
            let pid = self.pid.context("missing --pid or --input")?;
            let target_vec: Vec<u64> = targets.iter().copied().collect();
            let config = LiveScanConfig {
                pid,
                max_address,
                width,
                align4: self.align4,
                cross_page_step4: self.cross_page_step4,
                pagemap: self.pagemap,
                restricted: self.restricted,
                value_margin: max_limit,
                targets: &target_vec,
            };
            live::scan_process(&config, &self.reader)?
        };
        let owned_roots = Segment::select_roots(&snapshot.segments, &self.modules)?;
        let segments: Vec<&Segment> = owned_roots.iter().collect();
        let mut output = File::create_new(&self.output)
            .with_context(|| format!("creating {}", self.output.display()))?;
        if let Some(path) = &self.norm {
            snapshot.write(path)?;
        }
        let mut index = std::mem::take(&mut snapshot.pointers);
        index.retain(|pointer| pointer.value != 0 && pointer.address.is_multiple_of(alignment));
        index.sort_unstable_by_key(|pointer| (pointer.value, pointer.address));
        let mut writer = BufWriter::new(&mut output);
        let results = Results::new(&mut writer, self.bits.bits(), &segments)?;
        let mut search = Search {
            index: &index,
            segments: &segments,
            limits: &limits,
            negative: self.negative_offsets,
            nearest_first: self.auto_offset,
            started: Instant::now(),
            budget: self.budget_ms.map(Duration::from_millis),
            results,
        };
        let mut path = Path::default();
        let mut complete = true;
        for target in targets {
            path.target = target;
            if !search.walk(target, &mut path)? {
                complete = false;
                break;
            }
        }
        let count = search.results.finish(complete)?;
        writer.flush()?;
        crate::emit(&json!({"chains": count, "complete": complete}), true)
    }
}

#[derive(Default)]
struct Path {
    target: u64,
    slots: Vec<u64>,
    offsets: Vec<i64>,
}

struct Search<'a, W> {
    index: &'a [Pointer],
    segments: &'a [&'a Segment],
    limits: &'a [u64],
    negative: bool,
    nearest_first: bool,
    started: Instant,
    budget: Option<Duration>,
    results: Results<W>,
}

impl<W: Write> Search<'_, W> {
    fn expired(&self) -> bool {
        self.budget
            .is_some_and(|budget| self.started.elapsed() >= budget)
    }

    fn walk(&mut self, address: u64, path: &mut Path) -> Result<bool> {
        if self.expired() {
            return Ok(false);
        }
        let after = self
            .segments
            .partition_point(|segment| segment.start <= address);
        if let Some(root) = after.checked_sub(1) {
            let segment = self.segments[root];
            if address < segment.end {
                self.results.chain(path, root, address - segment.start)?;
                if !path.slots.is_empty() {
                    return Ok(true);
                }
            }
        }
        let Some(&limit) = self.limits.get(path.offsets.len()) else {
            return Ok(true);
        };
        if self.segments.is_empty() {
            return Ok(true);
        }
        for pointer in candidates(
            self.index,
            address,
            limit,
            self.negative,
            self.nearest_first,
        ) {
            if self.expired() {
                return Ok(false);
            }
            if pointer.address == path.target || path.slots.contains(&pointer.address) {
                continue;
            }
            let offset = i64::try_from(i128::from(address) - i128::from(pointer.value))?;
            path.slots.push(pointer.address);
            path.offsets.push(offset);
            let done = self.walk(pointer.address, path)?;
            path.offsets.pop();
            path.slots.pop();
            if !done {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

fn candidates(
    index: &[Pointer],
    address: u64,
    limit: u64,
    negative: bool,
    nearest_first: bool,
) -> impl Iterator<Item = Pointer> + '_ {
    let min = address.saturating_sub(limit);
    let max = if negative {
        address.saturating_add(limit)
    } else {
        address
    };
    let begin = index.partition_point(|entry| entry.value < min);
    let end = index.partition_point(|entry| entry.value <= max);
    let entries = &index[begin..end];
    let mut right = if nearest_first {
        entries.partition_point(|entry| entry.value <= address)
    } else {
        0
    };
    let mut left = right;
    std::iter::from_fn(move || {
        let before = left.checked_sub(1).map(|i| entries[i]);
        let after = entries.get(right).copied();
        if let Some(entry) = before
            && after.is_none_or(|next| address - entry.value <= next.value - address)
        {
            left -= 1;
            Some(entry)
        } else {
            right += usize::from(after.is_some());
            after
        }
    })
}
