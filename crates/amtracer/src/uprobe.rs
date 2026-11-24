use crate::{
    Common, RunControl, emit,
    target::{ProbeSpec, ProcessMaps},
    wait_readable,
};
use amtracer_abi::{Header, ProbeConfig};
use anyhow::{Context, Result, ensure};
use aya::{
    Ebpf,
    maps::{HashMap, PerCpuArray, RingBuf},
    programs::{
        UProbe,
        uprobe::{UProbeAttachLocation, UProbeAttachPoint, UProbeScope},
    },
};
use clap::Args;
use serde_json::json;
use std::{num::NonZeroU32, os::fd::AsRawFd, path::PathBuf};

#[derive(Args)]
pub struct Options {
    #[command(flatten)]
    pub common: Common,
    #[arg(long, required = true)]
    pub probe: Vec<ProbeSpec>,
    #[arg(long)]
    pub object: Option<PathBuf>,
    #[arg(long)]
    pub regs: bool,
    #[arg(long)]
    pub stack: bool,
    #[arg(long, default_value_t = 8192, value_parser = clap::value_parser!(u32).range(1..=16384))]
    pub stack_bytes: u32,
}

#[repr(transparent)]
#[derive(Clone, Copy)]
struct MapConfig(ProbeConfig);
// SAFETY: ProbeConfig consists of two u32 fields, without padding or invalid bit patterns.
unsafe impl aya::Pod for MapConfig {}

pub fn run(options: Options) -> Result<()> {
    let pid = options.common.pid;
    let maps = ProcessMaps::read(pid)?;
    ensure!(
        options.probe.len() <= amtracer_abi::MAX_PROBES as usize,
        "too many probes"
    );
    let resolved = options
        .probe
        .iter()
        .map(|p| maps.resolve(p))
        .collect::<Result<Vec<_>>>()?;
    let object = match options.object {
        Some(path) => path,
        None => std::env::current_exe()?.with_file_name("amtracer-ebpf.o"),
    };
    let mut ebpf =
        Ebpf::load_file(&object).with_context(|| format!("loading {}", object.display()))?;
    {
        let mut configs = HashMap::<_, u64, MapConfig>::try_from(
            ebpf.map_mut("CONFIGS").context("CONFIGS map missing")?,
        )?;
        for (index, _) in resolved.iter().enumerate() {
            configs.insert(
                &(index as u64 + 1),
                &MapConfig(ProbeConfig {
                    tgid: pid,
                    stack_bytes: if options.stack {
                        options.stack_bytes
                    } else {
                        0
                    },
                }),
                0,
            )?;
        }
    }
    let program: &mut UProbe = ebpf
        .program_mut("capture")
        .context("capture program missing")?
        .try_into()?;
    program.load().context("verifying uprobe program")?;
    for (index, probe) in resolved.iter().enumerate() {
        let point = UProbeAttachPoint {
            location: UProbeAttachLocation::AbsoluteOffset(probe.file_offset),
            cookie: Some(index as u64 + 1),
        };
        program
            .attach(
                [point],
                probe.attach_path(),
                UProbeScope::OneProcess(NonZeroU32::new(pid).context("invalid PID")?),
            )
            .with_context(|| {
                format!(
                    "attaching {}+{:#x}",
                    probe.path.display(),
                    probe.file_offset
                )
            })?;
    }
    let mut events = RingBuf::try_from(ebpf.take_map("EVENTS").context("EVENTS map missing")?)?;
    let mut control = RunControl::new(&options.common)?;
    while control.running() {
        while let Some(record) = events.next() {
            ensure!(record.len() >= size_of::<Header>(), "short uprobe record");
            // SAFETY: Header is repr(C) with integer/array fields only; all bit
            // patterns are valid and the complete prefix was checked above.
            let header = unsafe { record.as_ptr().cast::<Header>().read_unaligned() };
            ensure!(
                header.magic == amtracer_abi::EVENT_MAGIC
                    && header.version == amtracer_abi::EVENT_VERSION,
                "unsupported uprobe ABI"
            );
            ensure!(
                header.length as usize == record.len()
                    && header.stack_len as usize == record.len() - size_of::<Header>(),
                "invalid uprobe lengths"
            );
            let mut event = json!({"source":"uprobe","timestamp_ns":header.timestamp_ns,"tgid":header.tgid,"tid":header.tid,
                "cpu":header.cpu,"probe":header.cookie,"pc":format!("{:#x}",header.regs.pc),"flags":header.flags,"stack_bytes":header.stack_len});
            if options.regs {
                event["registers"] = json!({"x":header.regs.x,"sp":header.regs.sp,"pc":header.regs.pc,"pstate":header.regs.pstate});
            }
            emit(&event, options.common.json)?;
            control.emitted();
            if !control.running() {
                break;
            }
        }
        if !control.running() {
            break;
        }
        if !std::path::Path::new(&format!("/proc/{pid}")).exists() {
            break;
        }
        wait_readable(events.as_raw_fd())?;
    }
    let lost = PerCpuArray::<_, u64>::try_from(ebpf.map("LOST").context("LOST map missing")?)?
        .get(&0, 0)?;
    eprintln!(
        "uprobe: events={} kernel_lost={}",
        control.events,
        lost.iter().sum::<u64>()
    );
    Ok(())
}
