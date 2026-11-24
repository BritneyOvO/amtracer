pub mod plan;

use crate::{
    Common, RunControl, emit,
    process::{MappingChange, MappingMonitor, ProcessMonitor},
    wait_readable,
};
use amtracer_abi::instruction::{self, Address, Config, Header, Record, Stats};
use anyhow::{Context, Result, ensure};
use aya::{
    Ebpf,
    maps::{Array, HashMap, PerCpuArray, RingBuf},
    programs::{
        TracePoint, UProbe,
        uprobe::{UProbeAttachLocation, UProbeAttachPoint, UProbeScope},
    },
};
use clap::Args;
use serde_json::json;
use std::{
    collections::HashMap as StdHashMap, mem::size_of, num::NonZeroU32, os::fd::AsRawFd,
    path::PathBuf,
};

#[derive(Args)]
pub struct Options {
    #[arg(long = "range", required = true)]
    pub ranges: Vec<plan::RangeSpec>,
    #[command(flatten)]
    pub common: Common,
    #[arg(long)]
    pub object: Option<PathBuf>,
    #[arg(long)]
    pub regs: bool,
}

#[repr(transparent)]
#[derive(Clone, Copy)]
struct MapConfig(Config);
#[repr(transparent)]
#[derive(Clone, Copy)]
struct MapAddress(Address);
#[repr(transparent)]
#[derive(Clone, Copy)]
struct MapStats(Stats);
// SAFETY: each wrapper is a fixed integer-only repr(C) value with no invalid bit patterns.
unsafe impl aya::Pod for MapConfig {}
// SAFETY: each wrapper is a fixed integer-only repr(C) value with no invalid bit patterns.
unsafe impl aya::Pod for MapAddress {}
// SAFETY: each wrapper is a fixed integer-only repr(C) value with no invalid bit patterns.
unsafe impl aya::Pod for MapStats {}

pub fn run(options: Options) -> Result<()> {
    let pid = options.common.pid;
    let mut process = ProcessMonitor::new(pid)?;
    let maps = crate::target::ProcessMaps::read(pid)?;
    let plan = plan::Plan::resolve(&maps, &options.ranges)?;
    let mut mappings = MappingMonitor::new(
        &maps,
        plan.targets
            .iter()
            .map(|target| target.mappings.clone())
            .collect(),
    );
    let object = options.object.unwrap_or_else(|| {
        std::env::current_exe()
            .unwrap_or_else(|_| PathBuf::from("amtracer"))
            .with_file_name("amtracer-itrace.o")
    });
    let mut ebpf =
        Ebpf::load_file(&object).with_context(|| format!("loading {}", object.display()))?;
    {
        let mut settings = Array::<_, MapConfig>::try_from(
            ebpf.map_mut("IT_SETTINGS")
                .context("IT_SETTINGS map missing")?,
        )?;
        settings.set(
            0,
            &MapConfig(Config {
                tgid: pid,
                enabled: 0,
                flags: if options.regs {
                    u32::from(instruction::FLAG_REGS)
                } else {
                    0
                },
                site_count: u32::try_from(plan.points.len())?,
            }),
            0,
        )?;
        let mut allowed = HashMap::<_, MapAddress, u8>::try_from(
            ebpf.map_mut("IT_ALLOWED")
                .context("IT_ALLOWED map missing")?,
        )?;
        for (index, point) in plan.points.iter().enumerate() {
            let cookie = u64::try_from(index + 1)?;
            for pc in &point.addresses {
                allowed.insert(&MapAddress(Address { cookie, pc: *pc }), &1, 0)?;
            }
        }
    }
    let program: &mut UProbe = ebpf
        .program_mut("instruction_trace")
        .context("instruction_trace program missing")?
        .try_into()?;
    program
        .load()
        .context("verifying instruction trace uprobe program")?;
    for (index, point) in plan.points.iter().enumerate() {
        let target = &plan.targets[point.target];
        program
            .attach(
                [UProbeAttachPoint {
                    location: UProbeAttachLocation::AbsoluteOffset(point.file_offset),
                    cookie: Some(u64::try_from(index + 1)?),
                }],
                target.attach_path(),
                UProbeScope::OneProcess(NonZeroU32::new(pid).context("invalid PID")?),
            )
            .with_context(|| {
                format!(
                    "attaching instruction {}+{:#x}",
                    target.path.display(),
                    point.file_offset
                )
            })?;
    }
    // The lifecycle hook prevents a reused TID from inheriting a previous
    // sequence. Its link is retained by the loaded program until drop.
    let exit_program: &mut TracePoint = ebpf
        .program_mut("instruction_thread_exit")
        .context("instruction_thread_exit program missing")?
        .try_into()?;
    exit_program
        .load()
        .context("verifying instruction exit tracepoint")?;
    exit_program
        .attach("sched", "sched_process_exit")
        .context("attaching sched_process_exit")?;
    let mut settings = Array::<_, MapConfig>::try_from(
        ebpf.map_mut("IT_SETTINGS")
            .context("IT_SETTINGS map missing")?,
    )?;
    settings.set(
        0,
        &MapConfig(Config {
            tgid: pid,
            enabled: 1,
            flags: if options.regs {
                u32::from(instruction::FLAG_REGS)
            } else {
                0
            },
            site_count: u32::try_from(plan.points.len())?,
        }),
        0,
    )?;
    let mut events = RingBuf::try_from(
        ebpf.take_map("IT_EVENTS")
            .context("IT_EVENTS map missing")?,
    )?;
    let mut control = RunControl::new(&options.common)?;
    let mut metadata = StdHashMap::new();
    for (index, point) in plan.points.iter().enumerate() {
        metadata.insert(
            u64::try_from(index + 1)?,
            (point.elf_address, point.word, point.assembly.clone()),
        );
    }
    process.verify()?;
    match mappings.check(true)? {
        MappingChange::Unchanged => {}
        MappingChange::Changed(_) => {}
        MappingChange::ProbeRemoved => {
            anyhow::bail!("instruction trace mapping changed during setup")
        }
    }
    while control.running() {
        while let Some(record) = events.next() {
            if !process.check()? {
                break;
            }
            if matches!(mappings.check(false)?, MappingChange::ProbeRemoved) {
                break;
            }
            let header = parse_header(&record)?;
            ensure!(
                header.magic == instruction::MAGIC && header.version == instruction::VERSION,
                "unsupported instruction trace ABI"
            );
            ensure!(
                header.length as usize == record.len(),
                "invalid instruction trace length"
            );
            let (elf, word, assembly) = metadata
                .get(&header.cookie)
                .context("unknown instruction trace cookie")?;
            let mut event = json!({"source":"instruction","timestamp_ns":header.timestamp_ns,"tgid":header.tgid,"tid":header.tid,"cpu":header.cpu,"sequence":header.sequence,"thread_epoch":header.thread_epoch,"probe":header.cookie,"pc":format!("{:#x}",header.pc),"elf_address":format!("{:#x}",elf),"opcode":format!("{word:08x}"),"instruction":assembly});
            if header.flags & instruction::FLAG_REGS != 0 {
                let record = parse_record(&record)?;
                event["registers"] = json!({"x":record.regs.x,"sp":record.regs.sp,"pc":record.regs.pc,"pstate":record.regs.pstate});
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
        if !process.check()? {
            break;
        }
        if matches!(mappings.check(false)?, MappingChange::ProbeRemoved) {
            break;
        }
        wait_readable(events.as_raw_fd())?;
    }
    let stats = PerCpuArray::<_, MapStats>::try_from(
        ebpf.map("IT_STATS").context("IT_STATS map missing")?,
    )?
    .get(&0, 0)?;
    eprintln!(
        "itrace: sites={} events={} hits={} submitted={} ring_lost={} state_failed={}",
        plan.points.len(),
        control.events,
        stats.iter().map(|s| s.0.submitted).sum::<u64>(),
        stats.iter().map(|s| s.0.hits).sum::<u64>(),
        stats.iter().map(|s| s.0.ring_lost).sum::<u64>(),
        stats.iter().map(|s| s.0.state_failed).sum::<u64>()
    );
    Ok(())
}

fn parse_header(bytes: &[u8]) -> Result<Header> {
    ensure!(
        bytes.len() >= size_of::<Header>(),
        "short instruction trace event"
    );
    // SAFETY: the caller checked the complete fixed integer-only header.
    Ok(unsafe { bytes.as_ptr().cast::<Header>().read_unaligned() })
}

fn parse_record(bytes: &[u8]) -> Result<Record> {
    ensure!(
        bytes.len() >= size_of::<Record>(),
        "short register instruction trace event"
    );
    // SAFETY: the caller checked the complete fixed integer-only record.
    Ok(unsafe { bytes.as_ptr().cast::<Record>().read_unaligned() })
}
