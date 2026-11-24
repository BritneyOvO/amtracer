mod event;
pub mod plan;
mod uxn;

use crate::{
    Common, RunControl,
    process::{MappingChange, MappingMonitor, ProcessMonitor},
    wait_readable,
};
use amtracer_abi::instruction::{self, Address, Config, Stats};
use anyhow::{Context, Result, ensure};
use aya::{
    Ebpf,
    maps::{Array, HashMap, PerCpuArray, RingBuf},
    programs::{
        RawTracePoint, UProbe,
        uprobe::{UProbeAttachLocation, UProbeAttachPoint, UProbeScope},
    },
};
use clap::Args;
use std::{
    io::{self, BufWriter, Write},
    num::NonZeroU32,
    os::fd::AsRawFd,
    path::PathBuf,
    sync::atomic::Ordering,
    time::Instant,
};

#[derive(Args)]
pub struct Options {
    #[arg(long = "range", required = true, value_name = "START..END|START:BYTES")]
    pub ranges: Vec<plan::RangeSpec>,
    #[command(flatten)]
    pub common: Common,
    #[arg(long)]
    pub object: Option<PathBuf>,
    #[arg(long)]
    pub regs: bool,
    /// Collect and validate records, reporting statistics without writing each event.
    #[arg(long, conflicts_with = "json")]
    pub summary_only: bool,
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
// SAFETY: Config is a fixed repr(C) integer value without padding/invalid bit patterns.
unsafe impl aya::Pod for MapConfig {}
// SAFETY: Address is a fixed repr(C) integer value without padding/invalid bit patterns.
unsafe impl aya::Pod for MapAddress {}
// SAFETY: Stats is a fixed repr(C) integer value without padding/invalid bit patterns.
unsafe impl aya::Pod for MapStats {}

fn settings(ebpf: &mut Ebpf, config: Config) -> Result<()> {
    Array::<_, MapConfig>::try_from(
        ebpf.map_mut("IT_SETTINGS")
            .context("IT_SETTINGS map missing")?,
    )?
    .set(0, &MapConfig(config), 0)?;
    Ok(())
}

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
    let object = match options.object {
        Some(path) => path,
        None => std::env::current_exe()?.with_file_name("amtracer-itrace.o"),
    };
    let mut ebpf =
        Ebpf::load_file(&object).with_context(|| format!("loading {}", object.display()))?;
    let config = Config {
        tgid: pid,
        enabled: 0,
        flags: if options.regs {
            u32::from(instruction::FLAG_REGS)
        } else {
            0
        },
        site_count: u32::try_from(plan.points.len())?,
    };
    settings(&mut ebpf, config)?;
    {
        let mut allowed = HashMap::<_, MapAddress, u8>::try_from(
            ebpf.map_mut("IT_ALLOWED")
                .context("IT_ALLOWED map missing")?,
        )?;
        for (index, point) in plan.points.iter().enumerate() {
            for pc in &point.addresses {
                allowed.insert(
                    &MapAddress(Address {
                        cookie: u64::try_from(index + 1)?,
                        pc: *pc,
                    }),
                    &1,
                    0,
                )?;
            }
        }
    }
    // The raw lifecycle hook covers exits on all CPUs without a tracefs mount.
    // It must be attached before capture can create any thread entries.
    let exit_program: &mut RawTracePoint = ebpf
        .program_mut("instruction_thread_exit")
        .context("instruction_thread_exit program missing")?
        .try_into()?;
    exit_program
        .load()
        .context("verifying instruction exit hook")?;
    exit_program
        .attach("sched_process_exit")
        .context("attaching sched_process_exit")?;
    let mut control = RunControl::new(&options.common)?;
    let setup_started = Instant::now();
    let program: &mut UProbe = ebpf
        .program_mut("instruction_trace")
        .context("instruction_trace program missing")?
        .try_into()?;
    program
        .load()
        .context("verifying instruction trace uprobe program")?;
    for (index, point) in plan.points.iter().enumerate() {
        ensure!(
            !control.stop.load(Ordering::Relaxed),
            "instruction trace setup interrupted"
        );
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
                    "attaching instruction {}+{:#x} ({})",
                    target.path.display(),
                    point.file_offset,
                    point.assembly
                )
            })?;
    }
    let mut backend = uxn::Backend::verify(pid, &plan)?;
    process.verify()?;
    ensure!(
        !matches!(mappings.check(true)?, MappingChange::ProbeRemoved),
        "instruction trace mapping changed during setup"
    );
    let mut events = RingBuf::try_from(
        ebpf.take_map("IT_EVENTS")
            .context("IT_EVENTS map missing")?,
    )?;
    let mut sequences = event::Sequences::default();
    let stdout = io::stdout();
    let mut output = BufWriter::with_capacity(256 * 1024, stdout.lock());
    control.started = Instant::now();
    settings(
        &mut ebpf,
        Config {
            enabled: 1,
            ..config
        },
    )?;
    eprintln!(
        "itrace: ready pid={pid} sites={} pages={} backend=uxn setup_ns={}",
        plan.points.len(),
        backend.pages(),
        setup_started.elapsed().as_nanos()
    );
    let mut received = 0_u64;
    let mut discarded = 0_u64;
    let result = (|| -> Result<()> {
        'capture: while control.running() {
            if !process.check()? || matches!(mappings.check(false)?, MappingChange::ProbeRemoved) {
                break;
            }
            backend.check()?;
            while control.running() {
                if !process.check()?
                    || matches!(mappings.check(false)?, MappingChange::ProbeRemoved)
                {
                    break 'capture;
                }
                backend.check()?;
                let Some(record) = events.next() else {
                    break;
                };
                received += 1;
                let event = event::Event::decode(&record, pid, options.regs, &plan)?;
                let missed = sequences.observe(&event.header)?;
                if !options.summary_only {
                    event.write(
                        &plan,
                        missed,
                        sequences.incomplete,
                        options.common.json,
                        &mut output,
                    )?;
                }
                control.emitted();
            }
            output.flush()?;
            if !control.running() {
                break;
            }
            wait_readable(events.as_raw_fd())?;
        }
        Ok(())
    })();
    // Disable and detach on malformed records, output errors, exit, Ctrl-C and
    // count. Dropping Ebpf also releases links when setup fails before enable.
    let disable_result = settings(&mut ebpf, config);
    let detach_result = (|| -> Result<()> {
        let program: &mut UProbe = ebpf
            .program_mut("instruction_trace")
            .context("instruction_trace program missing")?
            .try_into()?;
        program.unload().context("detaching instruction trace")?;
        Ok(())
    })();
    let mut drain_error = None;
    while let Some(record) = events.next() {
        received += 1;
        let count_reached = options.common.count != 0 && control.events >= options.common.count;
        if result.is_err() || drain_error.is_some() || count_reached {
            discarded += 1;
            continue;
        }
        let drain = (|| -> Result<()> {
            let event = event::Event::decode(&record, pid, options.regs, &plan)?;
            let missed = sequences.observe(&event.header)?;
            if !options.summary_only {
                event.write(
                    &plan,
                    missed,
                    sequences.incomplete,
                    options.common.json,
                    &mut output,
                )?;
            }
            control.emitted();
            Ok(())
        })();
        if let Err(error) = drain {
            drain_error = Some(error);
            discarded += 1;
        }
    }
    let flush_result = output.flush().context("flushing instruction trace output");
    let stats = PerCpuArray::<_, MapStats>::try_from(
        ebpf.map("IT_STATS").context("IT_STATS map missing")?,
    )?
    .get(&0, 0)?;
    let submitted = stats.iter().map(|s| s.0.submitted).sum::<u64>();
    let ring_lost = stats.iter().map(|s| s.0.ring_lost).sum::<u64>();
    let state_failed = stats.iter().map(|s| s.0.state_failed).sum::<u64>();
    let queued = submitted.saturating_sub(received);
    let incomplete = sequences.incomplete
        || ring_lost != 0
        || state_failed != 0
        || queued != 0
        || discarded != 0
        || result.is_err()
        || disable_result.is_err()
        || detach_result.is_err()
        || drain_error.is_some()
        || flush_result.is_err();
    eprintln!(
        "itrace: sites={} events={} received={} hits={} submitted={} ring_lost={ring_lost} state_failed={state_failed} sequence_missing={} discarded={discarded} queued={queued} incomplete={incomplete}",
        plan.points.len(),
        control.events,
        received,
        stats.iter().map(|s| s.0.hits).sum::<u64>(),
        submitted,
        sequences.missed
    );
    result?;
    disable_result?;
    detach_result?;
    if let Some(error) = drain_error {
        return Err(error);
    }
    flush_result
}
