mod expr;
mod itrace;
mod ktools;
mod process;
mod session;
mod target;
mod unwind;
mod uprobe;

use anyhow::{Context, Result, ensure};
use clap::{Args, Parser, Subcommand};
use serde_json::{Value, json};
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

#[derive(Parser)]
#[command(
    version,
    about = "Android ARM64 tracer: Aya uprobes and ktools trace drivers"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Doctor,
    Run {
        #[arg(long)]
        config: PathBuf,
    },
    Resolve {
        #[arg(short, long)]
        pid: u32,
        #[arg(long, required_unless_present = "range", conflicts_with = "range")]
        probe: Option<target::ProbeSpec>,
        #[arg(long, required_unless_present = "probe")]
        range: Option<itrace::plan::RangeSpec>,
    },
    Uprobe(uprobe::Options),
    Itrace(itrace::Options),
    Syscall {
        #[command(flatten)]
        common: Common,
        #[arg(long, value_delimiter = ',')]
        syscalls: Vec<String>,
        #[arg(long = "capture", value_name = "SYSCALL:ARG:KIND[:BYTES]")]
        captures: Vec<String>,
        #[arg(long)]
        stack: bool,
        #[arg(long, default_value_t = 8192, value_parser = clap::value_parser!(u32).range(1..=16384))]
        stack_bytes: u32,
    },
    Binder {
        #[command(flatten)]
        common: Common,
        #[arg(long)]
        with_replies: bool,
    },
}

#[derive(Args, Clone)]
pub struct Common {
    #[arg(short, long, value_parser = clap::value_parser!(u32).range(1..=2147483647))]
    pub pid: u32,
    #[arg(long, default_value_t = 0)]
    pub duration: u64,
    #[arg(long, default_value_t = 0)]
    pub count: u64,
    #[arg(long)]
    pub json: bool,
}

struct RunControl {
    stop: Arc<AtomicBool>,
    started: Instant,
    duration: Duration,
    limit: u64,
    events: u64,
}
impl RunControl {
    fn new(common: &Common) -> Result<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let signal_stop = stop.clone();
        ctrlc::set_handler(move || signal_stop.store(true, Ordering::Relaxed))
            .context("installing signal handler")?;
        Ok(Self {
            stop,
            started: Instant::now(),
            duration: Duration::from_secs(common.duration),
            limit: common.count,
            events: 0,
        })
    }
    fn running(&self) -> bool {
        !self.stop.load(Ordering::Relaxed)
            && (self.duration.is_zero() || self.started.elapsed() < self.duration)
            && (self.limit == 0 || self.events < self.limit)
    }
    fn emitted(&mut self) {
        self.events += 1;
    }
}

fn emit(value: &Value, as_json: bool) -> Result<()> {
    use std::io::{self, Write};
    let mut out = io::stdout().lock();
    if as_json {
        serde_json::to_writer(&mut out, value)?;
        writeln!(out)?;
    } else {
        writeln!(out, "{value:#}")?;
    }
    Ok(())
}

fn wait_readable(fd: std::os::fd::RawFd) -> Result<()> {
    wait_readable_for(fd, Duration::from_millis(100))
}

fn wait_readable_for(fd: std::os::fd::RawFd, timeout: Duration) -> Result<()> {
    let mut poll = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let timeout_ms = i32::try_from(timeout.as_millis()).context("poll timeout is too large")?;
    // SAFETY: poll refers to one valid pollfd and a checked finite timeout.
    let ret = unsafe { libc::poll(&mut poll, 1, timeout_ms) };
    if ret < 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error.into());
        }
    }
    ensure!(
        poll.revents & libc::POLLNVAL == 0,
        "invalid event descriptor"
    );
    Ok(())
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Doctor => {
            let info = ktools::Control::open().and_then(|control| control.info());
            emit(
                &json!({"arch":std::env::consts::ARCH,
                "kernel_btf":PathBuf::from("/sys/kernel/btf/vmlinux").exists(),
                "ktools":match info { Ok(i) => json!({"abi":i.abi_version,"features":i.features}), Err(e) => json!({"error":format!("{e:#}")}) }}),
                true,
            )
        }
        Command::Run { config } => session::run(config),
        Command::Resolve { pid, probe, range } => {
            let maps = target::ProcessMaps::read(pid)?;
            if let Some(range) = range {
                emit(
                    &itrace::plan::Plan::resolve(&maps, &[range])?.preview(),
                    true,
                )
            } else {
                let resolved = maps.resolve(&probe.context("missing probe or range")?)?;
                emit(
                    &json!({"path":resolved.path,"file_offset":format!("{:#x}",resolved.file_offset),"elf_address":format!("{:#x}",resolved.elf_address)}),
                    true,
                )
            }
        }
        Command::Uprobe(options) => uprobe::run(options),
        Command::Itrace(options) => itrace::run(options),
        Command::Syscall {
            common,
            syscalls,
            captures,
            stack,
            stack_bytes,
        } => ktools::run_syscall(common, syscalls, captures, stack, stack_bytes),
        Command::Binder {
            common,
            with_replies,
        } => ktools::run_binder(common, with_replies),
    }
}
