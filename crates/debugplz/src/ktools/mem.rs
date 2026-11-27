use super::{
    Control,
    bindings::{
        AMT_KT_IOC_MEM_READ, AMT_KT_IOC_MEM_WRITE, AMT_KT_IOC_OPEN_MEM, KT_FEATURE_RWMEM,
        KT_MEM_MODE_AT, KT_MEM_MODE_DEVICE, KT_MEM_MODE_PGTABLE, KT_MEM_MODE_PROCESS_VM, kt_mem_io,
        kt_target_open,
    },
    ioctl,
};
use anyhow::{Context, Result, ensure};
use clap::{Subcommand, ValueEnum};
use serde_json::json;
use std::{
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

const BEFORE: [u8; 8] = *b"DebugPlz";
const AFTER: [u8; 8] = *b"rwmem-ok";

#[derive(Subcommand)]
pub enum Command {
    /// Query driver availability and the maximum request size.
    Info,
    /// Verify read and write on a scratch buffer in DebugPlz itself.
    Check {
        /// rwmem mode for the transfer checks.
        #[arg(long, value_enum, default_value = "process-vm")]
        mode: IoMode,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum IoMode {
    #[value(name = "process-vm", alias = "process_vm")]
    ProcessVm,
    Pgtable,
    At,
    Device,
}

impl IoMode {
    fn flags(self) -> u32 {
        match self {
            Self::ProcessVm => KT_MEM_MODE_PROCESS_VM,
            Self::Pgtable => KT_MEM_MODE_PGTABLE,
            Self::At => KT_MEM_MODE_AT,
            Self::Device => KT_MEM_MODE_DEVICE,
        }
    }
}

enum Transfer {
    Read(IoMode),
    Write(IoMode),
}

pub fn run(command: Command) -> Result<()> {
    let control = Control::open()?;
    let info = control.info()?;
    let available = info.features & KT_FEATURE_RWMEM != 0;
    let result = match command {
        Command::Info => json!({
            "available": available,
            "abi_version": info.abi_version,
            "max_io_bytes": info.max_io_bytes,
        }),
        Command::Check { mode } => {
            ensure!(available, "ktools rwmem unavailable");
            check(&control, mode).with_context(|| format!("checking rwmem with {mode:?} mode"))?;
            json!({"ok": true, "bytes": BEFORE.len()})
        }
    };
    crate::emit(&result, true)
}

fn check(control: &Control, mode: IoMode) -> Result<()> {
    let mut open = kt_target_open {
        size: size_of::<kt_target_open>().try_into()?,
        pid: 0,
        ..Default::default()
    };
    // SAFETY: OPEN_MEM reads the initialized UAPI struct for this call.
    let fd = unsafe {
        libc::ioctl(
            control.0.as_raw_fd(),
            AMT_KT_IOC_OPEN_MEM as _,
            std::ptr::from_mut(&mut open),
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error()).context("opening self rwmem session");
    }
    // SAFETY: OPEN_MEM returned a new descriptor owned by this process.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut scratch = BEFORE;
    let mut observed = [0; BEFORE.len()];
    transfer(&fd, Transfer::Read(mode), &mut scratch, &mut observed)
        .context("reading scratch buffer")?;
    ensure!(observed == BEFORE, "rwmem initial read did not match");

    let mut replacement = AFTER;
    transfer(&fd, Transfer::Write(mode), &mut scratch, &mut replacement)
        .context("writing scratch buffer")?;
    transfer(&fd, Transfer::Read(mode), &mut scratch, &mut observed)
        .context("reading back scratch buffer")?;
    ensure!(observed == AFTER, "rwmem readback did not match");
    Ok(())
}

fn transfer<const N: usize>(
    fd: &OwnedFd,
    operation: Transfer,
    scratch: &mut [u8; N],
    buffer: &mut [u8; N],
) -> Result<()> {
    let (request, flags) = match operation {
        Transfer::Read(mode) => (AMT_KT_IOC_MEM_READ, mode.flags()),
        Transfer::Write(mode) => (AMT_KT_IOC_MEM_WRITE, mode.flags()),
    };
    let length = u64::try_from(N)?;
    let mut value = kt_mem_io {
        size: size_of::<kt_mem_io>().try_into()?,
        flags,
        address: scratch.as_mut_ptr().addr().try_into()?,
        buffer: buffer.as_mut_ptr().addr().try_into()?,
        length,
        ..Default::default()
    };
    ioctl(fd.as_raw_fd(), request, &mut value)?;
    ensure!(
        value.transferred == length,
        "short rwmem transfer: {} of {length} bytes",
        value.transferred
    );
    Ok(())
}
