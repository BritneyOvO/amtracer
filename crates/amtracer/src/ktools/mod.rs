#![allow(non_camel_case_types)]

// Generated from fixed UAPI headers; unused constants are retained so ABI
// regeneration remains mechanical and reviewable.
#[allow(dead_code, non_upper_case_globals, clippy::undocumented_unsafe_blocks)]
pub mod bindings;

use crate::{Common, RunControl, emit, wait_readable};
use anyhow::{Context, Result, ensure};
use bindings::*;
use serde_json::json;
use std::{
    fs::File,
    io::{self, Read},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

pub struct Control(OwnedFd);
impl Control {
    pub fn open() -> Result<Self> {
        // SAFETY: PR_KTOOLS returns a fresh owned descriptor or -1/errno.
        let fd = unsafe {
            libc::prctl(
                PR_KTOOLS as i32,
                KT_OPEN_CONTROL as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
            )
        };
        ensure!(fd >= 0, "PR_KTOOLS: {}", io::Error::last_os_error());
        // SAFETY: the successful control open transferred ownership to us.
        Ok(Self(unsafe { OwnedFd::from_raw_fd(fd) }))
    }
    pub fn info(&self) -> Result<kt_info> {
        let mut info = kt_info::default();
        ioctl(self.0.as_raw_fd(), AMT_KT_IOC_GET_INFO, &mut info)?;
        ensure!(
            info.abi_version == KT_ABI_VERSION,
            "unsupported ktools ABI {}",
            info.abi_version
        );
        Ok(info)
    }
    fn trace(&self, request: u32) -> Result<File> {
        // SAFETY: OPEN requests require a zero argument and return a fresh FD.
        let fd = unsafe { libc::ioctl(self.0.as_raw_fd(), request as _, 0 as libc::c_ulong) };
        if fd < 0 {
            return Err(io::Error::last_os_error()).context("opening trace session");
        }
        // SAFETY: fd is a new O_CLOEXEC/O_NONBLOCK descriptor from the driver.
        Ok(File::from(unsafe { OwnedFd::from_raw_fd(fd) }))
    }
}

fn ioctl<T>(fd: i32, request: u32, value: &mut T) -> Result<()> {
    // SAFETY: callers pair each ioctl with its generated UAPI value type;
    // the exclusive reference stays valid for the full synchronous syscall.
    if unsafe { libc::ioctl(fd, request as _, value as *mut T) } < 0 {
        return Err(io::Error::last_os_error()).with_context(|| format!("ioctl {request:#x}"));
    }
    Ok(())
}

fn prefix<T: Copy>(bytes: &[u8]) -> Result<T> {
    ensure!(bytes.len() >= size_of::<T>(), "short trace record");
    // SAFETY: only the generated integer-only UAPI headers are decoded by the
    // calls in this module. The checked prefix can be unaligned.
    Ok(unsafe { bytes.as_ptr().cast::<T>().read_unaligned() })
}

fn read_record(file: &mut File, bytes: &mut [u8]) -> Result<Option<usize>> {
    match file.read(bytes) {
        Ok(0) => anyhow::bail!("trace session closed"),
        Ok(n) => Ok(Some(n)),
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) =>
        {
            Ok(None)
        }
        Err(e) => Err(e).context("reading trace record"),
    }
}

pub fn run_syscall(
    common: Common,
    names: Vec<String>,
    stack: bool,
    stack_bytes: u32,
) -> Result<()> {
    let control = Control::open()?;
    ensure!(
        control.info()?.features & KT_FEATURE_SYSCALL_TRACE != 0,
        "syscall_trace unavailable"
    );
    let mut file = control.trace(AMT_KT_IOC_OPEN_SYSCALL_TRACE)?;
    let mut config = sct_config {
        flags: SCT_FLAG_TRACE_ENTER
            | SCT_FLAG_TRACE_EXIT
            | if stack { SCT_FLAG_CAPTURE_STACK } else { 0 },
        stack_bytes: if stack { stack_bytes } else { 0 },
        target_tgid: common.pid,
        target_uid: u32::MAX,
        syscall_nr: -1,
        ret_filter: SCT_RETFILTER_ANY,
    };
    ioctl(file.as_raw_fd(), AMT_SCT_IOC_SET_CONFIG, &mut config)?;
    if !names.is_empty() {
        ensure!(
            names.len() <= SCT_MAX_NR_FILTERS as usize,
            "too many syscall filters"
        );
        let mut filter = sct_nr_filter {
            count: u32::try_from(names.len())?,
            ..Default::default()
        };
        for (slot, name) in filter.nr.iter_mut().zip(names) {
            *slot = syscall_number(&name)?;
        }
        ioctl(file.as_raw_fd(), AMT_SCT_IOC_SET_NR_FILTER, &mut filter)?;
    }
    let mut run = RunControl::new(&common)?;
    ioctl(file.as_raw_fd(), AMT_SCT_IOC_START, &mut 0_u32)?;
    let mut buffer = vec![0; 32768];
    let mut pending = std::collections::HashMap::new();
    let mut last_lost = 0;
    while run.running() {
        if let Some(n) = read_record(&mut file, &mut buffer)? {
            let header: sct_event_header = prefix(&buffer[..n])?;
            ensure!(
                header.magic == SCT_EVENT_MAGIC
                    && u32::from(header.version) == SCT_EVENT_VERSION
                    && header.size as usize == n,
                "invalid syscall event ABI/length"
            );
            if header.lost_before != last_lost {
                pending.clear();
                last_lost = header.lost_before;
            }
            let enter = u32::from(header.type_) == sct_event_type_SCT_EV_ENTER;
            let duration = if enter {
                pending.insert(header.tid, (header.nr, header.ts_ns));
                None
            } else {
                pending.remove(&header.tid).and_then(|(nr, time)| {
                    if nr == header.nr {
                        header.ts_ns.checked_sub(time)
                    } else {
                        None
                    }
                })
            };
            let event = json!({"source":"syscall","timestamp_ns":header.ts_ns,"tgid":header.pid,"tid":header.tid,"nr":header.nr,
                "phase":if enter {"enter"} else {"exit"},"args":header.args,"return":if enter {None} else {Some(header.ret)},
                "duration_ns":duration,"flags":header.flags,"lost_before":header.lost_before,"pc":header.user_pc,"sp":header.user_sp});
            emit(&event, common.json)?;
            run.emitted();
        } else {
            if !std::path::Path::new(&format!("/proc/{}", common.pid)).exists() {
                break;
            }
            wait_readable(file.as_raw_fd())?;
        }
    }
    ioctl(file.as_raw_fd(), AMT_SCT_IOC_STOP, &mut 0_u32)?;
    report_stats(&file, run.events)
}

pub fn run_binder(common: Common) -> Result<()> {
    let control = Control::open()?;
    ensure!(
        control.info()?.features & KT_FEATURE_BINDER_TRACE != 0,
        "binder_trace unavailable"
    );
    let mut file = control.trace(AMT_KT_IOC_OPEN_BINDER_TRACE)?;
    let mut feature = bt_driver_feature::default();
    ioctl(file.as_raw_fd(), AMT_BT_IOC_GET_FEATURE, &mut feature)?;
    ensure!(
        feature.magic == BT_DRIVER_FEATURE_MAGIC && feature.abi_version == BT_ABI_VERSION,
        "unsupported binder ABI"
    );
    let mut config = bt_capture_config {
        enabled: 1,
        point_mask: BT_CAPTURE_POINT_TRANSACTION,
        tgid: i32::try_from(common.pid)?,
        ..Default::default()
    };
    let mut run = RunControl::new(&common)?;
    ioctl(file.as_raw_fd(), AMT_BT_IOC_SET_CONFIG, &mut config)?;
    let mut buffer = vec![0; size_of::<bt_binder_event>()];
    while run.running() {
        if let Some(n) = read_record(&mut file, &mut buffer)? {
            ensure!(
                n == size_of::<bt_binder_event>(),
                "invalid Binder record size"
            );
            let h: bt_binder_event = prefix(&buffer[..n])?;
            ensure!(
                h.kind == BT_EVENT_KIND_BINDER_TRANSACTION && h.data_len <= BT_MAX_INLINE_DATA,
                "invalid Binder record"
            );
            let outcome = if feature.feature_flags & BT_FEATURE_TRANSACTION_RESULT == 0 {
                "unknown"
            } else {
                match u32::from(h.outcome) {
                    BT_OUTCOME_SUBMITTED => "submitted",
                    BT_OUTCOME_FAILED => "failed",
                    _ => "unknown",
                }
            };
            emit(
                &json!({"source":"binder","timestamp_ns":h.timestamp_ns,"tgid":h.tgid,"tid":h.pid,"transaction_id":h.transaction_debug_id,
                "reply_to_id":h.reply_to_debug_id,"reply":h.reply != 0,"code":h.code,"flags":h.flags,"sender_pid":h.sender_pid,"sender_euid":h.sender_euid,
                "outcome":outcome,"error":h.error,"data_size":h.data_size,"data":h.data[..h.data_len as usize],"truncated":h.data_truncated != 0,"lost_before":h.lost_before}),
                common.json,
            )?;
            run.emitted();
        } else {
            if !std::path::Path::new(&format!("/proc/{}", common.pid)).exists() {
                break;
            }
            wait_readable(file.as_raw_fd())?;
        }
    }
    config.enabled = 0;
    ioctl(file.as_raw_fd(), AMT_BT_IOC_SET_CONFIG, &mut config)?;
    report_stats(&file, run.events)
}

fn report_stats(file: &File, events: u64) -> Result<()> {
    let mut stats = kt_trace_stats::default();
    ioctl(file.as_raw_fd(), AMT_KT_IOC_TRACE_GET_STATS, &mut stats)?;
    eprintln!(
        "trace: events={events} kernel_lost={} queued={}",
        stats.lost, stats.queued
    );
    Ok(())
}

fn syscall_number(name: &str) -> Result<i32> {
    if let Ok(number) = name.parse::<i32>() {
        ensure!(number >= 0, "negative syscall number");
        return Ok(number);
    }
    // AArch64 numbers from the vendored asm-generic UAPI. A generated full table
    // will replace this small initial set before general decoder integration.
    Ok(match name {
        "openat" => 56,
        "close" => 57,
        "read" => 63,
        "write" => 64,
        "readv" => 65,
        "writev" => 66,
        "ioctl" => 29,
        "getpid" => 172,
        "gettid" => 178,
        "futex" => 98,
        "mmap" => 222,
        "munmap" => 215,
        "mprotect" => 226,
        "clone" => 220,
        "execve" => 221,
        "exit" => 93,
        "exit_group" => 94,
        _ => anyhow::bail!("unknown syscall name {name}; use its AArch64 number"),
    })
}
