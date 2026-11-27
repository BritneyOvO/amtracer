#![allow(non_camel_case_types)]

// Generated from fixed UAPI headers; unused constants are retained so ABI
// regeneration remains mechanical and reviewable.
mod binder;
#[allow(dead_code, non_upper_case_globals, clippy::undocumented_unsafe_blocks)]
pub mod bindings;
pub mod mem;
mod syscall;
mod syscall_names;

use crate::{
    Common, RunControl, emit,
    process::{MappingChange, MappingMonitor, ProcessMonitor},
    wait_readable,
};
use anyhow::{Context, Result, ensure};
use bindings::*;
use std::{
    fs::File,
    io::{self, Read},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

pub struct Control(OwnedFd);
impl Control {
    pub fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.0.as_raw_fd()
    }
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
    capture_specs: Vec<String>,
    stack: bool,
    stack_bytes: u32,
) -> Result<()> {
    let capture_rules = capture_specs
        .iter()
        .map(|spec| syscall::CaptureRule::try_from(spec.as_str()))
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        capture_rules.len() <= SCT_MAX_CAPTURE_RULES as usize,
        "too many syscall capture rules"
    );
    syscall::validate_capture_rules(&capture_rules)?;
    let filter_numbers = syscall::filter_numbers(&names, &capture_rules)?;
    ensure!(
        filter_numbers.len() <= SCT_MAX_NR_FILTERS as usize,
        "too many syscall filters after adding capture rules"
    );
    let capture_stack = stack
        || capture_rules
            .iter()
            .any(|rule| u32::from(rule.kind) == sct_blob_kind_SCT_BLOB_USER_STACK);
    let mut process = ProcessMonitor::new(common.pid)?;
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
    if !filter_numbers.is_empty() {
        let mut filter = sct_nr_filter {
            count: u32::try_from(filter_numbers.len())?,
            ..Default::default()
        };
        for (slot, number) in filter.nr.iter_mut().zip(filter_numbers) {
            *slot = number;
        }
        ioctl(file.as_raw_fd(), AMT_SCT_IOC_SET_NR_FILTER, &mut filter)?;
    }
    if !capture_rules.is_empty() {
        let mut rules = sct_capture_rules {
            count: u32::try_from(capture_rules.len())?,
            ..Default::default()
        };
        for (slot, rule) in rules.rules.iter_mut().zip(capture_rules) {
            *slot = rule.into();
        }
        ioctl(file.as_raw_fd(), AMT_SCT_IOC_SET_CAPTURE_RULES, &mut rules)?;
    }
    let mut run = RunControl::new(&common)?;
    let (mut unwinder, mut mappings) = if capture_stack {
        let maps = crate::target::ProcessMaps::read(common.pid)?;
        (
            Some(crate::unwind::NativeUnwinder::new(&maps)),
            Some(MappingMonitor::new(&maps, Vec::new())),
        )
    } else {
        (None, None)
    };
    ioctl(file.as_raw_fd(), AMT_SCT_IOC_START, &mut 0_u32)?;
    process.verify()?;
    if let Some(monitor) = &mut mappings
        && let MappingChange::Changed(maps) = monitor.check(true)?
    {
        unwinder = Some(crate::unwind::NativeUnwinder::new(&maps));
    }
    let mut buffer = vec![0; 32768];
    let mut decoder = syscall::Decoder::default();
    while run.running() {
        if !process.check()? {
            break;
        }
        if let Some(monitor) = &mut mappings
            && let MappingChange::Changed(maps) = monitor.check(false)?
        {
            unwinder = Some(crate::unwind::NativeUnwinder::new(&maps));
        }
        if let Some(n) = read_record(&mut file, &mut buffer)? {
            let record = syscall::Record::try_from(&buffer[..n])?;
            let event = decoder.event(record, unwinder.as_mut());
            emit(&event, common.json)?;
            run.emitted();
        } else {
            wait_readable(file.as_raw_fd())?;
        }
    }
    ioctl(file.as_raw_fd(), AMT_SCT_IOC_STOP, &mut 0_u32)?;
    eprintln!("syscall: invalidated_pairs={}", decoder.invalidated);
    report_stats(&file, run.events)
}

pub fn run_binder(common: Common, with_replies: bool) -> Result<()> {
    let mut process = ProcessMonitor::new(common.pid)?;
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
    ensure!(
        !with_replies || feature.feature_flags & BT_FEATURE_TRANSACTION_RESULT != 0,
        "--with-replies requires Binder transaction result and debug ID support"
    );
    let mut config = bt_capture_config {
        enabled: 1,
        point_mask: BT_CAPTURE_POINT_TRANSACTION,
        tgid: if with_replies {
            0
        } else {
            i32::try_from(common.pid)?
        },
        ..Default::default()
    };
    let mut run = RunControl::new(&common)?;
    let mut decoder = binder::Decoder::new(common.pid, with_replies);
    ioctl(file.as_raw_fd(), AMT_BT_IOC_SET_CONFIG, &mut config)?;
    process.verify()?;
    let mut buffer = vec![0; size_of::<bt_binder_event>()];
    while run.running() {
        if !process.check()? {
            break;
        }
        if let Some(n) = read_record(&mut file, &mut buffer)? {
            ensure!(
                n == size_of::<bt_binder_event>(),
                "invalid Binder record size"
            );
            let h: bt_binder_event = prefix(&buffer[..n])?;
            if let Some(event) = decoder.event(h, feature.feature_flags)? {
                emit(&event, common.json)?;
                run.emitted();
            }
        } else {
            wait_readable(file.as_raw_fd())?;
        }
    }
    config.enabled = 0;
    ioctl(file.as_raw_fd(), AMT_BT_IOC_SET_CONFIG, &mut config)?;
    eprintln!("binder: invalidated_pairs={}", decoder.invalidated);
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
    syscall_names::NAMES
        .iter()
        .find(|(_, entry)| *entry == name)
        .map(|(number, _)| *number)
        .with_context(|| format!("unknown syscall name {name}; use its AArch64 number"))
}
