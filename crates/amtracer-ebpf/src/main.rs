#![no_std]
#![no_main]

use amtracer_abi::*;
use aya_ebpf::{
    EbpfContext,
    helpers::{
        bpf_get_current_pid_tgid, bpf_get_smp_processor_id, bpf_ktime_get_ns, bpf_probe_read_user,
        bpf_probe_read_user_buf,
        generated::{bpf_get_attach_cookie, bpf_probe_read_user_str},
    },
    macros::{map, uprobe},
    maps::{HashMap, PerCpuArray, RingBuf},
    programs::ProbeContext,
};

#[map]
static CONFIGS: HashMap<u64, ProbeConfig> = HashMap::with_max_entries(MAX_PROBES, 0);
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(8 * 1024 * 1024, 0);
#[map]
static SCRATCH: PerCpuArray<Record> = PerCpuArray::with_max_entries(1, 0);
#[map]
static LOST: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

#[uprobe]
pub fn capture(ctx: ProbeContext) -> u32 {
    // SAFETY: helpers use the kernel-supplied probe context. Scratch is per CPU;
    // the kernel serializes this uprobe BPF execution on the current CPU.
    unsafe {
        try_capture(&ctx);
    }
    0
}

unsafe fn try_capture(ctx: &ProbeContext) {
    // SAFETY: ctx is the uprobe context and CONFIGS is immutable while attached.
    let cookie = unsafe { bpf_get_attach_cookie(ctx.as_ptr()) };
    // SAFETY: config entries are installed before attaching and never replaced.
    let Some(config) = (unsafe { CONFIGS.get(&cookie) }) else {
        return;
    };
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    if tgid != config.tgid {
        return;
    }
    let Some(record) = SCRATCH.get_ptr_mut(0) else {
        return;
    };
    // SAFETY: the map value is a full initialized Record and registers are the
    // AArch64 user_pt_regs prefix supplied by the kernel for this uprobe.
    unsafe {
        let user = &*(ctx.regs.cast::<aya_ebpf::bindings::user_pt_regs>());
        let h = &mut (*record).header;
        h.magic = EVENT_MAGIC;
        h.version = EVENT_VERSION;
        h.kind = 1;
        h.flags = 0;
        h.cookie = cookie;
        h.timestamp_ns = bpf_ktime_get_ns();
        h.tgid = tgid;
        h.tid = pid_tgid as u32;
        h.cpu = bpf_get_smp_processor_id();
        h.stack_len = 0;
        // Constant, volatile loads prevent LLVM from lowering the register
        // array copy into memmove with a variable ctx pointer (rejected on 5.15).
        macro_rules! copy_regs {
            ($($index:expr),*) => { $(h.regs.x[$index] = core::ptr::read_volatile(core::ptr::addr_of!(user.regs[$index]));)* };
        }
        copy_regs!(
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30
        );
        h.regs.pc = user.pc;
        h.regs.sp = user.sp;
        h.regs.pstate = user.pstate;
        (*record).results = [CaptureResult::default(); MAX_CAPTURES];
        let bytes = (config.stack_bytes as usize).min(MAX_STACK);
        let captured_len = copy_pages::<MAX_STACK, 5>(user.sp, record, 0, bytes);
        if captured_len < bytes {
            h.flags |= 1;
        }
        h.stack_len = captured_len as u32;
        let count = (config.capture_count as usize).min(MAX_CAPTURES);
        h.capture_count = count as u32;
        let mut extra = 0_usize;
        for index in 0..MAX_CAPTURES {
            if index >= count {
                break;
            }
            let read_len = amt_capture_item(cookie, index as u32, captured_len + extra);
            // Preserve a simple local bound across BPF-to-BPF calls.
            let read_len = core::ptr::read_volatile(&read_len) & 8191;
            if read_len > MAX_CAPTURE_BYTES || extra > MAX_CAPTURE_BYTES - read_len {
                return;
            }
            (*record).results[index].data_offset = extra as u32;
            extra += read_len;
        }
        // Recheck bounds after helper calls; 5.15 does not preserve bounds of
        // scalar fields reloaded from map values.
        if captured_len > MAX_STACK || extra > MAX_CAPTURE_BYTES {
            return;
        }
        h.capture_bytes = extra as u32;
        let length = PREFIX_SIZE + captured_len + extra;
        h.length = length as u32;
        let data = core::slice::from_raw_parts(record.cast::<u8>(), length);
        if EVENTS.output(data, 0).is_err() {
            if let Some(lost) = LOST.get_ptr_mut(0) {
                *lost += 1;
            }
        }
    }
}

// A global scalar-only function is verified once on 5.15. Keeping the bounded
// plan evaluator out of the caller prevents exponential states across 16 items.
#[unsafe(no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn amt_capture_item(cookie: u64, index: u32, offset: usize) -> usize {
    if index as usize >= MAX_CAPTURES {
        return 0;
    }
    // SAFETY: configs remain immutable while attached; scratch is per CPU.
    unsafe {
        let Some(config) = CONFIGS.get(&cookie) else {
            return 0;
        };
        let Some(record) = SCRATCH.get_ptr_mut(0) else {
            return 0;
        };
        let plan = &config.captures[index as usize];
        let result = &mut (*record).results[index as usize];
        evaluate(plan, &(*record).header.regs, result);
        if result.status != STATUS_OK || plan.kind == KIND_SCALAR {
            return 0;
        }
        capture_memory(plan, result, record, offset)
    }
}

#[inline(never)]
unsafe fn capture_memory(
    plan: &CapturePlan,
    result: &mut CaptureResult,
    record: *mut Record,
    offset: usize,
) -> usize {
    if offset > MAX_STACK + MAX_CAPTURE_BYTES {
        result.status = STATUS_OVERFLOW;
        return 0;
    }
    let requested = (plan.byte_length as usize).min(MAX_CAPTURE_BYTES);
    if requested == 0 {
        result.status = STATUS_OVERFLOW;
        return 0;
    }
    // SAFETY: offset <= the logical payload capacity and the map has a full
    // 4 KiB tail. Both helper arguments therefore have independent bounds.
    unsafe {
        result.address = result.value;
        let length = if plan.kind == KIND_STRING {
            let ret = bpf_probe_read_user_str(
                (*record).payload.as_mut_ptr().add(offset).cast(),
                requested as u32,
                result.value as *const _,
            );
            if ret < 0 {
                result.status = STATUS_FAULT;
                0
            } else {
                let length = (ret as usize).min(requested);
                if length == requested {
                    result.status = STATUS_TRUNCATED;
                }
                length.saturating_sub(1)
            }
        } else {
            let length =
                copy_pages::<MAX_CAPTURE_BYTES, 2>(result.value, record, offset, requested);
            if length < requested {
                result.status = STATUS_FAULT;
            }
            length
        };
        let length = core::ptr::read_volatile(&length) & 8191;
        if length > MAX_CAPTURE_BYTES {
            result.status = STATUS_OVERFLOW;
            return 0;
        }
        result.data_len = length as u32;
        length
    }
}

#[inline(never)]
unsafe fn copy_pages<const LIMIT: usize, const PAGES: usize>(
    address: u64,
    record: *mut Record,
    offset: usize,
    requested: usize,
) -> usize {
    if requested > LIMIT || offset > MAX_STACK + MAX_CAPTURE_BYTES {
        return 0;
    }
    let mut copied = 0_usize;
    for _ in 0..PAGES {
        if copied >= requested {
            break;
        }
        let Some(current) = address.checked_add(copied as u64) else {
            break;
        };
        let chunk = (4096 - (current as usize & 4095)).min(requested - copied);
        // LLVM can prove the subtraction cannot underflow, while the 5.15
        // verifier loses that relationship on later iterations. Keep a scalar
        // mask in the emitted instructions, even after loop unrolling.
        let chunk = unsafe { core::ptr::read_volatile(&chunk) } & 8191;
        if chunk == 0 || chunk > 4096 || copied > MAX_STACK {
            break;
        }
        let destination_offset = offset + copied;
        if destination_offset > MAX_STACK + MAX_CAPTURE_BYTES {
            break;
        }
        // SAFETY: the destination window is explicitly bounded in the map value. Each
        // iteration reads at most the current 4 KiB page; only successes count.
        if unsafe {
            bpf_probe_read_user_buf(
                current as *const u8,
                core::slice::from_raw_parts_mut(
                    (*record).payload.as_mut_ptr().add(destination_offset),
                    chunk,
                ),
            )
        }
        .is_err()
        {
            break;
        }
        copied += chunk;
    }
    copied
}

#[inline(always)]
fn offset(value: u64, delta: i64) -> Option<u64> {
    if delta >= 0 {
        value.checked_add(delta as u64)
    } else {
        value.checked_sub(delta.unsigned_abs())
    }
}

#[inline(never)]
unsafe fn evaluate(plan: &CapturePlan, regs: &Registers, result: &mut CaptureResult) {
    let mut value = match plan.base_register {
        index if index < 31 => regs.x[index as usize],
        31 => regs.sp,
        32 => regs.pc,
        33 => regs.pstate,
        _ => plan.immediate,
    };
    for index in 0..MAX_READS {
        if index >= plan.read_count as usize {
            break;
        }
        let step = &plan.reads[index];
        let Some(address) = offset(value, step.offset) else {
            result.status = STATUS_OVERFLOW;
            return;
        };
        result.address = address;
        // SAFETY: probe_read_user validates the target pointer and reports faults;
        // each helper writes only its fixed-size local integer result.
        let read = unsafe {
            match step.width {
                1 => bpf_probe_read_user(address as *const u8).map(u64::from),
                2 => bpf_probe_read_user(address as *const u16).map(u64::from),
                4 => bpf_probe_read_user(address as *const u32).map(u64::from),
                8 => bpf_probe_read_user(address as *const u64),
                _ => {
                    result.status = STATUS_OVERFLOW;
                    return;
                }
            }
        };
        match read {
            Ok(next) => value = next,
            Err(_) => {
                result.status = STATUS_FAULT;
                return;
            }
        }
    }
    match offset(value, plan.final_offset) {
        Some(value) => result.value = value,
        None => result.status = STATUS_OVERFLOW,
    }
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}
