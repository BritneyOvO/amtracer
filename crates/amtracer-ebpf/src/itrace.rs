#![no_std]
#![no_main]

use amtracer_abi::instruction::*;
use aya_ebpf::{
    EbpfContext,
    bindings::{BPF_RB_FORCE_WAKEUP, BPF_RB_NO_WAKEUP},
    helpers::{
        bpf_get_current_pid_tgid, bpf_get_smp_processor_id, bpf_ktime_get_ns,
        generated::bpf_get_attach_cookie,
    },
    macros::{map, raw_tracepoint, uprobe},
    maps::{Array, HashMap, PerCpuArray, RingBuf},
    programs::{ProbeContext, RawTracePointContext},
};

#[map]
static IT_SETTINGS: Array<Config> = Array::with_max_entries(1, 0);
#[map]
static IT_ALLOWED: HashMap<Address, u8> = HashMap::with_max_entries(MAX_ADDRESSES, 0);
#[map]
static IT_THREADS: HashMap<u64, ThreadState> = HashMap::with_max_entries(MAX_THREADS, 0);
#[map]
static IT_EVENTS: RingBuf = RingBuf::with_byte_size(32 * 1024 * 1024, 0);
#[map]
static IT_SCRATCH: PerCpuArray<Scratch> = PerCpuArray::with_max_entries(1, 0);
#[map]
static IT_INITIAL: PerCpuArray<ThreadState> = PerCpuArray::with_max_entries(1, 0);
#[map]
static IT_STATS: PerCpuArray<Stats> = PerCpuArray::with_max_entries(1, 0);

#[repr(C)]
struct Scratch {
    record: Record,
    current: [u64; REGISTER_COUNT],
}

#[uprobe]
pub fn instruction_trace(ctx: ProbeContext) -> u32 {
    // SAFETY: this program runs with kernel-supplied AArch64 pt_regs. Per-CPU
    // scratch/stats are serialized by the uprobe BPF execution context.
    unsafe { capture(&ctx) };
    0
}

unsafe fn capture(ctx: &ProbeContext) {
    let Some(config) = IT_SETTINGS.get(0) else {
        return;
    };
    let identity = bpf_get_current_pid_tgid();
    if config.enabled == 0 || (identity >> 32) as u32 != config.tgid {
        return;
    }
    // SAFETY: the cookie belongs to the current uprobe invocation; pt_regs is
    // the AArch64 user_pt_regs prefix, as in the existing capture program.
    let (cookie, user) = unsafe {
        (
            bpf_get_attach_cookie(ctx.as_ptr()),
            &*(ctx.regs.cast::<aya_ebpf::bindings::user_pt_regs>()),
        )
    };
    if cookie == 0 || cookie > u64::from(config.site_count) {
        return;
    }
    let address = Address {
        cookie,
        pc: user.pc,
    };
    // SAFETY: the address allowlist is immutable from enable through detach.
    if unsafe { IT_ALLOWED.get(&address) }.is_none() {
        return;
    }
    let Some(stats) = IT_STATS.get_ptr_mut(0) else {
        return;
    };
    let Some(scratch) = IT_SCRATCH.get_ptr_mut(0) else {
        return;
    };
    // SAFETY: the helper is valid in a uprobe context.
    let timestamp = unsafe { bpf_ktime_get_ns() };
    // SAFETY: stats and scratch are per CPU; only this task can access its
    // thread entry concurrently. sched_process_exit removes it before TID reuse.
    unsafe {
        (*stats).hits += 1;
        let mut thread = IT_THREADS.get_ptr_mut(&identity);
        if thread.is_none() {
            // A map-backed initializer keeps the expanded thread state off
            // BPF's 512-byte stack. Only epoch changes; all other fields stay zero.
            let Some(initial) = IT_INITIAL.get_ptr_mut(0) else {
                (*stats).state_failed += 1;
                return;
            };
            (*initial).epoch = timestamp;
            if IT_THREADS.insert(&identity, &*initial, 1).is_err() {
                (*stats).state_failed += 1;
                return;
            }
            thread = IT_THREADS.get_ptr_mut(&identity);
        }
        let Some(thread) = thread else {
            (*stats).state_failed += 1;
            return;
        };
        let Some(sequence) = (*thread).sequence.checked_add(1) else {
            (*stats).state_failed += 1;
            return;
        };
        (*thread).sequence = sequence;
        let record = core::ptr::addr_of_mut!((*scratch).record);
        let regs = config.flags & u32::from(FLAG_REGS) != 0;
        let full = regs
            && ((*thread).base_sequence == 0
                || sequence - (*thread).full_sequence >= FULL_INTERVAL);
        let flags = if full {
            FLAG_REGS | FLAG_REGS_FULL
        } else if regs {
            FLAG_REGS
        } else {
            0
        };
        let mut length = size_of::<Header>();
        (*record).header = Header {
            magic: MAGIC,
            version: VERSION,
            flags,
            length: 0,
            tgid: u32::try_from(identity >> 32).unwrap_or(0),
            tid: u32::try_from(identity & 0xffff_ffff).unwrap_or(0),
            cpu: bpf_get_smp_processor_id(),
            timestamp_ns: timestamp,
            sequence,
            thread_epoch: (*thread).epoch,
            cookie,
            pc: user.pc,
        };
        if regs {
            let mut count = 0_usize;
            let mut mask = 0_u64;
            // Constant volatile loads avoid a memmove with a variable ctx
            // pointer, which the target 5.15 verifier rejects.
            macro_rules! pack_value {
                ($i:expr, $value:expr) => {{
                    let value = $value;
                    (*scratch).current[$i] = value;
                    if (full || value != (*thread).values[$i]) && count < REGISTER_COUNT {
                        (*record).values[count] = value;
                        count += 1;
                        mask |= 1_u64 << $i;
                    }
                }};
            }
            macro_rules! pack_x {
                ($($i:expr),*) => { $(pack_value!($i,
                    core::ptr::read_volatile(core::ptr::addr_of!(user.regs[$i]))
                );)* };
            }
            pack_x!(
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                23, 24, 25, 26, 27, 28, 29, 30
            );
            pack_value!(31, user.sp);
            pack_value!(32, user.pstate);
            (*record).registers = RegisterHeader {
                base_sequence: if full { 0 } else { (*thread).base_sequence },
                changed_mask: mask,
            };
            length += size_of::<RegisterHeader>() + count * size_of::<u64>();
        }
        (*record).header.length = u32::try_from(length).unwrap_or(0);
        let bytes = core::slice::from_raw_parts(record.cast::<u8>(), length);
        // A fast consumer can otherwise empty the ring and sleep after only a
        // few records, forcing a wakeup in nearly every probe. Sparse tails are
        // drained by userspace's bounded poll timeout; the first record wakes now.
        let notification = if sequence % 64 == 1 {
            BPF_RB_FORCE_WAKEUP
        } else {
            BPF_RB_NO_WAKEUP
        };
        if IT_EVENTS.output(bytes, u64::from(notification)).is_err() {
            (*stats).ring_lost += 1;
            (*thread).base_sequence = 0;
        } else {
            (*stats).submitted += 1;
            (*stats).submitted_bytes += length as u64;
            if regs {
                // Commit the baseline only after submission. A failed delta
                // forces a full snapshot, so a gap cannot poison later values.
                (*thread).values = (*scratch).current;
                (*thread).base_sequence = sequence;
                if full {
                    (*thread).full_sequence = sequence;
                    (*stats).full_snapshots += 1;
                }
            }
        }
    }
}

#[raw_tracepoint]
pub fn instruction_thread_exit(_ctx: RawTracePointContext) -> u32 {
    let identity = bpf_get_current_pid_tgid();
    let Some(config) = IT_SETTINGS.get(0) else {
        return 0;
    };
    if identity >> 32 != u64::from(config.tgid) {
        return 0;
    }
    // Removal is synchronous on the exiting task. This lifecycle hook
    // is attached before any sites are enabled and held until after detach.
    let _ = IT_THREADS.remove(&identity);
    0
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}
