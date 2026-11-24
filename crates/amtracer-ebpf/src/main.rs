#![no_std]
#![no_main]

use amtracer_abi::{EVENT_MAGIC, EVENT_VERSION, Header, MAX_PROBES, ProbeConfig, Record};
use aya_ebpf::{
    EbpfContext,
    helpers::{
        bpf_get_current_pid_tgid, bpf_get_smp_processor_id, bpf_ktime_get_ns,
        bpf_probe_read_user_buf, generated::bpf_get_attach_cookie,
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
        let bytes = (config.stack_bytes as usize).min(amtracer_abi::MAX_STACK);
        let mut captured_len = 0_usize;
        if bytes != 0 {
            if bpf_probe_read_user_buf(user.sp as *const u8, &mut (&mut (*record).stack)[..bytes])
                .is_ok()
            {
                captured_len = bytes;
            } else {
                h.flags |= 1;
            }
        }
        // Keep length in a scalar and recheck after all helper calls: the 5.15
        // verifier does not preserve bounds of scalar fields reloaded from maps.
        if captured_len > amtracer_abi::MAX_STACK {
            return;
        }
        h.stack_len = captured_len as u32;
        let length = core::mem::size_of::<Header>() + captured_len;
        h.length = length as u32;
        let data = core::slice::from_raw_parts(record.cast::<u8>(), length);
        if EVENTS.output(data, 0).is_err() {
            if let Some(lost) = LOST.get_ptr_mut(0) {
                *lost += 1;
            }
        }
    }
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}
