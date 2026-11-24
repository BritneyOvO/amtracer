#![no_std]

pub const EVENT_MAGIC: u32 = 0x414d5431;
pub const EVENT_VERSION: u16 = 2;
pub const MAX_PROBES: u32 = 64;
pub const MAX_STACK: usize = 16384;
pub const MAX_CAPTURES: usize = 16;
pub const MAX_READS: usize = 4;
pub const MAX_CAPTURE_BYTES: usize = 4096;
pub const KIND_SCALAR: u32 = 0;
pub const KIND_BYTES: u32 = 1;
pub const KIND_STRING: u32 = 2;
pub const STATUS_OK: u32 = 0;
pub const STATUS_FAULT: u32 = 1;
pub const STATUS_OVERFLOW: u32 = 2;
pub const STATUS_TRUNCATED: u32 = 3;

#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct Registers {
    pub x: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct Header {
    pub magic: u32,
    pub version: u16,
    pub kind: u16,
    pub length: u32,
    pub flags: u32,
    pub cookie: u64,
    pub timestamp_ns: u64,
    pub tgid: u32,
    pub tid: u32,
    pub cpu: u32,
    pub stack_len: u32,
    pub capture_count: u32,
    pub capture_bytes: u32,
    pub regs: Registers,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ProbeConfig {
    pub tgid: u32,
    pub stack_bytes: u32,
    pub capture_count: u32,
    pub reserved: u32,
    pub captures: [CapturePlan; MAX_CAPTURES],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ReadStep {
    pub offset: i64,
    pub width: u32,
    pub reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct CapturePlan {
    pub base_register: u32,
    pub kind: u32,
    pub immediate: u64,
    pub final_offset: i64,
    pub read_count: u32,
    pub byte_length: u32,
    pub reads: [ReadStep; MAX_READS],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct CaptureResult {
    pub value: u64,
    pub address: u64,
    pub data_offset: u32,
    pub data_len: u32,
    pub status: u32,
    pub reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Record {
    pub header: Header,
    pub results: [CaptureResult; MAX_CAPTURES],
    // One read-sized tail lets old verifiers bound the destination and helper
    // length independently. This tail is never included in emitted records.
    pub payload: [u8; MAX_STACK + MAX_CAPTURE_BYTES + 4096],
}

pub const PREFIX_SIZE: usize =
    core::mem::size_of::<Header>() + core::mem::size_of::<[CaptureResult; MAX_CAPTURES]>();
const _: () = assert!(core::mem::size_of::<Header>() == 328);
