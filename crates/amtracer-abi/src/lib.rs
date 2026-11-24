#![no_std]

pub const EVENT_MAGIC: u32 = 0x414d5431;
pub const EVENT_VERSION: u16 = 1;
pub const MAX_PROBES: u32 = 64;
pub const MAX_STACK: usize = 16384;

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
    pub regs: Registers,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ProbeConfig {
    pub tgid: u32,
    pub stack_bytes: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Record {
    pub header: Header,
    pub stack: [u8; MAX_STACK],
}

const _: () = assert!(core::mem::size_of::<Header>() == 320);
