use crate::Registers;

pub const MAGIC: u32 = 0x414d5449;
pub const VERSION: u16 = 1;
pub const FLAG_REGS: u16 = 1;
pub const MAX_SITES: u32 = 1024;
pub const MAX_ADDRESSES: u32 = 4096;
pub const MAX_THREADS: u32 = 4096;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Config {
    pub tgid: u32,
    pub enabled: u32,
    pub flags: u32,
    pub site_count: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Address {
    pub cookie: u64,
    pub pc: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ThreadState {
    pub epoch: u64,
    pub sequence: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct Header {
    pub magic: u32,
    pub version: u16,
    pub flags: u16,
    pub length: u32,
    pub tgid: u32,
    pub tid: u32,
    pub cpu: u32,
    pub timestamp_ns: u64,
    pub sequence: u64,
    pub thread_epoch: u64,
    pub cookie: u64,
    pub pc: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Record {
    pub header: Header,
    pub regs: Registers,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Stats {
    pub hits: u64,
    pub submitted: u64,
    pub ring_lost: u64,
    pub state_failed: u64,
}

const _: () = {
    assert!(core::mem::size_of::<Config>() == 16);
    assert!(core::mem::size_of::<Address>() == 16);
    assert!(core::mem::size_of::<ThreadState>() == 16);
    assert!(core::mem::size_of::<Header>() == 64);
    assert!(core::mem::size_of::<Record>() == 336);
    assert!(core::mem::size_of::<Stats>() == 32);
};
