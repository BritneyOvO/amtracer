pub const MAGIC: u32 = 0x414d5449;
pub const VERSION: u16 = 2;
pub const FLAG_REGS: u16 = 1;
pub const FLAG_REGS_FULL: u16 = 2;
pub const REGISTER_COUNT: usize = 33;
pub const REGISTER_MASK: u64 = (1 << REGISTER_COUNT) - 1;
pub const FULL_INTERVAL: u64 = 1024;
pub const REGISTER_NAMES: [&str; REGISTER_COUNT] = [
    "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14",
    "x15", "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27",
    "x28", "x29", "x30", "sp", "pstate",
];
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
#[derive(Clone, Copy)]
pub struct ThreadState {
    pub epoch: u64,
    pub sequence: u64,
    /// Zero forces a full snapshot, including after a failed submission.
    pub base_sequence: u64,
    pub full_sequence: u64,
    /// x0..x30, sp, pstate at the last successfully submitted event. PC is in Header.
    pub values: [u64; REGISTER_COUNT],
}

impl Default for ThreadState {
    fn default() -> Self {
        Self {
            epoch: 0,
            sequence: 0,
            base_sequence: 0,
            full_sequence: 0,
            values: [0; REGISTER_COUNT],
        }
    }
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
pub struct RegisterHeader {
    /// Zero for full snapshots; otherwise the preceding submitted sequence.
    pub base_sequence: u64,
    /// Bit 0..30 = x0..x30, bit 31 = sp, bit 32 = pstate.
    pub changed_mask: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Record {
    pub header: Header,
    pub registers: RegisterHeader,
    /// Packed in ascending mask-bit order. Only popcount(mask) values are sent.
    pub values: [u64; REGISTER_COUNT],
}

impl Default for Record {
    fn default() -> Self {
        Self {
            header: Header::default(),
            registers: RegisterHeader::default(),
            values: [0; REGISTER_COUNT],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Stats {
    pub hits: u64,
    pub submitted: u64,
    pub ring_lost: u64,
    pub state_failed: u64,
    /// Payload bytes accepted by the ring buffer, excluding its internal header.
    pub submitted_bytes: u64,
    pub full_snapshots: u64,
}

const _: () = {
    assert!(core::mem::size_of::<Config>() == 16);
    assert!(core::mem::size_of::<Address>() == 16);
    assert!(core::mem::size_of::<ThreadState>() == 296);
    assert!(core::mem::size_of::<Header>() == 64);
    assert!(core::mem::size_of::<RegisterHeader>() == 16);
    assert!(core::mem::size_of::<Record>() == 344);
    assert!(core::mem::size_of::<Stats>() == 48);
};
