use super::export::{Pointer, Segment, Snapshot};
use crate::{
    ktools::{
        Control,
        bindings::{
            AMT_KT_IOC_MEM_READ, AMT_KT_IOC_OPEN_MEM, KT_FEATURE_RWMEM, KT_MEM_MODE_PROCESS_VM,
            kt_mem_io, kt_target_open,
        },
    },
    target::integer,
};
use anyhow::{Context, Result, bail, ensure};
use std::{
    collections::BTreeMap,
    ffi::{CStr, CString},
    fs::{self, File},
    io,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::fs::FileExt,
    },
    path::{Path, PathBuf},
    str::FromStr,
};

const PAGE_SIZE: u64 = 4096;
const PM_PRESENT_OR_SWAP: u64 = (1_u64 << 63) | (1_u64 << 62);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReaderSpec {
    Syscall,
    Pread,
    Custom(PathBuf),
}

impl FromStr for ReaderSpec {
    type Err = anyhow::Error;

    fn from_str(input: &str) -> Result<Self> {
        match input {
            "syscall" => Ok(Self::Syscall),
            "pread" => Ok(Self::Pread),
            _ => {
                let path = input.strip_prefix("custom:").unwrap_or(input);
                ensure!(
                    !path.is_empty()
                        && (input.starts_with("custom:")
                            || path.contains('/')
                            || Path::new(path)
                                .extension()
                                .is_some_and(|ext| ext.eq_ignore_ascii_case("so"))),
                    "unknown reader {input:?}; expected syscall, pread, or path to a custom .so"
                );
                Ok(Self::Custom(PathBuf::from(path)))
            }
        }
    }
}

pub trait MemoryReader {
    fn read_chunk(&mut self, address: u64, buffer: &mut [u8]) -> Result<usize>;
}

pub struct LiveScanConfig<'a> {
    pub pid: u32,
    pub max_address: u64,
    pub width: u64,
    pub align4: bool,
    pub cross_page_step4: bool,
    pub pagemap: bool,
    pub restricted: bool,
    pub value_margin: u64,
    pub targets: &'a [u64],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VmaRegion {
    pub start: u64,
    pub end: u64,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    pub shared: bool,
    pub path: String,
}

impl VmaRegion {
    pub fn parse_maps(text: &str) -> Result<Vec<Self>> {
        let mut regions = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let mut fields = line.splitn(6, char::is_whitespace);
            let range = fields.next().context("missing VMA range")?;
            let perms = fields
                .find(|s| !s.is_empty())
                .context("missing VMA permissions")?;
            let _offset = fields.find(|s| !s.is_empty()).context("missing offset")?;
            let _dev = fields.find(|s| !s.is_empty()).context("missing device")?;
            let _inode = fields.find(|s| !s.is_empty()).context("missing inode")?;
            let path = fields.next().unwrap_or("").trim().to_owned();
            let (start_hex, end_hex) = range.split_once('-').context("invalid VMA range")?;
            let start = u64::from_str_radix(start_hex, 16)?;
            let end = u64::from_str_radix(end_hex, 16)?;
            if start >= end {
                continue;
            }
            regions.push(Self {
                start,
                end,
                readable: perms.starts_with('r'),
                writable: perms.contains('w'),
                executable: perms.contains('x'),
                shared: perms.ends_with('s'),
                path,
            });
        }
        regions.sort_unstable_by_key(|region| (region.start, region.end));
        Ok(regions)
    }

    fn is_scannable(&self, restricted: bool) -> bool {
        if matches!(
            self.path.as_str(),
            "[vvar]" | "[vdso]" | "[vectors]" | "[sigpage]"
        ) {
            return false;
        }
        if self.path.starts_with("/dev/")
            && !self.path.starts_with("/dev/ashmem")
            && !self.path.starts_with("/dev/zero")
        {
            return false;
        }
        self.readable || restricted
    }

    fn module_name(&self) -> Option<String> {
        if self.path.is_empty() || self.path.starts_with('[') || self.path.starts_with("/dev/") {
            return None;
        }
        let clean = self.path.strip_suffix(" (deleted)").unwrap_or(&self.path);
        Path::new(clean)
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .filter(|name| !name.is_empty())
    }

    fn segment_kind(&self) -> &'static str {
        if self.executable {
            ".text"
        } else if self.writable {
            ".data"
        } else if self.readable {
            ".rodata"
        } else {
            ".prot_none"
        }
    }
}

pub fn build_segments(regions: &[VmaRegion], max_address: u64) -> Vec<Segment> {
    let mut counts: BTreeMap<(String, String), usize> = BTreeMap::new();
    let mut segments = Vec::new();
    let mut last_module: Option<String> = None;

    for region in regions {
        if region.start > max_address {
            continue;
        }
        let end = region.end.min(max_address);
        if region.start >= end {
            continue;
        }
        let (module, base_kind) = if let Some(name) = region.module_name() {
            last_module = Some(name.clone());
            (name, region.segment_kind().to_owned())
        } else if region.path == "[anon:.bss]"
            && let Some(prev) = &last_module
        {
            (prev.clone(), ".bss".to_owned())
        } else {
            last_module = None;
            continue;
        };
        let count = counts
            .entry((module.clone(), base_kind.clone()))
            .or_insert(0);
        let segment = if *count == 0 {
            base_kind
        } else {
            format!("{base_kind}.{}", *count)
        };
        *count += 1;
        segments.push(Segment {
            module,
            segment,
            start: region.start,
            end,
        });
    }
    segments
}

pub fn scan_process(config: &LiveScanConfig<'_>, spec: &ReaderSpec) -> Result<Snapshot> {
    ensure!(
        config.pid != 0 && i32::try_from(config.pid).is_ok(),
        "invalid process ID {}",
        config.pid
    );
    let maps_text = fs::read_to_string(format!("/proc/{}/maps", config.pid))
        .with_context(|| format!("reading /proc/{}/maps", config.pid))?;
    let regions = VmaRegion::parse_maps(&maps_text)?;
    let pagemap = if config.pagemap {
        File::open(format!("/proc/{}/pagemap", config.pid)).ok()
    } else {
        None
    };
    let mut reader = open_reader(config.pid, spec, config.restricted)?;
    scan_regions(config, &regions, reader.as_mut(), pagemap.as_ref())
}

pub fn scan_regions(
    config: &LiveScanConfig<'_>,
    regions: &[VmaRegion],
    reader: &mut dyn MemoryReader,
    pagemap: Option<&File>,
) -> Result<Snapshot> {
    let segments = build_segments(regions, config.max_address);
    let scannable: Vec<&VmaRegion> = regions
        .iter()
        .filter(|region| {
            region.is_scannable(config.restricted) && region.start < config.max_address
        })
        .collect();
    let valid_bounds = valid_target_bounds(&scannable, config);
    let step = usize::try_from(if config.align4 { 4 } else { config.width })?;
    let width = usize::try_from(config.width)?;
    let page_bytes = usize::try_from(PAGE_SIZE)?;
    let mut page_buf = vec![0_u8; page_bytes];
    let mut pointers = Vec::new();
    let mut prev_tail: Option<(u64, [u8; 4])> = None;

    for region in scannable {
        let region_end = region.end.min(config.max_address);
        let mut page_va = region.start;
        while page_va < region_end {
            let chunk_len = usize::try_from((region_end - page_va).min(PAGE_SIZE))?;
            if chunk_len < width {
                prev_tail = None;
                break;
            }
            if let Some(pm) = pagemap
                && !page_is_resident(pm, page_va)
            {
                prev_tail = None;
                page_va = page_va.saturating_add(PAGE_SIZE);
                continue;
            }
            let got = match reader.read_chunk(page_va, &mut page_buf[..chunk_len]) {
                Ok(n) if n >= width => n,
                _ => {
                    prev_tail = None;
                    page_va = page_va.saturating_add(PAGE_SIZE);
                    continue;
                }
            };
            let slice = &page_buf[..got];
            if config.cross_page_step4
                && width == 8
                && got >= 4
                && let Some((end_va, tail)) = prev_tail
                && end_va == page_va
            {
                let mut combined = [0_u8; 8];
                combined[..4].copy_from_slice(&tail);
                combined[4..].copy_from_slice(&slice[..4]);
                let value = decode_pointer(&combined, config.max_address);
                if is_candidate_value(value, &valid_bounds, config.max_address) {
                    pointers.push(Pointer {
                        address: page_va - 4,
                        value,
                    });
                }
            }

            let mut offset = 0;
            while offset + width <= got {
                let slot_va = page_va + u64::try_from(offset)?;
                if slot_va.is_multiple_of(u64::try_from(step)?) {
                    let value = decode_pointer(&slice[offset..offset + width], config.max_address);
                    if is_candidate_value(value, &valid_bounds, config.max_address) {
                        pointers.push(Pointer {
                            address: slot_va,
                            value,
                        });
                    }
                }
                offset += step;
            }

            if config.cross_page_step4 && width == 8 && got == page_bytes {
                let mut tail = [0_u8; 4];
                tail.copy_from_slice(&slice[got - 4..got]);
                prev_tail = Some((page_va + PAGE_SIZE, tail));
            } else {
                prev_tail = None;
            }
            page_va = page_va.saturating_add(PAGE_SIZE);
        }
    }

    pointers.sort_unstable_by_key(|p| (p.address, p.value));
    pointers.dedup_by_key(|p| p.address);
    Ok(Snapshot {
        version: 1,
        segments,
        pointers,
    })
}

fn valid_target_bounds(regions: &[&VmaRegion], config: &LiveScanConfig<'_>) -> Option<(u64, u64)> {
    let mut min_addr = u64::MAX;
    let mut max_addr = 0_u64;
    for region in regions {
        min_addr = min_addr.min(region.start);
        max_addr = max_addr.max(region.end.min(config.max_address));
    }
    for &target in config.targets {
        min_addr = min_addr.min(target);
        max_addr = max_addr.max(target);
    }
    (min_addr <= max_addr).then(|| {
        (
            min_addr.saturating_sub(config.value_margin),
            max_addr
                .saturating_add(config.value_margin)
                .min(config.max_address),
        )
    })
}

fn decode_pointer(bytes: &[u8], max_address: u64) -> u64 {
    if bytes.len() == 4 {
        let mut raw = [0_u8; 4];
        raw.copy_from_slice(bytes);
        u64::from(u32::from_le_bytes(raw))
    } else {
        let mut raw = [0_u8; 8];
        raw.copy_from_slice(&bytes[..8]);
        let value = u64::from_le_bytes(raw);
        if max_address == u64::MAX {
            value & 0x00ff_ffff_ffff_ffff
        } else {
            value
        }
    }
}

fn is_candidate_value(value: u64, bounds: &Option<(u64, u64)>, max_address: u64) -> bool {
    if value == 0 || value > max_address {
        return false;
    }
    bounds.is_none_or(|(lo, hi)| value >= lo && value <= hi)
}

fn page_is_resident(pagemap: &File, page_va: u64) -> bool {
    let index = (page_va / PAGE_SIZE) * 8;
    let mut entry = [0_u8; 8];
    if pagemap.read_at(&mut entry, index).is_ok_and(|n| n == 8) {
        u64::from_le_bytes(entry) & PM_PRESENT_OR_SWAP != 0
    } else {
        true
    }
}

fn open_reader(pid: u32, spec: &ReaderSpec, restricted: bool) -> Result<Box<dyn MemoryReader>> {
    let pid_i32 = i32::try_from(pid)?;
    match spec {
        ReaderSpec::Syscall => Ok(Box::new(SyscallReader {
            pid: pid_i32,
            rwmem_fd: if restricted {
                open_rwmem_session(pid_i32)
            } else {
                None
            },
        })),
        ReaderSpec::Pread => {
            let file = File::open(format!("/proc/{pid}/mem"))
                .with_context(|| format!("opening /proc/{pid}/mem"))?;
            Ok(Box::new(PreadReader { file }))
        }
        ReaderSpec::Custom(path) => Ok(Box::new(CustomSoReader::load(pid_i32, path)?)),
    }
}

fn open_rwmem_session(pid: i32) -> Option<OwnedFd> {
    let control = Control::open().ok()?;
    let info = control.info().ok()?;
    if info.features & KT_FEATURE_RWMEM == 0 {
        return None;
    }
    let mut req = kt_target_open {
        size: u32::try_from(size_of::<kt_target_open>()).ok()?,
        pid,
        ..Default::default()
    };
    // SAFETY: KT_IOC_OPEN_MEM reads the initialized kt_target_open struct and returns an owned FD or -1.
    let fd = unsafe {
        libc::ioctl(
            control.as_raw_fd(),
            AMT_KT_IOC_OPEN_MEM as _,
            std::ptr::from_mut(&mut req),
        )
    };
    if fd < 0 {
        return None;
    }
    // SAFETY: fd >= 0 is a newly created descriptor transferred to this process.
    Some(unsafe { OwnedFd::from_raw_fd(fd) })
}

struct SyscallReader {
    pid: libc::pid_t,
    rwmem_fd: Option<OwnedFd>,
}

impl MemoryReader for SyscallReader {
    fn read_chunk(&mut self, address: u64, buffer: &mut [u8]) -> Result<usize> {
        let local = libc::iovec {
            iov_base: buffer.as_mut_ptr().cast::<libc::c_void>(),
            iov_len: buffer.len(),
        };
        let remote = libc::iovec {
            iov_base: (usize::try_from(address)? as *mut libc::c_void),
            iov_len: buffer.len(),
        };
        // SAFETY: local points to the valid mutable buffer slice; remote describes the target VA range.
        let read = unsafe { libc::process_vm_readv(self.pid, &local, 1, &remote, 1, 0) };
        if read > 0 {
            return Ok(usize::try_from(read)?);
        }
        if let Some(fd) = &self.rwmem_fd {
            let mut io_req = kt_mem_io {
                size: u32::try_from(size_of::<kt_mem_io>())?,
                flags: KT_MEM_MODE_PROCESS_VM,
                address,
                buffer: u64::try_from(buffer.as_mut_ptr().addr())?,
                length: u64::try_from(buffer.len())?,
                transferred: 0,
            };
            // SAFETY: KT_IOC_MEM_READ writes up to io_req.length bytes into buffer and updates transferred.
            let rc = unsafe {
                libc::ioctl(
                    fd.as_raw_fd(),
                    AMT_KT_IOC_MEM_READ as _,
                    std::ptr::from_mut(&mut io_req),
                )
            };
            if rc == 0 && io_req.transferred > 0 {
                return Ok(usize::try_from(io_req.transferred)?);
            }
        }
        Err(io::Error::last_os_error()).context("process_vm_readv failed")
    }
}

struct PreadReader {
    file: File,
}

impl MemoryReader for PreadReader {
    fn read_chunk(&mut self, address: u64, buffer: &mut [u8]) -> Result<usize> {
        self.file
            .read_at(buffer, address)
            .context("pread /proc/pid/mem failed")
    }
}

type CustomReadFn =
    unsafe extern "C" fn(pid: libc::pid_t, address: u64, buffer: *mut u8, length: usize) -> isize;

pub struct CustomSoReader {
    pid: libc::pid_t,
    handle: *mut libc::c_void,
    read_fn: CustomReadFn,
}

impl CustomSoReader {
    pub fn load(pid: libc::pid_t, path: &Path) -> Result<Self> {
        let c_path = CString::new(path.as_os_str().to_string_lossy().as_bytes())
            .context("library path contains interior NUL")?;
        // SAFETY: c_path is a valid NUL-terminated string.
        let handle = unsafe { libc::dlopen(c_path.as_ptr(), libc::RTLD_NOW) };
        if handle.is_null() {
            // SAFETY: dlerror returns a thread-local NUL-terminated error string or NULL after dlopen fails.
            let msg = unsafe {
                let err = libc::dlerror();
                if err.is_null() {
                    "dlopen failed".to_owned()
                } else {
                    CStr::from_ptr(err).to_string_lossy().into_owned()
                }
            };
            bail!("loading custom reader {}: {msg}", path.display());
        }
        let symbols = [
            c"debugplz_read_mem",
            c"read_mem",
            c"rwmem_read",
            c"custom_read_mem",
        ];
        for sym in symbols {
            // SAFETY: handle is a valid non-null dlopen handle and sym is a NUL-terminated CStr literal.
            let raw = unsafe { libc::dlsym(handle, sym.as_ptr()) };
            if !raw.is_null() {
                // SAFETY: the resolved symbol in a custom reader library conforms to CustomReadFn ABI.
                let read_fn: CustomReadFn = unsafe { std::mem::transmute(raw) };
                return Ok(Self {
                    pid,
                    handle,
                    read_fn,
                });
            }
        }
        // SAFETY: handle was returned by dlopen above and is closed before returning the error.
        unsafe {
            libc::dlclose(handle);
        }
        bail!(
            "custom reader {} does not export debugplz_read_mem / read_mem",
            path.display()
        )
    }
}

impl MemoryReader for CustomSoReader {
    fn read_chunk(&mut self, address: u64, buffer: &mut [u8]) -> Result<usize> {
        // SAFETY: buffer points to buffer.len() writable bytes for the duration of the FFI call.
        let rc = unsafe { (self.read_fn)(self.pid, address, buffer.as_mut_ptr(), buffer.len()) };
        ensure!(rc > 0, "custom reader failed at {address:#x} (rc={rc})");
        let n = usize::try_from(rc)?;
        ensure!(
            n <= buffer.len(),
            "custom reader returned out-of-bounds length"
        );
        Ok(n)
    }
}

impl Drop for CustomSoReader {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            // SAFETY: self.handle was opened by dlopen in CustomSoReader::load and is closed once on drop.
            unsafe {
                libc::dlclose(self.handle);
            }
        }
    }
}

pub(super) struct ModuleRange<'a> {
    pub name: Option<&'a str>,
    pub range: Option<(u64, u64)>,
}

pub(super) fn parse_module_range(spec: &str) -> Result<ModuleRange<'_>> {
    if let Some((name, range)) = spec.split_once(':') {
        ensure!(!name.is_empty(), "empty module name in {spec:?}");
        let (start, end) = parse_addr_pair(range)?;
        return Ok(ModuleRange {
            name: Some(name),
            range: Some((start, end)),
        });
    }
    if spec.starts_with("0x")
        && let Some((start_s, end_s)) = spec.split_once('-')
        && end_s.starts_with("0x")
    {
        let (start, end) = parse_addr_pair(&format!("{start_s}-{end_s}"))?;
        return Ok(ModuleRange {
            name: None,
            range: Some((start, end)),
        });
    }
    Ok(ModuleRange {
        name: Some(spec),
        range: None,
    })
}

fn parse_addr_pair(range: &str) -> Result<(u64, u64)> {
    let (start_s, end_s) = range
        .split_once('-')
        .with_context(|| format!("expected START-END in {range:?}"))?;
    let start = integer(start_s)?;
    let end = integer(end_s)?;
    ensure!(start < end, "invalid module range {start:#x}-{end:#x}");
    Ok((start, end))
}
