use super::plan::Plan;
use crate::ktools::bindings::{
    PR_UXN_PROBE, UXN_PROBE_ABI_VERSION, UXN_PROBE_CMD_INFO, UXN_PROBE_CMD_STAT, uxn_probe_info,
    uxn_probe_stat,
};
use anyhow::{Context, Result, ensure};
use std::{
    collections::BTreeSet,
    io,
    time::{Duration, Instant},
};

pub struct Backend {
    pid: u32,
    pages: Vec<(u64, u32, u64)>,
    next_check: Instant,
}

impl Backend {
    pub fn verify(pid: u32, plan: &Plan) -> Result<Self> {
        // Native uprobe success alone does not prove that UXN was selected.
        // SAFETY: sysconf has no pointer arguments.
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        ensure!(page_size == 4096, "itrace requires 4 KiB pages");
        let mut info = uxn_probe_info::default();
        query(UXN_PROBE_CMD_INFO, &mut info)
            .context("itrace requires the existing UXN query ABI")?;
        ensure!(
            info.version == UXN_PROBE_ABI_VERSION,
            "unsupported UXN ABI {}",
            info.version
        );
        let addresses = plan
            .points
            .iter()
            .flat_map(|point| point.instructions.keys())
            .map(|pc| pc & !4095)
            .collect::<BTreeSet<_>>();
        let pages = addresses
            .into_iter()
            .map(|page| {
                let status = Self::page(pid, page)?;
                Ok((page, status.generation, status.recomp_addr))
            })
            .collect::<Result<_>>()?;
        Ok(Self {
            pid,
            pages,
            next_check: Instant::now() + Duration::from_millis(250),
        })
    }

    fn page(pid: u32, page: u64) -> Result<uxn_probe_stat> {
        let mut status = uxn_probe_stat {
            pid,
            page_addr: page,
            ..Default::default()
        };
        query(UXN_PROBE_CMD_STAT, &mut status).with_context(|| {
            format!("no active UXN recomp for {page:#x}; native BRK/XOL fallback cannot run itrace")
        })?;
        ensure!(
            status.active == 1 && status.recomp_addr != 0 && status.generation != 0,
            "UXN recomp inactive at {page:#x}"
        );
        Ok(status)
    }

    pub fn check(&mut self) -> Result<()> {
        if Instant::now() < self.next_check {
            return Ok(());
        }
        self.next_check = Instant::now() + Duration::from_millis(250);
        for (page, generation, recomp) in &self.pages {
            let status = Self::page(self.pid, *page)?;
            ensure!(
                status.generation == *generation && status.recomp_addr == *recomp,
                "UXN generation changed at {page:#x}; instruction trace is incomplete"
            );
        }
        Ok(())
    }

    pub fn pages(&self) -> usize {
        self.pages.len()
    }
}

fn query<T>(command: u32, value: &mut T) -> Result<()> {
    // SAFETY: private callers pair INFO/STAT with their generated UAPI struct.
    // The kernel copies synchronously; reserved prctl arguments are zero.
    let result = unsafe {
        libc::prctl(
            PR_UXN_PROBE as libc::c_int,
            libc::c_ulong::from(command),
            value as *mut T,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}
