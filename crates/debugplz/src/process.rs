use crate::target::{Mapping, ProcessMaps};
use anyhow::{Context, Result, ensure};
use std::{
    fs,
    os::unix::fs::MetadataExt,
    time::{Duration, Instant},
};

const CHECK_INTERVAL: Duration = Duration::from_millis(250);

struct Identity {
    start_time: u64,
    executable: (u64, u64),
}

pub enum MappingChange {
    Unchanged,
    Changed(ProcessMaps),
    ProbeRemoved,
}

pub struct MappingMonitor {
    pid: u32,
    executable: Vec<Mapping>,
    probes: Vec<Vec<Mapping>>,
    next_check: Instant,
    probe_removed: bool,
}

impl MappingMonitor {
    pub fn new(maps: &ProcessMaps, probes: Vec<Vec<Mapping>>) -> Self {
        Self {
            pid: maps.pid,
            executable: Self::executable(maps),
            probes,
            next_check: Instant::now(),
            probe_removed: false,
        }
    }

    fn executable(maps: &ProcessMaps) -> Vec<Mapping> {
        maps.mappings
            .iter()
            .filter(|m| m.executable)
            .cloned()
            .collect()
    }

    pub fn check(&mut self, force: bool) -> Result<MappingChange> {
        if self.probe_removed {
            return Ok(MappingChange::ProbeRemoved);
        }
        if !force && Instant::now() < self.next_check {
            return Ok(MappingChange::Unchanged);
        }
        self.next_check = Instant::now() + CHECK_INTERVAL;
        let maps = ProcessMaps::read(self.pid)?;
        Ok(self.compare(maps))
    }

    fn compare(&mut self, maps: ProcessMaps) -> MappingChange {
        let executable = Self::executable(&maps);
        if self
            .probes
            .iter()
            .any(|probe| probe.iter().any(|m| !executable.contains(m)))
        {
            eprintln!("target process {} probe mapping changed", self.pid);
            self.probe_removed = true;
            return MappingChange::ProbeRemoved;
        }
        if executable == self.executable {
            return MappingChange::Unchanged;
        }
        self.executable = executable;
        MappingChange::Changed(maps)
    }
}

impl Identity {
    fn read(pid: u32) -> Result<Option<Self>> {
        let stat = match fs::read_to_string(format!("/proc/{pid}/stat")) {
            Ok(stat) => stat,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).context("reading process identity"),
        };
        let Some(start_time) = parse_stat(&stat)? else {
            return Ok(None);
        };
        let metadata = match fs::metadata(format!("/proc/{pid}/exe")) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).context("reading process executable identity"),
        };
        Ok(Some(Self {
            start_time,
            executable: (metadata.dev(), metadata.ino()),
        }))
    }
}

fn parse_stat(stat: &str) -> Result<Option<u64>> {
    let fields = stat.rsplit_once(')').context("invalid process stat")?.1;
    let mut fields = fields.split_whitespace();
    let state = fields.next().context("missing process state")?;
    if state == "Z" || state == "X" || state == "x" {
        return Ok(None);
    }
    let start_time = fields
        .nth(18)
        .context("missing process start time")?
        .parse()?;
    Ok(Some(start_time))
}

pub struct ProcessMonitor {
    pid: u32,
    identity: Identity,
    next_check: Instant,
    stopped: bool,
}

impl ProcessMonitor {
    pub fn new(pid: u32) -> Result<Self> {
        let identity = Identity::read(pid)?.context("target process is not running")?;
        Ok(Self {
            pid,
            identity,
            next_check: Instant::now(),
            stopped: false,
        })
    }

    pub fn check(&mut self) -> Result<bool> {
        if self.stopped {
            return Ok(false);
        }
        if Instant::now() < self.next_check {
            return Ok(true);
        }
        self.next_check = Instant::now() + CHECK_INTERVAL;
        let Some(identity) = Identity::read(self.pid)? else {
            eprintln!("target process {} exited", self.pid);
            self.stopped = true;
            return Ok(false);
        };
        if identity.start_time != self.identity.start_time
            || identity.executable != self.identity.executable
        {
            eprintln!("target process {} identity changed", self.pid);
            self.stopped = true;
            return Ok(false);
        }
        Ok(true)
    }

    pub fn verify(&mut self) -> Result<()> {
        self.next_check = Instant::now();
        ensure!(self.check()?, "target process changed during setup");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stat_handles_spaces_and_parentheses() {
        let stat = "123 (name ) with spaces) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 987 20";
        assert_eq!(parse_stat(stat).unwrap(), Some(987));
        assert_eq!(parse_stat(&stat.replace(") S ", ") Z ")).unwrap(), None);
        assert!(parse_stat("invalid").is_err());
    }

    #[test]
    fn mapping_changes_refresh_and_probe_removal_stops() {
        let a: Mapping = "7000-8000 r-xp 00001000 08:01 42 /a.so".parse().unwrap();
        let b: Mapping = "9000-a000 r-xp 00001000 08:01 43 /b.so".parse().unwrap();
        let maps = ProcessMaps {
            pid: 1,
            mappings: vec![a.clone()],
        };
        let mut monitor = MappingMonitor::new(&maps, vec![vec![a.clone()]]);
        assert!(matches!(monitor.compare(maps), MappingChange::Unchanged));
        let maps = ProcessMaps {
            pid: 1,
            mappings: vec![a, b.clone()],
        };
        assert!(matches!(monitor.compare(maps), MappingChange::Changed(_)));
        let maps = ProcessMaps {
            pid: 1,
            mappings: vec![b],
        };
        assert!(matches!(monitor.compare(maps), MappingChange::ProbeRemoved));
        assert!(matches!(
            monitor.check(false).unwrap(),
            MappingChange::ProbeRemoved
        ));
    }
}
