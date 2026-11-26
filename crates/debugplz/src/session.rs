use crate::{Common, expr::Expression, target::ProbeSpec};
use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;
use std::{
    io::{BufRead, BufReader},
    path::PathBuf,
    process::{Child, Command, ExitStatus, Stdio},
    sync::mpsc::{self, SyncSender},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    pid: u32,
    #[serde(default)]
    duration: u64,
    #[serde(default)]
    count: u64,
    uprobe: Option<UprobeConfig>,
    syscall: Option<SyscallConfig>,
    binder: Option<BinderConfig>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UprobeConfig {
    probes: Vec<String>,
    #[serde(default)]
    expressions: Vec<String>,
    #[serde(default)]
    object: Option<PathBuf>,
    #[serde(default)]
    registers: bool,
    #[serde(default)]
    stack: bool,
    #[serde(default = "default_stack_bytes")]
    stack_bytes: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SyscallConfig {
    #[serde(default)]
    syscalls: Vec<String>,
    #[serde(default)]
    captures: Vec<String>,
    #[serde(default)]
    stack: bool,
    #[serde(default = "default_stack_bytes")]
    stack_bytes: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BinderConfig {
    #[serde(default)]
    with_replies: bool,
}

#[derive(Debug)]
struct ChildSpec {
    name: &'static str,
    args: Vec<String>,
}

struct Worker {
    name: &'static str,
    child: Child,
    status: Option<ExitStatus>,
    stdout_closed: bool,
    stderr_closed: bool,
}

#[derive(Clone, Copy)]
enum Stream {
    Stdout,
    Stderr,
}

enum Message {
    Line(usize, Stream, String),
    Closed(usize, Stream),
    ReadError(usize, Stream, String),
}

fn default_stack_bytes() -> u32 {
    8192
}

impl Config {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.pid > 0 && self.pid <= i32::MAX as u32,
            "invalid process ID"
        );
        ensure!(
            self.uprobe.is_some() || self.syscall.is_some() || self.binder.is_some(),
            "run config must enable at least one source"
        );
        if let Some(uprobe) = &self.uprobe {
            ensure!(!uprobe.probes.is_empty(), "uprobe source requires probes");
            ensure!(
                (1..=16384).contains(&uprobe.stack_bytes),
                "uprobe stack_bytes must be between 1 and 16384"
            );
            for probe in &uprobe.probes {
                let _: ProbeSpec = probe
                    .parse()
                    .with_context(|| format!("invalid probe {probe}"))?;
            }
            for expression in &uprobe.expressions {
                let expression: Expression = expression
                    .parse()
                    .with_context(|| format!("invalid expression {expression}"))?;
                expression.compile()?;
            }
        }
        if let Some(syscall) = &self.syscall {
            ensure!(
                (1..=16384).contains(&syscall.stack_bytes),
                "syscall stack_bytes must be between 1 and 16384"
            );
        }
        Ok(())
    }

    fn workers(&self) -> Vec<ChildSpec> {
        let mut workers = Vec::new();
        if let Some(uprobe) = &self.uprobe {
            let mut args = vec!["uprobe".to_owned(), "-p".to_owned(), self.pid.to_string()];
            for probe in &uprobe.probes {
                args.extend(["--probe".to_owned(), probe.clone()]);
            }
            for expression in &uprobe.expressions {
                args.extend(["--print".to_owned(), expression.clone()]);
            }
            if let Some(object) = &uprobe.object {
                args.extend(["--object".to_owned(), object.display().to_string()]);
            }
            if uprobe.registers {
                args.push("--regs".to_owned());
            }
            if uprobe.stack {
                args.extend([
                    "--stack".to_owned(),
                    "--stack-bytes".to_owned(),
                    uprobe.stack_bytes.to_string(),
                ]);
            }
            workers.push(ChildSpec {
                name: "uprobe",
                args,
            });
        }
        if let Some(syscall) = &self.syscall {
            let mut args = vec!["syscall".to_owned(), "-p".to_owned(), self.pid.to_string()];
            if !syscall.syscalls.is_empty() {
                args.extend(["--syscalls".to_owned(), syscall.syscalls.join(",")]);
            }
            for capture in &syscall.captures {
                args.extend(["--capture".to_owned(), capture.clone()]);
            }
            if syscall.stack {
                args.extend([
                    "--stack".to_owned(),
                    "--stack-bytes".to_owned(),
                    syscall.stack_bytes.to_string(),
                ]);
            }
            workers.push(ChildSpec {
                name: "syscall",
                args,
            });
        }
        if let Some(binder) = &self.binder {
            let mut args = vec!["binder".to_owned(), "-p".to_owned(), self.pid.to_string()];
            if binder.with_replies {
                args.push("--with-replies".to_owned());
            }
            workers.push(ChildSpec {
                name: "binder",
                args,
            });
        }
        for worker in &mut workers {
            worker.args.extend([
                "--duration".to_owned(),
                self.duration.to_string(),
                "--json".to_owned(),
            ]);
        }
        workers
    }
}

pub fn run(path: PathBuf) -> Result<()> {
    let input = std::fs::read_to_string(&path)
        .with_context(|| format!("reading session config {}", path.display()))?;
    let config: Config = serde_json::from_str(&input).context("parsing session config JSON")?;
    config.validate()?;
    supervise(config)
}

fn supervise(config: Config) -> Result<()> {
    let common = Common {
        pid: config.pid,
        duration: config.duration,
        count: config.count,
        json: true,
    };
    let mut control = crate::RunControl::new(&common)?;
    let specs = config.workers();
    let executable = std::env::current_exe().context("locating debugplz executable")?;
    let mut workers = Vec::with_capacity(specs.len());
    for spec in specs {
        let mut command = Command::new(&executable);
        command
            .args(&spec.args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        match command.spawn() {
            Ok(child) => workers.push(Worker {
                name: spec.name,
                child,
                status: None,
                stdout_closed: false,
                stderr_closed: false,
            }),
            Err(error) => {
                for worker in &mut workers {
                    let _ = worker.child.kill();
                    let _ = worker.child.wait();
                }
                return Err(error).with_context(|| format!("starting {} session", spec.name));
            }
        }
    }

    let (sender, receiver) = mpsc::sync_channel(512);
    let mut readers = Vec::with_capacity(workers.len() * 2);
    let mut pipe_error = None;
    for (index, worker) in workers.iter_mut().enumerate() {
        let Some(stdout) = worker.child.stdout.take() else {
            pipe_error = Some(format!("{} session stdout pipe missing", worker.name));
            break;
        };
        readers.push(read_stream(index, Stream::Stdout, stdout, sender.clone()));
        let Some(stderr) = worker.child.stderr.take() else {
            pipe_error = Some(format!("{} session stderr pipe missing", worker.name));
            break;
        };
        readers.push(read_stream(index, Stream::Stderr, stderr, sender.clone()));
    }
    if let Some(error) = pipe_error {
        stop_and_reap(&mut workers);
        bail!(error);
    }
    drop(sender);

    let mut stopping = false;
    let mut stop_started = None;
    let mut failure = None;
    let mut output_broken = false;
    loop {
        if !stopping && !control.running() {
            stopping = true;
            stop_started = Some(Instant::now());
            interrupt_workers(&mut workers);
        }

        let mut exited = false;
        for worker in &mut workers {
            if worker.status.is_some() {
                continue;
            }
            match worker.child.try_wait() {
                Ok(Some(status)) => {
                    worker.status = Some(status);
                    exited = true;
                }
                Ok(None) => {}
                Err(error) => {
                    failure.get_or_insert_with(|| {
                        format!("checking {} session: {error}", worker.name)
                    });
                    let _ = worker.child.kill();
                    exited = true;
                }
            }
        }
        if exited && !stopping {
            if let Some(worker) = workers
                .iter()
                .find(|worker| worker.status.is_some_and(|status| !status.success()))
                && let Some(status) = worker.status
            {
                failure
                    .get_or_insert_with(|| format!("{} session exited with {status}", worker.name));
            }
            stopping = true;
            stop_started = Some(Instant::now());
            interrupt_workers(&mut workers);
        }

        if stopping
            && stop_started.is_some_and(|started| started.elapsed() > Duration::from_secs(2))
        {
            for worker in &mut workers {
                if worker.status.is_none() {
                    let _ = worker.child.kill();
                }
            }
        }

        if workers
            .iter()
            .all(|worker| worker.status.is_some() && worker.stdout_closed && worker.stderr_closed)
        {
            break;
        }

        match receiver.recv_timeout(Duration::from_millis(20)) {
            Ok(Message::Line(index, Stream::Stdout, line)) => {
                if config.count > 0 && control.events >= config.count {
                    if !stopping {
                        stopping = true;
                        stop_started = Some(Instant::now());
                        interrupt_workers(&mut workers);
                    }
                    continue;
                }
                if output_broken {
                    continue;
                }
                match serde_json::from_str::<serde_json::Value>(&line) {
                    Ok(value) => match crate::emit(&value, true) {
                        Ok(()) => control.emitted(),
                        Err(error) => {
                            failure
                                .get_or_insert_with(|| format!("writing session output: {error}"));
                            output_broken = true;
                            if !stopping {
                                stopping = true;
                                stop_started = Some(Instant::now());
                                interrupt_workers(&mut workers);
                            }
                        }
                    },
                    Err(error) => {
                        failure.get_or_insert_with(|| {
                            format!("{} emitted invalid JSON: {error}", workers[index].name)
                        });
                        if !stopping {
                            stopping = true;
                            stop_started = Some(Instant::now());
                            interrupt_workers(&mut workers);
                        }
                    }
                }
            }
            Ok(Message::Line(index, Stream::Stderr, line)) => {
                eprintln!("[run:{}] {line}", workers[index].name);
            }
            Ok(Message::Closed(index, Stream::Stdout)) => workers[index].stdout_closed = true,
            Ok(Message::Closed(index, Stream::Stderr)) => workers[index].stderr_closed = true,
            Ok(Message::ReadError(index, stream, error)) => {
                let stream = match stream {
                    Stream::Stdout => "stdout",
                    Stream::Stderr => "stderr",
                };
                failure.get_or_insert_with(|| {
                    format!("reading {} session {stream}: {error}", workers[index].name)
                });
                if !stopping {
                    stopping = true;
                    stop_started = Some(Instant::now());
                    interrupt_workers(&mut workers);
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                if workers
                    .iter()
                    .any(|worker| !worker.stdout_closed || !worker.stderr_closed)
                {
                    failure.get_or_insert_with(|| "session output channel closed early".to_owned());
                    if !stopping {
                        stopping = true;
                        stop_started = Some(Instant::now());
                        interrupt_workers(&mut workers);
                    }
                }
            }
        }
        if !stopping && config.count > 0 && control.events >= config.count {
            stopping = true;
            stop_started = Some(Instant::now());
            interrupt_workers(&mut workers);
        }
    }

    for worker in &mut workers {
        if worker.status.is_none() {
            worker.status = Some(worker.child.wait().context("waiting for session worker")?);
        }
        if let Some(status) = worker.status
            && !status.success()
            && failure.is_none()
        {
            failure = Some(format!("{} session exited with {status}", worker.name));
        }
    }
    for reader in readers {
        reader
            .join()
            .map_err(|_| anyhow::anyhow!("session output reader panicked"))?;
    }
    if let Some(failure) = failure {
        bail!(failure);
    }
    Ok(())
}

fn read_stream<R: std::io::Read + Send + 'static>(
    index: usize,
    stream: Stream,
    reader: R,
    sender: SyncSender<Message>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        for line in BufReader::new(reader).lines() {
            match line {
                Ok(line) => {
                    if sender.send(Message::Line(index, stream, line)).is_err() {
                        return;
                    }
                }
                Err(error) => {
                    let _ = sender.send(Message::ReadError(index, stream, error.to_string()));
                    break;
                }
            }
        }
        let _ = sender.send(Message::Closed(index, stream));
    })
}

fn interrupt_workers(workers: &mut [Worker]) {
    for worker in workers {
        if worker.status.is_none() {
            interrupt(&worker.child);
        }
    }
}

fn stop_and_reap(workers: &mut [Worker]) {
    for worker in workers {
        let _ = worker.child.kill();
        let _ = worker.child.wait();
    }
}

fn interrupt(child: &Child) {
    if let Ok(pid) = i32::try_from(child.id()) {
        // SAFETY: pid is the live child process ID returned by std::process.
        unsafe {
            libc::kill(pid, libc::SIGINT);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_and_expands_selected_sources() {
        let config: Config = serde_json::from_str(
            r#"{"pid":42,"duration":5,"count":3,"syscall":{"syscalls":["openat"]},"binder":{"with_replies":true}}"#,
        )
        .unwrap();
        config.validate().unwrap();
        let workers = config.workers();
        assert_eq!(workers.len(), 2);
        assert_eq!(workers[0].name, "syscall");
        assert!(
            workers[0]
                .args
                .windows(2)
                .any(|pair| pair == ["--duration", "5"])
        );
        assert_eq!(workers[0].args.last().map(String::as_str), Some("--json"));
        assert_eq!(workers[1].name, "binder");
        assert!(workers[1].args.contains(&"--with-replies".to_owned()));
    }

    #[test]
    fn rejects_empty_sources_and_invalid_probe_expressions() {
        let empty: Config = serde_json::from_str(r#"{"pid":1}"#).unwrap();
        assert!(empty.validate().is_err());
        let invalid: Config = serde_json::from_str(
            r#"{"pid":1,"uprobe":{"probes":["lib+symbol"],"expressions":["x99"]}}"#,
        )
        .unwrap();
        assert!(invalid.validate().is_err());
    }
}
