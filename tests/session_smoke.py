#!/usr/bin/env python3
"""Verify a combined uprobe and syscall session on an owned fixture."""
import argparse
import json
from pathlib import Path
import select
import shlex
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--serial", required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    adb = ["adb", "-s", args.serial]
    remote = "/data/local/tmp/debugplz-smoke"
    subprocess.run(adb + ["shell", "mkdir", "-p", remote], check=True, capture_output=True)
    for source, name in [
        (root / "artifacts/debugplz", "debugplz"),
        (root / "artifacts/debugplz-ebpf.o", "debugplz-ebpf.o"),
        (root / "target/debugplz-fixture", "fixture"),
    ]:
        subprocess.run(adb + ["push", str(source), f"{remote}/{name}"], check=True,
                       capture_output=True)
    subprocess.run(adb + ["shell", "chmod", "700", f"{remote}/debugplz",
                          f"{remote}/fixture"], check=True)

    fixture = subprocess.Popen(adb + ["shell", f"{remote}/fixture 40"], text=True,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    trace = None
    pid = None
    config_path = f"{remote}/session.json"
    try:
        assert select.select([fixture.stdout], [], [], 10)[0], "fixture did not start"
        info = json.loads(fixture.stdout.readline())
        pid = info["pid"]
        config = {
            "pid": pid,
            "duration": 3,
            "uprobe": {"probes": ["fixture+amtracer_point"], "registers": True},
            "syscall": {"syscalls": ["getpid"]},
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json") as source:
            json.dump(config, source)
            source.flush()
            subprocess.run(adb + ["push", source.name, config_path], check=True,
                           capture_output=True)
        command = [remote + "/debugplz", "run", "--config", config_path]
        trace = subprocess.Popen(adb + ["shell", shlex.join(command)], text=True,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = trace.communicate(timeout=20)
        assert trace.returncode == 0, err
        events = [json.loads(line) for line in out.splitlines() if line]
        sources = {event["source"] for event in events}
        assert {"uprobe", "syscall"} <= sources, (sources, err)
        assert all(event["tgid"] == pid for event in events), events

        count_config = {
            "pid": pid,
            "duration": 10,
            "count": 12,
            "syscall": {"syscalls": ["getpid"]},
            "binder": {},
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json") as source:
            json.dump(count_config, source)
            source.flush()
            subprocess.run(adb + ["push", source.name, config_path], check=True,
                           capture_output=True)
        trace = subprocess.Popen(adb + ["shell", shlex.join(command)], text=True,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        count_out, count_err = trace.communicate(timeout=20)
        assert trace.returncode == 0, count_err
        count_events = [json.loads(line) for line in count_out.splitlines() if line]
        assert len(count_events) == 12, (len(count_events), count_err)
        assert all(event["source"] == "syscall" for event in count_events), count_events
        assert "[run:binder]" in count_err and "[run:syscall]" in count_err, count_err

        failed_config = {
            "pid": pid,
            "duration": 10,
            "uprobe": {"probes": ["debugplz-no-such-library.so+missing"]},
            "syscall": {"syscalls": ["getpid"]},
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json") as source:
            json.dump(failed_config, source)
            source.flush()
            subprocess.run(adb + ["push", source.name, config_path], check=True,
                           capture_output=True)
        failed = subprocess.run(adb + ["shell", shlex.join(command)], text=True,
                                capture_output=True, timeout=20)
        assert failed.returncode != 0 and "debugplz-no-such-library.so" in failed.stderr, failed

        retry = subprocess.run(
            adb + ["shell", shlex.join([remote + "/debugplz", "syscall", "-p", str(pid),
                                        "--syscalls", "getpid", "--count", "2", "--json"])],
            text=True, capture_output=True, timeout=10)
        assert retry.returncode == 0, retry.stderr
        assert len(retry.stdout.splitlines()) == 2, retry.stdout

        boot_id = subprocess.run(
            adb + ["shell", "cat", "/proc/sys/kernel/random/boot_id"],
            text=True, capture_output=True, check=True).stdout.strip()
        report = root / "artifacts" / "session-smoke.json"
        report.write_text(json.dumps({
            "serial": args.serial,
            "boot_id": boot_id,
            "fixture": info,
            "sources": sorted(sources),
            "events": events,
            "stats": err,
            "global_count": {"limit": 12, "events": count_events, "stats": count_err},
            "startup_failure": {"returncode": failed.returncode, "stats": failed.stderr,
                                "retry_stats": retry.stderr},
        }, indent=2) + "\n")
        print(report)
    finally:
        if pid is not None:
            subprocess.run(adb + ["shell", "kill", "-TERM", str(pid)], capture_output=True)
        if trace is not None and trace.poll() is None:
            trace.wait(timeout=8)
        if fixture.poll() is None:
            fixture.wait(timeout=5)
        subprocess.run(adb + ["shell", "rm", "-f", config_path], capture_output=True)


if __name__ == "__main__":
    main()
