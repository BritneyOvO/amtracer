#!/usr/bin/env python3
"""Capture rejected transactions from an owned Binder fixture."""
import argparse
import json
from pathlib import Path
import select
import shlex
import subprocess
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--serial", required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    adb = ["adb", "-s", args.serial]
    remote = "/data/local/tmp/amtracer-smoke"
    subprocess.run(adb + ["push", str(root / "target/amtracer-binder-fixture"),
                          remote + "/binder-fixture"], capture_output=True, check=True)
    subprocess.run(adb + ["shell", "chmod", "700", remote + "/binder-fixture"], check=True)
    fixture = subprocess.Popen(adb + ["shell", remote + "/binder-fixture"], text=True,
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    trace = None
    pid = None
    try:
        assert select.select([fixture.stdout], [], [], 5)[0], "fixture not ready"
        info = json.loads(fixture.stdout.readline())
        pid = info["pid"]
        command = [remote + "/amtracer", "binder", "-p", str(pid), "--duration", "3", "--json"]
        trace = subprocess.Popen(adb + ["shell", shlex.join(command)], text=True,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(0.5)
        fixture.stdin.write("x\n")
        fixture.stdin.flush()
        out, err = trace.communicate(timeout=10)
        assert trace.returncode == 0, err
        events = [json.loads(line) for line in out.splitlines() if line]
        assert len(events) == 6, (events, err)
        for index, event in enumerate(events):
            assert event["tgid"] == pid and event["sender_pid"] == pid, event
            assert event["code"] == 0x414d5400 + index, event
            assert event["outcome"] == "failed" and event["error"] == -22, event
            assert event["interface_token"] == "amtracer.ITest", event
            assert event["oneway"] == bool(index & 1), event
            assert event["data_size"] == 320 and len(event["data"]) == 256 and event["truncated"], event
        fixture.wait(timeout=5)
        assert fixture.returncode == 0, fixture.stderr.read()
        report = root / "artifacts/binder-smoke.json"
        boot_id = subprocess.run(adb + ["shell", "cat", "/proc/sys/kernel/random/boot_id"],
                                 text=True, capture_output=True, check=True).stdout.strip()
        report.write_text(json.dumps({"serial":args.serial,"boot_id":boot_id,"fixture":info,
                                      "events":events,"stats":err},indent=2)+"\n")
        print(report)
    finally:
        if trace is not None and trace.poll() is None:
            trace.terminate()
            trace.wait(timeout=5)
        if pid is not None and fixture.poll() is None:
            subprocess.run(adb + ["shell", "kill", "-TERM", str(pid)], capture_output=True)
        if fixture.poll() is None:
            fixture.wait(timeout=5)


if __name__ == "__main__":
    main()
