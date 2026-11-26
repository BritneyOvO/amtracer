#!/usr/bin/env python3
"""Verify successful Binder request/reply pairing on a private binderfs device."""
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
    parser.add_argument("--report", default="binder-pair-smoke.json")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    adb = ["adb", "-s", args.serial]
    remote = "/data/local/tmp/debugplz-smoke"
    subprocess.run(adb + ["shell", "mkdir", "-p", remote], capture_output=True, check=True)
    subprocess.run(adb + ["push", str(root / "target/debugplz-binder-pair"),
                          remote + "/binder-pair"], capture_output=True, check=True)
    subprocess.run(adb + ["push", str(root / "artifacts/debugplz"),
                          remote + "/debugplz"], capture_output=True, check=True)
    subprocess.run(adb + ["push", str(root / "artifacts/debugplz-ebpf.o"),
                          remote + "/debugplz-ebpf.o"], capture_output=True, check=True)
    subprocess.run(adb + ["shell", "chmod", "700", remote + "/binder-pair"], check=True)
    subprocess.run(adb + ["shell", "chmod", "700", remote + "/debugplz"], check=True)

    fixture = subprocess.Popen(adb + ["shell", remote + "/binder-pair"], text=True,
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    trace = None
    info = None
    try:
        assert select.select([fixture.stdout], [], [], 10)[0], "private Binder fixture did not start"
        info = json.loads(fixture.stdout.readline())
        command = [remote + "/debugplz", "binder", "-p", str(info["pid"]),
                   "--with-replies", "--duration", "3", "--json"]
        trace = subprocess.Popen(adb + ["shell", shlex.join(command)], text=True,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(0.5)
        fixture.stdin.write("go\n")
        fixture.stdin.flush()
        out, err = trace.communicate(timeout=8)
        assert trace.returncode == 0, err
        events = [json.loads(line) for line in out.splitlines() if line]
        assert len(events) == 4, (events, err)
        request = next(event for event in events if event["code"] == 0x414D5401)
        reply = next(event for event in events if event["reply"])
        assert request["tgid"] == info["pid"] and request["outcome"] == "submitted", request
        assert reply["tgid"] == info["service_pid"] and reply["outcome"] == "submitted", reply
        assert reply["reply_to_id"] == request["transaction_id"], (request, reply)
        assert reply["correlation"]["status"] == "matched", reply
        assert reply["correlation"]["request_tgid"] == info["pid"], reply
        assert reply["correlation"]["elapsed_ns"] > 0, reply
        assert reply["data"] == list(b"reply-ok\0"), reply
        oneway = [event for event in events if event["code"] in (0x414D5402, 0x414D54FE)]
        assert len(oneway) == 2 and all(event["oneway"] for event in oneway), oneway
        assert all(event["correlation"]["status"] == "not_expected" for event in oneway), oneway
        assert not any(event["tgid"] == info["service_pid"] and
                       event["code"] == 0x414D5401 and not event["reply"]
                       for event in events), events
        fixture.stdin.write("stop\n")
        fixture.stdin.flush()
        fixture.wait(timeout=5)
        assert fixture.returncode == 0, fixture.stderr.read()
        stats = err + fixture.stderr.read()
        assert "kernel_lost=0" in stats and "invalidated_pairs=0" in stats, stats
        report = root / "artifacts" / args.report
        report.write_text(json.dumps({
            "serial": args.serial,
            "boot_id": subprocess.run(
                adb + ["shell", "cat", "/proc/sys/kernel/random/boot_id"],
                text=True, capture_output=True, check=True).stdout.strip(),
            "fixture": info,
            "events": events,
            "stats": err,
        }, indent=2) + "\n")
        print(report)
    finally:
        if trace is not None and trace.poll() is None:
            trace.terminate()
            trace.wait(timeout=5)
        if fixture.poll() is None:
            if info:
                subprocess.run(adb + ["shell", "kill", "-TERM", str(info["pid"])],
                               capture_output=True)
                subprocess.run(adb + ["shell", "kill", "-TERM", str(info["service_pid"])],
                               capture_output=True)
            fixture.wait(timeout=5)
        subprocess.run(adb + ["shell", "rm", "-f", remote + "/debugplz",
                              remote + "/debugplz-ebpf.o", remote + "/binder-pair"],
                       capture_output=True)


if __name__ == "__main__":
    main()
