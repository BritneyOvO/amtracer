#!/usr/bin/env python3
"""Exercise dlopen, stack refresh and probe removal on an owned process."""
import argparse
import json
import os
from pathlib import Path
import select
import shlex
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--serial", required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    adb = ["adb", "-s", args.serial]
    remote = "/data/local/tmp/amtracer-mapping"

    def shell(*args):
        return subprocess.run(adb + ["shell", shlex.join(args)], check=True,
                              capture_output=True, text=True, timeout=15)

    shell("mkdir", "-p", remote)
    for source, name in [("artifacts/amtracer", "amtracer"),
                         ("artifacts/amtracer-ebpf.o", "amtracer-ebpf.o"),
                         ("target/mapping-runner", "runner"),
                         ("target/libmap_a.so", "libmap_a.so"),
                         ("target/libmap_b.so", "libmap_b.so")]:
        subprocess.run(adb + ["push", str(root / source), f"{remote}/{name}"],
                       check=True, capture_output=True)
    shell("chmod", "700", f"{remote}/amtracer", f"{remote}/runner")
    fixture = subprocess.Popen(adb + ["shell", shlex.join([f"{remote}/runner",
        f"{remote}/libmap_a.so", f"{remote}/libmap_b.so"])], stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
    traces = []
    try:
        assert select.select([fixture.stdout], [], [], 10)[0], "fixture did not start"
        pid = json.loads(fixture.stdout.readline())["pid"]
        with tempfile.TemporaryFile() as uout, tempfile.TemporaryFile() as sout:
            def launch(args, output):
                proc = subprocess.Popen(adb + ["shell", shlex.join(args)], stdout=output,
                                        stderr=subprocess.PIPE, text=True)
                traces.append(proc)
                return proc

            uprobe = launch([f"{remote}/amtracer", "uprobe", "-p", str(pid), "--probe",
                             "libmap_a.so+mapping_call", "--json"], uout)
            syscall = launch([f"{remote}/amtracer", "syscall", "-p", str(pid), "--syscalls",
                              "getpid", "--stack", "--stack-bytes", "512", "--json"], sout)
            deadline = time.monotonic() + 20
            while (uout.tell() == 0 or sout.tell() == 0) and time.monotonic() < deadline:
                if uprobe.poll() is not None or syscall.poll() is not None:
                    break
                time.sleep(0.1)
            assert uout.tell() and sout.tell(), "trace did not start"
            fixture.stdin.write("b\n"); fixture.stdin.flush()
            assert select.select([fixture.stdout], [], [], 5)[0] and fixture.stdout.readline().strip() == "b loaded"
            deadline = time.monotonic() + 15
            found = False
            while time.monotonic() < deadline:
                raw = os.pread(sout.fileno(), sout.tell(), 0)
                for line in raw.splitlines():
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if any(frame.get("symbol") == "mapping_call" and
                           frame.get("module", "").endswith("libmap_b.so")
                           for frame in (event.get("stack") or {}).get("frames", [])):
                        found = True
                        break
                if found:
                    break
                time.sleep(0.2)
            assert found, f"newly loaded library was not symbolized; recent events: {raw[-8000:].decode(errors='replace')}"
            fixture.stdin.write("a\n"); fixture.stdin.flush()
            assert select.select([fixture.stdout], [], [], 5)[0] and fixture.stdout.readline().strip() == "a unloaded"
            _, uerr = uprobe.communicate(timeout=10)
            assert uprobe.returncode == 0 and "probe mapping changed" in uerr, uerr
            print("dlopen: syscall stack resolved libmap_b.so mapping_call")
            print("dlclose: uprobe stopped and released its link")
    finally:
        if fixture.poll() is None:
            fixture.stdin.write("q\n"); fixture.stdin.flush()
            fixture.wait(timeout=10)
        for trace in traces:
            if trace.poll() is None:
                try:
                    trace.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    trace.terminate()
                    trace.wait(timeout=10)
        assert fixture.returncode == 0, fixture.stderr.read()


if __name__ == "__main__":
    main()
