#!/usr/bin/env python3
"""Check target exit and session cleanup on an explicitly selected device."""
import argparse
import json
import select
import shlex
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--serial", required=True)
    args = parser.parse_args()
    adb = ["adb", "-s", args.serial]
    remote = "/data/local/tmp/debugplz-smoke"

    def shell(*command):
        return subprocess.run(adb + ["shell", shlex.join(command)], check=True,
                              text=True, capture_output=True, timeout=10)

    for kind in ("uprobe", "syscall", "binder", "syscall", "binder"):
        fixture = subprocess.Popen(adb + ["shell", f"{remote}/fixture 30"],
                                   text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        trace = None
        pid = None
        try:
            assert select.select([fixture.stdout], [], [], 10)[0], "fixture did not start"
            pid = json.loads(fixture.stdout.readline())["pid"]
            command = [f"{remote}/debugplz", kind, "-p", str(pid), "--json"]
            if kind == "uprobe":
                command += ["--probe", "fixture+amtracer_point"]
            if kind == "syscall":
                command += ["--syscalls", "getpid"]
            with tempfile.TemporaryFile() as output:
                trace = subprocess.Popen(adb + ["shell", shlex.join(command)],
                                         stdout=output, stderr=subprocess.PIPE, text=True)
                deadline = time.monotonic() + 15
                if kind == "binder":
                    time.sleep(2)
                else:
                    while output.tell() == 0 and trace.poll() is None and time.monotonic() < deadline:
                        time.sleep(0.1)
                    assert output.tell() > 0, "trace did not receive events"
                assert trace.poll() is None, trace.stderr.read()
                shell("kill", "-TERM", str(pid))
                fixture.wait(timeout=10)
                pid = None
                _, stderr = trace.communicate(timeout=10)
            assert trace.returncode == 0 and "exited" in stderr, (kind, stderr)
            print(f"{kind}: target exit detected; {stderr.strip()}")
        finally:
            if pid is not None and fixture.poll() is None:
                shell("kill", "-TERM", str(pid))
            if fixture.poll() is None:
                fixture.wait(timeout=10)
            if trace is not None and trace.poll() is None:
                trace.terminate()
                trace.wait(timeout=10)


if __name__ == "__main__":
    main()
