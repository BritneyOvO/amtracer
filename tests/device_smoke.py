#!/usr/bin/env python3
"""Run only against a fresh, owned fixture on an explicitly selected device."""
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
    parser.add_argument("--fixture", type=Path)
    parser.add_argument("--report", default="device-smoke.json")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    adb = ["adb", "-s", args.serial]
    remote = "/data/local/tmp/debugplz-smoke"

    def shell(*command, timeout=20):
        return subprocess.run(adb + ["shell", shlex.join(command)], text=True,
                              capture_output=True, timeout=timeout, check=True)

    shell("mkdir", "-p", remote)
    for source, name in [(root / "artifacts/debugplz", "debugplz"),
                         (root / "artifacts/debugplz-ebpf.o", "debugplz-ebpf.o"),
                         (args.fixture or root / "target/debugplz-fixture", "fixture")]:
        subprocess.run(adb + ["push", str(source), f"{remote}/{name}"], check=True,
                       capture_output=True, text=True)
    shell("chmod", "700", f"{remote}/debugplz", f"{remote}/fixture")
    results = {"serial": args.serial, "boot_id": shell("cat", "/proc/sys/kernel/random/boot_id").stdout.strip(),
               "doctor": json.loads(shell(f"{remote}/debugplz", "doctor").stdout)}
    fixture = subprocess.Popen(adb + ["shell", f"{remote}/fixture 45"],
                               text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    pid = None
    try:
        ready, _, _ = select.select([fixture.stdout], [], [], 10)
        if not ready:
            raise RuntimeError("fixture did not start")
        info = json.loads(fixture.stdout.readline())
        pid = info["pid"]
        results["fixture"] = info
        tool = f"{remote}/debugplz"
        resolve = json.loads(shell(tool, "resolve", "-p", str(pid), "--probe", "fixture+amtracer_point").stdout)
        results["resolve"] = resolve
        for name, probe in [("symbol", "fixture+amtracer_point"), ("absolute", info["point"]),
                            ("elf_offset", "fixture+" + resolve["elf_address"]),
                            ("symbol_offset", "fixture+amtracer_target+0x4")]:
            result = shell(tool, "uprobe", "-p", str(pid), "--probe", probe,
                           "--regs", "--duration", "2", "--count", "3", "--json")
            events = [json.loads(line) for line in result.stdout.splitlines() if line]
            assert len(events) == 3, (name, result.stdout, result.stderr)
            assert all(e["tgid"] == pid and e["registers"]["x"][13] == int(info["memory"], 16) for e in events)
            results[name] = {"events": events, "stats": result.stderr}
        expressions = ["r13", "*r13", "*(r13+1B)", "*(r13+1W)", "*(r13+1D)",
                       "*(r13+1Q)", "*(r13+1W):u16", "*r13:i8",
                       f"**{info['pointer']}", f"cstr({info['string']},32)",
                       f"cstr({info['string']},5)", "bytes(r13,16)",
                       f"bytes({info['boundary']},16)", "*0", "r13-9223372036854775807",
                       f"*{info['boundary']}"]
        command = [tool, "uprobe", "-p", str(pid), "--probe", "fixture+amtracer_point",
                   "--duration", "2", "--count", "3", "--json"]
        for expression in expressions:
            command += ["--print", expression]
        result = shell(*command)
        events = [json.loads(line) for line in result.stdout.splitlines() if line]
        assert len(events) == 3
        raw = bytes.fromhex("88776655443322111122334455667788")
        expected = [int(info["memory"], 16), int.from_bytes(raw[:8], "little")]
        expected += [int.from_bytes(raw[offset:offset + 8], "little") for offset in [1, 2, 4, 8]]
        expected += [0x5566, -120, 0x1122334455667788]
        for event in events:
            captures = event["captures"]
            assert len(captures) == 16
            for capture, value in zip(captures, expected):
                assert capture["status"] == "ok" and capture["value"]["decimal"] == value, capture
            assert captures[9]["value"] == "amtracer-test" and captures[9]["status"] == "ok"
            assert captures[10]["value"] == "amtr" and captures[10]["status"] == "truncated"
            assert captures[11]["value"] == list(raw) and captures[11]["status"] == "ok"
            assert captures[12]["value"] == [0x5a] * 8 and captures[12]["status"] == "fault"
            assert captures[13]["value"] is None and captures[13]["status"] == "fault"
            assert captures[14]["value"] is None and captures[14]["status"] == "overflow"
            assert captures[15]["value"]["decimal"] == 0x5a5a5a5a5a5a5a5a
        results["expressions"] = {"events": events, "stats": result.stderr}
        result = shell(tool, "uprobe", "-p", str(pid), "--probe", "fixture+amtracer_point",
                       "--print", f"cstr({info['string']},14)", "--duration", "2", "--count", "1", "--json")
        event = json.loads(result.stdout)
        assert event["captures"][0]["status"] == "ok" and event["captures"][0]["value"] == "amtracer-test", event
        results["exact_string"] = {"events": [event], "stats": result.stderr}
        result = shell(tool, "uprobe", "-p", str(pid), "--probe", "fixture+amtracer_point",
                       "--stack", "--duration", "2", "--count", "3", "--json")
        events = [json.loads(line) for line in result.stdout.splitlines() if line]
        assert len(events) == 3
        for event in events:
            frames = event["stack"]["frames"]
            assert sum(f.get("symbol") == "call_chain" for f in frames) >= 5, event
        results["uprobe_stack"] = {"events": events, "stats": result.stderr}
        result = shell(tool, "uprobe", "-p", str(pid), "--probe", "fixture+amtracer_target",
                       "--probe", "fixture+amtracer_point", "--duration", "2", "--count", "8", "--json")
        events = [json.loads(line) for line in result.stdout.splitlines() if line]
        assert len(events) == 8 and {e["probe"] for e in events} == {1, 2}, events
        results["multiple_probes"] = {"events": events, "stats": result.stderr}
        result = shell(tool, "uprobe", "-p", str(pid), "--probe", "fixture+amtracer_point",
                       "--duration", "4", "--json")
        events = [json.loads(line) for line in result.stdout.splitlines() if line]
        assert len({e["tid"] for e in events}) >= 2, "existing/new worker coverage failed"
        results["threads"] = {"tids": sorted({e["tid"] for e in events}), "count": len(events), "stats": result.stderr}
        result = shell(tool, "syscall", "-p", str(pid), "--syscalls", "getpid", "--duration", "2", "--count", "4", "--json")
        events = [json.loads(line) for line in result.stdout.splitlines() if line]
        assert len(events) == 4 and all(e["source"] == "syscall" and e["nr"] == 172 for e in events)
        results["syscall"] = {"events": events, "stats": result.stderr}
        result = shell(tool, "syscall", "-p", str(pid), "--syscalls", "getpid", "--stack",
                       "--stack-bytes", "512", "--duration", "2", "--count", "4", "--json")
        events = [json.loads(line) for line in result.stdout.splitlines() if line]
        assert len(events) == 4
        assert all(e["stack"]["snapshot_bytes"] == 512 for e in events), events
        assert all(any(f.get("symbol") == "worker" for f in e["stack"]["frames"]) for e in events), events
        results["syscall_stack"] = {"events": events, "stats": result.stderr}
        result = shell(tool, "syscall", "-p", str(pid),
                       "--capture", "openat:1:string:32", "--capture", "write:1:bytes:16",
                       "--duration", "2", "--count", "12", "--json")
        events = [json.loads(line) for line in result.stdout.splitlines() if line]
        assert len(events) == 12
        path_captures = [blob for event in events for blob in event["blobs"]
                         if event["nr"] == 56 and blob["index"] == 1]
        write_captures = [blob for event in events for blob in event["blobs"]
                          if event["nr"] == 64 and blob["index"] == 1]
        assert path_captures and all(blob["kind"] == "string" and blob["text"] == "/dev/null"
                                     and not blob["fault"] for blob in path_captures), path_captures
        assert write_captures and all(blob["kind"] == "bytes" and blob["data"] == list(b"amtracer-write-d")
                                      and not blob["fault"] for blob in write_captures), write_captures
        results["syscall_captures"] = {"events": events, "stats": result.stderr}
        # No Binder traffic is created yet: opening and stopping exercises its ABI
        # without issuing transactions to any system service.
        result = shell(tool, "binder", "-p", str(pid), "--duration", "1", "--json")
        assert not result.stdout.strip()
        results["binder_session"] = result.stderr
    except subprocess.CalledProcessError as error:
        results["error"] = {"command": error.cmd, "stdout": error.stdout, "stderr": error.stderr}
        raise
    finally:
        if pid is not None:
            shell("kill", "-TERM", str(pid))
        fixture.wait(timeout=10)
        output = root / "artifacts" / args.report
        output.write_text(json.dumps(results, indent=2) + "\n")
        print(output)


if __name__ == "__main__":
    main()
