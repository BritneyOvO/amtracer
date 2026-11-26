#!/usr/bin/env python3
"""Validate private runtime opcodes; --resolve-only works before flashing the fix."""
import argparse
import json
import re
import shlex
import subprocess
import time
from pathlib import Path
from instruction_device import Device, read_json, statistics


def request(device, command):
    device.fixture.stdin.write(command + "\n")
    device.fixture.stdin.flush()
    result = read_json(device.fixture)
    assert result["faults"] == 0 and result["failures"] == 0, result
    assert result["word"] == "d2800540" and result["alias_word"] == "d28009a0", result
    return result


def ordinary_probe(device, info):
    """Exercise the unchanged ordinary uprobe CLI against private plaintext."""
    source = device.root / "artifacts/debugplz-ebpf.o"
    remote_object = f"{device.remote}/debugplz-ebpf.o"
    subprocess.run(device.adb + ["push", str(source), remote_object], check=True, capture_output=True)
    output = device.output / "runtime-uprobe.jsonl"
    error = device.output / "runtime-uprobe.stderr"
    command = [device.tool_path, "uprobe", "-p", str(info["pid"]),
               "--probe", info["point"], "--print", "r0", "--print", "*sp",
               "--print", f"bytes({info['point']},4)", "--stack", "--regs",
               "--duration", "8", "--count", "3", "--json"]
    process = None
    pid = None
    try:
        with output.open("w") as stdout, error.open("w") as stderr:
            process = subprocess.Popen(device.adb + ["shell", "-T",
                'echo "DEBUGPLZ_PID=$$" >&2\nexec ' + shlex.join(command)],
                stdout=stdout, stderr=stderr, text=True)
            deadline = time.monotonic() + 12
            while process.poll() is None and time.monotonic() < deadline:
                if match := re.search(r"DEBUGPLZ_PID=(\d+)", error.read_text()):
                    pid = int(match[1])
                request(device, "run 2")
                time.sleep(0.1)
            assert process.wait(timeout=2) == 0, error.read_text()
        events = [json.loads(line) for line in output.read_text().splitlines()]
        assert len(events) == 3 and "kernel_lost=0" in error.read_text(), error.read_text()
        for event in events:
            assert event["pc"] in (info["point"], info["alias"]), event
            assert event["captures"][0]["value"]["decimal"] == event["registers"]["x"][0], event
            assert event["captures"][1]["status"] == "ok", event
            assert event["captures"][2]["value"] == [0x40, 0x05, 0x80, 0xd2], event
            assert event["stack"]["frames"], event
        request(device, "run 2")
        return {"events": len(events), "stats": error.read_text(), "command": command}
    finally:
        if process is not None and process.poll() is None:
            if pid is not None:
                device.signal(pid, "INT")
            process.wait(timeout=10)
        device.shell("rm", "-f", remote_object, check=False)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--serial", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, default=Path("target/debugplz-runtime-fixture"))
    parser.add_argument("--resolve-only", action="store_true")
    args = parser.parse_args()
    report = {"mode": "resolve-only" if args.resolve_only else "hook"}
    try:
        with Device(args.serial, args.output, args.fixture) as device:
            info = device.start_fixture()
            report["device"] = device.report
            report["fixture"] = info
            report["baseline"] = request(device, "run 2")
            executable = device.tool_path
            scope = "fixture+amtracer_runtime_point:8"
            resolved = json.loads(device.shell(executable, "resolve", "-p", str(info["pid"]),
                                               "--range", scope).stdout)
            assert resolved["instruction_source"] == "runtime" and resolved["sites"] == 2, resolved
            words = {instance["pc"]: instance["opcode"] for instance in resolved["instructions"][0]["instances"]}
            assert words == {info["point"]: "d2800540", info["alias"]: "d28009a0"}, words
            absolute = json.loads(device.shell(executable, "resolve", "-p", str(info["pid"]),
                                               "--range", f'{info["alias"]}:8').stdout)
            assert absolute["instructions"][0]["instances"] == [
                next(i for i in resolved["instructions"][0]["instances"] if i["pc"] == info["alias"])]
            report["resolve"] = resolved
            report["absolute"] = absolute
            if not args.resolve_only:
                report["traces"] = []
                for index in range(2):
                    trace = device.tracer(f"runtime-{index}", [scope], regs=True)
                    trace.ready()
                    report[f"run-{index}"] = request(device, "run 3")
                    finished = trace.stop()
                    assert finished["returncode"] == 0, finished
                    stats = statistics(finished["stderr"])
                    assert stats["received"] == 12 and not stats["incomplete"], stats
                    events = [json.loads(line) for line in trace.path.read_text().splitlines()]
                    expected = []
                    for _ in range(3):
                        expected += [(info["point"], "d2800540"), (hex(int(info["point"], 16) + 4), "d65f03c0"),
                                     (info["alias"], "d28009a0"), (hex(int(info["alias"], 16) + 4), "d65f03c0")]
                    assert [(e["pc"], e["opcode"]) for e in events] == expected, events
                    report["traces"].append(stats)
                    request(device, "run 2")  # detach must not restore ciphertext
                report["ordinary_uprobe"] = ordinary_probe(device, info)
            report["after"] = request(device, "run 2")
            report["passed"] = True
    finally:
        args.output.mkdir(parents=True, exist_ok=True)
        (args.output / "runtime-report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"passed": True, "mode": report["mode"]}))


if __name__ == "__main__":
    main()
