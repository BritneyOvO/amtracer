#!/usr/bin/env python3
"""Check fixture control flow in emulation; this does not validate uprobes."""
import argparse
import json
from pathlib import Path
import struct
import subprocess
import unicorn
from unicorn import arm64_const as reg
from instruction_device import expected_offsets, read_json


def emulate(fixture, nm):
    data = fixture.read_bytes()
    assert data[:6] == b"\x7fELF\x02\x01"
    assert struct.unpack_from("<H", data, 18)[0] == 183
    phoff = struct.unpack_from("<Q", data, 32)[0]
    phsize, count = struct.unpack_from("<HH", data, 54)
    segments = [struct.unpack_from("<IIQQQQQQ", data, phoff + i * phsize) for i in range(count)]
    segments = [s for s in segments if s[0] == 1]
    names = subprocess.check_output([nm, "-n", str(fixture)], text=True)
    symbols = {fields[2]: int(fields[0], 16) for line in names.splitlines()
               if len(fields := line.split()) == 3 and fields[2].startswith("amtracer_trace")}
    base = 0x1000000
    stop = 0x2000000
    result = []
    for name, value, expected, returned in [
        ("amtracer_trace", 3, [symbols["amtracer_trace"] + off for off in expected_offsets()], 17),
        ("amtracer_trace", 0, [symbols["amtracer_trace"] + off for off in expected_offsets(True)], 106),
        ("amtracer_trace_many", 3, list(range(symbols["amtracer_trace_many"], symbols["amtracer_trace_many_end"], 4)), 3),
        ("amtracer_trace_cross", 3, [symbols["amtracer_trace_cross"], symbols["amtracer_trace_cross"] + 4,
                                   symbols["amtracer_trace_cross_leaf"], symbols["amtracer_trace_cross_leaf"] + 4,
                                   symbols["amtracer_trace_cross"] + 8, symbols["amtracer_trace_cross"] + 12], 4),
    ]:
        machine = unicorn.Uc(unicorn.UC_ARCH_ARM64, unicorn.UC_MODE_ARM)
        end = max(s[3] + s[6] for s in segments)
        machine.mem_map(base, (end + 4095) & ~4095)
        for s in segments:
            if s[5]:
                machine.mem_write(base + s[3], data[s[2]:s[2] + s[5]])
        machine.reg_write(reg.UC_ARM64_REG_X0, value)
        machine.reg_write(reg.UC_ARM64_REG_X30, stop)
        addresses = []
        machine.hook_add(unicorn.UC_HOOK_CODE, lambda uc, pc, size, opaque: addresses.append(pc - base))
        machine.emu_start(base + symbols[name], stop, count=2000)
        assert addresses == expected, (name, value, addresses, expected)
        assert machine.reg_read(reg.UC_ARM64_REG_X0) == returned
        result.append({"symbol": name, "input": value, "offsets": [x - symbols[name] for x in addresses], "return": returned})
    return result


def run_fixture(binary, qemu, sysroot):
    process = subprocess.Popen([qemu, "-L", str(sysroot), str(binary)], stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
    results = []
    try:
        read_json(process, 10)
        for command in ["run 3 1 3 0 0 0", "run 3 3 0 0 0 0", "run 2 1 3 1 0 0", "run 2 2 3 2 0 0",
                        "run 3 1 3 3 0 0", "run 8 1 3 0 0 1", "run 16 4 3 0 100 0"]:
            process.stdin.write(command + "\n")
            process.stdin.flush()
            result = read_json(process, 20)
            assert result["failures"] == result["fault_bad_pc"] == 0, result
            if command == "run 2 1 3 1 0 0":
                assert result["faults"] == 2, result
            results.append({"command": command, "calls": result["calls"], "faults": result["faults"], "failures": result["failures"]})
        process.stdin.write("quit\n")
        process.stdin.flush()
        assert process.wait(timeout=5) == 0, process.stderr.read()
    finally:
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=5)
    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--android-fixture", type=Path, default=Path("target/debugplz-instruction-fixture"))
    parser.add_argument("--linux-fixture", type=Path, default=Path("target/debugplz-instruction-fixture-linux"))
    parser.add_argument("--nm", default="aarch64-linux-gnu-nm")
    parser.add_argument("--qemu", default="qemu-aarch64")
    parser.add_argument("--sysroot", type=Path, default=Path("/usr/aarch64-linux-gnu"))
    parser.add_argument("--report", type=Path, default=Path("artifacts/instruction-host.json"))
    args = parser.parse_args()
    report = {"kind": "fixture-emulation-only", "kernel_uprobe_verified": False,
              "android_instruction_paths": emulate(args.android_fixture, args.nm),
              "fixture_commands": run_fixture(args.linux_fixture, args.qemu, args.sysroot)}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(args.report)


if __name__ == "__main__":
    main()
