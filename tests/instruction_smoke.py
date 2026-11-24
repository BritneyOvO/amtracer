#!/usr/bin/env python3
"""Validate actual instruction sequences on an owned ARM64 target."""
import argparse
from collections import defaultdict
import json
from pathlib import Path
from instruction_device import Device, expected_offsets, statistics


def check_trace(trace, info, expected, rounds, threads, regs=False, value=17):
    result = trace.stop()
    assert result["returncode"] == 0, result
    events = trace.events()
    grouped = defaultdict(list)
    for event in events:
        assert event["tgid"] == info["pid"]
        assert event["missed_before"] == 0 and not event["incomplete"], event
        grouped[(event["tid"], event["thread_epoch"])].append(event)
    assert len(grouped) == threads, (len(grouped), threads)
    for records in grouped.values():
        assert [int(e["pc"], 16) for e in records] == expected * rounds
        assert [e["sequence"] for e in records] == list(range(1, len(records) + 1))
        if regs:
            start = int(info["trace"], 16)
            for event in records:
                assert event["registers"]["pc"] == int(event["pc"], 16)
                pc = int(event["pc"], 16)
                if pc == start + 44:
                    assert event["registers"]["x"][3] == int(info["leaf"], 16)
                if pc == start + 60:
                    assert event["registers"]["x"][30] in (start + 32, start + 48)
                if pc == start + 56:
                    assert event["registers"]["x"][0] == value
    stats = statistics(result["stderr"])
    assert stats["events"] == len(events) and stats["submitted"] == len(events), stats
    assert stats["ring_lost"] == stats["state_failed"] == stats["queued"] == stats["discarded"] == 0, stats
    assert not stats["incomplete"], stats
    return {"events": len(events), "threads": threads, "stats": stats, "stderr": result["stderr"]}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--serial", required=True)
    parser.add_argument("--fixture", type=Path)
    parser.add_argument("--report", type=Path, default=Path("artifacts/instruction-smoke.json"))
    args = parser.parse_args()
    records = {}
    try:
        with Device(args.serial, args.report.parent / "instruction-smoke", args.fixture) as device:
            info = device.start_fixture()
            scope = "fixture+amtracer_trace..amtracer_trace_end"
            preview = json.loads(device.shell(f"{device.remote}/amtracer", "resolve", "-p", info["pid"], "--range", scope).stdout)
            assert preview["sites"] == 17, preview
            records["resolve"] = preview
            for name, value, threads, migrate, regs in [("flow", 3, 1, 0, True), ("zero", 0, 1, 0, True),
                                                        ("threads", 3, 3, 0, False), ("migration", 3, 1, 1, False)]:
                trace = device.tracer(name, [scope, scope], regs=regs)
                trace.ready()
                call = device.run_fixture(rounds=3, threads=threads, value=value, migrate=migrate)
                expected = [int(info["trace"], 16) + off for off in expected_offsets(value == 0)]
                records[name] = check_trace(trace, info, expected, 3, threads, regs, 106 if value == 0 else 17)
                records[name]["fixture"] = call
            # More than the ordinary uprobe command's 64-point budget.
            trace = device.tracer("many", ["fixture+amtracer_trace_many..amtracer_trace_many_end"])
            trace.ready()
            device.run_fixture(rounds=2, mode=2)
            records["many"] = check_trace(trace, info, list(range(int(info["many"], 16), int(info["many_end"], 16), 4)), 2, 1)
            cross_ranges = ["fixture+amtracer_trace_cross..amtracer_trace_cross_end", "fixture+amtracer_trace_cross_leaf..amtracer_trace_cross_leaf_end"]
            trace = device.tracer("cross_page", cross_ranges)
            trace.ready()
            device.run_fixture(rounds=2, mode=3)
            a, b = int(info["cross"], 16), int(info["cross_leaf"], 16)
            records["cross_page"] = check_trace(trace, info, [a, a + 4, b, b + 4, a + 8, a + 12], 2, 1)
            trace = device.tracer("fault", ["fixture+amtracer_trace_fault:8"])
            trace.ready()
            result = device.run_fixture(rounds=2, mode=1)
            assert result["faults"] == 2, result
            a = int(info["fault"], 16)
            records["fault"] = check_trace(trace, info, [a, a + 4], 2, 1)
            records["fault"]["fixture"] = result
            for name, invalid in [("exclusive", "fixture+amtracer_trace_atomic+0x4:4"),
                                  ("svc", "fixture+amtracer_trace_svc:4"),
                                  ("fallback", "fixture+amtracer_trace_fallback:8")]:
                trace = device.tracer(name, [invalid])
                try:
                    trace.ready()
                except RuntimeError:
                    pass
                else:
                    raise AssertionError(f"{name} incorrectly started itrace")
                result = trace.stop()
                assert result["returncode"] != 0 and not trace.events(), result
                records[name] = result
                device.run_fixture(rounds=1)
            trace = device.tracer("count", [scope], count=7)
            trace.ready()
            device.run_fixture(rounds=3)
            trace.process.wait(timeout=10)
            result = trace.stop()
            assert result["returncode"] == 0 and len(trace.events()) == 7, result
            records["count"] = result
            # No count and no duration trigger: target exit must stop the tool.
            trace = device.tracer("target_exit", [scope])
            trace.ready()
            device.stop_fixture()
            trace.process.wait(timeout=10)
            assert trace.stop()["returncode"] == 0
            records["target_exit"] = trace.stop()
            records["environment"] = device.report
    except BaseException as error:
        records["error"] = repr(error)
        raise
    finally:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(records, indent=2) + "\n")
        print(args.report)


if __name__ == "__main__":
    main()
