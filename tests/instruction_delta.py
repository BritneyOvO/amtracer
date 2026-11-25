#!/usr/bin/env python3
"""Validate register deltas, periodic snapshots and real ring-buffer loss recovery."""
import argparse
import json
from pathlib import Path
import time
from instruction_device import Device, RegisterDecoder, check_register_step, expected_offsets, statistics


def inspect(trace, info):
    decoder = RegisterDecoder()
    result = {"events": 0, "full_snapshots": 0, "empty_deltas": 0, "recovered_gaps": 0,
              "missing": 0, "submitted_bytes": 0, "last_sequence": 0}
    previous = 0
    previous_event, before = None, None
    for event in trace.iter_events():
        block = event["registers"]
        current = decoder.observe(event)
        check_register_step(info, previous_event, before, event, current)
        previous_event, before = event, current
        assert event["sequence"] > previous
        gap = event["sequence"] - previous - 1
        assert event["missed_before"] == gap, event
        if gap:
            assert block["kind"] == "full", event
            result["recovered_gaps"] += 1
        result["missing"] += gap
        result["full_snapshots"] += block["kind"] == "full"
        result["empty_deltas"] += block["kind"] == "delta" and not block["values"]
        result["submitted_bytes"] += 80 + 8 * len(block["values"])
        result["events"] += 1
        previous = event["sequence"]
        if int(event["pc"], 16) == int(info["trace"], 16) + 56:
            assert current["x0"] == 17, event
    result["last_sequence"] = previous
    return result


def settle_output(trace, timeout=30):
    deadline = time.monotonic() + timeout
    size = -1
    stable = 0
    while time.monotonic() < deadline:
        if trace.process.poll() is not None:
            raise RuntimeError(trace.error_path.read_text())
        current = trace.path.stat().st_size
        stable = stable + 1 if current == size and current > 0 else 0
        if stable >= 5:
            return
        size = current
        time.sleep(0.1)
    raise TimeoutError("instruction output did not drain")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--serial", required=True)
    parser.add_argument("--fixture", type=Path)
    parser.add_argument("--report", type=Path, default=Path("artifacts/instruction-delta.json"))
    args = parser.parse_args()
    report = {}
    per_call = len(expected_offsets())
    try:
        with Device(args.serial, args.report.with_suffix(""), args.fixture) as device:
            report["environment"] = device.report
            info = device.start_fixture()
            scope = ["fixture+amtracer_trace..amtracer_trace_end"]
            trace = device.tracer("checkpoints", scope, regs=True)
            trace.ready()
            device.run_fixture(rounds=100)
            result = trace.stop()
            assert result["returncode"] == 0, result
            data = inspect(trace, info)
            stats = statistics(result["stderr"])
            assert data["events"] == stats["hits"] == 100 * per_call, (data, stats)
            assert stats["ring_lost"] == stats["state_failed"] == data["missing"] == 0, stats
            assert data["submitted_bytes"] == stats["submitted_bytes"], (data, stats)
            assert data["full_snapshots"] == stats["full_snapshots"] == 3, (data, stats)
            assert data["empty_deltas"] > 0, data
            report["checkpoints"] = data | {"stats": stats, "trace": result}

            trace = device.tracer("loss_recovery", scope, regs=True)
            trace.ready()
            device.run_fixture(rounds=2)
            # SIGSTOP only pauses this test's consumer. Its BPF program remains
            # attached, so 720k hits exceed even a 32 MiB ring buffer.
            device.signal(trace.pid, "STOP")
            try:
                device.run_fixture(rounds=30000)
            finally:
                device.signal(trace.pid, "CONT")
            settle_output(trace)
            device.run_fixture(rounds=10, rate=100)
            result = trace.stop()
            assert result["returncode"] == 0, result
            data = inspect(trace, info)
            stats = statistics(result["stderr"])
            assert stats["hits"] == (2 + 30000 + 10) * per_call, stats
            assert stats["ring_lost"] > 0 and stats["state_failed"] == 0, stats
            assert data["recovered_gaps"] >= 1, data
            assert data["missing"] == stats["ring_lost"] == stats["sequence_missing"], (data, stats)
            assert data["events"] == stats["events"] == stats["submitted"], (data, stats)
            assert data["submitted_bytes"] == stats["submitted_bytes"], (data, stats)
            assert data["full_snapshots"] == stats["full_snapshots"], (data, stats)
            assert data["last_sequence"] == stats["hits"], (data, stats)
            assert stats["queued"] == stats["discarded"] == 0 and stats["incomplete"], stats
            report["loss_recovery"] = data | {"stats": stats, "trace": result}
    except BaseException as error:
        report["error"] = repr(error)
        raise
    finally:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(args.report)


if __name__ == "__main__":
    main()
