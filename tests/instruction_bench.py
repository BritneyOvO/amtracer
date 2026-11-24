#!/usr/bin/env python3
"""Measure an owned fixture with baseline, PC, registers and output costs."""
import argparse
import json
import math
from pathlib import Path
import statistics as math_statistics
from instruction_device import Device, expected_offsets, statistics


def process_usage(device, pid):
    result = device.shell("cat", f"/proc/{pid}/stat").stdout
    fields = result.rsplit(")", 1)[1].split()
    status = device.shell("cat", f"/proc/{pid}/status").stdout.splitlines()
    rss = next((int(s.split()[1]) for s in status if s.startswith("VmHWM:")), 0)
    # utime/stime are process stat fields 14/15; fields[0] here is state (#3).
    return {"cpu_ticks": int(fields[11]) + int(fields[12]), "maxrss_kb": rss}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--serial", required=True)
    parser.add_argument("--fixture", type=Path)
    parser.add_argument("--report", type=Path, default=Path("artifacts/instruction-bench.json"))
    parser.add_argument("--seconds", type=float, default=2)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--event-rates", default="0,1000,10000,50000", help="0 means unpaced throughput")
    parser.add_argument("--modes", default="baseline,pc,regs,pc-json", help="baseline,pc,regs,pc-json,regs-json")
    parser.add_argument("--unpaced-rounds", type=int, default=2000)
    args = parser.parse_args()
    modes = args.modes.split(",")
    rates = [int(x) for x in args.event_rates.split(",")]
    assert args.seconds > 0 and args.repeats > 0 and 0 < args.unpaced_rounds <= 1000000
    assert all(rate >= 0 for rate in rates)
    assert "baseline" in modes and set(modes) <= {"baseline", "pc", "regs", "pc-json", "regs-json"}
    per_call = len(expected_offsets())
    report = {"settings": vars(args) | {"fixture": str(args.fixture), "report": str(args.report)},
              "instructions_per_call": per_call, "samples": [],
              "notes": ["Warmup runs before attaching each trace; each sample gets a fresh target mm.",
                        "Rate 0 is unpaced; other rates pace calls and do not imply the requested rate was reached.",
                        "Latency percentiles use at most 1024 evenly spaced call samples per thread.",
                        "cpu_ticks uses the device CLK_TCK; raw counters are retained without assuming 100 Hz.",
                        "This benchmark includes consumer validation and uses summary-only to omit formatting where selected."]}
    try:
        with Device(args.serial, args.report.parent / "instruction-bench", args.fixture) as device:
            report["environment"] = device.report
            clock = device.shell("getconf", "CLK_TCK", check=False).stdout.strip()
            report["clk_tck"] = int(clock) if clock.isdecimal() else None
            for event_rate in rates:
                call_rate = max(1, event_rate // per_call) if event_rate else 0
                rounds = math.ceil(args.seconds * call_rate) if call_rate else args.unpaced_rounds
                assert 0 < rounds <= 1000000
                for repeat in range(args.repeats):
                    for mode in modes:
                        device.start_fixture()
                        device.run_fixture(rounds=100)
                        name = f"{event_rate}-{repeat}-{mode}"
                        trace = None
                        before = None
                        if mode != "baseline":
                            trace = device.tracer(name, ["fixture+amtracer_trace..amtracer_trace_end"],
                                                  regs=mode.startswith("regs"), summary=not mode.endswith("json"))
                            trace.ready()
                            before = process_usage(device, trace.pid)
                        measurement = device.run_fixture(rounds=rounds, rate=call_rate, timeout=max(30, args.seconds * 10))
                        sample = {"mode": mode, "repeat": repeat, "requested_events_per_second": event_rate,
                                  "paced_calls_per_second": call_rate, "fixture": measurement,
                                  "calls_per_second": measurement["calls"] * 1e9 / measurement["elapsed_ns"],
                                  "expected_events": measurement["calls"] * per_call}
                        if trace:
                            after = process_usage(device, trace.pid)
                            result = trace.stop()
                            assert result["returncode"] == 0, result
                            stats = statistics(result["stderr"])
                            assert stats["hits"] == sample["expected_events"], (sample, stats)
                            assert stats["submitted"] + stats["ring_lost"] + stats["state_failed"] == stats["hits"], stats
                            sample |= {"trace": result, "stats": stats, "tool_cpu_ticks": after["cpu_ticks"] - before["cpu_ticks"],
                                       "tool_maxrss_kb": after["maxrss_kb"],
                                       "loss_fraction": (stats["ring_lost"] + stats["state_failed"]) / stats["hits"]}
                        report["samples"].append(sample)
                        print(f"{name}: {sample['calls_per_second']:.1f} calls/s")
                        device.stop_fixture()
            report["comparisons"] = []
            for event_rate in rates:
                baseline = [s for s in report["samples"] if s["mode"] == "baseline" and s["requested_events_per_second"] == event_rate]
                base_elapsed = math_statistics.median(s["fixture"]["elapsed_ns"] for s in baseline)
                base_cpu = math_statistics.median(s["fixture"]["cpu_ns"] for s in baseline)
                for mode in modes:
                    selected = [s for s in report["samples"] if s["mode"] == mode and s["requested_events_per_second"] == event_rate]
                    elapsed = math_statistics.median(s["fixture"]["elapsed_ns"] for s in selected)
                    cpu = math_statistics.median(s["fixture"]["cpu_ns"] for s in selected)
                    report["comparisons"].append({"mode": mode, "requested_events_per_second": event_rate,
                                                  "median_target_elapsed_ratio": elapsed / base_elapsed,
                                                  "median_target_cpu_ratio": cpu / base_cpu,
                                                  "median_calls_per_second": math_statistics.median(s["calls_per_second"] for s in selected)})
    except BaseException as error:
        report["error"] = repr(error)
        raise
    finally:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(args.report)


if __name__ == "__main__":
    main()
