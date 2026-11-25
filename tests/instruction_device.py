"""Shared helpers for an explicitly selected Android device and owned fixture."""
import hashlib
import json
from pathlib import Path
import re
import select
import shlex
import subprocess
import time
import uuid


def read_json(process, timeout=30):
    if not select.select([process.stdout], [], [], timeout)[0]:
        raise TimeoutError("instruction fixture did not respond")
    line = process.stdout.readline()
    if not line:
        raise RuntimeError(f"instruction fixture exited: {process.poll()}")
    return json.loads(line)


def statistics(stderr):
    line = next((s for s in reversed(stderr.splitlines()) if s.startswith("itrace: sites=")), None)
    if line is None:
        raise AssertionError(f"missing itrace statistics: {stderr}")
    result = {}
    for name, value in re.findall(r"(\w+)=(\S+)", line):
        result[name] = value == "true" if value in ("true", "false") else int(value)
    return result


def expected_offsets(zero=False):
    path = [0, 4, 8] + [12, 16, 20] * 3 + [24]
    path += [36] if zero else [28, 60, 64, 32]
    return path + [40, 44, 60, 64, 48, 52, 56]


class RegisterDecoder:
    names = {f"x{i}" for i in range(31)} | {"sp", "pstate"}

    def __init__(self):
        self.threads = {}

    def observe(self, event):
        key = event["tid"], event["thread_epoch"]
        block = event["registers"]
        values = block["values"]
        assert set(values) <= self.names, block
        assert all(type(v) is int and 0 <= v < 1 << 64 for v in values.values()), block
        if block["kind"] == "full":
            assert block["base_sequence"] == 0 and set(values) == self.names, block
            current = values.copy()
        else:
            assert block["kind"] == "delta" and key in self.threads, block
            sequence, previous = self.threads[key]
            assert block["base_sequence"] == sequence and event["sequence"] == sequence + 1, event
            assert all(previous[name] != value for name, value in values.items()), block
            current = previous | values
        self.threads[key] = event["sequence"], current
        return current


def check_register_step(info, previous, before, event, current):
    if previous is None or event["sequence"] != previous["sequence"] + 1:
        return
    offset = int(previous["pc"], 16) - int(info["trace"], 16)
    if offset == 56:
        # The fixture executes untraced C code between calls.
        return
    expected = before.copy()
    if offset == 0:
        expected["x9"] = before["x30"]
    elif offset == 4:
        expected["x1"] = 0
    elif offset == 8:
        expected["x2"] = 3
    elif offset in (12, 60):
        expected["x1"] = before["x1"] + (1 if offset == 12 else 7)
    elif offset == 16:
        expected["x2"] = before["x2"] - 1
        expected["pstate"] = (before["pstate"] & ~0xf0000000) | (0x60000000 if expected["x2"] == 0 else 0x20000000)
    elif offset in (28, 44):
        expected["x30"] = int(info["trace"], 16) + offset + 4
    elif offset == 36:
        expected["x1"] = 99
    elif offset == 40:
        expected["x3"] = int(info["leaf"], 16)
    elif offset == 48:
        expected["x30"] = before["x9"]
    elif offset == 52:
        expected["x0"] = before["x1"]
    else:
        assert offset in (20, 24, 32, 64), offset
    assert current == expected, (previous, event, {k: (expected[k], current[k]) for k in expected if expected[k] != current[k]})


class Device:
    def __init__(self, serial, output, fixture=None):
        self.root = Path(__file__).resolve().parents[1]
        self.adb = ["adb", "-s", serial]
        self.remote = f"/data/local/tmp/amtracer-itrace-{uuid.uuid4().hex[:10]}"
        self.output = Path(output)
        self.output.mkdir(parents=True, exist_ok=True)
        self.fixture_path = fixture or self.root / "target/amtracer-instruction-fixture"
        self.children = []
        self.fixture = None
        self.info = None
        self.report = {"serial": serial, "commands": []}

    def shell(self, *arguments, check=True, timeout=30):
        command = self.adb + ["shell", shlex.join(map(str, arguments))]
        self.report["commands"].append(command)
        return subprocess.run(command, text=True, capture_output=True, check=check, timeout=timeout)

    def __enter__(self):
        self.shell("mkdir", "-p", self.remote)
        files = [(self.root / "artifacts/amtracer", "amtracer"),
                 (self.root / "artifacts/amtracer-itrace.o", "amtracer-itrace.o"),
                 (self.fixture_path, "fixture")]
        self.report["sha256"] = {}
        try:
            for source, name in files:
                self.report["sha256"][name] = hashlib.sha256(source.read_bytes()).hexdigest()
                subprocess.run(self.adb + ["push", str(source), f"{self.remote}/{name}"], check=True, capture_output=True)
            self.shell("chmod", "700", f"{self.remote}/amtracer", f"{self.remote}/fixture")
            self.report["boot_id"] = self.shell("cat", "/proc/sys/kernel/random/boot_id").stdout.strip()
            self.report["kernel"] = self.shell("uname", "-a").stdout.strip()
            self.report["selinux"] = self.shell("getenforce").stdout.strip()
            self.report["commit"] = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=self.root, text=True).strip()
        except BaseException:
            self.__exit__(None, None, None)
            raise
        return self

    def start_fixture(self):
        self.stop_fixture()
        self.fixture = subprocess.Popen(self.adb + ["shell", "-T", f"exec {shlex.quote(self.remote + '/fixture')}"],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
        self.info = read_json(self.fixture, 10)
        return self.info

    def stop_fixture(self):
        if self.fixture is None:
            return
        try:
            if self.fixture.poll() is None:
                self.fixture.stdin.write("quit\n")
                self.fixture.stdin.flush()
                self.fixture.wait(timeout=10)
        except (BrokenPipeError, subprocess.TimeoutExpired):
            if self.info:
                self.signal(self.info["pid"], "TERM", "fixture")
            self.fixture.terminate()
            self.fixture.wait(timeout=5)
        finally:
            self.fixture.stdin.close()
            self.fixture.stdout.close()
            self.fixture = None

    def run_fixture(self, rounds=2, threads=1, value=3, mode=0, rate=0, migrate=0, timeout=30):
        self.fixture.stdin.write(f"run {rounds} {threads} {value} {mode} {rate} {migrate}\n")
        self.fixture.stdin.flush()
        result = read_json(self.fixture, timeout)
        assert result["failures"] == 0 and result["fault_bad_pc"] == 0, result
        return result

    def signal(self, pid, name, executable="amtracer"):
        # Refuse to signal a reused PID or another test's process.
        expected = f"{self.remote}/{executable}"
        path = self.shell("readlink", f"/proc/{pid}/exe", check=False).stdout.strip()
        if path == expected:
            self.shell("kill", f"-{name}", str(pid), check=False)

    def tracer(self, name, ranges, regs=False, summary=False, count=0, output_sink="file"):
        trace = Trace(self, name, ranges, regs, summary, count, output_sink)
        self.children.append(trace)
        return trace

    def __exit__(self, exception, *_):
        errors = []
        for child in self.children:
            try:
                child.stop()
            except Exception as error:
                errors.append(repr(error))
        try:
            self.stop_fixture()
        except Exception as error:
            errors.append(repr(error))
        finally:
            self.shell("rm", "-f", f"{self.remote}/fixture", f"{self.remote}/amtracer", f"{self.remote}/amtracer-itrace.o", check=False)
            self.shell("rmdir", self.remote, check=False)
        if errors and exception is None:
            raise RuntimeError(f"instruction test cleanup failed: {errors}")


class Trace:
    def __init__(self, device, name, ranges, regs, summary, count, output_sink="file"):
        self.device = device
        self.path = device.output / f"{name}.jsonl"
        self.error_path = device.output / f"{name}.stderr"
        self.output_sink = output_sink
        self.output = Path("/dev/null").open("w") if output_sink == "host-null" else self.path.open("w")
        self.error = self.error_path.open("w")
        args = [f"{device.remote}/amtracer", "itrace", "-p", str(device.info["pid"]), "--duration", "120"]
        for scope in ranges:
            args += ["--range", scope]
        args += ["--summary-only"] if summary else ["--json"]
        if regs:
            args += ["--regs"]
        if count:
            args += ["--count", str(count)]
        self.command = args
        # Record the shell's PID before exec so setup failures can be cleaned too.
        shell = 'echo "AMTRACER_PID=$$" >&2\nexec ' + shlex.join(args)
        if output_sink == "device-null":
            shell += " > /dev/null"
        device.report["commands"].append(device.adb + ["shell", "-T", shell])
        self.process = subprocess.Popen(device.adb + ["shell", "-T", shell], stdout=self.output, stderr=self.error, text=True)
        self.pid = None
        self.finished = None
        self.ready_at = None

    def ready(self, timeout=30):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            text = self.error_path.read_text()
            if match := re.search(r"AMTRACER_PID=(\d+)", text):
                self.pid = int(match[1])
            if "itrace: ready " in text:
                self.ready_at = time.monotonic_ns()
                return text
            if self.process.poll() is not None:
                raise RuntimeError(text)
            time.sleep(0.05)
        raise TimeoutError(self.error_path.read_text())

    def stop(self):
        if self.finished is not None:
            return self.finished
        if self.pid is None:
            match = re.search(r"AMTRACER_PID=(\d+)", self.error_path.read_text())
            if match:
                self.pid = int(match[1])
        if self.process.poll() is None and self.pid is not None:
            self.device.signal(self.pid, "INT")
        try:
            code = self.process.wait(timeout=20)
            finished_at = time.monotonic_ns()
        except subprocess.TimeoutExpired:
            if self.pid is not None:
                self.device.signal(self.pid, "KILL")
            self.process.terminate()
            self.process.wait(timeout=5)
            raise
        finally:
            self.output.close()
            self.error.close()
        self.finished = {"returncode": code, "stderr": self.error_path.read_text(),
                         "output_bytes": 0 if self.output_sink == "host-null" else self.path.stat().st_size,
                         "output_sink": self.output_sink,
                         "ready_to_exit_ns": finished_at - self.ready_at if self.ready_at is not None else None,
                         "command": self.command}
        return self.finished

    def events(self):
        return list(self.iter_events())

    def iter_events(self):
        with self.path.open() as source:
            for line in source:
                yield json.loads(line)
