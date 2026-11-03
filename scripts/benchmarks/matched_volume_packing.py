#!/usr/bin/env python3
"""Same-host, unlogged ABBA evidence from two exact storage revisions.

Runs only in a disposable GitHub-hosted macOS workspace. The frozen public-API
probe is injected identically as an untracked example in both clean checkouts;
the report records that injection explicitly. No automatic speed verdict.
"""

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import tempfile
import time


PROBE_SHA = "bff5f6b391f7ae2ed1b2c43d94def378733de4c89c9287c5c767b7a173ea7faf"
INJECTION = "crates/astrid-storage/examples/volume_packing_probe.rs"
RUN_BUDGET_SECONDS = 45 * 60


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def command(args, cwd=None):
    return subprocess.check_output(args, cwd=cwd, text=True).strip()


def require(condition, detail):
    if not condition:
        raise RuntimeError(detail)


def clean_checkout(path, head, injected=False):
    require(re.fullmatch(r"[0-9a-f]{40}", head), "expected a full commit SHA")
    require(command(["git", "rev-parse", "HEAD"], path) == head, "head mismatch")
    require(not command(["git", "diff", "HEAD", "--"], path), "tracked source changed")
    others = command(["git", "ls-files", "--others", "--exclude-standard"], path)
    require(others == (INJECTION if injected else ""), "unexpected untracked source")


def cpu_ticks():
    # Darwin mach/host_info.h: HOST_CPU_LOAD_INFO=3, four natural_t counters
    # in USER, SYSTEM, IDLE, NICE order. Release this call's host-port right.
    lib = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
    port_type = ctypes.c_uint32
    lib.mach_host_self.restype = port_type
    lib.mach_host_self.argtypes = []
    lib.host_statistics.restype = ctypes.c_int
    lib.host_statistics.argtypes = [port_type, ctypes.c_int,
                                   ctypes.POINTER(ctypes.c_int),
                                   ctypes.POINTER(ctypes.c_uint32)]
    lib.mach_port_deallocate.restype = ctypes.c_int
    lib.mach_port_deallocate.argtypes = [port_type, port_type]
    host = lib.mach_host_self()
    require(host != 0, "no Mach host port for CPU measurement")
    ticks = (ctypes.c_uint32 * 4)()
    count = ctypes.c_uint32(4)
    try:
        code = lib.host_statistics(host, 3, ctypes.cast(
            ticks, ctypes.POINTER(ctypes.c_int)), ctypes.byref(count))
        require(code == 0 and count.value == 4, "CPU counter query failed")
        return list(ticks)
    finally:
        task = port_type.in_dll(lib, "mach_task_self_").value
        require(lib.mach_port_deallocate(task, host) == 0,
                "CPU measurement host-port release failed")


def quiet_snapshot():
    # Measure actual host-wide CPU, including this observer and kernel work.
    # ps %CPU decays across time: hashing build artifacts made this otherwise
    # idle observer look busy after it had stopped doing that work.
    cores = int(command(["sysctl", "-n", "hw.logicalcpu"]))
    require(cores > 0, "invalid logical CPU count")
    started = time.monotonic()
    before = cpu_ticks()
    time.sleep(1)
    after = cpu_ticks()
    elapsed = time.monotonic() - started
    delta = [(end - start) % (1 << 32) for start, end in zip(before, after)]
    total = sum(delta)
    require(total > 0, "CPU counters did not advance")
    cpu = 100.0 * cores * (total - delta[2]) / total
    rows = command(["ps", "-axo", "pcpu=,comm="]).splitlines()
    return {"background_cpu_percent": cpu, "rows": rows,
            "rows_are_decaying_context_only": True,
            "method": "Darwin host CPU tick delta; percent of one logical core",
            "cpu_ticks_before": before, "cpu_ticks_after": after,
            "cpu_tick_deltas": delta, "logical_cpus": cores,
            "interval_seconds": elapsed, "quiet": cpu <= 10.0}


def build(path, head, probe, output, arm, deadline):
    clean_checkout(path, head)
    source = path / INJECTION
    require(not source.exists(), "example path already exists")
    source.parent.mkdir(exist_ok=True)
    shutil.copyfile(probe, source)
    require(sha(source) == PROBE_SHA, "injected probe changed during copy")
    clean_checkout(path, head, injected=True)
    require(shutil.disk_usage(path).free >= 2 * 1024**3, "build disk reserve")
    log = output / f"{arm}-build.jsonl"
    budget = min(900, deadline - time.monotonic())
    require(budget > 0, "run budget exhausted before build")
    with log.open("w") as stream:
        process = subprocess.Popen([
            "cargo", "build", "--release", "--locked", "-j", "1", "-p",
            "astrid-storage", "--features", "legacy-surrealkv", "--example",
            "volume_packing_probe", "--message-format=json",
        ], cwd=path, stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            code = process.wait(timeout=budget)
        except subprocess.TimeoutExpired:
            # Only the disposable build's new process group; no shared services.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            raise
        require(code == 0, f"{arm} build failed: {code}")
    require(sha(source) == PROBE_SHA, "injected probe changed during build")
    artifacts = []
    executable = None
    for line in log.read_text().splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if event.get("reason") != "compiler-artifact":
            continue
        for filename in event["filenames"]:
            file = Path(filename)
            if file.is_file():
                artifacts.append({"path": filename, "sha256": sha(file),
                                  "package_id": event["package_id"],
                                  "features": event["features"], "profile": event["profile"]})
        if event["target"]["name"] == "volume_packing_probe":
            executable = event.get("executable")
    require(executable is not None, "Cargo emitted no probe executable")
    binary = output / f"{arm}-probe"
    shutil.copy2(executable, binary)
    clean_checkout(path, head, injected=True)
    return {"head": head, "tree": command(["git", "rev-parse", "HEAD^{tree}"], path),
            "rustc": command(["rustc", "-Vv"], path),
            "lock_sha256": sha(path / "Cargo.lock"), "binary": str(binary),
            "binary_sha256": sha(binary), "artifacts": artifacts,
            "injected_source": INJECTION, "injected_sha256": sha(source),
            "tracked_source_clean": True, "build_log_sha256": sha(log)}


def metrics(stdout):
    return dict(line.split("=", 1) for line in stdout.splitlines() if "=" in line)


def run_sample(binary, fixture, output, index, sample):
    started = time.monotonic()
    try:
        try:
            proc = subprocess.run([binary, str(fixture / "volume"),
                                   str(sample["count"]), str(sample["regions"])],
                                  capture_output=True, timeout=180)
            sample.update(exit=proc.returncode, timed_out=False, child_reaped=True)
            stdout, stderr = proc.stdout, proc.stderr
        except subprocess.TimeoutExpired as error:
            # subprocess.run kills and waits for this direct, non-forking probe.
            sample.update(exit=None, timed_out=True, child_reaped=True)
            stdout, stderr = error.stdout or b"", error.stderr or b""
        sample["elapsed_s"] = time.monotonic() - started
        for name, data in [("stdout", stdout), ("stderr", stderr)]:
            log = output / f"sample-{index:02d}.{name}"
            log.write_bytes(data)
            sample[f"{name}_sha256"] = sha(log)
        sample["metrics"] = metrics(stdout.decode("utf-8", errors="replace"))
        sample["quiet_after"] = quiet_snapshot()
        require(not sample["timed_out"], "probe exceeded unchanged 180-second ceiling")
        if sample["phase"] == "negative-control":
            require(sample["exit"] != 0 and stderr.strip() ==
                    b"probe_error=commit snapshot exceeds format bound",
                    "unexpected baseline capacity failure")
        else:
            require(sample["exit"] == 0 and sample["metrics"].get("complete") == "true",
                    "probe failed exact-readback/functional checks")
        require(sample["quiet_after"]["quiet"], "background load after sample: HOLD")
        shutil.rmtree(fixture)
        sample["fixture_reaped"] = True
    finally:
        sample["fixture_preserved"] = fixture.exists()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--baseline-head", required=True)
    parser.add_argument("--candidate-head", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    require(os.environ.get("GITHUB_ACTIONS") == "true" and
            os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted",
            "disposable GitHub-hosted runner required")
    require(platform.system() == "Darwin" and platform.machine() == "arm64",
            "native macOS arm64 required")
    deadline = time.monotonic() + RUN_BUDGET_SECONDS
    protocol = Path(command(["git", "rev-parse", "--show-toplevel"], Path(__file__).parent))
    protocol_head = os.environ.get("GITHUB_SHA", "")
    clean_checkout(protocol, protocol_head)
    output = args.output.resolve()
    output.mkdir(exist_ok=False)
    probe = Path(__file__).with_name("volume_packing_probe.rs")
    require(sha(probe) == PROBE_SHA, "frozen probe changed")
    receipt = {"complete": False, "performance_accepted": False, "samples": [],
               "probe_sha256": PROBE_SHA, "runner_sha256": sha(Path(__file__)),
               "platform": platform.platform(), "machine": platform.machine(),
               "workflow_sha": os.environ.get("GITHUB_SHA"),
               "workflow_run_id": os.environ.get("GITHUB_RUN_ID"),
               "protocol_checkout_head": protocol_head,
               "protocol_tree": command(["git", "rev-parse", "HEAD^{tree}"], protocol),
               "run_budget_seconds": RUN_BUDGET_SECONDS,
               "build_timeout_seconds": 900, "sample_timeout_seconds": 180,
               "cpu": command(["sysctl", "-n", "machdep.cpu.brand_string"]),
               "ram_bytes": command(["sysctl", "-n", "hw.memsize"]),
               "method": "2 warmups and 16 timed ABBA samples per matched config; 3 capacity controls",
               "instrumentation_removed": [],
               "disk_policy": "Disposable CI only: 2 GiB before builds, 1 GiB before samples; local 40 GiB guard unchanged"}
    result = output / "receipt.json"

    def save():
        temporary = result.with_suffix(".tmp")
        temporary.write_text(json.dumps(receipt, indent=2) + "\n")
        temporary.replace(result)

    try:
        for key in list(os.environ):
            if key.startswith(("Malloc", "DYLD_", "ASAN_", "LSAN_", "HEAPTRACK")):
                receipt["instrumentation_removed"].append(key)
                del os.environ[key]
        save()
        builds = {}
        receipt["builds"] = builds
        for arm, path, head in [("main", args.baseline, args.baseline_head),
                                ("candidate", args.candidate, args.candidate_head)]:
            builds[arm] = build(path.resolve(), head, probe, output, arm, deadline)
            save()
        require(all(b["injected_sha256"] == PROBE_SHA for b in builds.values()),
                "producer probe injections differ")
        schedule = []
        for count, regions in [(32768, 7), (600000, 1)]:
            schedule.extend((arm, count, regions, "warmup") for arm in builds)
            schedule.extend((arm, count, regions, "timed")
                            for arm in ["main", "candidate", "candidate", "main"] * 4)
        schedule.extend([("main", 699051, 1, "negative-control"),
                         ("candidate", 699051, 1, "capacity"),
                         ("candidate", 699051, 7, "capacity")])
        receipt["schedule"] = schedule
        save()
        for index, (arm, count, regions, phase) in enumerate(schedule):
            require(deadline - time.monotonic() >= 180,
                    "run budget cannot contain another full sample: HOLD")
            before = quiet_snapshot()
            receipt["quiet_gate_before_sample"] = {"index": index, **before}
            save()
            require(before["quiet"], "background load before sample: HOLD")
            require(shutil.disk_usage(output).free >= 1024**3, "sample disk reserve")
            fixture = Path(tempfile.mkdtemp(prefix="packing-", dir=output))
            sample = {"arm": arm, "count": count, "regions": regions,
                      "phase": phase, "quiet_before": before, "fixture": str(fixture)}
            receipt["samples"].append(sample)
            save()
            try:
                run_sample(builds[arm]["binary"], fixture, output, index, sample)
            finally:
                save()
        for arm, path in [("main", args.baseline), ("candidate", args.candidate)]:
            clean_checkout(path, builds[arm]["head"], injected=True)
            require(sha(path / INJECTION) == PROBE_SHA, "injected probe changed during samples")
            require(sha(Path(builds[arm]["binary"])) == builds[arm]["binary_sha256"],
                    "probe binary changed")
        clean_checkout(protocol, protocol_head)
        receipt["complete"] = True
    except BaseException as error:
        receipt["failure"] = str(error)
        raise
    finally:
        save()


if __name__ == "__main__":
    main()
