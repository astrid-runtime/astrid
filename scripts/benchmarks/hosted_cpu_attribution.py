#!/usr/bin/env python3
"""Disposable hosted diagnostic; never a quiet/performance or causal verdict."""
import argparse
import ctypes as C
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import shutil
import subprocess
import time

# Exact SDK sys/resource.h rusage_info_v2: UUID + 18 uint64_t (160 bytes).
FIELDS = "user_time system_time pkg_idle_wkups interrupt_wkups pageins wired_size resident_size phys_footprint proc_start_abstime proc_exit_abstime child_user_time child_system_time child_pkg_idle_wkups child_interrupt_wkups child_pageins child_elapsed_abstime diskio_bytesread diskio_byteswritten".split()


class Usage(C.Structure):
    _fields_ = [("uuid", C.c_uint8 * 16)] + [(name, C.c_uint64) for name in FIELDS]


class Timebase(C.Structure):
    _fields_ = [("numer", C.c_uint32), ("denom", C.c_uint32)]


def require(value, reason):
    if not value:
        raise RuntimeError(reason)


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def guard(binary=None, expected=None):
    for key, value in {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted",
                       "RUNNER_OS": "macOS", "GITHUB_REPOSITORY": "astrid-runtime/astrid"}.items():
        require(os.environ.get(key) == value, f"hosted diagnostic guard: {key}")
    require(platform.system() == "Darwin" and os.environ.get("GITHUB_JOB") in
            {"matched-packing", "matched-native250"}, "hosted macOS matched job required")
    workspace = Path(os.environ.get("GITHUB_WORKSPACE", ""))
    require(workspace.is_absolute(), "absolute workspace required")
    root = workspace / "astrid-benchmark.noindex"
    source = Path(__file__).absolute()
    require(source == root / "diagnostic/hosted_cpu_attribution.py", "owned diagnostic source required")
    for path in (workspace, root, source):
        require(path.absolute() == path.resolve(strict=True) and path.stat().st_uid == os.getuid(),
                "nonaliased owned namespace required")
    require(root.is_dir() and root.stat().st_mode & 0o777 == 0o700, "private .noindex root required")
    if binary is not None:
        require(os.environ.get("GITHUB_JOB") == "matched-packing", "baseline pulse requires matched-packing")
        binary = Path(binary)
        require(binary == root / "packing-evidence/main-storage-io" and binary.resolve(strict=True) == binary,
                "only frozen baseline storage_io binary is allowed")
        require(binary.is_file() and binary.stat().st_uid == os.getuid() and
                isinstance(expected, str) and len(expected) == 64 and sha(binary) == expected,
                "exact baseline binary hash required")
        baseline = root / "baseline"
        require(baseline.is_dir() and baseline.resolve() == baseline and baseline.stat().st_uid == os.getuid(),
                "nonaliased owned baseline checkout required")
    else:
        require(expected is None, "binary hash without binary")
    return root


class Darwin:
    """Read-only libproc + Mach APIs, initialized only after the hosted guard."""
    def __init__(self):
        self.proc = C.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        self.mach = C.CDLL("/usr/lib/libSystem.B.dylib")
        self.proc.proc_listallpids.argtypes = [C.c_void_p, C.c_int]
        self.proc.proc_listallpids.restype = C.c_int
        self.proc.proc_pid_rusage.argtypes = [C.c_int, C.c_int, C.c_void_p]
        self.proc.proc_pid_rusage.restype = C.c_int
        self.proc.proc_name.argtypes = [C.c_int, C.c_void_p, C.c_uint32]
        self.proc.proc_name.restype = C.c_int
        self.mach.mach_timebase_info.argtypes = [C.POINTER(Timebase)]
        self.mach.mach_timebase_info.restype = C.c_int
        self.mach.mach_host_self.argtypes = []
        self.mach.mach_host_self.restype = C.c_uint32
        self.mach.host_statistics.argtypes = [C.c_uint32, C.c_int, C.c_void_p, C.POINTER(C.c_uint32)]
        self.mach.host_statistics.restype = C.c_int
        self.mach.mach_port_deallocate.argtypes = [C.c_uint32, C.c_uint32]
        self.mach.mach_port_deallocate.restype = C.c_int
        self.task = C.c_uint32.in_dll(self.mach, "mach_task_self_").value
        info = Timebase()
        require(self.mach.mach_timebase_info(C.byref(info)) == 0 and info.denom > 0 and info.numer > 0,
                "Mach timebase unavailable")
        self.numer, self.denom = info.numer, info.denom
        self.cores = os.cpu_count()
        require(isinstance(self.cores, int) and self.cores > 0, "logical CPU count unavailable")

    def ticks(self):
        host = self.mach.mach_host_self()
        require(host != 0, "Mach host port unavailable")
        primary_error = None
        try:
            values, count = (C.c_uint32 * 4)(), C.c_uint32(4)
            require(self.mach.host_statistics(host, 3, values, C.byref(count)) == 0 and count.value == 4,
                    "Mach CPU counters unavailable")
            return list(values)
        except BaseException as error:
            primary_error = error
            raise
        finally:
            try:
                require(self.mach.mach_port_deallocate(self.task, host) == 0, "Mach host port release failed")
            except BaseException:
                if primary_error is None:
                    raise

    def snapshot(self):
        started = time.monotonic_ns()
        # Fixed diagnostic enumeration bound; a saturated list is an explicit gap.
        pids = (C.c_int * 8192)()
        count = self.proc.proc_listallpids(pids, C.sizeof(pids))
        require(count > 0, "PID enumeration failed")
        rows, missing = {}, []
        for pid in sorted(set(pids[:min(count, len(pids))])):
            if pid <= 0:
                continue
            usage = Usage()
            if self.proc.proc_pid_rusage(pid, 2, C.byref(usage)) != 0:
                missing.append({"pid": pid, "errno": C.get_errno()})
                continue
            if usage.proc_start_abstime == 0:
                missing.append({"pid": pid, "reason": "start identity unavailable"})
                continue
            row = {name: int(getattr(usage, name)) for name in
                   ("user_time", "system_time", "proc_start_abstime", "diskio_bytesread", "diskio_byteswritten")}
            row["at_ns"] = time.monotonic_ns()
            name = C.create_string_buffer(256)
            size = self.proc.proc_name(pid, name, len(name))
            row["name"] = name.value.decode("utf-8", "replace") if size > 0 else None
            rows[pid] = row
        return {"rows": rows, "missing": missing, "enumeration_saturated": count >= len(pids),
                "enumeration_ns": time.monotonic_ns() - started}


def compare(before, after, numer, denom):
    require(numer > 0 and denom > 0, "invalid timebase")
    rows, gaps = [], {"disappeared": [], "new": [], "reused": [], "counter_regression": []}
    first, last = before["rows"], after["rows"]
    for pid in sorted(set(first) | set(last)):
        if pid not in last:
            gaps["disappeared"].append(pid)
        elif pid not in first:
            gaps["new"].append(pid)
        elif first[pid]["proc_start_abstime"] != last[pid]["proc_start_abstime"]:
            gaps["reused"].append(pid)
        else:
            keys = ("user_time", "system_time", "diskio_bytesread", "diskio_byteswritten")
            delta = {key: last[pid][key] - first[pid][key] for key in keys}
            elapsed = last[pid]["at_ns"] - first[pid]["at_ns"]
            if min(delta.values()) < 0 or elapsed <= 0:
                gaps["counter_regression"].append(pid)
                continue
            user_ns, system_ns = (delta[key] * numer // denom for key in keys[:2])
            rows.append({"pid": pid, "start_abstime": last[pid]["proc_start_abstime"],
                         "name": last[pid]["name"], "raw_delta": delta,
                         "user_ns": user_ns, "system_ns": system_ns, "interval_ns": elapsed,
                         "one_core_cpu_percent": 100 * (user_ns + system_ns) / elapsed})
    return {"process_deltas": rows, "identity_gaps": gaps,
            "missing_before": before["missing"], "missing_after": after["missing"],
            "unseen_short_lived_processes_possible": True}


def self_cpu():
    usage = resource.getrusage(resource.RUSAGE_SELF)
    return usage.ru_utime + usage.ru_stime


def interval(api):
    observer_start = self_cpu()
    started, first = time.monotonic_ns(), api.ticks()
    before = api.snapshot()
    time.sleep(1)
    after = api.snapshot()
    last, ended = api.ticks(), time.monotonic_ns()
    observer_seconds = self_cpu() - observer_start
    delta = [(b - a) % (1 << 32) for a, b in zip(first, last, strict=True)]
    require(sum(delta) > 0 and ended > started, "invalid host CPU interval")
    result = compare(before, after, api.numer, api.denom)
    result.update(host_ticks_before=first, host_ticks_after=last, host_tick_deltas=delta,
                  host_one_core_cpu_percent=100 * api.cores * (sum(delta) - delta[2]) / sum(delta),
                  wall_ns=ended - started, observer_cpu_seconds=observer_seconds,
                  observer_one_core_cpu_percent=100 * observer_seconds / ((ended - started) / 1e9),
                  before=before, after=after)
    return result


def invoke(root, output, binary, expected, receipt):
    require(sha(binary) == expected, "baseline binary changed before invocation")
    require(shutil.disk_usage(output).free >= 1024**3, "diagnostic disk reserve")
    (output / "fixture").mkdir(mode=0o700, exist_ok=False)
    argv = [str(binary), "--only", "evolving-kv", "--samples", "1", "--root",
            str(output / "fixture"), "--output", str(output / "baseline.report.json")]
    receipt["invocation"] = {"argv": argv, "expected_binary_sha256": expected}
    try:
        child = subprocess.run(argv, cwd=root / "baseline", capture_output=True, timeout=180)
        stdout, stderr = child.stdout, child.stderr
        receipt["invocation"].update(exit=child.returncode, timed_out=False)
    except subprocess.TimeoutExpired as error:
        stdout, stderr = error.stdout or b"", error.stderr or b""
        receipt["invocation"].update(exit=None, timed_out=True)
    return receipt["invocation"].get("exit") == 0, stdout, stderr


def preserve_invocation(output, binary, expected, stdout, stderr, receipt):
    for suffix, data in (("stdout", stdout), ("stderr", stderr)):
        path = output / f"baseline.{suffix}"
        path.write_bytes(data)
        receipt["invocation"][suffix + "_sha256"] = sha(path)
    require(sha(binary) == expected, "baseline binary changed during invocation")
    report = output / "baseline.report.json"
    if report.is_file() and not report.is_symlink():
        receipt["invocation"]["report_sha256"] = sha(report)
    else:
        receipt["invocation"]["report_error"] = "baseline report missing or aliased"
        require(receipt["invocation"].get("exit") != 0, "baseline report missing or aliased")


def run(binary=None, expected=None):
    root = guard(binary, expected)
    output = root / "cpu-attribution"
    output.mkdir(mode=0o700, exist_ok=False)
    receipt = {"complete": False, "diagnostic_only": True, "observer_pid": os.getpid(), "performance_verdict": None,
               "causal_verdict": None, "observer_windows": [], "tail_windows": [],
               "source_sha256": sha(Path(__file__)),
               "context": {key: os.environ.get(key) for key in ("GITHUB_REPOSITORY", "GITHUB_JOB", "GITHUB_RUN_ID", "GITHUB_SHA")}}
    def save():
        target = output / "receipt.json"
        temporary = output / "receipt.tmp"
        temporary.write_text(json.dumps(receipt, indent=2) + "\n")
        temporary.replace(target)
    try:
        save()
        api = Darwin()
        receipt["timebase"] = {"numer": api.numer, "denom": api.denom}
        receipt["logical_cpus"] = api.cores
        for _ in range(3):
            receipt["observer_windows"].append(interval(api))
        successful = True
        if binary is not None:
            successful, stdout, stderr = invoke(root, output, Path(binary), expected, receipt)
            # Begin the first tail immediately after subprocess exit/capture, before
            # binary hashing, report parsing or stdout/stderr publication.
            tail_error = None
            try:
                for _ in range(3):
                    receipt["tail_windows"].append(interval(api))
            except BaseException as error:
                tail_error = error
                raise
            finally:
                try:
                    preserve_invocation(output, Path(binary), expected, stdout, stderr, receipt)
                except BaseException as error:
                    receipt["preservation_error"] = f"{type(error).__name__}: {error}"
                    if tail_error is None:
                        raise
        require(successful, "baseline invocation failed; retained diagnostic is not a benchmark")
        receipt["complete"] = True
    except BaseException as error:
        receipt["failure"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        save()
    return output


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-binary", type=Path)
    parser.add_argument("--baseline-sha256")
    args = parser.parse_args()
    run(args.baseline_binary, args.baseline_sha256)
