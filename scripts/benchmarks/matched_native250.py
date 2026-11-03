#!/usr/bin/env python3
"""Portable matched native250 evidence on disposable GitHub-hosted macOS.

Generates a new owned 250-agent seed once per job from source (baseline head +
baseline public CLI install path), freezes its sha/size, then runs the accepted
2-warmup + 16-timed ABBA protocol with first_upgrade/recovered lives, exact
readback, wrong-marker negative, and three overwrites. Seed provenance is
explicitly new — not byte-identical to the historical cfa7 fixture.

Reuses packing runner gates (GitHub-hosted Darwin arm64, interval quiet <=10,
bounded postbuild settle, disposable disk, terminal compact receipt fallback).
Does not lower the local 40 GiB campaign floor, auto-accept timings, upload
local volumes/keys, or touch unprotected host daemons. No allocation logging.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
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

HERE = Path(__file__).resolve().parent
PACKING_PATH = HERE / "matched_volume_packing.py"
CLIENT_SOURCE = HERE / "native_lifecycle_client.rs"
CAPSULE_SOURCE = HERE / "native250_capsule"
OWNERSHIP_SENTINEL = "isolated native250 portable fixture 20261103\n"
COHORT = 250
READY_SECS = 60
PRODUCT_SHUTDOWN_SECS = 8
CLEANUP_SECS = 60
STAGE_TIMEOUT_SECS = 600
WARMUPS = 2
TIMED = 16
OVERWRITE_ROLES = ("overwrite-1", "overwrite-2", "overwrite-3")
WANTED_LIBS = {
    "anyhow", "astrid_core", "astrid_storage", "astrid_uplink", "astrid_types",
    "uuid", "chrono", "tokio", "serde_json", "astrid_capsule", "astrid_crypto",
}
PROTECTED_PIDS = {1361, 54628, 64147, 87781}
LOCAL_DISK_FLOOR = 40 * 1024 ** 3
STRIP_ENV_PREFIXES = ("Malloc", "DYLD_", "ASAN_", "LSAN_", "HEAPTRACK", "RUST_LOG")
STRIP_ENV_EXACT = {
    "ASTRID_ALLOC_LOG", "MALLOC_LOG", "ASTRID_PRINCIPAL", "ASTRID_PRINCIPAL_ID",
    "ASTRID_CLIENT_CONFIG", "ASTRID_WORKSPACE_STATE_DIR",
}
IS_DARWIN = platform.system() == "Darwin"


def load_packing():
    spec = importlib.util.spec_from_file_location("matched_volume_packing", PACKING_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


packing = load_packing()


def sha(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def require(condition, detail):
    if not condition:
        raise RuntimeError(detail)


def atomic_write(path: Path, payload: dict) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2) + "\n")
    temporary.replace(path)


def sanitized_env() -> dict[str, str]:
    env = {
        key: value for key, value in os.environ.items()
        if not key.startswith(STRIP_ENV_PREFIXES) and key not in STRIP_ENV_EXACT
    }
    for key in list(STRIP_ENV_EXACT):
        env.pop(key, None)
    leaked = sorted(k for k in env if k.startswith(STRIP_ENV_PREFIXES) or k in STRIP_ENV_EXACT)
    require(not leaked, f"allocator/principal env leaked: {leaked}")
    require("ASTRID_PRINCIPAL" not in env and "ASTRID_PRINCIPAL_ID" not in env,
            "inherited principal must be cleared")
    return env


def child_env(home: Path, run: Path) -> dict[str, str]:
    env = sanitized_env()
    env.update({"ASTRID_HOME": str(home), "ASTRID_RUN_DIR": str(run),
                "ASTRID_DAEMON_LOG_TARGET": "stderr"})
    return env


if IS_DARWIN:
    import ctypes

    class RusageInfoV2(ctypes.Structure):
        _fields_ = [("ri_uuid", ctypes.c_uint8 * 16)] + [
            (name, ctypes.c_uint64) for name in (
                "ri_user_time", "ri_system_time", "ri_pkg_idle_wkups", "ri_interrupt_wkups",
                "ri_pageins", "ri_wired_size", "ri_resident_size", "ri_phys_footprint",
                "ri_proc_start_abstime", "ri_proc_exit_abstime", "ri_child_user_time",
                "ri_child_system_time", "ri_child_pkg_idle_wkups", "ri_child_interrupt_wkups",
                "ri_child_pageins", "ri_child_elapsed_abstime", "ri_diskio_bytesread",
                "ri_diskio_byteswritten")]

    require(ctypes.sizeof(RusageInfoV2) == 160, "RUSAGE_INFO_V2 layout mismatch")
    _PROC = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    _PROC.proc_pid_rusage.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
    _PROC.proc_pid_rusage.restype = ctypes.c_int
    _SYS = ctypes.CDLL("/usr/lib/libSystem.B.dylib")

    class MachTimebase(ctypes.Structure):
        _fields_ = [("numer", ctypes.c_uint32), ("denom", ctypes.c_uint32)]

    _TIMEBASE = MachTimebase()
    require(_SYS.mach_timebase_info(ctypes.byref(_TIMEBASE)) == 0 and _TIMEBASE.denom != 0,
            "mach_timebase_info failed")

    def ticks_to_ns(ticks: int) -> int:
        return ticks * _TIMEBASE.numer // _TIMEBASE.denom
else:
    RusageInfoV2 = None  # type: ignore
    _PROC = None
    _TIMEBASE = None

    def ticks_to_ns(ticks: int) -> int:
        raise RuntimeError("native process metrics require Darwin")


def capture_process_identity(process: subprocess.Popen, binary: Path, workspace: Path) -> dict:
    require(process.pid not in PROTECTED_PIDS, f"refusing protected pid {process.pid}")
    ppid = int(subprocess.check_output(["ps", "-p", str(process.pid), "-o", "ppid="], text=True))
    require(ppid == os.getpid(), f"unowned process ppid={ppid} pid={process.pid}")
    lstart = subprocess.check_output(
        ["ps", "-p", str(process.pid), "-o", "lstart="], text=True).strip()
    require(lstart, f"missing lstart for pid {process.pid}")
    command = subprocess.check_output(
        ["ps", "-p", str(process.pid), "-o", "command="], text=True).strip()
    expected = f"{binary} --workspace {workspace}"
    require(command == expected, f"daemon identity mismatch: {command!r} != {expected!r}")
    return {
        "pid": process.pid,
        "ppid": ppid,
        "lstart": lstart,
        "command": command,
        "binary": str(binary),
        "workspace": str(workspace),
    }


def sample_owned(process: subprocess.Popen, identity: dict | None = None) -> dict:
    require(IS_DARWIN, "sample_owned requires Darwin")
    require(process.pid not in PROTECTED_PIDS, f"refusing protected pid {process.pid}")
    if identity is not None:
        current = capture_process_identity(
            process, Path(identity["binary"]), Path(identity["workspace"]))
        require(current == identity, f"process identity drifted: {current} != {identity}")
    else:
        ppid = int(subprocess.check_output(["ps", "-p", str(process.pid), "-o", "ppid="], text=True))
        require(ppid == os.getpid(), f"unowned process ppid={ppid} pid={process.pid}")
    data = RusageInfoV2()
    status = _PROC.proc_pid_rusage(process.pid, 2, ctypes.byref(data))
    if status != 0:
        raise OSError(ctypes.get_errno(), "proc_pid_rusage failed", process.pid)
    return {
        "pid": process.pid,
        "user_cpu_ns": ticks_to_ns(data.ri_user_time),
        "system_cpu_ns": ticks_to_ns(data.ri_system_time),
        "rss_bytes": data.ri_resident_size,
        "physical_footprint_bytes": data.ri_phys_footprint,
        "source": "proc_pid_rusage(RUSAGE_INFO_V2); owned daemon only",
    }


def wait_owned(process: subprocess.Popen, timeout: float, identity: dict | None = None) -> dict:
    require(process.pid not in PROTECTED_PIDS, f"refusing protected pid {process.pid}")
    if identity is not None:
        require(identity["pid"] == process.pid, "wait4 child identity mismatch")
    # wait4 addresses only this owned child. Popen.poll() would reap a child
    # that exited promptly and discard the terminal resource measurements.
    deadline = time.monotonic() + timeout
    while True:
        pid, status, usage = os.wait4(process.pid, os.WNOHANG)
        if pid:
            require(pid == process.pid, "wait4 reaped unexpected child")
            process.returncode = os.waitstatus_to_exitcode(status)
            return {
                "user_cpu_ns": round(usage.ru_utime * 1e9),
                "system_cpu_ns": round(usage.ru_stime * 1e9),
                "max_rss_bytes": usage.ru_maxrss,
                "source": "wait4 exact owned child",
            }
        if time.monotonic() >= deadline:
            raise subprocess.TimeoutExpired(process.args, timeout)
        time.sleep(0.005)


def lsof_idle(path: Path) -> None:
    result = subprocess.run(["lsof", "-t", str(path)], capture_output=True, text=True)
    require(result.stderr == "", f"lsof stderr not empty for {path}: {result.stderr!r}")
    if result.returncode == 1 and not result.stdout.strip():
        return
    if result.returncode == 0 and result.stdout.strip():
        raise RuntimeError(f"{path} is open: {result.stdout.strip()}")
    raise RuntimeError(
        f"lsof failed closed for {path}: exit={result.returncode} stdout={result.stdout!r} "
        f"stderr={result.stderr!r}")


def clone_volume(source: Path, destination: Path, source_sha: str) -> None:
    lsof_idle(source)
    subprocess.run(["/bin/cp", "-c", str(source), str(destination)], check=True)
    src, dst = source.stat(), destination.stat()
    require((src.st_dev, src.st_ino) != (dst.st_dev, dst.st_ino), "clone aliased seed inode")
    require(sha(destination) == source_sha, "clone sha mismatch")


def volume_stat(path: Path) -> dict:
    info = path.lstat()
    return {"path": str(path), "logical_bytes": info.st_size, "inode": info.st_ino,
            "dev": info.st_dev, "allocated_bytes": info.st_blocks * 512}


def disk_policy(output: Path, local: bool = False) -> None:
    free = shutil.disk_usage(output).free
    if local:
        require(free >= LOCAL_DISK_FLOOR, "local 40 GiB campaign floor")
    else:
        require(free >= 2 * 1024 ** 3, "disposable CI disk reserve")


def cargo_build(checkout: Path, head: str, packages: list[str], target_dir: Path,
                log: Path, deadline: float) -> dict:
    packing.clean_checkout(checkout, head)
    target_dir.mkdir(parents=True, exist_ok=True)
    disk_policy(target_dir)
    budget = min(1200, deadline - time.monotonic())
    require(budget > 0, "run budget exhausted before cargo")
    env = sanitized_env()
    env["CARGO_TARGET_DIR"] = str(target_dir)
    for key in ("CARGO_HOME", "RUSTUP_HOME"):
        env.pop(key, None)
    cmd = ["cargo", "build", "--release", "--locked", "-j", "1",
           "--message-format=json"]
    for package in packages:
        cmd.extend(["-p", package])
    with log.open("w") as stream:
        process = subprocess.Popen(cmd, cwd=checkout, env=env, stdout=stream,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        try:
            code = process.wait(timeout=budget)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            raise
        require(code == 0, f"cargo failed in {checkout}: {code}")
    packing.clean_checkout(checkout, head)
    artifacts = []
    binaries = {}
    for line in log.read_text().splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if event.get("reason") != "compiler-artifact":
            continue
        name = event["target"]["name"]
        executable = event.get("executable")
        if executable:
            binaries[name] = Path(executable)
        filenames = [Path(filename) for filename in event.get("filenames", [])]
        artifacts.append({
            "path": str(filenames[0]) if filenames else None,
            "filenames": [str(path) for path in filenames],
            "sha256": sha(filenames[0]) if filenames and filenames[0].is_file() else None,
            "package_id": event.get("package_id"),
            "target": name,
            "profile": event.get("profile"),
        })
    # Both arms reuse dependency compilation. Freeze executables before the
    # next Cargo invocation can replace target/release/astrid[-daemon|-build].
    frozen = log.with_suffix(".binaries")
    frozen.mkdir()
    for name, executable in binaries.items():
        destination = frozen / name
        shutil.copy2(executable, destination)
        require(sha(destination) == sha(executable), "executable changed while freezing")
        binaries[name] = destination
    return {
        "head": head,
        "checkout": str(checkout),
        "tree": packing.command(["git", "rev-parse", "HEAD^{tree}"], checkout),
        "rustc": packing.command(["rustc", "-Vv"], checkout),
        "lock_sha256": sha(checkout / "Cargo.lock"),
        "target_dir": str(target_dir),
        "binaries": {name: {"path": str(path), "sha256": sha(path)}
                     for name, path in binaries.items()},
        "artifacts": artifacts,
        "build_log_sha256": sha(log),
        "packages": packages,
    }


def select_release_rlibs(artifacts: list[dict]) -> dict[str, dict]:
    selected: dict[str, dict] = {}
    for item in artifacts:
        name = item.get("target")
        profile = item.get("profile") or {}
        if name not in WANTED_LIBS:
            continue
        if profile.get("opt_level") != "3" or profile.get("test"):
            continue
        rlibs = [Path(path) for path in item.get("filenames") or [] if str(path).endswith(".rlib")]
        require(rlibs, f"compiler-artifact for {name} missing rlib")
        require(len(rlibs) == 1, f"ambiguous rlib filenames for {name}: {rlibs}")
        path = rlibs[0]
        require(path.is_file(), f"missing rlib file for {name}: {path}")
        digest = sha(path)
        record = {
            "path": str(path),
            "sha256": digest,
            "package_id": item.get("package_id"),
            "profile": profile,
        }
        if name in selected:
            require(selected[name]["path"] == record["path"]
                    and selected[name]["sha256"] == record["sha256"],
                    f"conflicting compiler-artifact provenance for {name}")
            continue
        selected[name] = record
    missing = WANTED_LIBS - set(selected)
    require(not missing, f"missing release rlib provenance: {sorted(missing)}")
    parents = {Path(info["path"]).parent for info in selected.values()}
    require(len(parents) == 1, f"rlibs must share one deps directory, found {parents}")
    return selected


def build_shared_client(candidate_build: dict, ownership_root: Path, output: Path,
                        deadline: float) -> dict:
    require(CLIENT_SOURCE.is_file(), "native_lifecycle_client.rs missing")
    source_sha = sha(CLIENT_SOURCE)
    libraries = select_release_rlibs(candidate_build["artifacts"])
    checkout = Path(candidate_build["checkout"])
    compiler = packing.command(["rustc", "-Vv"], checkout)
    require(compiler == candidate_build["rustc"], "client compiler differs from producer")
    deps = Path(next(iter(libraries.values()))["path"]).parent
    binary = output / "native250-lifecycle-client"
    log = output / "client-rustc.log"
    require(not binary.exists(), "client binary already exists")
    cmd = ["rustc", "--edition=2024", "-O", "--crate-name", "native250_lifecycle_client",
           str(CLIENT_SOURCE), "-L", f"dependency={deps}", "-o", str(binary)]
    for name, info in sorted(libraries.items()):
        cmd.extend(["--extern", f"{name}={info['path']}"])
    env = sanitized_env()
    env["NATIVE250_OWNERSHIP_ROOT"] = str(ownership_root)
    budget = min(300, deadline - time.monotonic())
    require(budget > 0, "run budget exhausted before client link")
    with log.open("w") as stream:
        result = subprocess.run(cmd, cwd=checkout, env=env, stdout=stream, stderr=subprocess.STDOUT,
                                timeout=budget)
    require(result.returncode == 0, f"client rustc failed; see {log}")
    require(sha(CLIENT_SOURCE) == source_sha, "client source changed during link")
    for info in libraries.values():
        require(sha(Path(info["path"])) == info["sha256"], "rlib changed during link")
    return {
        "path": str(binary), "sha256": sha(binary), "source": str(CLIENT_SOURCE),
        "source_sha256": source_sha,
        "ownership_root": str(ownership_root),
        "libraries": libraries,
        "log_sha256": sha(log),
        "shared_both_arms": True,
        "rustc": compiler,
        "linked_against": "candidate producer libraries via compiler-artifact provenance",
    }


def tree_file_hashes(root: Path) -> dict[str, str]:
    hashes = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise RuntimeError(f"refusing symlink in capsule source: {path}")
        if path.is_file():
            hashes[str(path.relative_to(root))] = sha(path)
    return hashes


def stage_capsule_source(ownership_root: Path) -> tuple[Path, dict[str, str]]:
    require(CAPSULE_SOURCE.is_dir(), "native250_capsule missing")
    for forbidden in ("dist", "target", "builder-home"):
        require(not (CAPSULE_SOURCE / forbidden).exists(),
                f"capsule source must not include {forbidden}")
    staged = ownership_root / "capsule-src"
    require(not staged.exists(), "capsule staging already exists")
    shutil.copytree(CAPSULE_SOURCE, staged, symlinks=False)
    hashes = tree_file_hashes(staged)
    require("src/lib.rs" in hashes, "capsule lib.rs missing after stage")
    require(hashes["src/lib.rs"] == sha(CAPSULE_SOURCE / "src" / "lib.rs"),
            "staged capsule lib hash mismatch")
    return staged, hashes


def build_capsule(cli: Path, ownership_root: Path, output: Path, deadline: float) -> dict:
    staged, source_hashes = stage_capsule_source(ownership_root)
    out = output / "capsule-dist"
    out.mkdir(mode=0o700)
    home = ownership_root / "capsule-builder-home"
    home.mkdir(mode=0o700)
    run = private_run_dir("capsule-build")
    env = child_env(home, run)
    budget = min(900, deadline - time.monotonic())
    require(budget > 0, "run budget exhausted before capsule build")
    log = output / "capsule-build.log"
    with log.open("w") as stream:
        result = subprocess.run(
            [str(cli), "capsule", "build", str(staged), "--output", str(out)],
            env=env, stdout=stream, stderr=subprocess.STDOUT, timeout=budget)
    require(result.returncode == 0, f"capsule build failed; see {log}")
    require(tree_file_hashes(staged) == source_hashes, "capsule source mutated during build")
    require(tree_file_hashes(CAPSULE_SOURCE)["src/lib.rs"] == source_hashes["src/lib.rs"],
            "original capsule source changed during build")
    capsules = list(out.glob("*.capsule"))
    require(len(capsules) == 1, f"expected one capsule, found {capsules}")
    return {
        "path": str(capsules[0]), "sha256": sha(capsules[0]),
        "source_lib_sha256": source_hashes["src/lib.rs"],
        "source_tree_sha256s": source_hashes,
        "staged_source": str(staged),
        "cli_sha256": sha(cli), "log_sha256": sha(log),
        "builder_home": str(home),
    }


class OwnedDaemon:
    def __init__(self, binary: Path, home: Path, workspace: Path, run: Path, log_path: Path):
        self.binary = binary
        self.home = home
        self.workspace = workspace
        self.run = run
        self.log_path = log_path
        self.process = None
        self.log = None
        self.identity = None

    def assert_owned(self) -> None:
        require(self.process is not None, "daemon not started")
        require(self.identity is not None, "daemon identity not captured")
        require(self.process.pid not in PROTECTED_PIDS, "protected pid")
        current = capture_process_identity(self.process, self.binary, self.workspace)
        require(current == self.identity, f"daemon identity mismatch: {current} != {self.identity}")
        sample_owned(self.process, self.identity)

    def start(self, boot: dict) -> None:
        require(not (self.run / "system.ready").exists(), "stale readiness marker")
        require(not self.log_path.exists(), f"refusing overwrite {self.log_path}")
        self.log = self.log_path.open("x")
        boot["spawn_monotonic"] = time.monotonic()
        self.process = subprocess.Popen(
            [str(self.binary), "--workspace", str(self.workspace)],
            env=child_env(self.home, self.run), stdout=self.log, stderr=subprocess.STDOUT)
        boot["pid"] = self.process.pid
        require(self.process.pid not in PROTECTED_PIDS, "spawned protected pid")
        self.identity = capture_process_identity(self.process, self.binary, self.workspace)
        boot["process_identity"] = dict(self.identity)
        while not (self.run / "system.ready").exists():
            require(self.process.poll() is None,
                    f"daemon exited {self.process.returncode} before ready")
            elapsed = time.monotonic() - boot["spawn_monotonic"]
            if elapsed >= READY_SECS:
                boot["ready_containment_exceeded"] = True
                raise RuntimeError("ready containment 60s exceeded; startup failure, not performance pass")
            time.sleep(0.02)
        boot["ready_seconds"] = time.monotonic() - boot["spawn_monotonic"]
        boot["ready_is_performance_pass"] = False
        boot["ready_process_metrics"] = sample_owned(self.process, self.identity)

    def stop(self, boot: dict, require_volume_only: bool = True) -> None:
        if self.process is None:
            return
        self.assert_owned()
        boot["before_shutdown_process_metrics"] = sample_owned(self.process, self.identity)
        started = time.monotonic()
        if self.process.poll() is None:
            self.assert_owned()
            self.process.terminate()
            try:
                boot["terminal_process_metrics"] = wait_owned(
                    self.process, PRODUCT_SHUTDOWN_SECS, self.identity)
            except subprocess.TimeoutExpired:
                boot["shutdown_deadline_exceeded"] = True
                try:
                    boot["terminal_process_metrics"] = wait_owned(
                        self.process, CLEANUP_SECS, self.identity)
                except subprocess.TimeoutExpired:
                    self.assert_owned()
                    self.process.kill()
                    boot["terminal_process_metrics"] = wait_owned(
                        self.process, CLEANUP_SECS, self.identity)
                    boot["cleanup_kill"] = True
                boot["shutdown_seconds"] = time.monotonic() - started
                boot["exit"] = self.process.returncode
                self._close()
                raise RuntimeError("product 8s shutdown exceeded; cleanup cannot PASS")
        boot["shutdown_seconds"] = time.monotonic() - started
        boot["exit"] = self.process.returncode
        self._close()
        require(boot["exit"] == 0, f"daemon exit {boot['exit']}")
        if require_volume_only:
            require(sorted(p.name for p in self.home.iterdir()) == ["astrid.volume"],
                    "home not volume-only after stop")

    def force_kill_owned(self, record: dict, original_error: BaseException | None = None) -> None:
        if self.process is None:
            return
        try:
            require(self.process.pid not in PROTECTED_PIDS, "protected")
            if self.process.poll() is None:
                self.assert_owned()
                self.process.kill()
            self.process.wait(timeout=5)
            record["failure_cleanup_child_reaped"] = True
        except BaseException as cleanup_error:
            record["failure_cleanup_error"] = repr(cleanup_error)
            if original_error is not None:
                raise original_error from cleanup_error
            raise
        finally:
            self._close()

    def _close(self) -> None:
        if self.log is not None:
            self.log.close()
            self.log = None
        self.process = None
        self.identity = None


def run_client(client: Path, home: Path, run: Path, log_path: Path, args: list[str],
               daemon: OwnedDaemon) -> dict:
    daemon.assert_owned()
    before = sample_owned(daemon.process, daemon.identity)
    began = time.monotonic()
    output = subprocess.run([str(client), *args], env=child_env(home, run),
                            capture_output=True, text=True, timeout=STAGE_TIMEOUT_SECS)
    text = output.stdout + output.stderr
    log_path.write_text(text)
    after = sample_owned(daemon.process, daemon.identity)
    item = {
        "args": args, "seconds": time.monotonic() - began, "exit": output.returncode,
        "log": str(log_path), "log_sha256": sha(log_path),
        "daemon_before": before, "daemon_after": after,
        "daemon_stage_cpu_ns": {
            "user": after["user_cpu_ns"] - before["user_cpu_ns"],
            "system": after["system_cpu_ns"] - before["system_cpu_ns"],
            "source": "owned proc_pid_rusage delta; not ps %CPU",
        },
    }
    require(output.returncode == 0, f"client failed {args}: {text[-4000:]}")
    return item


def install_capsule(cli: Path, capsule: Path, home: Path, workspace: Path, run: Path,
                    principal: str, log_path: Path) -> dict:
    env = child_env(home, run)
    began = time.monotonic()
    command = [
        str(cli), "--daemon-workspace", str(workspace), "--principal", principal,
        "capsule", "install", str(capsule), "--yes", "--approve-untrusted",
    ]
    output = subprocess.run(command, env=env, capture_output=True, text=True,
                            timeout=STAGE_TIMEOUT_SECS)
    log_path.write_text(output.stdout + output.stderr)
    item = {
        "command": command, "principal": principal, "seconds": time.monotonic() - began,
        "exit": output.returncode, "log": str(log_path), "log_sha256": sha(log_path),
        "cli_sha256": sha(cli), "capsule_sha256": sha(capsule),
        "daemon_workspace": str(workspace),
    }
    require(output.returncode == 0, f"capsule install failed: {log_path.read_text()[-2000:]}")
    return item


def private_run_dir(name: str) -> Path:
    # Public daemon sockets live under ASTRID_RUN_DIR; keep paths short.
    path = Path("/private/tmp") / f"ast-n250-{os.getpid()}-{time.time_ns()}-{name}"
    require(not path.exists(), f"run dir exists {path}")
    path.mkdir(mode=0o700)
    return path


def make_owned_dir(root: Path, name: str) -> Path:
    require(root.is_absolute(), "ownership root must be absolute")
    require(".." not in Path(name).parts and name not in (".", ""), "owned name traversal")
    directory = (root / name).resolve()
    try:
        directory.relative_to(root.resolve())
    except ValueError as error:
        raise RuntimeError("escape ownership root") from error
    require(not directory.exists(), f"refusing reuse {directory}")
    directory.mkdir(mode=0o700)
    (directory / "ownership.txt").write_text(OWNERSHIP_SENTINEL)
    (directory / "home").mkdir(mode=0o700)
    (directory / "workspace").mkdir(mode=0o700)
    return directory


def record_offline(client: Path, home: Path, args: list[str], log_path: Path,
                   operations: list[dict], phase: str) -> dict:
    lsof_idle(home / "astrid.volume")
    run = private_run_dir(f"offline-{phase}")
    began = time.monotonic()
    output = subprocess.run([str(client), *args], env=child_env(home, run),
                            capture_output=True, text=True, timeout=STAGE_TIMEOUT_SECS)
    log_path.write_text(output.stdout + output.stderr)
    item = {
        "phase": phase, "args": args, "seconds": time.monotonic() - began,
        "exit": output.returncode, "log": str(log_path), "log_sha256": sha(log_path),
    }
    operations.append(item)
    lsof_idle(home / "astrid.volume")
    shutil.rmtree(run)
    require(output.returncode == 0, output.stderr[-2000:] or output.stdout[-2000:])
    return item


def generate_seed(ownership_root: Path, daemon: Path, cli: Path, client: Path,
                  capsule: Path, output: Path, receipt: dict, save) -> dict:
    """Reconstructed multifleet seed procedure; new provenance each job."""
    seed_dir = make_owned_dir(ownership_root, "seed")
    home, workspace = seed_dir / "home", seed_dir / "workspace"
    boots: list[dict] = []
    operations: list[dict] = []
    owned = None

    def boot_seed(log_name: str) -> tuple[OwnedDaemon, Path, dict]:
        nonlocal owned
        boot = {"kind": f"seed-{log_name}", "ready_is_performance_pass": False}
        boots.append(boot)
        run = private_run_dir(f"seed-{log_name}")
        daemon_owned = OwnedDaemon(daemon, home, workspace, run, seed_dir / f"{log_name}.log")
        owned = daemon_owned
        daemon_owned.start(boot)
        save()
        return daemon_owned, run, boot

    try:
        owned, run, boot = boot_seed("install-daemon")
        operations.append(install_capsule(
            cli, capsule, home, workspace, run, "default", seed_dir / "install.log"))
        owned.stop(boot, require_volume_only=False)
        owned = None

        owned, run, boot = boot_seed("roots-daemon")
        operations.append(run_client(client, home, run, seed_dir / "create-roots.log",
                                     ["create-roots", "0", str(COHORT)], owned))
        for index in (0, 100, 200):
            operations.append(install_capsule(
                cli, capsule, home, workspace, run, f"scale-agent-{index:05}",
                seed_dir / f"install-root-{index:05}.log"))
        owned.stop(boot, require_volume_only=False)
        owned = None

        record_offline(client, home, ["prepare-fleets", "0", str(COHORT)],
                       seed_dir / "prepare-fleets.log", operations, "prepare-fleets")
        record_offline(client, home, ["rehome-roots", "0", str(COHORT)],
                       seed_dir / "rehome-roots.log", operations, "rehome-roots")

        owned, run, boot = boot_seed("derive-daemon")
        operations.append(run_client(client, home, run, seed_dir / "derive.log",
                                     ["derive", "0", str(COHORT)], owned))
        operations.append(run_client(client, home, run, seed_dir / "census.log",
                                     ["census"], owned))
        operations.append(run_client(client, home, run, seed_dir / "empty.log",
                                     ["empty", "0", str(COHORT)], owned))
        operations.append(run_client(client, home, run, seed_dir / "wrong-marker.log",
                                     ["probe-wrong-marker", "0", "1"], owned))
        owned.stop(boot, require_volume_only=False)
        owned = None

        record_offline(client, home, ["offline-census", "0", str(COHORT)],
                       seed_dir / "offline-census.log", operations, "offline-census")

        agents = json.loads((seed_dir / "census.log").read_text())
        aliases = {agent["principal"] for agent in agents}
        require("default" in aliases, "census missing default")
        expected = {f"scale-agent-{i:05}" for i in range(COHORT)}
        require(expected <= aliases, "census missing scale-agent aliases")
        require(len(expected & aliases) == COHORT, "census alias count")
        fleet_lines = [line for line in (seed_dir / "offline-census.log").read_text().splitlines()
                       if line.startswith("{")]
        require(fleet_lines, "offline census JSON missing")
        fleets = json.loads(fleet_lines[-1])
        require(sum(fleets.values()) == COHORT, f"offline census size {fleets}")

        lsof_idle(home / "astrid.volume")
        for child in list(home.iterdir()):
            if child.name != "astrid.volume":
                if child.is_dir():
                    shutil.rmtree(child)
                else:
                    child.unlink()
        require(sorted(p.name for p in home.iterdir()) == ["astrid.volume"], "seed not volume-only")
        lsof_idle(home / "astrid.volume")
        volume = home / "astrid.volume"
        digest = sha(volume)
        info = {
            "directory": str(seed_dir),
            "volume": str(volume),
            "sha256": digest,
            "bytes": volume.stat().st_size,
            "cohort": COHORT,
            "boots": boots,
            "operations": operations,
            "provenance": {
                "kind": "source-generated-on-runner",
                "not_byte_identical_to_historical_cfa7": True,
                "historical_cfa7_sha256": "cfa7fe7e403b65d94c2a96b113edc02ffc5f8a1d1c771e25a8a083465fee4be9",
                "identity_minted_once_per_job": True,
                "seed_daemon_head_role": "baseline",
                "capsule_install_cli_role": "baseline-built-public-path",
                "released_2026_10_1_cli_used": False,
                "gap": "seed content reflects baseline head + baseline CLI, not historical released-2026.10.1 capture",
            },
            "oracle": {"census_aliases": COHORT, "offline_fleet_total": COHORT,
                       "empty_complete": True, "wrong_marker_rejected": True,
                       "offline_fleets": fleets},
            "volume_stat": volume_stat(volume),
        }
        receipt["seed"] = info
        save()
        return info
    except BaseException as error:
        if owned is not None:
            owned.force_kill_owned({"seed_cleanup": True}, original_error=error)
        raise


def provision_life(ownership_root: Path, seed: dict, ordinal: int, label: str) -> dict:
    directory = make_owned_dir(ownership_root, f"life-{ordinal:02d}-{label}")
    volume = directory / "home" / "astrid.volume"
    clone_volume(Path(seed["volume"]), volume, seed["sha256"])
    require(sha(Path(seed["volume"])) == seed["sha256"], "seed mutated during clone")
    return {"directory": str(directory), "home": str(directory / "home"),
            "workspace": str(directory / "workspace"), "volume": str(volume),
            "seed_sha256": seed["sha256"]}


def boot_cycle(rec, kind, binary, home, workspace, directory, client, cli, capsule, output, operation):
    run = private_run_dir(f"{rec['ordinal']}-{rec['label']}-{kind}")
    cycle = {"kind": kind, "run_dir": str(run), "ready_is_performance_pass": False}
    rec[kind] = cycle
    daemon = OwnedDaemon(binary, home, workspace, run, Path(directory) / f"{kind}-daemon.log")
    original_error = None
    try:
        before = packing.quiet_snapshot()
        cycle["quiet_before"] = before
        require(before["quiet"], f"background load before {kind}: HOLD")
        daemon.start(cycle)
        operation(cycle, home, run, Path(directory), daemon)
        daemon.stop(cycle)
        after = packing.quiet_snapshot()
        cycle["quiet_after"] = after
        require(after["quiet"], f"background load after {kind}: HOLD")
        require(cycle.get("exit") == 0 and not cycle.get("shutdown_deadline_exceeded"),
                "unclean stop")
        cycle["owned_child_reaped"] = True
        lsof_idle(home / "astrid.volume")
        shutil.rmtree(run)
        cycle["run_dir_removed"] = True
        return cycle
    except BaseException as error:
        original_error = error
        raise
    finally:
        if daemon.process is not None:
            daemon.force_kill_owned(cycle, original_error=original_error)


def run_one(ordinal, label, binary, cli, client, capsule, seed, ownership_root, output, receipt, save):
    fixture = provision_life(ownership_root, seed, ordinal, label)
    directory = Path(fixture["directory"])
    home = Path(fixture["home"])
    workspace = Path(fixture["workspace"])
    rec = {"ordinal": ordinal, "label": label, "warmup": ordinal < WARMUPS,
           "fixture": fixture, "complete": False, "operations": [],
           "compare_first_upgrade_to_recovered_forbidden": True}
    receipt["runs"].append(rec)
    save()

    def first_ops(cycle, home, run, directory, daemon):
        rec["operations"].append(run_client(client, home, run, directory / "first-empty.log",
                                            ["empty", "0", "1"], daemon))
        rec["operations"].append(run_client(
            client, home, run, directory / "remaining-empty.log",
            ["empty", "1", str(COHORT)], daemon))
        write = run_client(client, home, run, directory / "timed-probe-pattern.log",
                           ["probe-pattern", "0", str(COHORT)], daemon)
        write["role"] = "timed-known-write"
        rec["operations"].append(write)
        neg = run_client(client, home, run, directory / "wrong-marker.log",
                         ["probe-wrong-marker", "0", "1"], daemon)
        neg["role"] = "negative-control"
        rec["operations"].append(neg)
        read = run_client(client, home, run, directory / "timed-probe.log",
                          ["probe", "0", str(COHORT)], daemon)
        read["role"] = "timed-known-read"
        rec["operations"].append(read)
        for index, role in enumerate(OVERWRITE_ROLES, start=1):
            item = run_client(client, home, run, directory / f"timed-overwrite-{index}.log",
                              ["probe-pattern", "0", str(COHORT)], daemon)
            item["role"] = role
            rec["operations"].append(item)

    def recovered_ops(cycle, home, run, directory, daemon):
        first = run_client(client, home, run, directory / "recovered-first-probe.log",
                           ["probe", "0", "1"], daemon)
        first["role"] = "first-authenticated-recovered"
        rec["operations"].append(first)
        rest = run_client(client, home, run, directory / "remaining-recovered-probe.log",
                          ["probe", "1", str(COHORT)], daemon)
        rest["role"] = "remaining-recovered-readback"
        rec["operations"].append(rest)

    try:
        disk_policy(output)
        boot_cycle(rec, "first_upgrade", binary, home, workspace, directory, client, cli, capsule,
                   output, first_ops)
        require(sha(Path(seed["volume"])) == seed["sha256"], "seed hash changed after life")
        boot_cycle(rec, "recovered", binary, home, workspace, directory, client, cli, capsule,
                   output, recovered_ops)
        require(sha(Path(seed["volume"])) == seed["sha256"], "seed hash changed after recovered")
        rec["complete"] = True
        rec["final_volume"] = volume_stat(home / "astrid.volume")
        shutil.rmtree(home)
        rec["out_home_reaped"] = True
        save()
        return rec
    except BaseException as error:
        rec["error"] = repr(error)
        rec["complete"] = False
        rec["failed_state_preserved"] = True
        save()
        raise


def schedule_arms() -> list[str]:
    arms = ["main", "candidate"]
    arms.extend(["main", "candidate", "candidate", "main"] * 4)
    require(len(arms) == WARMUPS + TIMED, "schedule length")
    return arms


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--baseline-head", required=True)
    parser.add_argument("--candidate-head", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    require(IS_DARWIN, "native macOS arm64 required")
    require(os.environ.get("GITHUB_ACTIONS") == "true" and
            os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted",
            "disposable GitHub-hosted runner required")
    require(platform.machine() == "arm64", "native macOS arm64 required")
    for head in (args.baseline_head, args.candidate_head):
        require(re.fullmatch(r"[0-9a-f]{40}", head), "exact 40-char commit SHA required")
    deadline = time.monotonic() + packing.RUN_BUDGET_SECONDS
    protocol = Path(packing.command(["git", "rev-parse", "--show-toplevel"], HERE))
    protocol_head = os.environ.get("GITHUB_SHA", "")
    packing.clean_checkout(protocol, protocol_head)
    output = args.output.resolve()
    output.mkdir(exist_ok=False)
    ownership_root = output / "ownership-root"
    ownership_root.mkdir(mode=0o700)
    receipt = {
        "complete": False, "performance_accepted": False, "runs": [],
        "runner_sha256": sha(Path(__file__)),
        "client_source_sha256": sha(CLIENT_SOURCE),
        "capsule_source_lib_sha256": sha(CAPSULE_SOURCE / "src" / "lib.rs"),
        "packing_helper_sha256": sha(PACKING_PATH),
        "platform": platform.platform(), "machine": platform.machine(),
        "cpu": packing.command(["sysctl", "-n", "machdep.cpu.brand_string"]),
        "ram_bytes": packing.command(["sysctl", "-n", "hw.memsize"]),
        "workflow_sha": os.environ.get("GITHUB_SHA"),
        "workflow_run_id": os.environ.get("GITHUB_RUN_ID"),
        "protocol_checkout_head": protocol_head,
        "baseline_head": args.baseline_head, "candidate_head": args.candidate_head,
        "method": "2 warmups + 16 timed ABBA; first_upgrade + recovered; 3 overwrites; 8s shutdown",
        "ready_containment_secs": READY_SECS, "product_shutdown_secs": PRODUCT_SHUTDOWN_SECS,
        "quiet_threshold_percent": 10.0, "quiet_method": "packing interval Mach CPU",
        "disk_policy": "Disposable CI: 2 GiB before builds/samples; local 40 GiB campaign floor unchanged and not used to loosen CI",
        "seed_policy": "source-generated once per job; frozen sha/size; APFS clones; not historical cfa7",
        "instrumentation_removed": [],
        "protected_pids_never_signalled": sorted(PROTECTED_PIDS),
        "darwin_only_native_metrics": True,
    }
    result = output / "receipt.json"

    def save():
        atomic_write(result, receipt)

    try:
        for key in list(os.environ):
            if key.startswith(STRIP_ENV_PREFIXES) or key in STRIP_ENV_EXACT:
                receipt["instrumentation_removed"].append(key)
                del os.environ[key]
        save()
        shared_target = output / "cargo-target"
        builds = {}
        receipt["builds"] = builds
        for arm, path, head, packages in [
            ("main", args.baseline, args.baseline_head, ["astrid-daemon", "astrid-cli", "astrid-build"]),
            ("candidate", args.candidate, args.candidate_head, ["astrid-daemon", "astrid-cli", "astrid-build"]),
        ]:
            builds[arm] = cargo_build(path.resolve(), head, packages,
                                      shared_target, output / f"{arm}-cargo.jsonl", deadline)
            save()
        packing.settle_after_builds(receipt, save, deadline)
        baseline_cli = Path(builds["main"]["binaries"]["astrid"]["path"])
        baseline_daemon = Path(builds["main"]["binaries"]["astrid-daemon"]["path"])
        candidate_daemon = Path(builds["candidate"]["binaries"]["astrid-daemon"]["path"])
        receipt["cli_choice"] = {
            "role": "baseline-built-astrid",
            "sha256": sha(baseline_cli),
            "released_2026_10_1_pinned_cli_used": False,
            "rationale": "baseline CLI exercises the same public capsule install path without uploading release binaries",
            "gap_vs_historical_seed": "historical cfa7 seed used released-2026.10.1 CLI; this job uses baseline-head CLI",
            "install_flags": ["--daemon-workspace", "--yes", "--approve-untrusted"],
        }
        capsule = build_capsule(baseline_cli, ownership_root, output, deadline)
        receipt["capsule"] = capsule
        save()
        packing.clean_checkout(protocol, protocol_head)
        client = build_shared_client(builds["candidate"], ownership_root, output, deadline)
        receipt["client"] = client
        save()
        seed = generate_seed(ownership_root, baseline_daemon, baseline_cli,
                             Path(client["path"]), Path(capsule["path"]), output, receipt, save)
        arms = schedule_arms()
        receipt["schedule"] = arms
        save()
        binaries = {"main": baseline_daemon, "candidate": candidate_daemon}
        for ordinal, label in enumerate(arms):
            require(deadline - time.monotonic() >= 180, "run budget cannot contain another life: HOLD")
            before = packing.quiet_snapshot()
            receipt["quiet_gate_before_life"] = {"ordinal": ordinal, **before}
            save()
            require(before["quiet"], "background load before life: HOLD")
            disk_policy(output)
            run_one(ordinal, label, binaries[label], baseline_cli, Path(client["path"]),
                    Path(capsule["path"]), seed, ownership_root, output, receipt, save)
            require(sha(Path(seed["volume"])) == seed["sha256"], "immutable seed hash violated")
        packing.clean_checkout(protocol, protocol_head)
        receipt["complete"] = True
        receipt["performance_accepted"] = False
    except BaseException as error:
        receipt["failure"] = str(error)
        raise
    finally:
        save()
        packing.emit_terminal_receipt(receipt)


if __name__ == "__main__":
    main()
