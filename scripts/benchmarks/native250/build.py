"""Build-side helpers for portable native250 evidence.

Owns cargo producer builds, frozen install-binary selection, shared client
linking, and capsule packaging. The orchestrator uses these helpers for
producer and consumer provenance.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import time

BENCH_DIR = Path(__file__).resolve().parent.parent
PACKING_PATH = BENCH_DIR / "matched_volume_packing.py"
CLIENT_SOURCE = BENCH_DIR / "native_lifecycle_client.rs"
CLIENT_ADMIN_SOURCE = BENCH_DIR / "native250_admin.rs"
CAPSULE_SOURCE = BENCH_DIR / "native250_capsule"

WANTED_LIBS = {
    "anyhow",
    "astrid_core",
    "astrid_storage",
    "astrid_uplink",
    "astrid_types",
    "uuid",
    "chrono",
    "tokio",
    "serde_json",
    "astrid_capsule",
    "astrid_crypto",
}
REQUIRED_FROZEN_BINARIES = frozenset({"astrid", "astrid-daemon", "astrid-build"})
INSTALL_PACKAGES = ["astrid"]
STRIP_ENV_PREFIXES = ("Malloc", "DYLD_", "ASAN_", "LSAN_", "HEAPTRACK", "RUST_LOG")
STRIP_ENV_EXACT = {
    "ASTRID_ALLOC_LOG",
    "MALLOC_LOG",
    "ASTRID_PRINCIPAL",
    "ASTRID_PRINCIPAL_ID",
    "ASTRID_CLIENT_CONFIG",
    "ASTRID_WORKSPACE_STATE_DIR",
}
LOCAL_DISK_FLOOR = 40 * 1024 ** 3
# Inventory hashes every present compiler-artifact filename; selected rlibs are
# additionally strict-bound by select_release_rlibs.
ARTIFACT_INVENTORY_BINDING = "all_present_filenames_sha256"


def load_packing():
    spec = importlib.util.spec_from_file_location("matched_volume_packing", PACKING_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


packing = load_packing()


def sha(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def require(condition, detail):
    if not condition:
        raise RuntimeError(detail)


def disk_policy(output: Path, local: bool = False) -> None:
    free = shutil.disk_usage(output).free
    if local:
        require(free >= LOCAL_DISK_FLOOR, "local 40 GiB campaign floor")
    else:
        require(free >= 2 * 1024 ** 3, "disposable CI disk reserve")


def sanitized_env() -> dict[str, str]:
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(STRIP_ENV_PREFIXES) and key not in STRIP_ENV_EXACT
    }
    for key in list(STRIP_ENV_EXACT):
        env.pop(key, None)
    leaked = sorted(
        key for key in env if key.startswith(STRIP_ENV_PREFIXES) or key in STRIP_ENV_EXACT
    )
    require(not leaked, f"allocator/principal env leaked: {leaked}")
    require(
        "ASTRID_PRINCIPAL" not in env and "ASTRID_PRINCIPAL_ID" not in env,
        "inherited principal must be cleared",
    )
    return env


def child_env(home: Path, run: Path) -> dict[str, str]:
    env = sanitized_env()
    env.update(
        {
            "ASTRID_HOME": str(home),
            "ASTRID_RUN_DIR": str(run),
            "ASTRID_DAEMON_LOG_TARGET": "stderr",
        }
    )
    return env


def private_run_dir(name: str) -> Path:
    # Keep short paths for sockets; also hosts the CI-only capsule cargo target.
    path = Path("/private/tmp") / f"ast-n250-{os.getpid()}-{time.time_ns()}-{name}"
    require(not path.exists(), f"run dir exists {path}")
    path.mkdir(mode=0o700)
    return path


def _host_cargo_caches(env: dict[str, str]) -> None:
    # Leave Cargo/rustup on the shared host caches. Never rewrite them under a
    # worktree, staged capsule source, builder home, or evidence publication root.
    for key in ("CARGO_HOME", "RUSTUP_HOME"):
        env.pop(key, None)


def _wait_owned_group(process: subprocess.Popen, budget: float) -> int:
    try:
        return process.wait(timeout=budget)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        raise


def _filename_bindings(filenames: list[Path]) -> dict[str, str | None]:
    bindings: dict[str, str | None] = {}
    for path in filenames:
        key = str(path)
        if path.is_file():
            bindings[key] = sha(path)
        else:
            bindings[key] = None
    return bindings


def cargo_build(
    checkout: Path,
    head: str,
    packages: list[str],
    target_dir: Path,
    log: Path,
    deadline: float,
) -> dict:
    packing.clean_checkout(checkout, head)
    target_dir.mkdir(parents=True, exist_ok=True)
    disk_policy(target_dir)
    budget = min(1200, deadline - time.monotonic())
    require(budget > 0, "run budget exhausted before cargo")
    env = sanitized_env()
    env["CARGO_TARGET_DIR"] = str(target_dir)
    _host_cargo_caches(env)
    cmd = ["cargo", "build", "--release", "--locked", "-j", "1", "--message-format=json"]
    for package in packages:
        cmd.extend(["-p", package])
    with log.open("w") as stream:
        process = subprocess.Popen(
            cmd,
            cwd=checkout,
            env=env,
            stdout=stream,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        code = _wait_owned_group(process, budget)
        require(code == 0, f"cargo failed in {checkout}: {code}")
    packing.clean_checkout(checkout, head)
    artifacts = []
    binaries: dict[str, Path] = {}
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
        artifacts.append(
            {
                "path": str(filenames[0]) if filenames else None,
                "filenames": [str(path) for path in filenames],
                "sha256": sha(filenames[0]) if filenames and filenames[0].is_file() else None,
                "filename_sha256s": _filename_bindings(filenames),
                "package_id": event.get("package_id"),
                "target": name,
                "profile": event.get("profile"),
            }
        )
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
        "binaries": {
            name: {"path": str(path), "sha256": sha(path)} for name, path in binaries.items()
        },
        "artifacts": artifacts,
        "artifact_inventory_binding": ARTIFACT_INVENTORY_BINDING,
        "build_log_sha256": sha(log),
        "packages": list(packages),
        "public_command": list(cmd),
    }


def require_frozen_install_binaries(binaries: dict) -> None:
    missing = sorted(REQUIRED_FROZEN_BINARIES - set(binaries))
    require(not missing, f"frozen install binaries missing: {missing}")
    for name in sorted(REQUIRED_FROZEN_BINARIES):
        record = binaries[name]
        path = Path(record["path"])
        require(path.is_file(), f"frozen binary missing on disk: {name}")
        require(path.name == name, f"frozen binary name mismatch for {name}: {path.name}")
        require(record.get("sha256") == sha(path), f"frozen binary sha drift for {name}")


def build_install_set(
    checkout: Path,
    head: str,
    target_dir: Path,
    log: Path,
    deadline: float,
) -> dict:
    """Build the public `astrid` package and freeze CLI/daemon/build companions."""
    result = cargo_build(checkout, head, list(INSTALL_PACKAGES), target_dir, log, deadline)
    require(result["packages"] == INSTALL_PACKAGES, "install set must build package astrid only")
    require(
        result["public_command"][result["public_command"].index("-p") + 1] == "astrid",
        "public cargo command must select -p astrid",
    )
    require("astrid-cli" not in result["public_command"], "nonexistent package astrid-cli")
    require_frozen_install_binaries(result["binaries"])
    result["required_frozen_binaries"] = sorted(REQUIRED_FROZEN_BINARIES)
    return result


def select_release_rlibs(artifacts: list[dict]) -> dict[str, dict]:
    selected: dict[str, dict] = {}
    for item in artifacts:
        name = item.get("target")
        profile = item.get("profile") or {}
        if name not in WANTED_LIBS:
            continue
        if profile.get("opt_level") != "3" or profile.get("test"):
            continue
        rlibs = [
            Path(path) for path in item.get("filenames") or [] if str(path).endswith(".rlib")
        ]
        require(rlibs, f"compiler-artifact for {name} missing rlib")
        require(len(rlibs) == 1, f"ambiguous rlib filenames for {name}: {rlibs}")
        path = rlibs[0]
        require(path.is_file(), f"missing rlib file for {name}: {path}")
        digest = sha(path)
        bindings = item.get("filename_sha256s") or {}
        if str(path) in bindings and bindings[str(path)] is not None:
            require(
                bindings[str(path)] == digest,
                f"rlib sha disagrees with artifact inventory for {name}",
            )
        record = {
            "path": str(path),
            "sha256": digest,
            "package_id": item.get("package_id"),
            "profile": profile,
        }
        if name in selected:
            require(
                selected[name]["path"] == record["path"]
                and selected[name]["sha256"] == record["sha256"],
                f"conflicting compiler-artifact provenance for {name}",
            )
            continue
        selected[name] = record
    missing = WANTED_LIBS - set(selected)
    require(not missing, f"missing release rlib provenance: {sorted(missing)}")
    parents = {Path(info["path"]).parent for info in selected.values()}
    require(len(parents) == 1, f"rlibs must share one deps directory, found {parents}")
    return selected


def build_shared_client(
    candidate_build: dict,
    ownership_root: Path,
    output: Path,
    deadline: float,
) -> dict:
    require(CLIENT_SOURCE.is_file(), "native_lifecycle_client.rs missing")
    require(CLIENT_ADMIN_SOURCE.is_file(), "native250_admin.rs missing")
    source_records = [
        {"source": str(CLIENT_SOURCE), "sha256": sha(CLIENT_SOURCE)},
        {"source": str(CLIENT_ADMIN_SOURCE), "sha256": sha(CLIENT_ADMIN_SOURCE)},
    ]
    libraries = select_release_rlibs(candidate_build["artifacts"])
    checkout = Path(candidate_build["checkout"])
    compiler = packing.command(["rustc", "-Vv"], checkout)
    require(compiler == candidate_build["rustc"], "client compiler differs from producer")
    deps = Path(next(iter(libraries.values()))["path"]).parent
    binary = output / "native250-lifecycle-client"
    log = output / "client-rustc.log"
    require(not binary.exists(), "client binary already exists")
    cmd = [
        "rustc",
        "--edition=2024",
        "-O",
        "--crate-name",
        "native250_lifecycle_client",
        str(CLIENT_SOURCE),
        "-L",
        f"dependency={deps}",
        "-o",
        str(binary),
    ]
    for name, info in sorted(libraries.items()):
        cmd.extend(["--extern", f"{name}={info['path']}"])
    env = sanitized_env()
    env["NATIVE250_OWNERSHIP_ROOT"] = str(ownership_root)
    budget = min(300, deadline - time.monotonic())
    require(budget > 0, "run budget exhausted before client link")
    with log.open("w") as stream:
        result = subprocess.run(
            cmd,
            cwd=checkout,
            env=env,
            stdout=stream,
            stderr=subprocess.STDOUT,
            timeout=budget,
        )
    require(result.returncode == 0, f"client rustc failed; see {log}")
    after_sources = [
        {"source": str(CLIENT_SOURCE), "sha256": sha(CLIENT_SOURCE)},
        {"source": str(CLIENT_ADMIN_SOURCE), "sha256": sha(CLIENT_ADMIN_SOURCE)},
    ]
    require(after_sources == source_records, "client compiler inputs changed during link")
    for info in libraries.values():
        require(sha(Path(info["path"])) == info["sha256"], "rlib changed during link")
    return {
        "path": str(binary),
        "sha256": sha(binary),
        "source": str(CLIENT_SOURCE),
        "source_sha256": source_records[0]["sha256"],
        "client_sources": source_records,
        "ownership_root": str(ownership_root),
        "libraries": libraries,
        "log_sha256": sha(log),
        "shared_both_arms": True,
        "rustc": compiler,
        "linked_against": "candidate producer libraries via compiler-artifact provenance",
        "public_command": list(cmd),
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
        require(
            not (CAPSULE_SOURCE / forbidden).exists(),
            f"capsule source must not include {forbidden}",
        )
    staged = ownership_root / "capsule-src"
    require(not staged.exists(), "capsule staging already exists")
    shutil.copytree(CAPSULE_SOURCE, staged, symlinks=False)
    hashes = tree_file_hashes(staged)
    require("src/lib.rs" in hashes, "capsule lib.rs missing after stage")
    require(
        hashes["src/lib.rs"] == sha(CAPSULE_SOURCE / "src" / "lib.rs"),
        "staged capsule lib hash mismatch",
    )
    return staged, hashes


def build_capsule(cli: Path, ownership_root: Path, output: Path, deadline: float) -> dict:
    staged, source_hashes = stage_capsule_source(ownership_root)
    out = output / "capsule-dist"
    out.mkdir(mode=0o700)
    home = ownership_root / "capsule-builder-home"
    home.mkdir(mode=0o700)
    run = private_run_dir("capsule-build")
    # CI-only exception: capsule Cargo target lives outside staged hashed
    # source, outside builder home, and outside the evidence publication root.
    cargo_target = private_run_dir("capsule-cargo-target")
    companion = cli.parent / "astrid-build"
    require(cli.is_file(), f"frozen CLI missing: {cli}")
    require(
        companion.is_file(),
        "frozen astrid-build companion missing beside CLI; refusing PATH fallback",
    )
    env = child_env(home, run)
    env["CARGO_TARGET_DIR"] = str(cargo_target)
    _host_cargo_caches(env)
    require(env["CARGO_TARGET_DIR"] != str(staged), "capsule target must leave staged source")
    require(
        Path(env["CARGO_TARGET_DIR"]).resolve() != home.resolve(),
        "capsule target must leave builder home",
    )
    try:
        Path(env["CARGO_TARGET_DIR"]).resolve().relative_to(output.resolve())
    except ValueError:
        pass
    else:
        raise RuntimeError("capsule cargo target must stay outside publication output")
    budget = min(900, deadline - time.monotonic())
    require(budget > 0, "run budget exhausted before capsule build")
    log = output / "capsule-build.log"
    cmd = [str(cli), "capsule", "build", str(staged), "--output", str(out)]
    with log.open("w") as stream:
        process = subprocess.Popen(
            cmd,
            env=env,
            stdout=stream,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        code = _wait_owned_group(process, budget)
    require(code == 0, f"capsule build failed; see {log}")
    require(tree_file_hashes(staged) == source_hashes, "capsule source mutated during build")
    require(
        not (staged / "target").exists(),
        "capsule build polluted staged source with target/",
    )
    require(
        tree_file_hashes(CAPSULE_SOURCE)["src/lib.rs"] == source_hashes["src/lib.rs"],
        "original capsule source changed during build",
    )
    capsules = list(out.glob("*.capsule"))
    require(len(capsules) == 1, f"expected one capsule, found {capsules}")
    return {
        "path": str(capsules[0]),
        "sha256": sha(capsules[0]),
        "source_lib_sha256": source_hashes["src/lib.rs"],
        "source_tree_sha256s": source_hashes,
        "staged_source": str(staged),
        "cli_sha256": sha(cli),
        "cli_companion_sha256": sha(companion),
        "log_sha256": sha(log),
        "builder_home": str(home),
        "cargo_target_dir": str(cargo_target),
        "public_command": list(cmd),
    }
