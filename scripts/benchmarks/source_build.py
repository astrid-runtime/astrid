"""Owned Cargo target preparation for disposable GitHub-hosted matched builds.

Prevents a shared evidence ``cargo-target`` from reusing another checkout's
workspace artifacts when source mtimes predate the first compile. Only the
explicitly owned target is cleaned; host Cargo/rustup caches and default
targets stay untouched. Callers keep the original build deadline and append
the same compile log the public publisher already captures.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import time
import tomllib
from typing import Any
from urllib.parse import unquote, urlparse


def require(condition: Any, detail: str) -> None:
    if not condition:
        raise RuntimeError(detail)


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _refuse_symlink_ancestors(path: Path) -> Path:
    absolute = path if path.is_absolute() else path.absolute()
    cursor = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        cursor = cursor / part
        if cursor.is_symlink():
            raise RuntimeError(f"refusing symlink ancestor: {cursor}")
    # This is a static check within an exclusively owned CI workspace, not
    # protection from a malicious process replacing paths during Cargo execution.
    return absolute.resolve()


def _host_cache_roots(env: dict[str, str], checkout: Path) -> list[Path]:
    # Cargo resolves HOME from its own environment, and relative cache-home
    # overrides from its cwd. Never expand '~' using the observer's HOME.
    child_home = Path(env.get("HOME", ""))
    require(child_home.is_absolute(), "child HOME must be an explicit absolute path")
    homes = {Path.home().resolve(), child_home.resolve()}
    roots = [home / suffix for home in homes
             for suffix in (".cargo", ".rustup", ".cache", "Library/Caches")]
    for name in ("CARGO_HOME", "RUSTUP_HOME"):
        if name in env:
            require(bool(env[name]), f"{name} must not be empty")
            value = Path(env[name])
            roots.append(value if value.is_absolute() else checkout / value)
    return [root.resolve() for root in roots]


def _validate_owned_target(
    checkout: Path,
    target: Path,
    env: dict[str, str],
) -> tuple[Path, Path, Path]:
    require(
        os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted",
        "disposable GitHub-hosted runner required",
    )
    workspace = os.environ.get("GITHUB_WORKSPACE")
    require(isinstance(workspace, str) and workspace.strip(), "GITHUB_WORKSPACE required")
    workspace_root = _refuse_symlink_ancestors(Path(workspace))
    require(workspace_root.is_dir(), f"GITHUB_WORKSPACE is not a directory: {workspace_root}")

    checkout_root = _refuse_symlink_ancestors(checkout)
    require(checkout_root.is_dir(), f"checkout is not a directory: {checkout_root}")
    require(
        _is_relative_to(checkout_root, workspace_root),
        "checkout must remain under GITHUB_WORKSPACE",
    )

    target_path = target if target.is_absolute() else target.absolute()
    require(target_path.name == "cargo-target", "owned target must be named cargo-target")
    if target_path.is_symlink() or target_path.exists():
        require(not target_path.is_symlink() and target_path.is_dir(),
                f"owned target must be a regular directory: {target_path}")
    target_root = _refuse_symlink_ancestors(target_path)
    require(
        _is_relative_to(target_root, workspace_root),
        "owned target must remain under GITHUB_WORKSPACE",
    )
    require(
        not _is_relative_to(target_root, checkout_root)
        and not _is_relative_to(checkout_root, target_root),
        "owned target must stay outside the producer checkout",
    )
    for cache_root in _host_cache_roots(env, checkout_root):
        require(
            not _is_relative_to(target_root, cache_root)
            and not _is_relative_to(cache_root, target_root),
            f"owned target must stay outside host cache/rustup home: {cache_root}",
        )
    if "CARGO_TARGET_DIR" in env:
        existing = Path(env["CARGO_TARGET_DIR"])
        existing = existing if existing.is_absolute() else existing.absolute()
        require(
            existing.resolve() == target_root,
            "CARGO_TARGET_DIR must match the owned cargo-target",
        )
    return workspace_root, checkout_root, target_root


def _run_owned(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    log: Path,
    deadline: float,
    label: str,
) -> tuple[int, str]:
    budget = deadline - time.monotonic()
    require(budget > 0, f"run budget exhausted before {label}")
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=budget)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        stdout, stderr = process.communicate()
        with log.open("a", encoding="utf-8") as stream:
            if stdout:
                stream.write(stdout)
                if not stdout.endswith("\n"):
                    stream.write("\n")
            if stderr:
                stream.write(stderr)
                if not stderr.endswith("\n"):
                    stream.write("\n")
            stream.write(
                json.dumps(
                    {
                        "reason": "source-build-timeout",
                        "label": label,
                        "command": command,
                    }
                )
                + "\n"
            )
        raise
    require(process.returncode is not None, f"{label} exited without a return code")
    code = process.returncode
    with log.open("a", encoding="utf-8") as stream:
        if stdout:
            stream.write(stdout)
            if not stdout.endswith("\n"):
                stream.write("\n")
        if stderr:
            stream.write(stderr)
            if not stderr.endswith("\n"):
                stream.write("\n")
        stream.write(
            json.dumps(
                {
                    "reason": f"source-build-{label}",
                    "command": command,
                    "exit": code,
                    "stderr_bytes": len(stderr.encode()) if stderr else 0,
                }
            )
            + "\n"
        )
    return code, stdout or ""


def _workspace_packages(metadata: dict[str, Any], checkout: Path) -> list[dict[str, str]]:
    require(isinstance(metadata, dict), "cargo metadata must be an object")
    workspace_root = Path(str(metadata.get("workspace_root", "")))
    require(workspace_root.is_absolute(), "cargo metadata missing workspace_root")
    require(
        workspace_root.resolve() == checkout.resolve(),
        "cargo metadata workspace_root must match checkout",
    )
    members = metadata.get("workspace_members")
    packages = metadata.get("packages")
    require(isinstance(members, list) and members, "cargo metadata missing workspace_members")
    require(isinstance(packages, list) and packages, "cargo metadata missing packages")
    member_ids = set(members)
    require(len(member_ids) == len(members), "duplicate workspace member ids")

    selected: list[dict[str, str]] = []
    seen_names: set[str] = set()
    seen_ids: set[str] = set()
    for package in packages:
        require(isinstance(package, dict), "cargo metadata package must be an object")
        package_id = package.get("id")
        if package_id not in member_ids:
            continue
        name = package.get("name")
        manifest = package.get("manifest_path")
        require(isinstance(package_id, str) and package_id, "workspace package missing id")
        require(isinstance(name, str) and name, "workspace package missing name")
        require(isinstance(manifest, str) and manifest, "workspace package missing manifest_path")
        manifest_path = Path(manifest)
        require(manifest_path.is_absolute(), f"manifest path must be absolute: {manifest}")
        require(
            not manifest_path.is_symlink()
            and manifest_path.exists()
            and manifest_path.is_file(),
            f"workspace manifest missing or redirected: {manifest_path}",
        )
        resolved_manifest = _refuse_symlink_ancestors(manifest_path)
        require(
            _is_relative_to(resolved_manifest, checkout.resolve()),
            f"workspace manifest escapes checkout: {resolved_manifest}",
        )
        require(package_id not in seen_ids, f"duplicate workspace package id: {package_id}")
        require(name not in seen_names, f"duplicate workspace package name: {name}")
        seen_ids.add(package_id)
        seen_names.add(name)
        selected.append(
            {
                "id": package_id,
                "name": name,
                "manifest_path": str(resolved_manifest),
            }
        )
    require(seen_ids == member_ids, "workspace member inventory incomplete")
    require(selected, "no workspace packages discovered")
    selected.sort(key=lambda row: (row["name"], row["id"]))
    return selected


def _validate_clean_names(packages: list[dict[str, str]], checkout: Path) -> str:
    # Cargo 1.95 clean ignores package URL/version qualifiers. Prove each name
    # is unique across the locked dependency graph before using that interface.
    lock = checkout / "Cargo.lock"
    raw = lock.read_bytes()
    graph = tomllib.loads(raw.decode())
    locked = graph.get("package", [])
    for package in packages:
        matches = [row for row in locked if row.get("name") == package["name"]]
        require(len(matches) == 1 and "source" not in matches[0],
                f"workspace clean name is not unique and local in Cargo.lock: {package['name']}")
    return hashlib.sha256(raw).hexdigest()


def _path_from_package_id(package_id: str) -> Path | None:
    if not isinstance(package_id, str) or not package_id.startswith("path+file://"):
        return None
    # Cargo ids look like path+file:///abs/path#name@version
    body = package_id[len("path+") :]
    parsed = urlparse(body.split("#", 1)[0])
    if parsed.scheme != "file":
        return None
    path = Path(unquote(parsed.path))
    if not path.is_absolute():
        return None
    return path


def _event_source_path(event: dict[str, Any]) -> Path | None:
    target = event.get("target")
    if not isinstance(target, dict):
        return None
    src = target.get("src_path")
    if not isinstance(src, str) or not src:
        return None
    path = Path(src)
    return path if path.is_absolute() else None


def prepare(
    checkout: Path,
    target: Path,
    log: Path,
    env: dict[str, str],
    deadline: float,
) -> dict[str, Any]:
    """Clean only local workspace artifacts from an owned disposable target."""
    require(isinstance(env, dict), "build env must be a dict")
    require(all(isinstance(key, str) and isinstance(value, str) for key, value in env.items()),
            "build env must be str:str")
    require(isinstance(deadline, (int, float)), "deadline must be monotonic seconds")
    workspace_root, checkout_root, target_root = _validate_owned_target(checkout, target, env)
    log_path = log if log.is_absolute() else log.absolute()
    require(log_path.name, "compile log path required")
    require(
        not log_path.is_symlink()
        and (not log_path.exists() or log_path.is_file()),
        f"compile log must be a regular file: {log_path}",
    )
    log_path.parent.mkdir(parents=True, exist_ok=True)

    env["CARGO_TARGET_DIR"] = str(target_root)
    metadata_command = [
        "cargo",
        "metadata",
        "--locked",
        "--no-deps",
        "--format-version",
        "1",
    ]
    metadata_exit, metadata_text = _run_owned(
        metadata_command,
        cwd=checkout_root,
        env=env,
        log=log_path,
        deadline=deadline,
        label="metadata",
    )
    require(metadata_exit == 0, f"cargo metadata failed: {metadata_exit}")
    metadata_text = metadata_text.strip()
    require(metadata_text, "cargo metadata returned empty stdout")
    try:
        metadata = json.loads(metadata_text)
    except ValueError as error:
        raise RuntimeError(
            "cargo metadata stdout must be a single JSON object; warnings belong on stderr"
        ) from error
    packages = _workspace_packages(metadata, checkout_root)
    metadata_sha256 = hashlib.sha256(metadata_text.encode()).hexdigest()
    lock_sha256 = _validate_clean_names(packages, checkout_root)

    clean_command = [
        "cargo",
        "clean",
        "--release",
        "--target-dir",
        str(target_root),
    ]
    for package in packages:
        clean_command.extend(["-p", package["name"]])
    clean_exit, _ = _run_owned(
        clean_command,
        cwd=checkout_root,
        env=env,
        log=log_path,
        deadline=deadline,
        label="clean",
    )
    require(clean_exit == 0, f"cargo clean failed: {clean_exit}")

    return {
        "workspace": str(workspace_root),
        "checkout": str(checkout_root),
        "target": str(target_root),
        "log": str(log_path),
        "packages": packages,
        "package_ids": [package["id"] for package in packages],
        "package_names": [package["name"] for package in packages],
        "metadata_command": metadata_command,
        "metadata_exit": metadata_exit,
        "metadata_sha256": metadata_sha256,
        "lock_sha256": lock_sha256,
        "clean_selection": "Cargo1.95 name-scoped clean; names proven unique and local across locked graph",
        "clean_command": clean_command,
        "clean_exit": clean_exit,
        "provenance": (
            "cargo metadata --locked --no-deps selects unique workspace packages whose "
            "manifests resolve under the producer checkout; cargo clean --release "
            "--target-dir <owned cargo-target> -p <each> removes only those local "
            "artifact/fingerprint outputs while preserving registry dependencies"
        ),
    }


def verify_artifact(event: dict[str, Any], checkout: Path, receipt: dict[str, Any]) -> None:
    """Require cleaned local workspace artifacts to recompile; reject inventory gaps.

    Binary-hash inequality alone is never used: distinct source can still emit
    identical optimized bytes, which is exactly why ``fresh`` is the authority.
    """
    require(isinstance(event, dict), "compiler-artifact event must be an object")
    require(event.get("reason") == "compiler-artifact", "verify_artifact requires compiler-artifact")
    require(isinstance(receipt, dict), "source-build receipt must be an object")
    checkout_root = Path(receipt.get("checkout", ""))
    require(checkout_root.is_absolute(), "source-build receipt missing checkout")
    require(
        checkout_root.resolve() == _refuse_symlink_ancestors(checkout),
        "verify_artifact checkout does not match prepare receipt",
    )
    package_ids = receipt.get("package_ids")
    require(isinstance(package_ids, list) and package_ids, "source-build receipt missing package_ids")
    package_id_set = set(package_ids)
    require(len(package_id_set) == len(package_ids), "source-build receipt has duplicate package_ids")

    package_id = event.get("package_id")
    require(isinstance(package_id, str) and package_id, "compiler-artifact missing package_id")
    source = _event_source_path(event)
    package_path = _path_from_package_id(package_id)
    local = package_id in package_id_set
    under_checkout = False
    for candidate in (package_path, source):
        if candidate is None:
            continue
        try:
            resolved = candidate.resolve()
        except OSError as error:
            raise RuntimeError(f"compiler-artifact path is not resolvable: {candidate}") from error
        if _is_relative_to(resolved, checkout_root.resolve()):
            under_checkout = True
            break

    if local:
        require(
            event.get("fresh") is False,
            "local workspace compiler-artifact must rebuild after owned target clean "
            f"(fresh={event.get('fresh')!r}, package_id={package_id})",
        )
        return

    if under_checkout:
        raise RuntimeError(
            "unlisted local package manifest under checkout: "
            f"package_id={package_id}"
        )
