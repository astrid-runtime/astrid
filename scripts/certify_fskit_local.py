#!/usr/bin/env python3
"""Test released bytes on a supervised Mac without installing/removing an app.

The operator must first install and enable the archive's signed app. This script
only starts its own disposable runtime and never kills foreign processes. Logs
and the receipt are retained under a short temporary directory on failure too.
"""

import argparse
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import stat
import subprocess
import tarfile
import tempfile

from supervised_fskit import CHECKS, RUNNER_FILES, TARGET, manifest, sha256


def verify_runner_source(source_commit, script=None):
    """Reject copied or edited runners rather than attesting a different test."""
    script = Path(script or __file__).resolve()
    root = script.parent.parent
    if script.name != "certify_fskit_local.py" or script.parent.name != "scripts":
        raise ValueError("certification must use scripts/certify_fskit_local.py")
    if not re.fullmatch(r"[0-9a-f]{40}", source_commit):
        raise ValueError("invalid certification source commit")
    head = subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
    if head != source_commit:
        raise ValueError("certification checkout differs from release source")
    for name in RUNNER_FILES:
        expected = subprocess.check_output(
            ["git", "-C", str(root), "show", f"{source_commit}:scripts/{name}"])
        if (script.parent / name).read_bytes() != expected:
            raise ValueError(f"certification script differs from release source: {name}")


def write_receipt(root, expected, checks):
    """Only the unchanged canonical runner with every check complete emits PASS."""
    verify_runner_source(expected["source_commit"])
    actual = {name: sha256(Path(__file__).resolve().parent / name) for name in RUNNER_FILES}
    if actual != expected.get("runner_sha256"):
        raise ValueError("runner differs from release-run manifest")
    if set(checks) != CHECKS or not all(value is True for value in checks.values()):
        raise ValueError("incomplete certification; no PASS receipt")
    receipt = dict(expected, result="PASS", checks=checks)
    (root / "receipt.json").write_text(json.dumps(receipt, sort_keys=True) + "\n")
    print(json.dumps(receipt, sort_keys=True))


def run_logged(command, env, log_path, timeout=90):
    """Wait for the command, not pipe EOF held open by a detached daemon."""
    with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as output:
        try:
            result = subprocess.run(command, env=env, text=True, stdout=output,
                                    stderr=subprocess.STDOUT, timeout=timeout, check=False)
        except subprocess.TimeoutExpired:
            output.seek(0)
            with log_path.open("a") as log:
                log.write(f"command={command!r}\ntimeout={timeout}\n{output.read()}\n")
            raise
        output.seek(0)
        text = output.read()
    with log_path.open("a") as log:
        log.write(f"command={command!r}\nexit={result.returncode}\n{text}\n")
    if result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {command}; see {log_path}")
    return text


def prepare_directories(root):
    home, mount = root / "home", root / "mount"
    home.mkdir(mode=0o700)
    mount.mkdir(mode=0o700)
    return home, mount


def is_astridfs(mount, mount_table):
    """Bind macOS mount output to the exact canonical mount, not a sibling."""
    expected = str(mount.resolve())
    for line in mount_table.splitlines():
        match = re.fullmatch(r".+ on (.+) \(([^, )]+)(?:, [^\n]*)?\)", line)
        if match and match[1] == expected and match[2] == "astridfs":
            return True
    return False


def inventory(root):
    result = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError(f"redirected app member: {path}")
        relative = str(path.relative_to(root))
        if path.is_file():
            result[relative] = (stat.S_IMODE(path.stat().st_mode), sha256(path))
        elif path.is_dir():
            result[relative] = ("directory",)
        else:
            raise ValueError(f"special app member: {path}")
    if not result:
        raise ValueError("empty app inventory")
    return result


def unpack(archive, destination):
    root_name = archive.name.removesuffix(".tar.gz")
    with tarfile.open(archive, "r:gz") as stream:
        members = stream.getmembers()
        if len(members) > 20000 or sum(member.size for member in members) > 2 * 1024**3:
            raise ValueError("archive exceeds member/size limit")
        seen = set()
        for member in members:
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or not path.parts or path.parts[0] != root_name:
                raise ValueError("archive member escapes expected root")
            if path in seen or not (member.isfile() or member.isdir()):
                raise ValueError("duplicate, redirected or special archive member")
            seen.add(path)
        stream.extractall(destination, filter="data")
    return destination / root_name


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--app", type=Path, default=Path("/Applications/AstridFS.app"))
    args = parser.parse_args()
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        parser.error("this certification covers an Apple Silicon macOS host")
    expected = json.loads(args.manifest.read_text())
    verify_runner_source(expected["source_commit"])
    archive = args.archive.absolute()
    # Hash the selected archive, not a filename inferred from some other tree.
    actual = manifest(archive.parent, expected["source_commit"], expected["run_id"], expected["run_attempt"])
    if actual != expected or actual["archive"] != archive.name or actual["target"] != TARGET:
        raise ValueError("archive differs from the release-run manifest")
    if args.app.is_symlink() or not args.app.is_dir():
        raise ValueError("installed app must be a real directory")
    root = Path(tempfile.mkdtemp(prefix="fsc.", dir="/tmp")).resolve()
    print(f"Evidence directory: {root}", flush=True)
    stage = unpack(archive, root / "release")
    if inventory(stage / "AstridFS.app") != inventory(args.app):
        raise ValueError("installed app differs from archive; no runtime started or app changed")
    home, mount = prepare_directories(root)
    env = {key: value for key, value in os.environ.items() if not key.startswith("ASTRID_")}
    env.update(ASTRID_HOME=str(home), ASTRID_FSKIT_APP_DEST=str(args.app.absolute()),
               ASTRID_FSKIT_BIN_DIR=str(stage), PATH=f"{stage}:{env.get('PATH', '')}")
    version = archive.name.removeprefix("astrid-").removesuffix(f"-{TARGET}.tar.gz")
    env["ASTRID_FSKIT_EXPECTED_VERSION"] = version
    checks = {key: False for key in CHECKS}
    checks["installed_app_bytes"] = True
    binary = str(stage / "astrid")

    def run(*command):
        return run_logged(command, env, root / "commands.log")

    def cli(*command):
        return run(binary, "--principal", "default", *command)

    def status(dirty):
        output = cli("storage", "status", str(mount))
        if f"dirty={str(dirty).lower()}" not in output or "ReadWrite" not in output:
            raise ValueError(f"unexpected mount status: {output}")

    run("/bin/bash", str(stage / "macos/validate-macos-fskit.sh"), str(stage / "AstridFS.app"))
    checks["apple_trust"] = True
    for command in ("validate", "status", "check-process"):
        run("/bin/bash", str(stage / "macos/manage-macos-fskit.sh"), command)
    checks["provider_identity"] = True
    started = False
    try:
        # Own this disposable home even if a partially successful start fails.
        started = True
        cli("start")
        cli("storage", "mount", "--as", "default", str(mount))
        if not is_astridfs(mount, run("/sbin/mount")):
            raise ValueError("mount is not astridfs")
        status(False)
        checks["mount"] = True
        (mount / "probe.txt").write_text("supervised FSKit round trip\n")
        (mount / "probe.txt").rename(mount / "renamed.txt")
        if (mount / "renamed.txt").read_text() != "supervised FSKit round trip\n":
            raise ValueError("mounted read differs from write")
        status(True)
        checks["write_rename_read"] = True
        cli("storage", "sync", str(mount))
        status(False)
        checks["sync"] = True
        (mount / "renamed.txt").unlink()
        cli("storage", "sync", str(mount))
        status(False)
        checks["delete_sync"] = True
        cli("storage", "unmount", str(mount))
        if is_astridfs(mount, run("/sbin/mount")):
            raise ValueError("filesystem remained mounted")
        checks["unmount"] = True
        cli("stop")
        started = False
        if {path.name for path in home.iterdir()} != {"astrid.volume"}:
            raise ValueError("stopped runtime is not exactly astrid.volume")
        checks["stop"] = True
    finally:
        if started:
            # Only this script's mount and runtime; never pkill or remove app.
            try:
                if is_astridfs(mount, run("/sbin/mount")):
                    cli("storage", "unmount", str(mount))
            finally:
                cli("stop")
        (root / "checks.json").write_text(json.dumps(checks, sort_keys=True))
    if inventory(stage / "AstridFS.app") != inventory(args.app):
        raise ValueError("installed app changed during certification")
    if manifest(archive.parent, expected["source_commit"], expected["run_id"], expected["run_attempt"]) != expected:
        raise ValueError("archive changed during certification")
    write_receipt(root, expected, checks)


if __name__ == "__main__":
    main()
