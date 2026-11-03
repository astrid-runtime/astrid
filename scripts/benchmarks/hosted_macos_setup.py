#!/usr/bin/env python3
"""Disable Spotlight only for disposable hosted matched-benchmark jobs.

This is runner preparation, never a performance sample or proof of quiet.
The existing before/after CPU admission gates remain authoritative.
"""
import datetime
import json
import os
from pathlib import Path
import platform
import subprocess
import time


DISABLE = ["/usr/bin/sudo", "-n", "/usr/bin/mdutil", "-i", "off", "/"]
STATUS = ["/usr/bin/mdutil", "-s", "/"]


def validate_context():
    expected = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted",
                "RUNNER_OS": "macOS", "GITHUB_REPOSITORY": "astrid-runtime/astrid"}
    if any(os.environ.get(key) != value for key, value in expected.items()):
        raise RuntimeError("disposable GitHub-hosted Astrid macOS job required")
    job = os.environ.get("GITHUB_JOB")
    if job not in {"matched-packing", "matched-native250"} or platform.system() != "Darwin":
        raise RuntimeError("native macOS matched benchmark job required")
    workspace = Path(os.environ.get("GITHUB_WORKSPACE", ""))
    root = workspace / "astrid-benchmark.noindex"
    source = Path(__file__).absolute()
    expected_source = root / "protocol/scripts/benchmarks/hosted_macos_setup.py"
    if not workspace.is_absolute() or source != expected_source:
        raise RuntimeError("setup must run from the owned protocol checkout")
    for path in (workspace, root, root / "protocol", source):
        if path.absolute() != path.resolve(strict=True) or path.stat().st_uid != os.getuid():
            raise RuntimeError("nonaliased owned workspace, namespace and protocol required")
    if not root.is_dir() or root.stat().st_mode & 0o777 != 0o700 or not source.is_file():
        raise RuntimeError("private existing .noindex namespace and protocol source required")
    return root, {**expected, "GITHUB_JOB": job, "GITHUB_WORKSPACE": str(workspace)}


def prepare():
    root, context = validate_context()  # No commands or writes before authorization checks.
    receipt = {"context": context, "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
               "platform": {"system": platform.system(), "release": platform.release(),
                            "machine": platform.machine()},
               "commands": [], "complete": False, "proves_quiet": False}
    # Exclusive creation also rejects a pre-existing file or symlink; never overwrite evidence.
    with (root / "host-indexing-setup.json").open("x", encoding="utf-8") as output:
        started = time.monotonic()
        try:
            for command in (DISABLE, STATUS):
                entry = {"argv": command, "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat()}
                receipt["commands"].append(entry)
                command_started = time.monotonic()
                try:
                    result = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
                    entry.update(returncode=result.returncode, stdout=result.stdout, stderr=result.stderr)
                finally:
                    entry["elapsed_seconds"] = time.monotonic() - command_started
                if result.returncode != 0:
                    raise RuntimeError(f"runner preparation command failed: {command}")
            if [line.strip() for line in result.stdout.splitlines() if line.strip()] != ["/:", "Indexing disabled."]:
                raise RuntimeError("Spotlight status did not confirm indexing disabled on /")
            receipt["complete"] = True
        except Exception as error:
            receipt["error"] = f"{type(error).__name__}: {error}"
            raise
        finally:
            receipt["elapsed_seconds"] = time.monotonic() - started
            receipt["finished_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            json.dump(receipt, output, indent=2)
            output.write("\n")


if __name__ == "__main__":
    prepare()
