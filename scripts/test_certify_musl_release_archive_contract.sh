#!/usr/bin/env bash

set -euo pipefail

python3 - "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" <<'PY'
from __future__ import annotations

import pathlib
import re
import subprocess
import sys
import tarfile
import tempfile


repo = pathlib.Path(sys.argv[1])
workflow_path = repo / ".github/workflows/release.yml"
script_path = repo / "scripts/certify_musl_release_archive.sh"
workflow = workflow_path.read_text(encoding="utf-8")
script = script_path.read_text(encoding="utf-8")


def fail(message: str) -> None:
    raise SystemExit(f"musl certification contract: {message}")


if len(workflow.splitlines()) > 1000:
    fail("release.yml exceeds its 1000-line ceiling")
for value in ("prepare_set:", "default: darwin", "type: choice", "- darwin", "- musl"):
    if value not in workflow:
        fail(f"workflow is missing prepare_set {value}")
if "PREPARE_SET = os.environ.get(" not in (repo / "scripts/classify_release_build_matrix.py").read_text():
    fail("classifier does not read PREPARE_SET from the environment")

marker = "\n  musl-certification:\n"
start = workflow.find(marker)
if start < 0:
    fail("missing musl-certification job")
start += 1
next_job = re.search(r"^  [A-Za-z0-9_-]+:\n", workflow[start + len(marker) - 1:], flags=re.MULTILINE)
cert = workflow[start:start + len(marker) - 1 + (next_job.start() if next_job else 0)]
if "if: ${{ inputs.prepare_only == true && inputs.prepare_set == 'musl' }}" not in cert:
    fail("musl certification is not confined to musl prepare-only runs")
if "ubuntu-latest" not in cert or "ubuntu-24.04-arm" not in cert:
    fail("certification runners do not match both musl triples")
for architecture, runner, target in (
    ("x86_64", "ubuntu-latest", "x86_64-unknown-linux-musl"),
    ("aarch64", "ubuntu-24.04-arm", "aarch64-unknown-linux-musl"),
):
    line = re.search(
        rf"architecture: {architecture}, target: {target}, runs-on: {runner}",
        cert,
    )
    if line is None:
        fail(f"certification matrix does not pair {architecture} with {runner}")
if "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c" not in cert:
    fail("certification does not use the pinned artifact action")
if not re.search(r"name: '?binary-\$\{\{ matrix\.target \}\}'?", cert):
    fail("certification does not download by its same-run artifact name")
if re.search(r"artifact-ids|run-id", cert, flags=re.IGNORECASE):
    fail("certification must not consume a cross-run artifact")
for forbidden in ("cargo", "rust-toolchain", "CARGO_TARGET_DIR"):
    if forbidden.casefold() in cert.casefold():
        fail(f"certification job contains forbidden build input {forbidden}")
if "actions/checkout@" not in cert or "source-commit" not in cert:
    fail("certification does not check out the classified source")
for fragment in (
    "apt-get install -y --no-install-recommends fuse3",
    "modprobe fuse",
    "[[ -c /dev/fuse ]]",
    "command -v fusermount3",
    "chmod 0666 /dev/fuse",
):
    if fragment not in cert:
        fail(f"FUSE substrate setup is missing {fragment}")
if "certify_musl_release_archive.sh" not in cert:
    fail("certification does not invoke the named executable")

for fragment in (
    "stage-before-extract",  # represented below by ordering assertions
    "tarfile.open",
    "hashlib.sha256",
    "def blake3_bytes",
    "ASTRID_HOME=",
    "--principal default start",
    "--principal default status",
    "storage mount",
    "--read-write",
    "storage sync",
    "storage status",
    "storage unmount",
    "--principal default stop",
    "system.sock",
    "system.token",
    "system.ready",
    "system.pid",
    "trap cleanup EXIT",
    "scripts/check_static_elf.py",
):
    if fragment in ("stage-before-extract",):
        if script.find("tarfile.open") > script.find("destination.write_bytes"):
            fail("archive members are extracted before staged digest verification")
        continue
    if fragment not in script:
        fail(f"cert executable is missing {fragment}")
if re.search(r"\btar\s+-x\b", script):
    fail("cert executable must stage members explicitly, not extract the archive wholesale")
for forbidden in ("apple", "windows", "fskit"):
    if forbidden not in script:
        fail(f"cert executable does not reject {forbidden} companions")

def archive_fixture(root: pathlib.Path, redirect: bool) -> pathlib.Path:
    target = "x86_64-unknown-linux-musl"
    release = root / f"astrid-2026.9.0-{target}"
    release.mkdir()
    binaries = (
        "astrid", "astrid-daemon", "astrid-build", "astrid-emit",
        "astrid-storage-provider-fuse",
    )
    for name in binaries:
        path = release / name
        path.write_bytes(f"#!/bin/sh\necho astrid 2026.9.0-{name}\n".encode())
        path.chmod(0o700)
    (release / "README.md").write_text("fixture\n", encoding="utf-8")
    (release / "LICENSE-APACHE").write_text("fixture\n", encoding="utf-8")
    archive = root / f"astrid-2026.9.0-{target}.tar.gz"
    with tarfile.open(archive, "w:gz") as output:
        output.add(release, arcname=release.name)
    if not redirect:
        with tarfile.open(archive, "w:gz") as output:
            output.add(release, arcname=release.name)
        return archive
    source_archive = root / f"astrid-2026.9.0-{target}.tar.gz"
    archive = root / f"astrid-redirect-{target}.tar.gz"
    with tarfile.open(source_archive, "r:gz") as source, tarfile.open(archive, "w:gz") as output:
        for member in source.getmembers():
            if member.name.endswith("/astrid-daemon"):
                member.type = tarfile.SYMTYPE
                member.linkname = "/etc/passwd"
                output.addfile(member)
            else:
                output.addfile(member, source.extractfile(member))
    return archive


with tempfile.TemporaryDirectory() as temporary:
    root = pathlib.Path(temporary)
    archive_fixture(root, redirect=False)
    result = subprocess.run(
        [str(script_path), "--architecture", "x86_64", "--target",
         "x86_64-unknown-linux-musl", "--artifact-dir", str(root),
         "--expected-version", "2026.9.0", "--stage-only"],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if result.returncode != 0 or "staging certification: PASS" not in result.stdout:
        fail(f"regular archive staging failed: {result.stdout}{result.stderr}")

with tempfile.TemporaryDirectory() as temporary:
    root = pathlib.Path(temporary)
    archive_fixture(root, redirect=True)
    result = subprocess.run(
        [str(script_path), "--architecture", "x86_64", "--target",
         "x86_64-unknown-linux-musl", "--artifact-dir", str(root),
         "--expected-version", "2026.9.0", "--stage-only"],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if result.returncode == 0:
        fail("redirecting archive member unexpectedly passed staging")

print("musl packaged archive certification contract: PASS")
PY
