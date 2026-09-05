#!/usr/bin/env bash
set -euo pipefail

python3 - "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" <<'PY'
from __future__ import annotations

import pathlib
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import uuid


repo = pathlib.Path(sys.argv[1])
workflow_path = repo / ".github/workflows/release.yml"
script_path = repo / "scripts/certify_musl_release_archive.sh"
workflow = workflow_path.read_text(encoding="utf-8")
script = script_path.read_text(encoding="utf-8")
setup_path = repo / "scripts/ci/setup_musl_certification.sh"
setup = setup_path.read_text(encoding="utf-8")
if not setup_path.stat().st_mode & stat.S_IXUSR:
    fail("shared certification setup is not executable")


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
    if not re.search(rf"architecture: {architecture}, target: {target}, runs-on: {runner}", cert):
        fail(f"certification matrix does not pair {architecture} with {runner}")
if "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c" not in cert:
    fail("certification does not use the pinned artifact action")
if not re.search(r"name: '?binary-\$\{\{ matrix\.target \}\}'?", cert):
    fail("certification does not download by its same-run artifact name")
if re.search(r"artifact-ids|run-id", cert, flags=re.IGNORECASE):
    fail("certification must not consume a cross-run artifact")
if "dtolnay/rust-toolchain@29eef336d9b2848a0b548edc03f92a220660cdb8" not in cert:
    fail("musl certification does not use the pinned release toolchain action")
if 'toolchain: "1.95.0"' not in cert:
    fail("musl certification does not pin Rust 1.95.0")
if "scripts/ci/setup_musl_certification.sh" not in cert:
    fail("musl certification does not use the shared certification setup")
for forbidden in ("cargo build", "cargo check", "cargo test", "-p astrid", "CARGO_TARGET_DIR"):
    if forbidden.casefold() in cert.casefold():
        fail(f"certification job contains forbidden product-build input {forbidden}")
if "actions/checkout@" not in cert or "source-commit" not in cert:
    fail("certification does not check out the classified source")
for fragment in (
    "apt-get install -y --no-install-recommends fuse3",
    "modprobe fuse",
    "[[ -c /dev/fuse ]]",
    "command -v fusermount3",
    "chmod 0666 /dev/fuse",
    'B3SUM_REQUIRED_VERSION="1.8.5"',
    "cargo install b3sum --version 1.8.5 --locked",
):
    if fragment not in setup:
        fail(f"shared certification setup is missing {fragment}")
if "certify_musl_release_archive.sh" not in cert:
    fail("certification does not invoke the named executable")

for fragment in (
    'B3SUM_REQUIRED_VERSION="1.8.5"',
    "command -v sha256sum",
    "command -v b3sum",
    '"$b3sum_bin" --version',
    '[[ "$b3sum_version" == "b3sum ${B3SUM_REQUIRED_VERSION}" ]]',
    "EXPECTED_EMPTY_BLAKE3=",
    "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
    'printf \'\' | "$b3sum_bin" --no-names',
    "sha256_digest",
    "b3sum_digest",
    "tarfile.open",
    "ASTRID_HOME=",
    "/usr/bin/uuidgen",
    "uuid.UUID",
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
    if fragment not in script:
        fail(f"cert executable is missing {fragment}")
if script.find("tarfile.open") > script.find('cp "$artifact_path" "$staged_path"'):
    fail("archive members are not safely staged before packaged-byte verification")
if re.search(r"\btar\s+-x\b", script):
    fail("cert executable must stage members explicitly, not extract the archive wholesale")
for forbidden in ("class " + "Blake3", "blake3" + "_bytes", "hashlib", "import hashlib"):
    if forbidden in script:
        fail(f"homemade or Python hashing remains in cert executable: {forbidden}")
if "sha256sum_bin=$(command -v sha256sum)" not in script:
    fail("system sha256sum is not the production digest authority")
if '"request_id": "musl-release-certification"' in script:
    fail("literal non-UUID request_id remains")
if "os.environ[\"REQUEST_ID\"]" not in script and "os.environ['REQUEST_ID']" not in script:
    fail("provider request_id is not taken from generated UUID environment")
try:
    uuid.UUID("musl-release-certification")
except ValueError:
    pass
else:
    fail("uuid decoder unexpectedly accepted the failed-run request_id literal")
generated = subprocess.run(
    ["/usr/bin/uuidgen"],
    check=True,
    text=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
).stdout.strip()
uuid.UUID(generated)
for rejected in ("apple", "windows", "fskit"):
    if rejected not in script:
        fail(f"cert executable does not reject {rejected} companions")


def archive_fixture(root: pathlib.Path, redirect: bool) -> pathlib.Path:
    target = "x86_64-unknown-linux-musl"
    release = root / f"astrid-2026.9.0-{target}"
    release.mkdir()
    binaries = (
        "astrid",
        "astrid-daemon",
        "astrid-build",
        "astrid-emit",
        "astrid-storage-provider-fuse",
    )
    for name in binaries:
        path = release / name
        path.write_bytes(f"#!/bin/sh\necho astrid 2026.9.0-{name}\n".encode())
        path.chmod(0o700)
    (release / "README.md").write_text("fixture\n", encoding="utf-8")
    (release / "LICENSE-APACHE").write_text("fixture\n", encoding="utf-8")
    source_archive = root / f"astrid-2026.9.0-{target}.tar.gz"
    with tarfile.open(source_archive, "w:gz") as output:
        output.add(release, arcname=release.name)
    if not redirect:
        return source_archive
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


def run_stage(root: pathlib.Path, archive: pathlib.Path, env: dict[str, str] | None = None):
    environment = {**os_environ(), **(env or {})}
    injected_path = (env or {}).get("PATH")
    certification_path = f"{b3sum_bin_dir}:{environment['PATH']}"
    environment["PATH"] = certification_path if not injected_path else f"{injected_path}:{certification_path}"
    return subprocess.run(
        [
            str(script_path), "--architecture", "x86_64", "--target",
            "x86_64-unknown-linux-musl", "--artifact-dir", str(root),
            "--expected-version", "2026.9.0", "--stage-only",
        ],
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def os_environ() -> dict[str, str]:
    import os

    return dict(os.environ)


provision = subprocess.run(
    [str(setup_path), "--b3sum-only"],
    env={name: value for name, value in os_environ().items() if name != "GITHUB_PATH"},
    text=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
)
if provision.returncode != 0:
    fail(f"pinned b3sum setup failed: {provision.stdout}{provision.stderr}")
b3sum_bin_dir = provision.stdout.strip()
if not b3sum_bin_dir or not pathlib.Path(b3sum_bin_dir, "b3sum").is_file():
    fail("pinned b3sum setup did not provide a binary directory")

with tempfile.TemporaryDirectory() as temporary:
    root = pathlib.Path(temporary)
    archive = archive_fixture(root, redirect=False)
    result = run_stage(root, archive)
    if result.returncode != 0 or "staging certification: PASS" not in result.stdout:
        fail(f"regular archive staging failed: {result.stdout}{result.stderr}")

with tempfile.TemporaryDirectory() as temporary:
    root = pathlib.Path(temporary)
    archive = archive_fixture(root, redirect=True)
    result = run_stage(root, archive)
    if result.returncode == 0:
        fail("redirecting archive member unexpectedly passed staging")

with tempfile.TemporaryDirectory() as temporary:
    wrapper_root = pathlib.Path(temporary) / "unpinned-b3sum"
    wrapper_root.mkdir()
    wrapper = wrapper_root / "b3sum"
    wrapper.write_text("#!/bin/sh\nprintf 'b3sum 1.8.4\\n'\n", encoding="utf-8")
    wrapper.chmod(0o700)
    root = pathlib.Path(temporary) / "fixture"
    root.mkdir()
    result = run_stage(root, archive_fixture(root, redirect=False), {"PATH": f"{wrapper_root}:{os_environ()['PATH']}"})
    if result.returncode == 0 or "b3sum must be pinned" not in result.stderr:
        fail("unpinned b3sum unexpectedly passed the tool gate")

with tempfile.TemporaryDirectory() as temporary:
    wrapper_root = pathlib.Path(temporary) / "disagreeing-b3sum"
    wrapper_root.mkdir()
    wrapper = wrapper_root / "b3sum"
    wrapper.write_text(
        "#!/bin/sh\n"
        "if [ \"$#\" -eq 1 ] && [ \"$1\" = \"--no-names\" ]; then\n"
        "  printf 'af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262\\n'\n"
        "  exit 0\n"
        "fi\n"
        "if [ \"$1\" = \"--version\" ]; then\n"
        "  printf 'b3sum 1.8.5\\n'\n"
        "  exit 0\n"
        "fi\n"
        "if [ \"$#\" -eq 2 ] && [ \"$1\" = \"--no-names\" ]; then\n"
        "  printf '%s' \"$2\" | sha256sum | cut -d' ' -f1\n"
        "  exit 0\n"
        "fi\n"
        "cat >/dev/null\n",
        encoding="utf-8",
    )
    wrapper.chmod(0o700)
    root = pathlib.Path(temporary) / "fixture"
    root.mkdir()
    result = run_stage(root, archive_fixture(root, redirect=False), {"PATH": f"{wrapper_root}:{os_environ()['PATH']}"})
    if result.returncode == 0 or "staged byte disagreement" not in result.stderr:
        fail("disagreeing staged hashes unexpectedly passed")

print("musl packaged archive certification contract: PASS")
PY
