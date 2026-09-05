#!/usr/bin/env bash
set -euo pipefail

B3SUM_REQUIRED_VERSION="1.8.5"
EXPECTED_EMPTY_BLAKE3="af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
EXPECTED_EMPTY_SHA256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

usage() {
  echo "usage: $0 --architecture ARCH --target TRIPLE --artifact-dir DIR --expected-version VERSION [--stage-only]" >&2
  exit 2
}

fail() {
  echo "$*" >&2
  exit 1
}

architecture=""
target=""
artifact_dir=""
expected_version=""
stage_only=false
while (($#)); do
  case "$1" in
    --architecture|--target|--artifact-dir|--expected-version)
      [[ $# -ge 2 ]] || usage
      case "$1" in
        --architecture) architecture=$2 ;;
        --target) target=$2 ;;
        --artifact-dir) artifact_dir=$2 ;;
        --expected-version) expected_version=$2 ;;
      esac
      shift 2
      ;;
    --stage-only)
      stage_only=true
      shift
      ;;
    *) usage ;;
  esac
done

[[ -n "$architecture" && -n "$target" && -n "$artifact_dir" && -n "$expected_version" ]] || usage
case "$architecture:$target" in
  x86_64:x86_64-unknown-linux-musl | aarch64:aarch64-unknown-linux-musl) ;;
  *) fail "architecture and target are not paired" ;;
esac
[[ -d "$artifact_dir" && ! -L "$artifact_dir" ]] || fail "artifact directory is invalid"

sha256sum_bin=$(command -v sha256sum) || fail "system sha256sum is unavailable"
b3sum_bin=$(command -v b3sum) || fail "pinned b3sum is unavailable"
b3sum_version=$("$b3sum_bin" --version) || fail "b3sum version could not be determined"
[[ "$b3sum_version" == "b3sum ${B3SUM_REQUIRED_VERSION}" ]] \
  || fail "b3sum must be pinned to ${B3SUM_REQUIRED_VERSION}, found: ${b3sum_version}"

empty_b3sum=$(printf '' | "$b3sum_bin" --no-names) || fail "b3sum empty-vector probe failed"
[[ "$empty_b3sum" == "$EXPECTED_EMPTY_BLAKE3" ]] || fail "pinned b3sum failed the empty BLAKE3 vector"
empty_sha256=$(printf '' | "$sha256sum_bin") || fail "sha256sum empty-vector probe failed"
empty_sha256=${empty_sha256%% *}
[[ "$empty_sha256" == "$EXPECTED_EMPTY_SHA256" ]] || fail "system sha256sum failed its empty vector"

repo_root=$PWD
base_temp=${RUNNER_TEMP:-${TMPDIR:-/tmp}}
cert_root=$(mktemp -d "$base_temp/astrid-musl-cert.XXXXXX")
cleanup() {
  local status=$?
  set +e
  if [[ -d "${cert_root:-}" ]]; then
    case "$cert_root" in
      "$base_temp"/astrid-musl-cert.*) rm -rf "$cert_root" ;;
    esac
  fi
  exit "$status"
}
trap cleanup EXIT

artifact_stage="$cert_root/artifact"
binary_stage="$cert_root/stage"
mkdir -m 0700 "$artifact_stage" "$binary_stage"

python3 - "$artifact_dir" "$artifact_stage" "$expected_version" "$target" <<'PY'
from __future__ import annotations

import os
import pathlib
import stat
import sys
import tarfile


REQUIRED = (
    "astrid",
    "astrid-daemon",
    "astrid-build",
    "astrid-emit",
    "astrid-storage-provider-fuse",
)


def fail(message: str) -> None:
    raise ValueError(message)


artifact_dir, stage_dir, expected_version, target = (
    pathlib.Path(sys.argv[1]),
    pathlib.Path(sys.argv[2]),
    sys.argv[3],
    sys.argv[4],
)
entries = list(artifact_dir.iterdir())
archives = [path for path in entries if path.name.endswith(".tar.gz")]
if len(archives) != 1:
    fail(f"expected exactly one archive in {artifact_dir}, found {len(archives)}")
archive = archives[0]
if archive.is_symlink() or not archive.is_file():
    fail(f"artifact archive is not a regular file: {archive}")
expected_asset = f"astrid-{expected_version}-{target}.tar.gz"
if archive.name != expected_asset:
    fail(f"artifact archive does not bind {target} at {expected_version}: {archive.name}")

root = f"astrid-{expected_version}-{target}"
allowed = {
    root,
    *(f"{root}/{name}" for name in REQUIRED),
    f"{root}/README.md",
}
staged: set[str] = set()
with tarfile.open(archive, mode="r:gz") as members:
    entries = members.getmembers()
    if len(entries) > 32:
        fail("certification archive has too many members")
    for member in entries:
        name = member.name.rstrip("/") if member.isdir() else member.name
        pure = pathlib.PurePosixPath(name)
        if pure.is_absolute() or ".." in pure.parts or name in staged:
            fail(f"unsafe or duplicate archive member: {member.name}")
        if member.issym() or member.islnk() or not (member.isfile() or member.isdir()):
            fail(f"archive member redirects or is special: {member.name}")
        if name.startswith(f"{root}/LICENSE"):
            allowed.add(name)
        if name not in allowed:
            lowered = name.casefold()
            if any(marker in lowered for marker in ("apple", "darwin", "windows", "fskit", ".app/")):
                fail(f"certification archive contains a non-musl companion: {member.name}")
            fail(f"certification archive has an unexpected member: {member.name}")
        if not member.isfile():
            continue
        member_name = pathlib.PurePosixPath(name).name
        if member_name not in REQUIRED:
            continue
        if not (member.mode & stat.S_IXUSR):
            fail(f"archive binary is not executable: {name}")
        source = members.extractfile(member)
        if source is None:
            fail(f"archive bytes are unavailable: {name}")
        destination = stage_dir / member_name
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        copied = 0
        try:
            descriptor = os.open(destination, flags, 0o700)
            with os.fdopen(descriptor, "wb") as output:
                while True:
                    block = source.read(1024 * 1024)
                    if not block:
                        break
                    copied += len(block)
                    output.write(block)
        except FileExistsError:
            fail(f"staging collision for required binary: {name}")
        if copied != member.size:
            fail(f"staged byte count differs from archive member: {name}")
        destination.chmod(0o700)
        if destination.is_symlink() or not destination.is_file():
            fail(f"staged binary is redirected or missing: {name}")
        staged.add(member_name)

if staged != set(REQUIRED):
    fail("certification archive does not have exactly the five required binaries")
print(f"staged {len(staged)} binaries from {archive.name}")
PY

sha256_digest() {
  local output
  output=$("$sha256sum_bin" "$1") || return 1
  output=${output%% *}
  [[ "$output" =~ ^[0-9a-f]{64}$ ]] || return 1
  printf '%s\n' "$output"
}

b3sum_digest() {
  local output
  output=$("$b3sum_bin" --no-names "$1") || return 1
  [[ "$output" =~ ^[0-9a-f]{64}$ ]] || return 1
  printf '%s\n' "$output"
}

for binary in astrid astrid-daemon astrid-build astrid-emit astrid-storage-provider-fuse; do
  artifact_path="$artifact_stage/$binary"
  staged_path="$binary_stage/$binary"
  [[ -f "$artifact_path" && ! -L "$artifact_path" ]] || fail "invalid staged artifact bytes: $binary"
  cp "$artifact_path" "$staged_path"
  chmod 0700 "$staged_path"
  [[ -f "$staged_path" && -x "$staged_path" && ! -L "$staged_path" ]] \
    || fail "invalid packaged binary after staging: $binary"

  artifact_sha256=$(sha256_digest "$artifact_path") || fail "sha256sum could not digest artifact bytes: $binary"
  staged_sha256=$(sha256_digest "$staged_path") || fail "sha256sum could not digest staged bytes: $binary"
  artifact_blake3=$(b3sum_digest "$artifact_path") || fail "pinned b3sum could not digest artifact bytes: $binary"
  staged_blake3=$(b3sum_digest "$staged_path") || fail "pinned b3sum could not digest staged bytes: $binary"

  [[ "$artifact_sha256" == "$staged_sha256" ]] \
    || fail "sha256sum detected staged byte disagreement: $binary"
  [[ "$artifact_blake3" == "$staged_blake3" ]] \
    || fail "pinned b3sum detected staged byte disagreement: $binary"
  cmp -s "$artifact_path" "$staged_path" || fail "staged bytes differ from artifact bytes: $binary"
  printf '%s  %s\n' "$staged_sha256" "$binary"
  printf '%s  %s\n' "$staged_blake3" "$binary"
done

if [[ "$stage_only" == true ]]; then
  echo "musl archive staging certification: PASS"
  exit 0
fi

[[ "$(uname -s)" == Linux ]] || fail "musl runtime certification requires Linux"
[[ -c /dev/fuse ]] || fail "Linux FUSE device is unavailable"
command -v fusermount3 >/dev/null || fail "fusermount3 is unavailable"
[[ -w /dev/fuse ]] || fail "/dev/fuse is not writable"

bin="$binary_stage"
home="$cert_root/home"
workspace="$cert_root/workspace"
mount="$cert_root/mount"
mkdir -m 0700 "$home" "$workspace" "$mount"
export HOME="$home"
export ASTRID_HOME="$home/.astrid"
cd "$workspace"

reported_version=$("$bin/astrid" --version)
[[ "$reported_version" == "astrid $expected_version" ]] \
  || fail "packaged version mismatch: $reported_version"
for binary in astrid astrid-daemon astrid-build astrid-emit astrid-storage-provider-fuse; do
  [[ -f "$bin/$binary" && -x "$bin/$binary" && ! -L "$bin/$binary" ]] \
    || fail "invalid packaged binary: $binary"
done
python3 "$repo_root/scripts/check_static_elf.py" --architecture "$architecture" \
  "$bin/astrid" "$bin/astrid-daemon" "$bin/astrid-build" \
  "$bin/astrid-emit" "$bin/astrid-storage-provider-fuse"

timeout 180s "$bin/astrid" --principal default start
timeout 30s "$bin/astrid" --principal default status

[[ -x /usr/bin/uuidgen ]] || fail "musl certification requires /usr/bin/uuidgen"
request_id="$(/usr/bin/uuidgen)"
if ! REQUEST_ID="$request_id" python3 - <<-'PY'
import os
import uuid

uuid.UUID(os.environ["REQUEST_ID"])
PY
then
  fail "provider request_id is not a UUID: $request_id"
fi
request=$(REQUEST_ID="$request_id" python3 - <<-'PY'
import json
import os
print(json.dumps({
    "protocol_version": 1,
    "request_id": os.environ["REQUEST_ID"],
    "acting_principal_hint": "default",
    "operation": {
        "operation": "status",
        "selector": {"kind": "native-path", "value": None},
    },
}, separators=(",", ":")))
PY
)
request=${request/null/\"$mount\"}
provider_output=$(printf '%s\n' "$request" | timeout 30s "$bin/astrid-storage-provider-fuse" --astrid-provider-stdio-v1)
ASTRID_VERSION="$expected_version" python3 - "$provider_output" <<-'PY'
import json
import os
import sys

response = json.loads(sys.argv[1])
expected = os.environ["ASTRID_VERSION"]
assert response["protocol_version"] == 1
assert response["provider"]["name"] == "astrid-storage-provider-fuse"
assert response["provider"]["version"] == expected
PY

mount_output=$(timeout 30s "$bin/astrid" --principal default storage mount \
  --as default --read-write "$mount")
printf '%s\n' "$mount_output"
mount_id=$(sed -nE 's/^mounted ([0-9a-f-]{36}) at .*/\1/p' <<<"$mount_output")
[[ "$mount_id" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]
[[ "$(findmnt -nro FSTYPE --target "$mount")" == fuse.astrid ]]
sentinel="musl-certified"
printf '%s\n' "$sentinel" > "$mount/certified.txt"
[[ "$(cat "$mount/certified.txt")" == "$sentinel" ]]
status_output=$(timeout 30s "$bin/astrid" --principal default storage status "$mount")
grep -Fq "mount $mount_id at $mount: ReadWrite, dirty=true" <<<"$status_output"
timeout 30s "$bin/astrid" --principal default storage sync "$mount"
status_output=$(timeout 30s "$bin/astrid" --principal default storage status "$mount")
grep -Fq "mount $mount_id at $mount: ReadWrite, dirty=false" <<<"$status_output"
timeout 30s "$bin/astrid" --principal default storage unmount "$mount"
[[ ! -e "/tmp/astrid-mounts-$(id -u)/$mount_id" ]]
if timeout 30s "$bin/astrid" --principal default storage status "$mount" \
  >"$cert_root/post-unmount.out" 2>"$cert_root/post-unmount.err"; then
  fail "storage status unexpectedly retained an unmounted path"
fi
timeout 30s "$bin/astrid" --principal default stop
if timeout 30s "$bin/astrid" --principal default status \
  >"$cert_root/post-stop.out" 2>"$cert_root/post-stop.err"; then
  fail "daemon status unexpectedly succeeded after authoritative stop"
fi
for marker in system.sock system.token system.ready system.pid; do
  [[ ! -e "$ASTRID_HOME/run/$marker" ]]
done
echo "musl packaged archive certification: PASS"
