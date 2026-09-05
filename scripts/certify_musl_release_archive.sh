#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 --architecture ARCH --target TRIPLE --artifact-dir DIR --expected-version VERSION [--stage-only]" >&2
  exit 2
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

[[ -n "$architecture" && -n "$target" && -n "$artifact_dir" && -n "$expected_version" ]]
case "$architecture:$target" in
  x86_64:x86_64-unknown-linux-musl | aarch64:aarch64-unknown-linux-musl) ;;
  *) echo "architecture and target are not paired" >&2; exit 2 ;;
esac
[[ -d "$artifact_dir" && ! -L "$artifact_dir" ]] || { echo "artifact directory is invalid" >&2; exit 2; }
repo_root=$PWD

cert_root=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/astrid-musl-cert.XXXXXX")
cleanup() {
  local status=$?
  set +e
  if [[ -d "${cert_root:-}" ]]; then
    case "$cert_root" in
      ${RUNNER_TEMP:-${TMPDIR:-/tmp}}/astrid-musl-cert.*) rm -rf "$cert_root" ;;
    esac
  fi
  exit "$status"
}
trap cleanup EXIT

python3 - "$artifact_dir" "$cert_root/stage" "$architecture" "$target" "$expected_version" <<'PY'
from __future__ import annotations

import hashlib
import json
import pathlib
import stat
import sys
import tarfile


BLOCK_LEN = 64
CHUNK_LEN = 1024
CHUNK_START = 1
CHUNK_END = 2
PARENT = 4
ROOT = 8
IV = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
]
PERMUTATION = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]


def rotate(value: int, count: int) -> int:
    return ((value << (32 - count)) | (value >> count)) & 0xFFFFFFFF


def mix(state: list[int], a: int, b: int, c: int, d: int, x: int, y: int) -> None:
    state[a] = (state[a] + state[b] + x) & 0xFFFFFFFF
    state[d] = rotate(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = rotate(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b] + y) & 0xFFFFFFFF
    state[d] = rotate(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = rotate(state[b] ^ state[c], 7)


def round(state: list[int], words: list[int]) -> None:
    mix(state, 0, 4, 8, 12, words[0], words[1])
    mix(state, 1, 5, 9, 13, words[2], words[3])
    mix(state, 2, 6, 10, 14, words[4], words[5])
    mix(state, 3, 7, 11, 15, words[6], words[7])
    mix(state, 0, 5, 10, 15, words[8], words[9])
    mix(state, 1, 6, 11, 12, words[10], words[11])
    mix(state, 2, 7, 8, 13, words[12], words[13])
    mix(state, 3, 4, 9, 14, words[14], words[15])


def compress(chaining_value: list[int], words: list[int], counter: int, length: int, flags: int) -> list[int]:
    state = [
        *chaining_value,
        *IV[:4],
        counter & 0xFFFFFFFF,
        (counter >> 32) & 0xFFFFFFFF,
        length,
        flags,
    ]
    words = list(words)
    for _ in range(7):
        round(state, words)
        if _ != 6:
            words = [words[index] for index in PERMUTATION]
    for index in range(8):
        state[index] ^= state[index + 8]
        state[index + 8] ^= chaining_value[index]
    return state


class Output:
    def __init__(self, chaining_value: list[int], words: list[int], counter: int, length: int, flags: int):
        self.chaining_value = chaining_value
        self.words = words
        self.counter = counter
        self.length = length
        self.flags = flags

    def chain(self) -> list[int]:
        return compress(self.chaining_value, self.words, self.counter, self.length, self.flags)[:8]


class Chunk:
    def __init__(self, counter: int):
        self.chain = list(IV)
        self.counter = counter
        self.block = bytearray(BLOCK_LEN)
        self.length = 0
        self.blocks = 0

    @property
    def total_length(self) -> int:
        return BLOCK_LEN * self.blocks + self.length

    def start_flag(self) -> int:
        return CHUNK_START if self.blocks == 0 else 0

    def update(self, data: bytes) -> None:
        while data:
            if self.length == BLOCK_LEN:
                words = [int.from_bytes(self.block[i:i + 4], "little") for i in range(0, BLOCK_LEN, 4)]
                self.chain = compress(self.chain, words, self.counter, BLOCK_LEN, self.flags())[:8]
                self.blocks += 1
                self.block = bytearray(BLOCK_LEN)
                self.length = 0
            take = min(BLOCK_LEN - self.length, len(data))
            self.block[self.length:self.length + take] = data[:take]
            self.length += take
            data = data[take:]

    def flags(self) -> int:
        return self.start_flag()

    def output(self) -> Output:
        words = [int.from_bytes(self.block[i:i + 4], "little") for i in range(0, BLOCK_LEN, 4)]
        return Output(self.chain, words, self.counter, self.length, self.flags() | CHUNK_END)


class Blake3:
    def __init__(self):
        self.chunk = Chunk(0)
        self.stack: list[list[int]] = []

    def add_chunk(self, chain: list[int], total_chunks: int) -> None:
        while total_chunks & 1 == 0:
            chain = self.parent_chain(self.stack.pop(), chain)
            total_chunks >>= 1
        self.stack.append(chain)

    def parent_chain(self, left: list[int], right: list[int]) -> list[int]:
        output = Output(list(IV), left + right, 0, BLOCK_LEN, PARENT)
        return output.chain()

    def update(self, data: bytes) -> None:
        while data:
            if self.chunk.total_length == CHUNK_LEN:
                chain = self.chunk.output().chain()
                total = self.chunk.counter + 1
                self.add_chunk(chain, total)
                self.chunk = Chunk(total)
            take = min(CHUNK_LEN - self.chunk.total_length, len(data))
            self.chunk.update(data[:take])
            data = data[take:]

    def digest(self) -> str:
        output = self.chunk.output()
        for chain in reversed(self.stack):
            output = Output(list(IV), chain + output.chain(), 0, BLOCK_LEN, PARENT)
        words = compress(output.chaining_value, output.words, output.counter, output.length, output.flags | ROOT)
        return b"".join(word.to_bytes(4, "little") for word in words[:8]).hex()


def blake3_bytes(data: bytes) -> str:
    hasher = Blake3()
    hasher.update(data)
    return hasher.digest()


def fail(message: str) -> None:
    raise ValueError(message)


artifact_dir, stage_dir, architecture, target, expected_version = (
    pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5]
)
archives = [path for path in artifact_dir.iterdir() if path.name.endswith(".tar.gz")]
if len(archives) != 1:
    fail(f"expected exactly one archive in {artifact_dir}, found {len(archives)}")
archive = archives[0]
if archive.is_symlink() or not archive.is_file():
    fail(f"artifact archive is not a regular file: {archive}")
expected_asset = f"astrid-{expected_version}-{target}.tar.gz"
if archive.name != expected_asset:
    fail(f"artifact archive does not bind {target} at {expected_version}: {archive.name}")

root = f"astrid-{expected_version}-{target}"
required = (
    "astrid", "astrid-daemon", "astrid-build", "astrid-emit",
    "astrid-storage-provider-fuse",
)
allowed = {root, *(f"{root}/{name}" for name in required), f"{root}/README.md"}
stage_dir.mkdir(mode=0o700)
staged: dict[str, dict[str, str]] = {}
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
        if pathlib.PurePosixPath(name).name in required and not (member.mode & stat.S_IXUSR):
            fail(f"archive binary is not executable: {member.name}")
        if pathlib.PurePosixPath(name).name not in required:
            continue
        source = members.extractfile(member)
        if source is None:
            fail(f"archive bytes are unavailable: {member.name}")
        data = source.read()
        destination = stage_dir / pathlib.PurePosixPath(name).relative_to(root)
        destination.write_bytes(data)
        destination.chmod(0o700)
        extracted = destination.read_bytes()
        sha256 = hashlib.sha256(data).hexdigest()
        blake3 = blake3_bytes(data)
        if (
            len(extracted) != len(data)
            or hashlib.sha256(extracted).hexdigest() != sha256
            or blake3_bytes(extracted) != blake3
        ):
            fail(f"staged bytes differ from artifact bytes: {name}")
        staged[name] = {
            "size": str(len(data)),
            "sha256": sha256,
            "blake3": blake3,
        }
if set(staged) != {f"{root}/{name}" for name in required}:
    fail("certification archive does not have exactly the five required binaries")
for name, data in staged.items():
    path = stage_dir / pathlib.PurePosixPath(name).relative_to(root)
    if path.is_symlink() or not path.is_file():
        fail(f"staged binary is redirected or missing: {name}")
    if (
        len(path.read_bytes()) != int(data["size"])
        or hashlib.sha256(path.read_bytes()).hexdigest() != data["sha256"]
        or blake3_bytes(path.read_bytes()) != data["blake3"]
    ):
        fail(f"staged bytes differ from artifact bytes: {name}")
stage_dir.parent.chmod(0o700)
(stage_dir / "digests.json").write_text(json.dumps(staged, sort_keys=True), encoding="utf-8")
print(f"staged {len(staged)} binaries from {archive.name}")
PY

if [[ "$stage_only" == true ]]; then
  echo "musl archive staging certification: PASS"
  exit 0
fi

[[ "$(uname -s)" == Linux ]]
[[ -c /dev/fuse ]] || { echo "Linux FUSE device is unavailable" >&2; exit 1; }
command -v fusermount3 >/dev/null || { echo "fusermount3 is unavailable" >&2; exit 1; }
[[ -w /dev/fuse ]] || { echo "/dev/fuse is not writable" >&2; exit 1; }

bin="$cert_root/stage"
home="$cert_root/home"
workspace="$cert_root/workspace"
mount="$cert_root/mount"
mkdir -m 0700 -p "$home" "$workspace" "$mount"
export HOME="$home"
export ASTRID_HOME="$home/.astrid"
cd "$workspace"

reported_version=$("$bin/astrid" --version)
[[ "$reported_version" == "astrid $expected_version" ]] || {
  echo "packaged version mismatch: $reported_version" >&2
  exit 1
}
for binary in astrid astrid-daemon astrid-build astrid-emit astrid-storage-provider-fuse; do
  [[ -f "$bin/$binary" && -x "$bin/$binary" && ! -L "$bin/$binary" ]] || {
    echo "invalid packaged binary: $binary" >&2
    exit 1
  }
done
python3 "$repo_root/scripts/check_static_elf.py" --architecture "$architecture" \
  "$bin/astrid" "$bin/astrid-daemon" "$bin/astrid-build" \
  "$bin/astrid-emit" "$bin/astrid-storage-provider-fuse"

timeout 180s "$bin/astrid" --principal default start
timeout 30s "$bin/astrid" --principal default status

request=$(python3 - <<-'PY'
import json
print(json.dumps({
    "protocol_version": 1,
    "request_id": "musl-release-certification",
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
  echo "storage status unexpectedly retained an unmounted path" >&2
  exit 1
fi
timeout 30s "$bin/astrid" --principal default stop
if timeout 30s "$bin/astrid" --principal default status \
  >"$cert_root/post-stop.out" 2>"$cert_root/post-stop.err"; then
  echo "daemon status unexpectedly succeeded after authoritative stop" >&2
  exit 1
fi
for marker in system.sock system.token system.ready system.pid; do
  [[ ! -e "$ASTRID_HOME/run/$marker" ]]
done
echo "musl packaged archive certification: PASS"
