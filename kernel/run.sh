#!/usr/bin/env bash
# Build the ring-0 kernel, wrap it into a UEFI image, boot it under QEMU with
# the frozen machine contract, and assert the serial evidence.
set -euo pipefail
root="$(cd -- "$(dirname -- "$0")" && pwd -P)"
cd "$root"

# Resolve Cargo's effective target root once, without setting
# CARGO_TARGET_DIR. This honors an explicit absolute/relative override,
# CARGO_BUILD_TARGET_DIR, or the host Cargo config in exactly the same way as
# the `cargo run` below. The absolute value is an internal handoff to ktest so
# its kernel, kimage host, and nested bootloader siblings cannot drift.
target_root="$({
  cargo metadata \
    --manifest-path "$root/Cargo.toml" \
    --no-deps \
    --format-version 1
} | sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p')"
if [[ -z "$target_root" || "$target_root" != /* ]]; then
  echo "run.sh: unable to resolve an absolute Cargo target root" >&2
  exit 1
fi
# Cargo preserves `..` components in metadata output for relative explicit
# overrides. Normalize lexically without requiring the target directory to
# exist yet; this is the exact absolute value handed to ktest.
target_root="$(python3 -c 'import os,sys; print(os.path.abspath(sys.argv[1]))' "$target_root")"
export ASTRID_CARGO_TARGET_ROOT="$target_root"
echo "run.sh: target root=$ASTRID_CARGO_TARGET_ROOT"

exec cargo run -p ktest --release --manifest-path "$root/Cargo.toml" -- "$@"
