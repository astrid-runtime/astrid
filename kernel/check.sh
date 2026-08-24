#!/usr/bin/env bash
# Supported split checks for this isolated kernel workspace.
# Do not run `cargo clippy --workspace` on stable: bootloader 0.11's
# build.rs requires nightly `-Zbuild-std` and fails on this host.
set -euo pipefail
root="$(cd "$(dirname "$0")" && pwd)"
cd "$root"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$root/target}"
toolchain="${KTEST_TOOLCHAIN:-nightly}"
host="$root/target/kimage-host"
nested="$root/target/bootloader-nested"

echo "== cargo fmt --all -- --check =="
cargo fmt --all -- --check

echo "== stable cargo test -p ktest --locked =="
cargo test -p ktest --locked

echo "== stable cargo clippy -p ktest =="
cargo clippy -p ktest --all-targets --locked -- -D warnings

echo "== stable cargo clippy -p astrid-native-kernel --target x86_64-unknown-none =="
cargo clippy -p astrid-native-kernel --target x86_64-unknown-none --locked -- -D warnings

echo "== nightly cargo clippy -p kimage (isolated target dirs) =="
env -u CARGO_BUILD_TARGET_DIR   CARGO_TARGET_DIR="$nested"   rustup run "$toolchain" cargo clippy -p kimage --all-targets --locked --target-dir "$host" -- -D warnings

echo "check.sh: PASS (split checks only; not workspace clippy)"
