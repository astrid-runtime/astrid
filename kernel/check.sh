#!/usr/bin/env bash
# Supported split checks for this isolated kernel workspace.
# Do not run `cargo clippy --workspace` on stable: bootloader 0.11's
# build.rs requires nightly `-Zbuild-std` and fails on this host.
# kimage/bootloader nightly is a dated pin, not rolling `nightly`.
set -euo pipefail
root="$(cd "$(dirname "$0")" && pwd)"
cd "$root"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$root/target}"
toolchain="${KTEST_TOOLCHAIN:-nightly-2026-07-21}"
host="$root/target/kimage-host"
nested="$root/target/bootloader-nested"

echo "== cargo fmt (kernel packages; vendored bootloader uses its own pinned toolchain) =="
cargo fmt -p astrid-native-closure -p astrid-native-kernel -p astrid-boot-selection -p astrid-init-plan -p astrid-system-generation -p kimage -p ktest -- --check

echo "== stable cargo test -p astrid-native-closure --locked =="
cargo test -p astrid-native-closure --locked

echo "== stable cargo test -p astrid-boot-selection --locked (default) =="
cargo test -p astrid-boot-selection --locked

echo "== stable cargo test -p astrid-boot-selection --locked (no default features) =="
cargo test -p astrid-boot-selection --no-default-features --locked

echo "== stable cargo test -p astrid-native-closure --no-default-features --locked =="
cargo test -p astrid-native-closure --no-default-features --locked

echo "== stable cargo clippy -p astrid-native-closure (host, all features) =="
cargo clippy -p astrid-native-closure --all-targets --all-features --locked -- -D warnings

echo "== stable cargo clippy -p astrid-native-closure --target x86_64-unknown-none =="
cargo clippy -p astrid-native-closure --target x86_64-unknown-none --locked -- -D warnings

echo "== stable cargo clippy -p astrid-boot-selection (host, all targets) =="
cargo clippy -p astrid-boot-selection --all-targets --all-features --locked -- -D warnings

echo "== stable cargo check -p astrid-boot-selection --target x86_64-unknown-none =="
cargo check -p astrid-boot-selection --no-default-features --target x86_64-unknown-none --locked

echo "== stable cargo test -p astrid-system-generation --locked =="
cargo test -p astrid-system-generation --locked

echo "== stable cargo check -p astrid-system-generation --target x86_64-unknown-none (no default features) =="
cargo check -p astrid-system-generation --target x86_64-unknown-none --no-default-features --locked

echo "== stable cargo clippy -p astrid-system-generation (host, all features) =="
cargo clippy -p astrid-system-generation --all-targets --all-features --locked -- -D warnings

echo "== stable cargo clippy -p astrid-system-generation --target x86_64-unknown-none (no default features) =="
cargo clippy -p astrid-system-generation --target x86_64-unknown-none --no-default-features --locked -- -D warnings

echo "== stable cargo test -p astrid-init-plan --locked =="
cargo test -p astrid-init-plan --locked

echo "== stable cargo clippy -p astrid-init-plan (host, all targets) =="
cargo clippy -p astrid-init-plan --all-targets --locked -- -D warnings

echo "== stable cargo check -p astrid-init-plan --target x86_64-unknown-none =="
cargo check -p astrid-init-plan --target x86_64-unknown-none --locked

echo "== stable cargo clippy -p astrid-init-plan --target x86_64-unknown-none =="
cargo clippy -p astrid-init-plan --target x86_64-unknown-none --locked -- -D warnings

echo "== stable cargo check -p astrid-native-closure --no-default-features (x86_64-unknown-none) =="
cargo check -p astrid-native-closure --no-default-features --target x86_64-unknown-none --locked

echo "== stable cargo test -p ktest --locked =="
cargo test -p ktest --locked

echo "== stable cargo clippy -p ktest =="
cargo clippy -p ktest --all-targets --locked -- -D warnings

echo "== stable cargo clippy -p astrid-native-kernel --target x86_64-unknown-none =="
cargo clippy -p astrid-native-kernel --target x86_64-unknown-none --locked -- -D warnings

echo "== nightly cargo clippy -p kimage (isolated target dirs, toolchain=$toolchain) =="
env -u CARGO_BUILD_TARGET_DIR \
  CARGO_TARGET_DIR="$nested" \
  rustup run "$toolchain" cargo clippy -p kimage --all-targets --locked --target-dir "$host" -- -D warnings

echo "check.sh: PASS (split checks only; not workspace clippy)"
