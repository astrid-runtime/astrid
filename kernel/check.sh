#!/usr/bin/env bash
# Supported split checks for this isolated kernel workspace.
# Do not run `cargo clippy --workspace` on stable: bootloader 0.11's
# build.rs requires nightly `-Zbuild-std` and fails on this host.
# kimage/bootloader nightly is a dated pin, not rolling `nightly`.
set -euo pipefail
root="$(cd "$(dirname "$0")" && pwd)"
cd "$root"
if [[ -z "${CARGO_TARGET_DIR:-}" ]]; then
  CARGO_TARGET_DIR="$(
    cargo metadata --no-deps --format-version 1 \
      | sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p'
  )"
fi
if [[ -z "$CARGO_TARGET_DIR" ]]; then
  echo "check.sh: unable to resolve Cargo target directory" >&2
  exit 1
fi
export CARGO_TARGET_DIR
toolchain="${KTEST_TOOLCHAIN:-nightly-2026-07-21}"
host="$CARGO_TARGET_DIR/kimage-host"
nested="$CARGO_TARGET_DIR/bootloader-nested"
echo "check.sh: target root=$CARGO_TARGET_DIR host=$host nested=$nested"

mode="${1:-all}"
if [[ $# -gt 1 ]]; then
  echo "usage: $0 [x86|portability|all]" >&2
  exit 2
fi

require_target() {
  local target="$1"
  local cfg installed_targets installed_target
  if ! cfg="$(rustc --print cfg --target "$target" 2>&1)"; then
    echo "check.sh: required target $target is not recognized by the active rustc" >&2
    echo "$cfg" >&2
    exit 1
  fi
  if ! installed_targets="$(rustup target list --installed 2>&1)"; then
    echo "check.sh: unable to query installed Rust targets" >&2
    echo "$installed_targets" >&2
    exit 1
  fi
  while IFS= read -r installed_target; do
    if [[ "$installed_target" == "$target" ]]; then
      return 0
    fi
  done <<< "$installed_targets"
  echo "check.sh: required target $target is missing; install it with 'rustup target add $target'" >&2
  exit 1
}

run_portability() {
  local target spec package feature_spec
  local -a package_args
  local -a targets=(
    "aarch64-unknown-none"
    "riscv64gc-unknown-none-elf"
  )
  local -a packages=(
    "astrid-native-closure|--no-default-features"
    "astrid-system-generation|--no-default-features"
    "astrid-boot-selection|--no-default-features"
    "astrid-init-plan|"
  )

  for target in "${targets[@]}"; do
    require_target "$target"
    for spec in "${packages[@]}"; do
      package="${spec%%|*}"
      feature_spec="${spec#*|}"
      package_args=(-p "$package")
      if [[ -n "$feature_spec" ]]; then
        package_args+=(--no-default-features)
      fi

      echo "== stable cargo check -p $package ${feature_spec:+$feature_spec }--target $target (compile-only) =="
      cargo check "${package_args[@]}" --target "$target" --locked

      echo "== stable cargo clippy -p $package ${feature_spec:+$feature_spec }--target $target (compile-only) =="
      cargo clippy "${package_args[@]}" --target "$target" --locked -- -D warnings
    done
  done

  echo "check.sh: PASS (compile-only portability checks; not boot or hardware evidence)"
}

case "$mode" in
  x86|all)
    require_target "x86_64-unknown-none"
    ;;
  portability)
    run_portability
    exit 0
    ;;
  *)
    echo "usage: $0 [x86|portability|all]" >&2
    exit 2
    ;;
esac

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
  ASTRID_BOOTLOADER_TARGET_DIR="$nested" \
  CARGO_TARGET_DIR="$nested" \
  rustup run "$toolchain" cargo clippy -p kimage --all-targets --locked --target-dir "$host" -- -D warnings

for worktree_target in "$root/target" "$root/tools/bootloader/target"; do
  if [[ -e "$worktree_target" ]]; then
    echo "check.sh: unexpected per-worktree target directory: $worktree_target" >&2
    exit 1
  fi
done

echo "check.sh: PASS (split checks only; not workspace clippy)"

if [[ "$mode" == all ]]; then
  run_portability
fi
