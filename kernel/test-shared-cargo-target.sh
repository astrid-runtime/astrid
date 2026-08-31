#!/usr/bin/env bash
# Exercise the nested UEFI build against an external Cargo target root.
#
# This regression intentionally leaves CARGO_TARGET_DIR unset in the first
# case. Cargo's build.target-dir override supplies the shared root, while the
# parent kimage build and nested bootloader install use sibling directories.
set -euo pipefail

root="$(cd "$(dirname "$0")" && pwd)"
toolchain="${KTEST_TOOLCHAIN:-nightly-2026-07-21}"
cd "$root"

assert_no_worktree_targets() {
  local worktree_target
  for worktree_target in "$root/target" "$root/tools/bootloader/target"; do
    if [[ -e "$worktree_target" ]]; then
      echo "target regression: unexpected per-worktree output at $worktree_target" >&2
      exit 1
    fi
  done
}

run_kimage_check() {
  local label="$1"
  local target_root="$2"
  local mode="$3"
  local host="$target_root/kimage-host"
  local nested="$target_root/bootloader-nested"

  echo "== $label =="
  mkdir -p "$target_root"
  case "$mode" in
    configured)
      # CARGO_BUILD_TARGET_DIR is Cargo's build.target-dir configuration
      # override. Keep CARGO_TARGET_DIR genuinely unset for this case.
      env -u CARGO_TARGET_DIR \
        CARGO_BUILD_TARGET_DIR="$target_root" \
        rustup run "$toolchain" cargo clippy -p kimage --all-targets --locked \
          --target-dir "$host" -- -D warnings
      ;;
    explicit)
      # An explicit caller override remains the parent root; build.rs must
      # derive the distinct nested sibling from it.
      env -u CARGO_BUILD_TARGET_DIR \
        CARGO_TARGET_DIR="$target_root" \
        rustup run "$toolchain" cargo clippy -p kimage --all-targets --locked \
          --target-dir "$host" -- -D warnings
      ;;
    *)
      echo "unknown regression mode: $mode" >&2
      exit 2
      ;;
  esac

  assert_no_worktree_targets
  [[ -d "$host" ]] || {
    echo "target regression: missing host target $host" >&2
    exit 1
  }
  [[ -d "$nested" ]] || {
    echo "target regression: missing nested target $nested" >&2
    exit 1
  }
  echo "target regression: PASS (host=$host nested=$nested)"
}

assert_no_worktree_targets
shared_root="$(mktemp -d "${RUNNER_TEMP:-/tmp}/astrid-cargo-shared.XXXXXX")"
explicit_root="$(mktemp -d "${RUNNER_TEMP:-/tmp}/astrid-cargo-explicit.XXXXXX")"
echo "shared_root=$shared_root"
echo "explicit_root=$explicit_root"

run_kimage_check \
  "unset CARGO_TARGET_DIR with external Cargo target configuration" \
  "$shared_root" configured
run_kimage_check \
  "explicit CARGO_TARGET_DIR remains an isolated parent root" \
  "$explicit_root" explicit

echo "target regression: PASS (no kernel/target or tools/bootloader/target)"
