#!/usr/bin/env bash
# Exercise the run.sh -> ktest target handoff and the nested UEFI layout.
#
# Every target root below is an owned mktemp directory. The EXIT trap removes
# only those exact directories after validating their parent/name; no shared
# Cargo cache or pre-existing worktree output is ever touched.
set -euo pipefail

root="$(cd -- "$(dirname -- "$0")" && pwd -P)"
cd "$root"
toolchain="${KTEST_TOOLCHAIN:-nightly-2026-07-21}"
temp_parent="${RUNNER_TEMP:-/tmp}"
if [[ "$temp_parent" != /* || ! -d "$temp_parent" ]]; then
  echo "target regression: RUNNER_TEMP must be an existing absolute directory" >&2
  exit 1
fi
temp_parent="$(cd -- "$temp_parent" && pwd -P)"

owned_roots=()
cleanup_owned_roots() {
  local path parent name
  for path in "${owned_roots[@]}"; do
    [[ -n "$path" ]] || continue
    parent="${path%/*}"
    name="${path##*/}"
    case "$name" in
      astrid-cargo-configured.*|astrid-cargo-relative.*|astrid-cargo-absolute.*|\
      astrid-cargo-escaped-backslash.*|astrid-cargo-escaped-quote.*|\
      astrid-cargo-newline.*)
        ;;
      *)
        echo "target regression: refusing to clean unvalidated path $path" >&2
        continue
        ;;
    esac
    if [[ "$parent" != "$temp_parent" ]]; then
      echo "target regression: refusing to clean foreign parent $path" >&2
      continue
    fi
    if [[ -d "$path" && ! -L "$path" ]]; then
      rm -rf -- "$path"
    fi
  done
}
trap cleanup_owned_roots EXIT

assert_no_worktree_targets() {
  local worktree_target
  for worktree_target in "$root/target" "$root/tools/bootloader/target"; do
    if [[ -e "$worktree_target" ]]; then
      echo "target regression: unexpected per-worktree output at $worktree_target" >&2
      exit 1
    fi
  done
}

relative_path() {
  python3 - "$1" "$2" <<'PY'
import os
import sys

print(os.path.relpath(sys.argv[2], sys.argv[1]))
PY
}

run_layout_probe() {
  local label="$1"
  local target_root="$2"
  local mode="$3"
  local relative_override=""
  local output
  local expected="ktest: target root=$target_root kernel=$target_root host=$target_root/kimage-host nested=$target_root/bootloader-nested"

  echo "== $label =="
  case "$mode" in
    configured)
      if ! output="$(env -u CARGO_TARGET_DIR -u ASTRID_CARGO_TARGET_ROOT \
        CARGO_BUILD_TARGET_DIR="$target_root" ./run.sh --target-layout-only 2>&1)"; then
        printf '%s\n' "$output"
        echo "target regression: run.sh configured-layout probe failed" >&2
        exit 1
      fi
      ;;
    relative)
      relative_override="$(relative_path "$root" "$target_root")"
      if ! output="$(env -u CARGO_BUILD_TARGET_DIR -u ASTRID_CARGO_TARGET_ROOT \
        CARGO_TARGET_DIR="$relative_override" ./run.sh --target-layout-only 2>&1)"; then
        printf '%s\n' "$output"
        echo "target regression: run.sh relative-layout probe failed" >&2
        exit 1
      fi
      ;;
    absolute)
      if ! output="$(env -u CARGO_BUILD_TARGET_DIR -u ASTRID_CARGO_TARGET_ROOT \
        CARGO_TARGET_DIR="$target_root" ./run.sh --target-layout-only 2>&1)"; then
        printf '%s\n' "$output"
        echo "target regression: run.sh absolute-layout probe failed" >&2
        exit 1
      fi
      ;;
    *)
      echo "target regression: unknown layout mode $mode" >&2
      exit 2
      ;;
  esac

  printf '%s\n' "$output"
  grep -Fqx "$expected" <<< "$output" || {
    echo "target regression: ktest did not report exact shared siblings" >&2
    echo "expected: $expected" >&2
    exit 1
  }
  assert_no_worktree_targets
  echo "target regression: layout PASS (root=$target_root)"
}

run_kimage_check() {
  local label="$1"
  local target_root="$2"
  local host="$target_root/kimage-host"
  local nested="$target_root/bootloader-nested"

  echo "== $label =="
  env -u CARGO_BUILD_TARGET_DIR \
    CARGO_TARGET_DIR="$target_root" \
    ASTRID_BOOTLOADER_TARGET_DIR="$nested" \
    rustup run "$toolchain" cargo clippy -p kimage --all-targets --locked \
      --target-dir "$host" -- -D warnings
  assert_no_worktree_targets
  [[ -d "$host" ]] || {
    echo "target regression: missing host target $host" >&2
    exit 1
  }
  [[ -d "$nested" ]] || {
    echo "target regression: missing nested target $nested" >&2
    exit 1
  }
  echo "target regression: kimage PASS (host=$host nested=$nested)"
}

run_check_relative() {
  local target_root="$1"
  local host="$target_root/kimage-host"
  local nested="$target_root/bootloader-nested"
  local relative_override output expected
  relative_override="$(relative_path "$root" "$target_root")"
  expected="check.sh: target root=$target_root host=$host nested=$nested"

  echo "== check.sh x86 with relative shared root =="
  if ! output="$(
    env -u CARGO_BUILD_TARGET_DIR \
      CARGO_TARGET_DIR="$relative_override" \
      ./check.sh x86 2>&1
  )"; then
    printf '%s\n' "$output"
    echo "target regression: check.sh relative-root x86 failed" >&2
    exit 1
  fi

  grep -Fqx "$expected" <<< "$output" || {
    echo "target regression: check.sh did not normalize the relative root" >&2
    echo "expected: $expected" >&2
    exit 1
  }
  assert_no_worktree_targets
  [[ -d "$host" ]] || {
    echo "target regression: missing check.sh host target $host" >&2
    exit 1
  }
  [[ -d "$nested" ]] || {
    echo "target regression: missing check.sh nested target $nested" >&2
    exit 1
  }
  echo "target regression: check.sh PASS (root=$target_root host=$host nested=$nested)"
}

run_check_metadata_probe() {
  local target_root="$1"
  local host="$target_root/kimage-host"
  local nested="$target_root/bootloader-nested"
  local output expected
  expected="check.sh: target root=$target_root host=$host nested=$nested"

  echo "== check.sh metadata JSON escape probe =="
  if output="$(
    env -u CARGO_TARGET_DIR -u ASTRID_CARGO_TARGET_ROOT \
      CARGO_BUILD_TARGET_DIR="$target_root" \
      ./check.sh invalid 2>&1
  )"; then
    printf '%s\n' "$output"
    echo "target regression: check.sh metadata probe unexpectedly passed" >&2
    exit 1
  fi

  printf '%s\n' "$output"
  grep -Fqx "$expected" <<< "$output" || {
    echo "target regression: check.sh did not decode the escaped root" >&2
    echo "expected: $expected" >&2
    exit 1
  }
  assert_no_worktree_targets
  echo "target regression: check.sh metadata PASS (root=$target_root host=$host nested=$nested)"
}

run_newline_rejection_probe() {
  local target_root="$1"
  local output

  echo "== shell transport rejects trailing-newline target root =="
  if output="$(
    env -u CARGO_TARGET_DIR -u CARGO_BUILD_TARGET_DIR -u ASTRID_CARGO_TARGET_ROOT \
      CARGO_BUILD_TARGET_DIR="$target_root" \
      ./run.sh --target-layout-only 2>&1
  )"; then
    printf '%s\n' "$output"
    echo "target regression: run.sh accepted a newline-bearing target root" >&2
    exit 1
  fi
  printf '%s\n' "$output"
  grep -Fq "shell transport rejects newline-bearing roots" <<< "$output" || {
    echo "target regression: run.sh did not reject the metadata root before shortening" >&2
    exit 1
  }
  if grep -Fq "ktest: target root=" <<< "$output"; then
    echo "target regression: run.sh transported a silently shortened root" >&2
    exit 1
  fi

  if output="$(
    env -u CARGO_BUILD_TARGET_DIR -u ASTRID_CARGO_TARGET_ROOT \
      CARGO_TARGET_DIR="$target_root" \
      ./check.sh invalid 2>&1
  )"; then
    printf '%s\n' "$output"
    echo "target regression: check.sh accepted a newline-bearing target root" >&2
    exit 1
  fi
  printf '%s\n' "$output"
  grep -Fq "shell transport rejects newline-bearing roots" <<< "$output" || {
    echo "target regression: check.sh did not reject the explicit root before shortening" >&2
    exit 1
  }
  if grep -Fq "check.sh: target root=" <<< "$output"; then
    echo "target regression: check.sh transported a silently shortened root" >&2
    exit 1
  fi
  assert_no_worktree_targets
  echo "target regression: newline transport PASS (root rejected before command substitution)"
}

run_kimage_metadata_check() {
  local target_root="$1"
  local host="$target_root/kimage-host"
  local nested="$target_root/bootloader-nested"

  echo "== kimage build.rs metadata JSON escape probe =="
  env -u CARGO_TARGET_DIR -u ASTRID_BOOTLOADER_TARGET_DIR \
    CARGO_BUILD_TARGET_DIR="$target_root" \
    rustup run "$toolchain" cargo clippy -p kimage --all-targets --locked \
      --target-dir "$host" -- -D warnings
  assert_no_worktree_targets
  [[ -d "$host" ]] || {
    echo "target regression: missing metadata-probe host target $host" >&2
    exit 1
  }
  [[ -d "$nested" ]] || {
    echo "target regression: missing metadata-probe nested target $nested" >&2
    exit 1
  }
  echo "target regression: build.rs metadata PASS (root=$target_root host=$host nested=$nested)"
}

assert_no_worktree_targets
configured_root="$(mktemp -d "$temp_parent/astrid-cargo-configured.XXXXXX")"
owned_roots+=("$configured_root")
relative_root="$(mktemp -d "$temp_parent/astrid-cargo-relative.XXXXXX")"
owned_roots+=("$relative_root")
absolute_root="$(mktemp -d "$temp_parent/astrid-cargo-absolute.XXXXXX")"
owned_roots+=("$absolute_root")
escaped_backslash_root="$(mktemp -d "$temp_parent/astrid-cargo-escaped-backslash.\XXXXXX")"
owned_roots+=("$escaped_backslash_root")
escaped_quote_root="$(mktemp -d "$temp_parent/astrid-cargo-escaped-quote.\"XXXXXX")"
owned_roots+=("$escaped_quote_root")
newline_root="$(mktemp -d "$temp_parent/astrid-cargo-newline.XXXXXX")"
owned_roots+=("$newline_root")
newline_root_with_suffix="${newline_root}"$'\n'
owned_roots+=("$newline_root_with_suffix")
mv -- "$newline_root" "$newline_root_with_suffix"
newline_root="$newline_root_with_suffix"
echo "configured_root=$configured_root"
echo "relative_root=$relative_root"
echo "absolute_root=$absolute_root"
echo "escaped_backslash_root=$escaped_backslash_root"
echo "escaped_quote_root=$escaped_quote_root"
printf 'newline_root=%q\n' "$newline_root"

run_layout_probe \
  "unset CARGO_TARGET_DIR with external Cargo target configuration" \
  "$configured_root" configured
run_layout_probe \
  "relative explicit CARGO_TARGET_DIR normalized by run.sh" \
  "$relative_root" relative
run_layout_probe \
  "absolute explicit CARGO_TARGET_DIR preserved by run.sh" \
  "$absolute_root" absolute
run_layout_probe \
  "JSON escaped backslash target root decoded by run.sh" \
  "$escaped_backslash_root" configured
run_layout_probe \
  "JSON escaped quote target root decoded by run.sh" \
  "$escaped_quote_root" configured

run_check_metadata_probe "$escaped_backslash_root"
run_check_metadata_probe "$escaped_quote_root"
run_newline_rejection_probe "$newline_root"

run_check_relative "$relative_root"

# Build kimage once in the configured and explicit roots. This exercises the
# parent host target, nested bootloader target, and build.rs handoff in
# addition to the lightweight run.sh/ktest layout probes above.
run_kimage_check "configured shared-root kimage + nested UEFI" "$configured_root"
run_kimage_check "explicit shared-root kimage + nested UEFI" "$absolute_root"
run_kimage_metadata_check "$escaped_backslash_root"
run_kimage_metadata_check "$escaped_quote_root"

echo "target regression: PASS (run.sh/ktest layout and nested kimage; no kernel/target or tools/bootloader/target)"
