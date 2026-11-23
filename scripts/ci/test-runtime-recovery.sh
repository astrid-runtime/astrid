#!/usr/bin/env bash
# Qualify the eight named interrupted-instance recovery regressions.
# Fail closed if any named case is missing, ignored, or not executed as ok,
# even when other module tests keep passed >= 8.
set -euo pipefail

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

module=engine::wasm::interruption_tests
regressions=(
  fuel_interruption_denies_instead_of_returning_a_skippable_error
  fuel_interruption_discards_mutated_guest_state
  fixed_size_pool_replaces_a_trapped_instance
  successful_calls_keep_the_warm_guest_instance
  epoch_interruption_denies_and_recovers
  guest_trap_denies_instead_of_skipping_the_guard
  cancelled_call_discards_mutated_guest_state
  fuel_interruption_halts_the_real_dispatcher_chain_then_recovers
)

cargo test --locked -p astrid-capsule --lib "$module" -- --list >"$work/list"
for regression in "${regressions[@]}"; do
  grep -Fxq "$module::$regression: test" "$work/list" || {
    echo "runtime recovery regression is missing: $regression" >&2
    exit 1
  }
done

cargo test --locked -p astrid-capsule --lib "$module" | tee "$work/result"

for regression in "${regressions[@]}"; do
  line=$(grep -E "^test ${module}::${regression} " "$work/result" || true)
  if [[ -z "$line" ]]; then
    echo "runtime recovery regression did not execute: $regression" >&2
    exit 1
  fi
  case "$line" in
    *"... ignored")
      echo "runtime recovery regression was ignored: $regression" >&2
      exit 1
      ;;
    *"FAILED")
      echo "runtime recovery regression failed: $regression" >&2
      exit 1
      ;;
    *"... ok")
      ;;
    *)
      echo "runtime recovery regression did not pass: $regression ($line)" >&2
      exit 1
      ;;
  esac
done
