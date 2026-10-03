#!/usr/bin/env bash
set -euo pipefail

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
module=engine::wasm::interruption_tests
cargo test --locked -p astrid-capsule --lib "$module" -- --list > "$work/list"
for regression in \
  fuel_interruption_denies_instead_of_returning_a_skippable_error \
  fuel_interruption_discards_mutated_guest_state \
  fixed_size_pool_replaces_a_trapped_instance \
  successful_calls_keep_the_warm_guest_instance \
  epoch_interruption_denies_and_recovers \
  guest_trap_denies_instead_of_skipping_the_guard \
  cancelled_call_discards_mutated_guest_state \
  fuel_interruption_halts_the_real_dispatcher_chain_then_recovers; do
  grep -Fxq "$module::$regression: test" "$work/list" || {
    echo "runtime recovery regression is missing: $regression" >&2
    exit 1
  }
done
cargo test --locked -p astrid-capsule --lib "$module" | tee "$work/result"
summary=$(grep '^test result: ok\.' "$work/result")
pattern='^test result: ok\. ([0-9]+) passed; 0 failed; 0 ignored;'
[[ "$summary" =~ $pattern ]] && [[ "${BASH_REMATCH[1]}" -ge 8 ]] || {
  echo 'runtime recovery suite did not execute all regressions' >&2
  exit 1
}
