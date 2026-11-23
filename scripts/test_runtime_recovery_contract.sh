#!/usr/bin/env bash
# Fake-cargo contracts for scripts/ci/test-runtime-recovery.sh.
# Proves missing / ignored / non-executed named cases fail even when passed >= 8.
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
script="$repo_root/scripts/ci/test-runtime-recovery.sh"
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

extras=(
  occupied_pool_cannot_outlive_the_invocation_deadline
  admission_wait_spends_the_real_guest_invocation_deadline
)

fail() {
  echo "runtime recovery contract: $*" >&2
  exit 1
}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin"

write_cargo() {
  local fixture=$1
  cat >"$work/bin/cargo" <<CARGO
#!/usr/bin/env bash
set -euo pipefail
fixture="$fixture"
args=("\$@")
listing=false
for arg in "\${args[@]}"; do
  if [[ "\$arg" == "--list" ]]; then
    listing=true
  fi
done
if [[ "\$listing" == true ]]; then
  cat "\$fixture/list"
  exit 0
fi
cat "\$fixture/result"
if grep -Fq 'FAILED' "\$fixture/result"; then
  exit 101
fi
exit 0
CARGO
  chmod +x "$work/bin/cargo"
}

write_list() {
  local fixture=$1
  shift
  : >"$fixture/list"
  local name
  for name in "$@"; do
    printf '%s::%s: test\n' "$module" "$name" >>"$fixture/list"
  done
}

write_result_ok() {
  local fixture=$1
  shift
  : >"$fixture/result"
  local name
  local count=0
  for name in "$@"; do
    printf 'test %s::%s ... ok\n' "$module" "$name" >>"$fixture/result"
    count=$((count + 1))
  done
  printf 'test result: ok. %s passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n' \
    "$count" >>"$fixture/result"
}

run_script() {
  env PATH="$work/bin:/usr/bin:/bin" bash "$script"
}

pass_fix=$work/pass
mkdir -p "$pass_fix"
write_list "$pass_fix" "${regressions[@]}" "${extras[@]}"
write_result_ok "$pass_fix" "${regressions[@]}" "${extras[@]}"
write_cargo "$pass_fix"
run_script || fail "expected happy path to pass"

missing_fix=$work/missing
mkdir -p "$missing_fix"
write_list "$missing_fix" "${regressions[@]:1}" "${extras[@]}"
write_result_ok "$missing_fix" "${regressions[@]:1}" "${extras[@]}"
write_cargo "$missing_fix"
if run_script >/dev/null 2>"$work/missing.err"; then
  fail "missing named list entry must fail"
fi
grep -Fq "runtime recovery regression is missing: ${regressions[0]}" "$work/missing.err" \
  || fail "missing case must name the absent regression"

ignored_fix=$work/ignored
mkdir -p "$ignored_fix"
write_list "$ignored_fix" "${regressions[@]}" "${extras[@]}"
{
  for name in "${regressions[@]:1}" "${extras[@]}"; do
    printf 'test %s::%s ... ok\n' "$module" "$name"
  done
  printf 'test %s::%s ... ignored\n' "$module" "${regressions[0]}"
  echo 'test result: ok. 9 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out'
} >"$ignored_fix/result"
write_cargo "$ignored_fix"
if run_script >/dev/null 2>"$work/ignored.err"; then
  fail "ignored named case must fail"
fi
grep -Fq "runtime recovery regression was ignored: ${regressions[0]}" "$work/ignored.err" \
  || fail "ignored case must be reported"

absent_fix=$work/absent
mkdir -p "$absent_fix"
write_list "$absent_fix" "${regressions[@]}" "${extras[@]}"
{
  for name in "${regressions[@]:1}" "${extras[@]}" filler_keeps_count_high; do
    printf 'test %s::%s ... ok\n' "$module" "$name"
  done
  echo 'test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out'
} >"$absent_fix/result"
write_cargo "$absent_fix"
if run_script >/dev/null 2>"$work/absent.err"; then
  fail "non-executed named case must fail even when passed >= 8"
fi
grep -Fq "runtime recovery regression did not execute: ${regressions[0]}" "$work/absent.err" \
  || fail "absent result line must be reported"

echo "runtime recovery contract: PASS"
