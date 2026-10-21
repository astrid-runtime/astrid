#!/usr/bin/env bash
# Exercise authenticated quota writes against an isolated real daemon.
set -euo pipefail
if [[ $# != 1 || "$1" != /* || ! -x "$1" ]]; then
  echo 'usage: test-quota-self-ceilings.sh /absolute/candidate/astrid' >&2
  exit 2
fi
cli=$1
test_root=$(mktemp -d /tmp/astrid-quota-ceilings.XXXXXX)
export ASTRID_HOME="$test_root/runtime"
export ASTRID_PRINCIPAL=default
unset ASTRID_RUN_DIR ASTRID_ENFORCED_DISTRO ASTRID_CLIENT_CONFIG_PATH
mkdir -m 700 "$ASTRID_HOME"
cd "$test_root"
cleanup() {
  local result=$?
  trap - EXIT
  if ! "$cli" stop > cleanup.log 2>&1; then
    echo "Disposable runtime cleanup failed: $test_root/cleanup.log" >&2
    result=1
  fi
  echo "Retained test evidence: $test_root"
  exit "$result"
}
trap cleanup EXIT
assert_processes() {
  "$cli" quota show --agent quota-child --format json > "$1"
  python3 - "$1" "$2" <<'PY'
import json
import sys
quota = json.load(open(sys.argv[1], encoding="utf-8"))
assert quota["max_background_processes"] == int(sys.argv[2]), quota
PY
}
refuse_self_increase() {
  if "$cli" --principal quota-child quota set --agent quota-child --processes "$1" > "$2" 2>&1; then
    echo 'Self-scoped principal raised its allocation' >&2
    exit 1
  fi
  grep -q 'increasing resource quotas requires quota:set' "$2"
}

shasum -a 256 "$cli" > candidate.sha256
"$cli" start > start.log 2>&1
"$cli" agent create quota-child > create.log 2>&1
"$cli" quota set --agent quota-child --processes 5 > operator-set.log 2>&1
assert_processes before.json 5
refuse_self_increase 6 refused-increase.log
assert_processes after-refusal.json 5
cmp before.json after-refusal.json
"$cli" --principal quota-child quota set --agent quota-child --processes 4 > self-reduce.log 2>&1
assert_processes after-reduction.json 4
refuse_self_increase 5 refused-restore.log
assert_processes after-restore-refusal.json 4
"$cli" quota set --agent quota-child --processes 5 > operator-restore.log 2>&1
assert_processes restored.json 5
"$cli" stop > stop.log 2>&1
"$cli" start > restart.log 2>&1
assert_processes restarted.json 5
refuse_self_increase 6 refused-after-restart.log
echo 'PASS: authenticated self attenuation, refusal without mutation, operator increase, restart'
