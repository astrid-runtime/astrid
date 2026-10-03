#!/usr/bin/env bash
# Exercise operator attribution using discovered identities, never live homes.
set -euo pipefail
if [[ $# != 1 || "$1" != /* || ! -x "$1" ]]; then
  echo 'usage: test-resource-user-recovery.sh /absolute/candidate/astrid' >&2
  exit 2
fi
cli=$1
test_root=$(mktemp -d /tmp/astrid-resource-user.XXXXXX)
export ASTRID_HOME="$test_root/runtime" ASTRID_PRINCIPAL=default
unset ASTRID_RUN_DIR ASTRID_ENFORCED_DISTRO ASTRID_CLIENT_CONFIG_PATH
mkdir -m 700 "$ASTRID_HOME"
cd "$test_root"
cleanup() {
  local result=$?
  trap - EXIT
  if ! "$cli" stop > cleanup.log 2>&1; then result=1; fi
  echo "Retained test evidence: $test_root"
  exit "$result"
}
trap cleanup EXIT
"$cli" start > start.log 2>&1
"$cli" agent create recovery-child > create.log 2>&1
"$cli" agent list --mine --format json > before.json
user=$(python3 - <<'PY'
import json
rows = {row['principal']: row for row in json.load(open('before.json'))}
user = rows['default']['accountable_user']
assert rows['recovery-child']['accountable_user'] == user, rows
assert len(user) == 64 and all(c in '0123456789abcdef' for c in user), user
print(user)
PY
)
for attempt in 1 2; do
  "$cli" quota assign-user --agent recovery-child --user "$user" > "assign-$attempt.log" 2>&1
done
if "$cli" --principal recovery-child quota assign-user --agent recovery-child --user "$user" > self-denied.log 2>&1; then
  echo 'Child assigned its own resource user' >&2; exit 1
fi
grep -q 'missing capability quota:set' self-denied.log
if "$cli" quota assign-user --agent recovery-child --user "$(printf '%064d' 0)" > transfer-denied.log 2>&1; then
  echo 'Recovery command replaced the existing payer' >&2; exit 1
fi
grep -q 'already has an accountable user' transfer-denied.log
"$cli" agent list --mine --format json > after.json
cmp before.json after.json
"$cli" stop > stop.log 2>&1
"$cli" start > restart.log 2>&1
"$cli" agent list --mine --format json > restarted.json
cmp before.json restarted.json
echo 'PASS: discovered payer, idempotent operator assignment, self/transfer denial, restart persistence'
