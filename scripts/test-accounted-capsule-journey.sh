#!/usr/bin/env bash
# Real lifecycle/background/CLI use under an operator-configured user budget.
set -euo pipefail
if [[ $# != 1 || "$1" != /* || ! -x "$1" ]]; then
  echo 'usage: test-accounted-capsule-journey.sh /absolute/candidate/astrid' >&2
  exit 2
fi
cli=$1
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
test_root=$(mktemp -d /tmp/astrid-accounted-capsule.XXXXXX)
export ASTRID_HOME="$test_root/runtime"
export ASTRID_PRINCIPAL=default
unset ASTRID_RUN_DIR ASTRID_ENFORCED_DISTRO ASTRID_CLIENT_CONFIG_PATH
mkdir -m 700 "$ASTRID_HOME"
cd "$test_root"
run() {
  python3 - "$cli" "$@" <<'PY'
import subprocess
import sys
try:
    result = subprocess.run(sys.argv[1:], timeout=90, check=False)
except subprocess.TimeoutExpired:
    raise SystemExit("candidate command exceeded 90 seconds")
raise SystemExit(result.returncode)
PY
}
cleanup() {
  local result=$?
  trap - EXIT
  if ! run stop > cleanup.log 2>&1; then
    echo "Disposable runtime cleanup failed: $test_root/cleanup.log" >&2
    result=1
  fi
  echo "Retained test evidence: $test_root"
  exit "$result"
}
trap cleanup EXIT
shasum -a 256 "$cli" "$(dirname -- "$cli")/astrid-daemon" > candidate.sha256
# Bootstrap the setup-free personal home, then configure its running projection.
# Writing sidecars into a fresh/stopped volume-only root is not permitted.
run start > initial-start.log 2>&1
# This is an explicitly configured test operator, not a product default.
printf '[resources]\ndefault_user_cpu_fuel_per_sec = 100000000\n' > "$ASTRID_HOME/config.toml"
run stop > configure-stop.log 2>&1
run start > start.log 2>&1
grep -Fq 'default_user_cpu_fuel_per_sec = 100000000' "$ASTRID_HOME/config.toml"
run capsule install --yes --var adversarial_lifecycle_probe=runtime-lifecycle-ok \
  "$repo/e2e/fixtures/astrid-capsule-adversarial" > install.log 2>&1
run capsule run astrid-capsule-adversarial adversarial-home-ready > before.txt
grep -Fq 'adversarial lifecycle home mounted' before.txt
run capsule run astrid-capsule-adversarial adversarial > capabilities.json
python3 - capabilities.json <<'PY'
import json
import sys
result = json.load(open(sys.argv[1]))
assert result == {
    "undeclared_publish_denied": True,
    "undeclared_subscribe_denied": True,
    "invalid_subscribe_denied": True,
}, result
PY
run stop > stop.log 2>&1
python3 - "$ASTRID_HOME" <<'PY'
import os
import sys
assert sorted(os.listdir(sys.argv[1])) == ["astrid.volume"]
PY
run start > restart.log 2>&1
grep -Fq 'default_user_cpu_fuel_per_sec = 100000000' "$ASTRID_HOME/config.toml"
run capsule run astrid-capsule-adversarial adversarial-home-ready > after.txt
cmp before.txt after.txt
echo 'PASS: configured user budget permits real install, background command, capability enforcement and persisted capsule use after restart'
