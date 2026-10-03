#!/usr/bin/env bash
# Test fixture isolation by executing the real HTTP sweep with a stateful stub.
# This is a harness regression, not evidence of a real gateway journey.
set -euo pipefail
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
PYTHON=${PYTHON:-python3}
ARTIFACTS=$(mktemp -d)
trap 'rm -r -- "$ARTIFACTS"' EXIT
export ARTIFACTS
# shellcheck source=e2e/runtime-gateway-smoke.sh
source "${1:-$SCRIPT_DIR/e2e/runtime-gateway-smoke.sh}"

http_status() {
  "$PYTHON" - "$@" <<'PY'
import json
import os
import sys

method, path, bearer, body, output = sys.argv[1:]
state_path = os.path.join(os.environ["ARTIFACTS"], "state.json")
state = json.load(open(state_path, encoding="utf-8"))
status = 200
reply = state
if "/other/" in path and bearer == "user":
    status, reply = 403, {}
elif path.endswith("/usage"):
    reply = {"principal": "worker"}
elif method == "PUT":
    requested = json.loads(body)["quotas"]
    if bearer == "user" and requested["max_background_processes"] > state["max_background_processes"]:
        status, reply = 403, {}
    else:
        state = requested
        reply = state
        with open(state_path, "w", encoding="utf-8") as stream:
            json.dump(state, stream)
with open(output, "w", encoding="utf-8") as stream:
    json.dump(reply, stream)
print(status)
PY
}

assert_status() { [[ "$2" == "$3" ]] || { echo "$1: expected $3 got $2" >&2; return 1; }; }
json_assert_field_equals() {
  "$PYTHON" - "$@" <<'PY'
import json
import sys
assert str(json.load(open(sys.argv[1], encoding="utf-8"))[sys.argv[2]]) == sys.argv[3]
PY
}
json_assert_usage_principal() { json_assert_field_equals "$1" principal "$2"; }

# Different initial quotas ensure restoration follows the snapshot, not a
# replacement hard-coded number. Keep another field to catch partial restores.
for initial in 4 8; do
  "$PYTHON" - "$ARTIFACTS/state.json" "$initial" <<'PY'
import json
import sys
with open(sys.argv[1], "w", encoding="utf-8") as stream:
    json.dump({"max_background_processes": int(sys.argv[2]), "max_memory_bytes": 123456}, stream)
PY
  run_gateway_quota_write_smoke worker other user admin
  json_assert_field_equals "$ARTIFACTS/state.json" max_background_processes "$initial"
  json_assert_field_equals "$ARTIFACTS/state.json" max_memory_bytes 123456
done
echo 'PASS: quota HTTP sweep restores the original shared fixture'
