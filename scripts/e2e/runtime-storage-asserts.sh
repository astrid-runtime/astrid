#!/usr/bin/env bash

assert_user_only_model_fallback_in_storage() {
  local capsule=$1
  local default_principal=$2
  local user_principal=$3
  local ops_principal=$4
  local default_bearer=$5
  local user_bearer=$6
  local ops_bearer=$7
  local model=$8
  local mode=$9
  local deadline status

  json_assert_no_native_capsule_env "$ASTRID_HOME" "$capsule" "$default_principal" \
    "$user_principal" "$ops_principal"

  deadline=$((SECONDS + 45))
  while true; do
    status="$(http_status GET /api/models "$default_bearer" "" \
      "$ARTIFACTS/adversarial-env-model-default.json")"
    [[ "$status" == 200 ]] || fail "default model catalog returned HTTP $status"
    status="$(http_status GET /api/models "$user_bearer" "" \
      "$ARTIFACTS/adversarial-env-model-user.json")"
    [[ "$status" == 200 ]] || fail "user model catalog returned HTTP $status"
    status="$(http_status GET /api/models "$ops_bearer" "" \
      "$ARTIFACTS/adversarial-env-model-ops.json")"
    [[ "$status" == 200 ]] || fail "operator model catalog returned HTTP $status"
    if "$PYTHON" - "$ARTIFACTS" "$model" "$mode" <<'PY'
import json
import sys
from pathlib import Path

artifacts = Path(sys.argv[1])
model = f"openai-compat:{sys.argv[2]}"
mode = sys.argv[3]

def ids(name: str) -> set[str]:
    data = json.loads((artifacts / name).read_text(encoding="utf-8"))
    if isinstance(data, dict):
        data = data.get("data", [])
    return {entry.get("id") for entry in data if isinstance(entry, dict)}

default = ids("adversarial-env-model-default.json")
user = ids("adversarial-env-model-user.json")
ops = ids("adversarial-env-model-ops.json")
expected = model in user and model not in default and model not in ops
if mode == "user-present":
    expected = model in user
elif mode == "absent":
    expected = model not in default and model not in user and model not in ops
if not expected:
    raise SystemExit(1)
PY
    then
      return
    fi
    (( SECONDS < deadline )) || fail "governed model fallback did not reach expected scope"
    sleep 1
  done
}
