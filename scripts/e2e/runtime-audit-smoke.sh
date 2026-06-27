#!/usr/bin/env bash

collect_audit_artifacts() {
  local user_bearer=$1
  local ops_bearer=$2
  local user_principal=$3
  local ops_principal=$4
  local paired_key_id=$5
  shift 5
  local status

  status="$(http_status GET "/api/sys/audit?limit=1000" "$user_bearer" "" "$ARTIFACTS/agent-audit.json")"
  assert_status "agent scoped audit export" "$status" 200
  status="$(http_status GET "/api/sys/audit?limit=1000" "$ops_bearer" "" "$ARTIFACTS/operator-audit.json")"
  assert_status "operator scoped audit export" "$status" 200
  json_assert_audit_scope_and_events "$ARTIFACTS/agent-audit.json" "$user_principal" \
    admin.auth.pair.issue:success \
    admin.auth.pair.issue:failure \
    admin.invite.issue:failure
  json_assert_audit_token_evidence_and_redaction "$ARTIFACTS/agent-audit.json" "$paired_key_id" "$@"
  json_assert_audit_scope_and_events "$ARTIFACTS/operator-audit.json" "$ops_principal" \
    admin.invite.issue:success \
    admin.agent.delete:failure \
    admin.auth.pair.issue:failure \
    admin.caps.grant:failure
}

json_assert_audit_token_evidence_and_redaction() {
  local file=$1
  local paired_key_id=$2
  shift 2
  "$PYTHON" - "$file" "$paired_key_id" "$@" <<'PY'
import json
import sys

path = sys.argv[1]
paired_key_id = sys.argv[2]
forbidden_values = [value for value in sys.argv[3:] if value]
data = json.load(open(path, encoding="utf-8"))
entries = data.get("entries", [])
blob = json.dumps(data, sort_keys=True)

for forbidden in forbidden_values:
    if forbidden in blob:
        raise SystemExit("audit response leaked raw token or bearer material")

for marker in ("Authorization: Bearer", "session_token", "DO_NOT_LEAK"):
    if marker in blob:
        raise SystemExit(f"audit response leaked sensitive marker {marker!r}")

def walk(value):
    if isinstance(value, dict):
        for key, nested in value.items():
            if key in {"token", "public_key", "session_token", "authorization"}:
                raise SystemExit(f"audit response leaked raw sensitive field {key!r}: {value!r}")
            walk(nested)
    elif isinstance(value, list):
        for nested in value:
            walk(nested)

walk(data)

if not any(
    entry.get("method") == "admin.auth.pair.issue"
    and entry.get("outcome") == "failure"
    and entry.get("device_key_id") == paired_key_id
    for entry in entries
):
    summary = [
        {
            "method": entry.get("method"),
            "outcome": entry.get("outcome"),
            "device_key_id": entry.get("device_key_id"),
        }
        for entry in entries
    ]
    raise SystemExit(
        "audit response missed paired-device token-authenticated denial "
        f"for key {paired_key_id!r}; saw {summary!r}"
    )
PY
}
