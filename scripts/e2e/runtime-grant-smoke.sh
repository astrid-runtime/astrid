#!/usr/bin/env bash

json_capsule_list_has_state() {
  json_assert_capsule_list_state "$@" >/dev/null 2>&1
}

wait_for_grant_request_id() {
  local path=$1
  local principal=$2
  local capsule=$3
  local deadline=$((SECONDS + 10))
  local python_bin="${PYTHON:-python3}"
  local request_id
  until request_id="$("$python_bin" - "$path" "$principal" "$capsule" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
principal = sys.argv[2]
capsule = sys.argv[3]
if not path.exists():
    raise SystemExit(1)

text = path.read_text(encoding="utf-8", errors="replace")
for block in text.split("\n\n"):
    event = None
    data_lines = []
    for line in block.splitlines():
        if line.startswith("event:"):
            event = line.split(":", 1)[1].strip()
        elif line.startswith("data:"):
            data_lines.append(line.split(":", 1)[1].strip())
    if event != "approval" or not data_lines:
        continue
    try:
        payload = json.loads("\n".join(data_lines))
    except json.JSONDecodeError:
        continue
    if payload.get("type") != "grant_required":
        continue
    if payload.get("principal") != principal or payload.get("capsule_id") != capsule:
        continue
    request_id = payload.get("request_id")
    if request_id:
        print(request_id)
        raise SystemExit(0)
raise SystemExit(1)
PY
  )"; do
    if (( SECONDS >= deadline )); then
      return 1
    fi
    sleep 0.1
  done
  printf '%s\n' "$request_id"
}

wait_for_capsule_visibility() {
  local bearer=$1
  local capsule=$2
  local expected=$3
  local out=$4
  local deadline=$((SECONDS + 10))
  local status
  until (( SECONDS >= deadline )); do
    status="$(http_status GET /api/capsules "$bearer" "" "$out")"
    assert_status "capsule visibility poll" "$status" 200
    if json_capsule_list_has_state "$out" "$capsule" "$expected"; then
      return 0
    fi
    sleep 0.2
  done
  return 1
}

run_grant_on_use_smoke() {
  local user_bearer=$1
  local user_principal=$2
  local status
  local grant_capsule=astrid-capsule-adversarial

  note "checking live grant-on-use request stream and response path"
  run_cli agent modify "$user_principal" --remove-capsule "$grant_capsule"
  wait_for_capsule_visibility "$user_bearer" "$grant_capsule" absent \
    "$ARTIFACTS/adversarial-grant-on-use-hidden-before.json" \
    || fail "grant-on-use setup did not hide $grant_capsule from $user_principal"

  local deny_sse="$ARTIFACTS/adversarial-grant-on-use-deny.sse"
  local deny_out="$ARTIFACTS/adversarial-grant-on-use-deny-cli.txt"
  curl -sN --max-time 20 \
    -H "Authorization: Bearer $user_bearer" \
    "$GATEWAY/api/agent/requests" \
    > "$deny_sse" 2>&1 &
  local deny_stream_pid=$!
  wait_for_sse_ready "$deny_sse" || {
    terminate_pid "$deny_stream_pid"
    cat "$deny_sse" >&2 2>/dev/null || true
    fail "grant-on-use deny stream did not become ready"
  }
  bounded_principal_cli "$user_principal" 10 "$deny_out" \
    capsule run "$grant_capsule" adversarial &
  local deny_cli_pid=$!
  local deny_request_id
  deny_request_id="$(wait_for_grant_request_id "$deny_sse" "$user_principal" "$grant_capsule")" || {
    terminate_pid "$deny_cli_pid"
    terminate_pid "$deny_stream_pid"
    cat "$deny_sse" >&2 2>/dev/null || true
    fail "grant-on-use deny stream did not forward grant_required"
  }
  terminate_pid "$deny_cli_pid"
  status="$(http_status POST /api/agent/approval-response "$user_bearer" \
    "{\"request_id\":\"$deny_request_id\",\"decision\":\"deny\",\"reason\":\"runtime e2e grant deny\"}" \
    "$ARTIFACTS/adversarial-grant-on-use-deny-response.json")"
  assert_status "grant-on-use denial response accepted" "$status" 202
  wait "$deny_cli_pid" || true
  terminate_pid "$deny_stream_pid"
  sleep 0.5
  wait_for_capsule_visibility "$user_bearer" "$grant_capsule" absent \
    "$ARTIFACTS/adversarial-grant-on-use-hidden-after-deny.json" \
    || fail "grant-on-use denial unexpectedly granted $grant_capsule"

  local approve_sse="$ARTIFACTS/adversarial-grant-on-use-approve.sse"
  local approve_out="$ARTIFACTS/adversarial-grant-on-use-approve-cli.txt"
  curl -sN --max-time 20 \
    -H "Authorization: Bearer $user_bearer" \
    "$GATEWAY/api/agent/requests" \
    > "$approve_sse" 2>&1 &
  local approve_stream_pid=$!
  wait_for_sse_ready "$approve_sse" || {
    terminate_pid "$approve_stream_pid"
    cat "$approve_sse" >&2 2>/dev/null || true
    fail "grant-on-use approve stream did not become ready"
  }
  bounded_principal_cli "$user_principal" 10 "$approve_out" \
    capsule run "$grant_capsule" adversarial &
  local approve_cli_pid=$!
  local approve_request_id
  approve_request_id="$(wait_for_grant_request_id "$approve_sse" "$user_principal" "$grant_capsule")" || {
    terminate_pid "$approve_cli_pid"
    terminate_pid "$approve_stream_pid"
    cat "$approve_sse" >&2 2>/dev/null || true
    fail "grant-on-use approve stream did not forward grant_required"
  }
  terminate_pid "$approve_cli_pid"
  status="$(http_status POST /api/agent/approval-response "$user_bearer" \
    "{\"request_id\":\"$approve_request_id\",\"decision\":\"approve\",\"reason\":\"runtime e2e grant approve\"}" \
    "$ARTIFACTS/adversarial-grant-on-use-approve-response.json")"
  assert_status "grant-on-use approval response accepted" "$status" 202
  wait "$approve_cli_pid" || true
  terminate_pid "$approve_stream_pid"
  wait_for_capsule_visibility "$user_bearer" "$grant_capsule" present \
    "$ARTIFACTS/adversarial-grant-on-use-visible-after-approve.json" \
    || fail "grant-on-use approval did not grant $grant_capsule"
  run_principal_cli "$user_principal" capsule run "$grant_capsule" adversarial \
    > "$ARTIFACTS/adversarial-grant-on-use-post-grant.json"
  json_assert_adversarial_probe_report "$ARTIFACTS/adversarial-grant-on-use-post-grant.json"
}
