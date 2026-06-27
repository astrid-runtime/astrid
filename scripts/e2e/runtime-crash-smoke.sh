#!/usr/bin/env bash

crash_daemon_process() {
  [[ -n "$DAEMON_PID" ]] || fail "cannot crash daemon: no daemon pid recorded"
  kill -KILL "$DAEMON_PID" 2>/dev/null || true
  wait "$DAEMON_PID" 2>/dev/null || true
  DAEMON_PID=""
}

wait_for_fake_llm_prompt() {
  local prompt=$1
  local deadline=$((SECONDS + 10))
  until "$PYTHON" - "$ARTIFACTS/fake-openai.jsonl" "$prompt" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
prompt = sys.argv[2]
if not path.exists():
    raise SystemExit(1)

for line in path.read_text(encoding="utf-8").splitlines():
    if not line.strip():
        continue
    entry = json.loads(line)
    if entry.get("method") != "POST" or entry.get("path") != "/v1/chat/completions":
        continue
    if prompt in json.dumps(entry.get("messages", []), sort_keys=True):
        raise SystemExit(0)
raise SystemExit(1)
PY
  do
    if (( SECONDS >= deadline )); then
      return 1
    fi
    sleep 0.1
  done
}

run_inflight_prompt_crash_smoke() {
  local principal=$1
  local session=$2
  local prompt="ASTRID_E2E_INFLIGHT_CRASH_$RANDOM$RANDOM"
  local out="$ARTIFACTS/crash-inflight-run.txt"
  local rc=0

  note "checking crash recovery while a prompt is in flight"
  bounded_principal_run "$principal" 12 "$out" --format json --session "$session" "$prompt" &
  local run_pid=$!
  wait_for_fake_llm_prompt "$prompt" || {
    terminate_pid "$run_pid"
    cat "$out" >&2 2>/dev/null || true
    fail "in-flight crash prompt did not reach fake LLM before deadline"
  }

  crash_daemon_process
  wait "$run_pid" || rc=$?
  if [[ "$rc" -eq 0 ]]; then
    cat "$out" >&2
    fail "in-flight prompt unexpectedly succeeded after daemon crash"
  fi
  if [[ "$rc" -eq 124 ]]; then
    cat "$out" >&2
    fail "in-flight prompt hung until timeout after daemon crash"
  fi
  assert_fake_llm_request_model "$ARTIFACTS/fake-openai.jsonl" "$prompt" "fake-slow"
}

run_crash_recovery_smoke() {
  local user_bearer=$1
  local ops_bearer=$2
  local user_principal=$3
  local user_session=$4
  local ops_session=$5

  run_inflight_prompt_crash_smoke "$user_principal" "$user_session"
  start_daemon "restarting daemon after abrupt process death"

  local status
  status="$(http_status GET /api/auth/me "$user_bearer" "" "$ARTIFACTS/crash-restart-agent-me.json")"
  assert_status "crash restart agent auth/me" "$status" 200
  json_assert_field_equals "$ARTIFACTS/crash-restart-agent-me.json" principal "$user_principal"

  status="$(http_status GET /api/models/active "$user_bearer" "" \
    "$ARTIFACTS/crash-restart-agent-active-model.json")"
  assert_status "crash restart agent active model" "$status" 200
  json_assert_model_id "$ARTIFACTS/crash-restart-agent-active-model.json" "openai-compat:fake-slow"

  status="$(http_status GET /api/models/active "$ops_bearer" "" \
    "$ARTIFACTS/crash-restart-operator-active-model.json")"
  assert_status "crash restart operator active model" "$status" 200
  json_assert_model_id "$ARTIFACTS/crash-restart-operator-active-model.json" "openai-compat:fake-toolish"

  status="$(http_status GET "/api/agent/sessions?include_archived=true&limit=20" "$user_bearer" "" \
    "$ARTIFACTS/crash-restart-agent-sessions.json")"
  assert_status "crash restart agent session list" "$status" 200
  json_assert_session_list_scope "$ARTIFACTS/crash-restart-agent-sessions.json" "$user_session" "$ops_session"

  status="$(http_status GET "/api/agent/sessions/$ops_session" "$user_bearer" "" \
    "$ARTIFACTS/crash-restart-agent-cross-session-get-hidden.json")"
  assert_status "crash restart cross-principal session get hidden" "$status" 404
}
