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

bounded_principal_cli() {
  local principal=$1
  local timeout_secs=$2
  local out=$3
  shift 3
  "$PYTHON" - "$CORE_DIR/target/debug/astrid" "$principal" "$timeout_secs" "$out" "$@" <<'PY'
import subprocess
import sys
from pathlib import Path

binary = sys.argv[1]
principal = sys.argv[2]
timeout_secs = float(sys.argv[3])
out_path = Path(sys.argv[4])
args = sys.argv[5:]

try:
    proc = subprocess.run(
        [binary, "--principal", principal, *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=timeout_secs,
        check=False,
    )
except subprocess.TimeoutExpired as exc:
    stdout = exc.stdout or ""
    if isinstance(stdout, bytes):
        stdout = stdout.decode("utf-8", errors="replace")
    out_path.write_text(stdout, encoding="utf-8")
    raise SystemExit(124) from exc

out_path.write_text(proc.stdout, encoding="utf-8")
raise SystemExit(proc.returncode)
PY
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
    printf 'in-flight prompt returned bounded success after daemon crash\n' \
      >> "$ARTIFACTS/cli-transcript.log"
  fi
  if [[ "$rc" -eq 124 ]]; then
    cat "$out" >&2
    fail "in-flight prompt hung until timeout after daemon crash"
  fi
  assert_fake_llm_request_model "$ARTIFACTS/fake-openai.jsonl" "$prompt" "fake-slow"
}

run_mid_capsule_command_crash_smoke() {
  local principal=$1
  local out="$ARTIFACTS/crash-capsule-command.txt"
  local rc=0

  note "checking crash recovery while a capsule command is in flight"
  bounded_principal_cli "$principal" 12 "$out" \
    capsule run astrid-capsule-adversarial adversarial-slow &
  local run_pid=$!

  sleep 1
  crash_daemon_process
  wait "$run_pid" || rc=$?
  if [[ "$rc" -eq 0 ]]; then
    printf 'capsule command returned bounded success after daemon crash\n' \
      >> "$ARTIFACTS/cli-transcript.log"
  fi
  if [[ "$rc" -eq 124 ]]; then
    cat "$out" >&2
    fail "in-flight capsule command hung until timeout after daemon crash"
  fi
}

run_mid_approval_wait_crash_smoke() {
  local principal=$1
  local bearer=$2
  local sse="$ARTIFACTS/crash-approval-requests.sse"
  local out="$ARTIFACTS/crash-approval-command.txt"
  local rc=0

  note "checking crash recovery while an approval request is waiting"
  curl -sN --max-time 20 \
    -H "Authorization: Bearer $bearer" \
    "$GATEWAY/api/agent/requests" \
    > "$sse" 2>&1 &
  local stream_pid=$!
  wait_for_sse_ready "$sse" || {
    terminate_pid "$stream_pid"
    cat "$sse" >&2 2>/dev/null || true
    fail "approval crash request stream did not become ready"
  }
  bounded_principal_cli "$principal" 12 "$out" \
    capsule run astrid-capsule-adversarial adversarial-approval &
  local run_pid=$!
  wait_for_approval_request_id "$sse" > "$ARTIFACTS/crash-approval-request-id.txt" || {
    terminate_pid "$run_pid"
    terminate_pid "$stream_pid"
    cat "$sse" >&2 2>/dev/null || true
    fail "approval request was not forwarded before crash deadline"
  }

  crash_daemon_process
  terminate_pid "$stream_pid"
  wait "$run_pid" || rc=$?
  if [[ "$rc" -eq 0 ]]; then
    cat "$out" >&2
    fail "in-flight approval command unexpectedly succeeded after daemon crash"
  fi
  if [[ "$rc" -eq 124 ]]; then
    cat "$out" >&2
    fail "in-flight approval command hung until timeout after daemon crash"
  fi
}

run_mid_elicit_wait_crash_smoke() {
  local principal=$1
  local bearer=$2
  local sse="$ARTIFACTS/crash-elicit-requests.sse"
  local out="$ARTIFACTS/crash-elicit-command.txt"
  local rc=0

  note "checking crash recovery while an elicit request is waiting"
  curl -sN --max-time 20 \
    -H "Authorization: Bearer $bearer" \
    "$GATEWAY/api/agent/requests" \
    > "$sse" 2>&1 &
  local stream_pid=$!
  wait_for_sse_ready "$sse" || {
    terminate_pid "$stream_pid"
    cat "$sse" >&2 2>/dev/null || true
    fail "elicit crash request stream did not become ready"
  }
  bounded_principal_cli "$principal" 12 "$out" \
    capsule run astrid-capsule-adversarial adversarial-elicit &
  local run_pid=$!
  wait_for_elicit_request_id "$sse" > "$ARTIFACTS/crash-elicit-request-id.txt" || {
    terminate_pid "$run_pid"
    terminate_pid "$stream_pid"
    cat "$sse" >&2 2>/dev/null || true
    fail "elicit request was not forwarded before crash deadline"
  }

  crash_daemon_process
  terminate_pid "$stream_pid"
  wait "$run_pid" || rc=$?
  if [[ "$rc" -eq 0 ]]; then
    cat "$out" >&2
    fail "in-flight elicit command unexpectedly succeeded after daemon crash"
  fi
  if [[ "$rc" -eq 124 ]]; then
    cat "$out" >&2
    fail "in-flight elicit command hung until timeout after daemon crash"
  fi
}

run_post_admin_mutation_crash_smoke() {
  local principal="e2e-crash-created"

  note "checking crash recovery immediately after a mutating admin operation"
  run_cli agent create "$principal" --group agent -y
  [[ -f "$ASTRID_HOME/etc/profiles/$principal.toml" ]] \
    || fail "admin mutation did not write profile before crash: $principal"

  crash_daemon_process
  start_daemon "restarting daemon after post-admin-mutation crash"

  run_cli agent show "$principal" --format json > "$ARTIFACTS/crash-admin-created-agent.json"
  json_assert_cli_agent_show "$ARTIFACTS/crash-admin-created-agent.json" "$principal" agent
  json_assert_cli_agent_enabled "$ARTIFACTS/crash-admin-created-agent.json" "$principal" true
}

assert_no_stale_control_requests_after_crashes() {
  local bearer=$1
  local sse="$ARTIFACTS/crash-restart-agent-requests.sse"

  note "checking crash restart has no stale approval or elicit requests"
  curl --connect-timeout 2 \
    --max-time 3 \
    -sS \
    -N \
    -H "Authorization: Bearer $bearer" \
    "$GATEWAY/api/agent/requests" \
    > "$sse" 2>&1 || true
  grep -q '^event: ready' "$sse" || {
    cat "$sse" >&2 || true
    fail "crash restart request stream did not emit ready event"
  }
  if grep -Eq '^event: (approval|elicit)$' "$sse"; then
    cat "$sse" >&2 || true
    fail "crash restart exposed stale approval/elicit request"
  fi
}

run_crash_recovery_smoke() {
  local user_bearer=$1
  local ops_bearer=$2
  local user_principal=$3
  local user_session=$4
  local ops_session=$5

  run_inflight_prompt_crash_smoke "$user_principal" "$user_session"
  start_daemon "restarting daemon after abrupt process death"
  run_mid_capsule_command_crash_smoke "$user_principal"
  start_daemon "restarting daemon after capsule command crash"
  run_mid_approval_wait_crash_smoke "$user_principal" "$user_bearer"
  start_daemon "restarting daemon after approval wait crash"
  run_mid_elicit_wait_crash_smoke "$user_principal" "$user_bearer"
  start_daemon "restarting daemon after elicit wait crash"
  run_post_admin_mutation_crash_smoke

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

  assert_no_stale_control_requests_after_crashes "$user_bearer"
}
