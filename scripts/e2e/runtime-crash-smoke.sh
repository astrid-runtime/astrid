#!/usr/bin/env bash

crash_daemon_process() {
  [[ -n "$DAEMON_PID" ]] || fail "cannot crash daemon: no daemon pid recorded"
  kill -KILL "$DAEMON_PID" 2>/dev/null || true
  wait "$DAEMON_PID" 2>/dev/null || true
  DAEMON_PID=""
}

run_crash_recovery_smoke() {
  local user_bearer=$1
  local ops_bearer=$2
  local user_principal=$3
  local user_session=$4
  local ops_session=$5

  note "checking crash recovery after abrupt daemon death"
  crash_daemon_process
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
