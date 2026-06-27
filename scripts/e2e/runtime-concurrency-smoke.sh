#!/usr/bin/env bash

concurrent_model_write() {
  local bearer=$1 model=$2 status_file=$3 out_file=$4
  http_status PUT /api/models/active "$bearer" "{\"id\":\"$model\"}" "$out_file" > "$status_file"
}

assert_model_write_status() {
  local label=$1 status_file=$2 out_file=$3
  local status
  status="$(<"$status_file")"
  LAST_HTTP_OUT="$out_file"
  assert_status "$label" "$status" 200
}

assert_active_model_for_bearer() {
  local label=$1 bearer=$2 model=$3 out_file=$4
  local status
  status="$(http_status GET /api/models/active "$bearer" "" "$out_file")"
  assert_status "$label" "$status" 200
  json_assert_model_id "$out_file" "$model"
}

concurrent_principal_prompt() {
  local principal=$1 session=$2 out=$3 prompt=$4
  bounded_principal_run "$principal" 30 "$out" --format json --session "$session" "$prompt"
}

concurrent_http_prompt() {
  local bearer=$1 session=$2 prompt=$3 out=$4 status_file=$5
  local body
  body="$("$PYTHON" - "$session" "$prompt" <<'PY'
import json
import sys

print(json.dumps({"session_id": sys.argv[1], "text": sys.argv[2]}))
PY
)"
  curl --connect-timeout 2 \
    --max-time 30 \
    -sS \
    -N \
    -o "$out" \
    -w "%{http_code}" \
    -X POST \
    -H "Authorization: Bearer $bearer" \
    -H "Content-Type: application/json" \
    -d "$body" \
    "$GATEWAY/api/agent/prompt" \
    > "$status_file"
}

concurrent_session_title_update() {
  local bearer=$1 session=$2 title=$3 out=$4 status_file=$5
  local body
  body="$("$PYTHON" - "$title" <<'PY'
import json
import sys

print(json.dumps({"title": sys.argv[1]}))
PY
)"
  curl --connect-timeout 2 \
    --max-time 10 \
    -sS \
    -o "$out" \
    -w "%{http_code}" \
    -X PATCH \
    -H "Authorization: Bearer $bearer" \
    -H "Content-Type: application/json" \
    -d "$body" \
    "$GATEWAY/api/agent/sessions/$session" \
    > "$status_file"
}

assert_http_prompt_stream() {
  local label=$1 out=$2 status_file=$3 principal=$4 expected_text=$5 forbidden_text=$6
  local status
  status="$(<"$status_file")"
  LAST_HTTP_OUT="$out"
  assert_status "$label HTTP prompt" "$status" 200
  grep -q '^event: ready' "$out" || fail "$label HTTP prompt missed ready event"
  grep -q "\"principal\":\"$principal\"" "$out" \
    || fail "$label HTTP prompt ready event missed principal"
  grep -q '^event: response' "$out" || fail "$label HTTP prompt missed response event"
  if [[ "$expected_text" != "-" ]]; then
    grep -Fq "$expected_text" "$out" || fail "$label HTTP prompt missed expected text"
  fi
  if grep -Fq "$forbidden_text" "$out"; then
    cat "$out" >&2 || true
    fail "$label HTTP prompt leaked peer prompt text"
  fi
}

run_concurrent_cli_control_mutation_smoke() {
  local user_principal=$1 ops_principal=$2

  note "checking concurrent CLI capability mutations stay scoped"

  local user_pid ops_pid user_wait=0 ops_wait=0
  run_cli caps grant "$user_principal" system:status \
    > "$ARTIFACTS/concurrent-cli-user-grant.txt" &
  user_pid=$!
  run_cli caps grant "$ops_principal" system:status \
    > "$ARTIFACTS/concurrent-cli-ops-grant.txt" &
  ops_pid=$!

  wait "$user_pid" || user_wait=$?
  wait "$ops_pid" || ops_wait=$?
  [[ "$user_wait" -eq 0 ]] || fail "concurrent user caps grant failed"
  [[ "$ops_wait" -eq 0 ]] || fail "concurrent operator caps grant failed"

  run_cli caps check "$user_principal" system:status \
    > "$ARTIFACTS/concurrent-cli-user-check-granted.txt"
  grep -q "allowed" "$ARTIFACTS/concurrent-cli-user-check-granted.txt" \
    || fail "concurrent user caps grant was not effective"
  run_cli caps check "$ops_principal" system:status \
    > "$ARTIFACTS/concurrent-cli-ops-check-granted.txt"
  grep -q "allowed" "$ARTIFACTS/concurrent-cli-ops-check-granted.txt" \
    || fail "concurrent operator caps grant was not effective"

  run_cli caps revoke "$user_principal" system:status \
    > "$ARTIFACTS/concurrent-cli-user-revoke.txt" &
  user_pid=$!
  run_cli caps revoke "$ops_principal" system:status \
    > "$ARTIFACTS/concurrent-cli-ops-revoke.txt" &
  ops_pid=$!

  user_wait=0
  ops_wait=0
  wait "$user_pid" || user_wait=$?
  wait "$ops_pid" || ops_wait=$?
  [[ "$user_wait" -eq 0 ]] || fail "concurrent user caps revoke failed"
  [[ "$ops_wait" -eq 0 ]] || fail "concurrent operator caps revoke failed"

  run_cli caps check "$user_principal" system:status \
    > "$ARTIFACTS/concurrent-cli-user-check-revoked.txt"
  grep -q "denied" "$ARTIFACTS/concurrent-cli-user-check-revoked.txt" \
    || fail "concurrent user caps revoke was not effective"
  run_cli caps check "$ops_principal" system:status \
    > "$ARTIFACTS/concurrent-cli-ops-check-revoked.txt"
  grep -q "denied" "$ARTIFACTS/concurrent-cli-ops-check-revoked.txt" \
    || fail "concurrent operator caps revoke was not effective"
}

run_concurrent_prompt_correlation_smoke() {
  local user_principal=$1 ops_principal=$2

  note "checking concurrent prompt attribution stays principal-scoped"

  local user_session ops_session user_prompt ops_prompt
  user_session="$("$PYTHON" -c 'import uuid; print(uuid.uuid4())')"
  ops_session="$("$PYTHON" -c 'import uuid; print(uuid.uuid4())')"
  user_prompt="ASTRID_E2E_CONCURRENT_USER_PROMPT_$RANDOM$RANDOM"
  ops_prompt="ASTRID_E2E_CONCURRENT_OPS_PROMPT_$RANDOM$RANDOM"

  local user_pid ops_pid user_wait=0 ops_wait=0
  concurrent_principal_prompt "$user_principal" "$user_session" \
    "$ARTIFACTS/concurrent-prompt-user.txt" "$user_prompt" &
  user_pid=$!
  concurrent_principal_prompt "$ops_principal" "$ops_session" \
    "$ARTIFACTS/concurrent-prompt-ops.txt" "$ops_prompt" &
  ops_pid=$!

  wait "$user_pid" || user_wait=$?
  wait "$ops_pid" || ops_wait=$?
  [[ "$user_wait" -eq 0 ]] || {
    cat "$ARTIFACTS/concurrent-prompt-user.txt" >&2 || true
    fail "agent concurrent prompt failed"
  }
  [[ "$ops_wait" -eq 0 ]] || {
    cat "$ARTIFACTS/concurrent-prompt-ops.txt" >&2 || true
    fail "operator concurrent prompt failed"
  }

  assert_fake_llm_request_model "$ARTIFACTS/fake-openai.jsonl" "$user_prompt" "fake-slow"
  assert_fake_llm_request_model "$ARTIFACTS/fake-openai.jsonl" "$ops_prompt" "fake-toolish"
}

run_concurrent_http_prompt_correlation_smoke() {
  local user_bearer=$1 ops_bearer=$2 user_principal=$3 ops_principal=$4

  note "checking concurrent HTTP prompt streams stay principal-scoped"

  local user_session ops_session user_prompt ops_prompt
  user_session="$("$PYTHON" -c 'import uuid; print(uuid.uuid4())')"
  ops_session="$("$PYTHON" -c 'import uuid; print(uuid.uuid4())')"
  user_prompt="ASTRID_E2E_HTTP_USER_PROMPT_$RANDOM$RANDOM"
  ops_prompt="ASTRID_E2E_HTTP_OPS_PROMPT_$RANDOM$RANDOM"

  local user_out="$ARTIFACTS/concurrent-http-prompt-user.sse"
  local ops_out="$ARTIFACTS/concurrent-http-prompt-ops.sse"
  local user_status="$ARTIFACTS/concurrent-http-prompt-user.status"
  local ops_status="$ARTIFACTS/concurrent-http-prompt-ops.status"
  local user_pid ops_pid user_wait=0 ops_wait=0

  concurrent_http_prompt "$user_bearer" "$user_session" "$user_prompt" \
    "$user_out" "$user_status" &
  user_pid=$!
  concurrent_http_prompt "$ops_bearer" "$ops_session" "$ops_prompt" \
    "$ops_out" "$ops_status" &
  ops_pid=$!

  wait "$user_pid" || user_wait=$?
  wait "$ops_pid" || ops_wait=$?
  [[ "$user_wait" -eq 0 ]] || {
    cat "$user_out" >&2 || true
    fail "agent concurrent HTTP prompt failed before HTTP status"
  }
  [[ "$ops_wait" -eq 0 ]] || {
    cat "$ops_out" >&2 || true
    fail "operator concurrent HTTP prompt failed before HTTP status"
  }

  assert_http_prompt_stream agent "$user_out" "$user_status" "$user_principal" \
    "$user_prompt" "$ops_prompt"
  assert_http_prompt_stream operator "$ops_out" "$ops_status" "$ops_principal" \
    "-" "$user_prompt"
  assert_fake_llm_request_model "$ARTIFACTS/fake-openai.jsonl" "$user_prompt" "fake-slow"
  assert_fake_llm_request_model "$ARTIFACTS/fake-openai.jsonl" "$ops_prompt" "fake-toolish"

  note "checking concurrent HTTP session mutations stay principal-scoped"
  local user_title="regular concurrent session title"
  local ops_title="operator concurrent session title"
  local user_update_out="$ARTIFACTS/concurrent-session-user-update.json"
  local ops_update_out="$ARTIFACTS/concurrent-session-ops-update.json"
  local user_update_status="$ARTIFACTS/concurrent-session-user-update.status"
  local ops_update_status="$ARTIFACTS/concurrent-session-ops-update.status"
  local status
  concurrent_session_title_update "$user_bearer" "$user_session" "$user_title" \
    "$user_update_out" "$user_update_status" &
  user_pid=$!
  concurrent_session_title_update "$ops_bearer" "$ops_session" "$ops_title" \
    "$ops_update_out" "$ops_update_status" &
  ops_pid=$!

  user_wait=0
  ops_wait=0
  wait "$user_pid" || user_wait=$?
  wait "$ops_pid" || ops_wait=$?
  [[ "$user_wait" -eq 0 ]] || {
    cat "$user_update_out" >&2 || true
    fail "agent concurrent session update failed before HTTP status"
  }
  [[ "$ops_wait" -eq 0 ]] || {
    cat "$ops_update_out" >&2 || true
    fail "operator concurrent session update failed before HTTP status"
  }

  status="$(<"$user_update_status")"
  LAST_HTTP_OUT="$user_update_out"
  assert_status "agent concurrent session update" "$status" 200
  status="$(<"$ops_update_status")"
  LAST_HTTP_OUT="$ops_update_out"
  assert_status "operator concurrent session update" "$status" 200
  json_assert_session_summary "$user_update_out" "$user_session" "$user_title"
  json_assert_session_summary "$ops_update_out" "$ops_session" "$ops_title"

  note "checking concurrent cross-principal session mutation is hidden"
  local forbidden_title="forbidden concurrent session title"
  local ops_final_title="operator concurrent session owner title"
  local cross_update_out="$ARTIFACTS/concurrent-session-cross-update.json"
  local cross_update_status="$ARTIFACTS/concurrent-session-cross-update.status"
  local ops_final_update_out="$ARTIFACTS/concurrent-session-ops-final-update.json"
  local ops_final_update_status="$ARTIFACTS/concurrent-session-ops-final-update.status"
  concurrent_session_title_update "$user_bearer" "$ops_session" "$forbidden_title" \
    "$cross_update_out" "$cross_update_status" &
  user_pid=$!
  concurrent_session_title_update "$ops_bearer" "$ops_session" "$ops_final_title" \
    "$ops_final_update_out" "$ops_final_update_status" &
  ops_pid=$!

  user_wait=0
  ops_wait=0
  wait "$user_pid" || user_wait=$?
  wait "$ops_pid" || ops_wait=$?
  [[ "$user_wait" -eq 0 ]] || {
    cat "$cross_update_out" >&2 || true
    fail "agent cross-principal concurrent session update failed before HTTP status"
  }
  [[ "$ops_wait" -eq 0 ]] || {
    cat "$ops_final_update_out" >&2 || true
    fail "operator owner concurrent session update failed before HTTP status"
  }

  status="$(<"$cross_update_status")"
  LAST_HTTP_OUT="$cross_update_out"
  assert_status "agent cross-principal concurrent session update hidden" "$status" 404
  assert_artifact_lacks_text "$cross_update_out" "$ops_session"
  status="$(<"$ops_final_update_status")"
  LAST_HTTP_OUT="$ops_final_update_out"
  assert_status "operator owner concurrent session update" "$status" 200
  json_assert_session_summary "$ops_final_update_out" "$ops_session" "$ops_final_title"
}

run_concurrent_model_write_smoke() {
  local user_bearer=$1 ops_bearer=$2 user_principal=$3 ops_principal=$4

  note "checking concurrent active model writes stay principal-scoped"

  local user_status_file="$ARTIFACTS/concurrent-model-user.status"
  local ops_status_file="$ARTIFACTS/concurrent-model-ops.status"
  local user_out="$ARTIFACTS/concurrent-model-user-set.json"
  local ops_out="$ARTIFACTS/concurrent-model-ops-set.json"
  local user_pid ops_pid user_wait=0 ops_wait=0

  (concurrent_model_write "$user_bearer" \
    "openai-compat:fake-echo" "$user_status_file" "$user_out") &
  user_pid=$!
  (concurrent_model_write "$ops_bearer" \
    "openai-compat:fake-slow" "$ops_status_file" "$ops_out") &
  ops_pid=$!

  wait "$user_pid" || user_wait=$?
  wait "$ops_pid" || ops_wait=$?
  [[ "$user_wait" -eq 0 ]] || fail "agent concurrent active model request failed before HTTP status"
  [[ "$ops_wait" -eq 0 ]] || fail "operator concurrent active model request failed before HTTP status"

  assert_model_write_status "agent concurrent active model" "$user_status_file" "$user_out"
  assert_model_write_status "operator concurrent active model" "$ops_status_file" "$ops_out"
  json_assert_model_id "$user_out" "openai-compat:fake-echo"
  json_assert_model_id "$ops_out" "openai-compat:fake-slow"

  assert_active_model_for_bearer "agent active model after concurrent write" "$user_bearer" \
    "openai-compat:fake-echo" "$ARTIFACTS/concurrent-model-user-active.json"
  assert_active_model_for_bearer "operator active model after concurrent write" "$ops_bearer" \
    "openai-compat:fake-slow" "$ARTIFACTS/concurrent-model-ops-active.json"

  run_concurrent_cli_control_mutation_smoke "$user_principal" "$ops_principal"

  local status
  status="$(http_status PUT /api/models/active "$user_bearer" \
    '{"id":"openai-compat:fake-slow"}' \
    "$ARTIFACTS/concurrent-model-user-restore.json")"
  assert_status "agent restore active model after concurrent write" "$status" 200
  json_assert_model_id "$ARTIFACTS/concurrent-model-user-restore.json" "openai-compat:fake-slow"

  status="$(http_status PUT /api/models/active "$ops_bearer" \
    '{"id":"openai-compat:fake-toolish"}' \
    "$ARTIFACTS/concurrent-model-ops-restore.json")"
  assert_status "operator restore active model after concurrent write" "$status" 200
  json_assert_model_id "$ARTIFACTS/concurrent-model-ops-restore.json" "openai-compat:fake-toolish"

  run_concurrent_prompt_correlation_smoke "$user_principal" "$ops_principal"
  run_concurrent_http_prompt_correlation_smoke "$user_bearer" "$ops_bearer" \
    "$user_principal" "$ops_principal"
}
