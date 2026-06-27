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
}
