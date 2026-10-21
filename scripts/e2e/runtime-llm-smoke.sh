#!/usr/bin/env bash

bounded_principal_run() {
  local principal=$1
  local timeout_secs=$2
  local out=$3
  shift 3

  printf '$ astrid --principal %s run %s\n' "$principal" "$*" >> "$ARTIFACTS/cli-transcript.log"
  "$PYTHON" - "$CORE_DIR/target/debug/astrid" "$principal" "$timeout_secs" "$out" "$@" <<'PY'
import subprocess
import sys
from pathlib import Path

astrid = sys.argv[1]
principal = sys.argv[2]
timeout_secs = float(sys.argv[3])
out = Path(sys.argv[4])
args = sys.argv[5:]
cmd = [astrid, "--principal", principal, "run", *args]

try:
    completed = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout_secs,
        check=False,
    )
except subprocess.TimeoutExpired as exc:
    stdout = exc.stdout or ""
    stderr = exc.stderr or ""
    if isinstance(stdout, bytes):
        stdout = stdout.decode("utf-8", errors="replace")
    if isinstance(stderr, bytes):
        stderr = stderr.decode("utf-8", errors="replace")
    out.write_text(stdout + stderr + "\ncommand timed out\n", encoding="utf-8")
    raise SystemExit(124)

out.write_text(completed.stdout + completed.stderr, encoding="utf-8")
raise SystemExit(completed.returncode)
PY
}

assert_model_list_count() {
  local file=$1
  local expected_id=$2
  local expected_count=$3
  "$PYTHON" - "$file" "$expected_id" "$expected_count" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
expected_id = sys.argv[2]
expected_count = int(sys.argv[3])
if isinstance(data, dict) and isinstance(data.get("data"), list):
    data = data["data"]
found = sum(1 for entry in data if isinstance(entry, dict) and entry.get("id") == expected_id)
if found != expected_count:
    raise SystemExit(f"expected {expected_count} copies of {expected_id!r}, found {found}")
PY
}

set_openai_model_env() {
  local bearer=$1
  local value=$2
  local out=$3
  local status

  status="$(http_status POST /api/capsules/astrid-capsule-openai-compat/env/model "$bearer" \
    "{\"value\":\"$value\"}" "$out")"
  assert_status "openai model env write ($value)" "$status" 204
}

run_shared_model_baseline_smoke() {
  local bearer=$1
  local status

  note "checking fake-echo model catalog before scoped overrides"
  status="$(http_status GET /api/models "$bearer" "" "$ARTIFACTS/shared-models.json")"
  assert_status "shared model list" "$status" 200
  json_assert_model_list_contains "$ARTIFACTS/shared-models.json" "openai-compat:fake-echo"
  assert_model_list_count "$ARTIFACTS/shared-models.json" "openai-compat:fake-echo" 1
  status="$(http_status PUT /api/models/active "$bearer" \
    '{"id":"openai-compat:fake-echo"}' \
    "$ARTIFACTS/shared-set-active-model.json")"
  assert_status "shared set active model" "$status" 200
  json_assert_model_id "$ARTIFACTS/shared-set-active-model.json" "openai-compat:fake-echo"
  status="$(http_status GET /api/models "$bearer" "" "$ARTIFACTS/shared-models-after-active.json")"
  assert_status "shared model list after active set" "$status" 200
  json_assert_model_list_contains "$ARTIFACTS/shared-models-after-active.json" \
    "openai-compat:fake-echo"
}

run_active_model_isolation_smoke() {
  local user_bearer=$1 ops_bearer=$2 user_principal=$3 ops_principal=$4
  local status deadline

  note "checking per-principal active model isolation"
  status="$(http_status GET /api/models "$user_bearer" "" "$ARTIFACTS/agent-models.json")"
  assert_status "agent model list" "$status" 200
  json_assert_model_list_contains "$ARTIFACTS/agent-models.json" "openai-compat:fake-slow"
  assert_model_list_count "$ARTIFACTS/agent-models.json" "openai-compat:fake-slow" 1
  status="$(http_status PUT /api/models/active "$user_bearer" \
    '{"id":"openai-compat:fake-slow"}' \
    "$ARTIFACTS/agent-set-active-model.json")"
  assert_status "agent set active model" "$status" 200
  json_assert_model_id "$ARTIFACTS/agent-set-active-model.json" "openai-compat:fake-slow"

  # A scoped refresh for the regular user says nothing about the operator's
  # registry view. Wait on the inventory we are about to mutate.
  local operator_models_out="$ARTIFACTS/operator-models.json"
  deadline=$((SECONDS + 45))
  until status="$(http_status GET /api/models "$ops_bearer" "" "$operator_models_out")" \
    && [[ "$status" == 200 ]] \
    && grep -q 'openai-compat:fake-toolish' "$operator_models_out"; do
    if (( SECONDS >= deadline )); then
      cat "$operator_models_out" >&2 2>/dev/null || true
      fail "operator registry did not discover fake-toolish via openai-compat"
    fi
    sleep 1
  done
  status="$(http_status PUT /api/models/active "$ops_bearer" \
    '{"id":"openai-compat:fake-toolish"}' \
    "$ARTIFACTS/operator-set-active-model.json")"
  assert_status "operator set active model" "$status" 200
  json_assert_model_id "$ARTIFACTS/operator-set-active-model.json" "openai-compat:fake-toolish"
  status="$(http_status GET /api/models/active "$user_bearer" "" "$ARTIFACTS/agent-active-model.json")"
  assert_status "agent active model" "$status" 200
  json_assert_model_id "$ARTIFACTS/agent-active-model.json" "openai-compat:fake-slow"
  status="$(http_status GET /api/models/active "$ops_bearer" "" "$ARTIFACTS/operator-active-model.json")"
  assert_status "operator active model" "$status" 200
  json_assert_model_id "$ARTIFACTS/operator-active-model.json" "openai-compat:fake-toolish"
  status="$(http_status GET "/api/models/active?principal=$ops_principal" "$user_bearer" "" \
    "$ARTIFACTS/agent-active-model-query-spoof.json")"
  assert_status "agent active model query spoof ignored" "$status" 200
  json_assert_model_id "$ARTIFACTS/agent-active-model-query-spoof.json" "openai-compat:fake-slow"
  status="$(http_status PUT /api/models/active "$user_bearer" \
    '{"id":"openai-compat:fake-slow","principal":"default"}' \
    "$ARTIFACTS/agent-set-active-model-body-spoof.json")"
  assert_status "agent active model body spoof ignored" "$status" 200
  json_assert_model_id "$ARTIFACTS/agent-set-active-model-body-spoof.json" "openai-compat:fake-slow"
  run_scoped_concurrent_model_write_smoke "$user_bearer" "$ops_bearer"
}

run_scoped_concurrent_model_write_smoke() {
  local user_bearer=$1 ops_bearer=$2
  local user_status_file ops_status_file user_out ops_out user_pid ops_pid
  local user_wait=0 ops_wait=0

  note "checking concurrent scoped active model writes stay principal-isolated"
  user_status_file="$ARTIFACTS/scoped-concurrent-model-user.status"
  ops_status_file="$ARTIFACTS/scoped-concurrent-model-ops.status"
  user_out="$ARTIFACTS/scoped-concurrent-model-user-set.json"
  ops_out="$ARTIFACTS/scoped-concurrent-model-ops-set.json"

  (http_status PUT /api/models/active "$user_bearer" \
    '{"id":"openai-compat:fake-slow"}' "$user_out" > "$user_status_file") &
  user_pid=$!
  (http_status PUT /api/models/active "$ops_bearer" \
    '{"id":"openai-compat:fake-toolish"}' "$ops_out" > "$ops_status_file") &
  ops_pid=$!
  wait "$user_pid" || user_wait=$?
  wait "$ops_pid" || ops_wait=$?
  [[ "$user_wait" -eq 0 ]] || fail "agent scoped concurrent active model request failed"
  [[ "$ops_wait" -eq 0 ]] || fail "operator scoped concurrent active model request failed"
  assert_model_write_status "agent scoped concurrent active model" \
    "$user_status_file" "$user_out"
  assert_model_write_status "operator scoped concurrent active model" \
    "$ops_status_file" "$ops_out"
  json_assert_model_id "$user_out" "openai-compat:fake-slow"
  json_assert_model_id "$ops_out" "openai-compat:fake-toolish"
}

run_empty_model_catalog_smoke() {
  local fake_base_url=$1
  local invite bearer principal status

  note "checking empty fake LLM model catalog fallback"
  invite="$("$CORE_DIR/target/debug/astrid" invite issue --group agent --max-uses 1 --expires-secs 600 --raw \
    2>> "$ARTIFACTS/cli-transcript.log")"
  printf '$ astrid invite issue --group agent --max-uses 1 --expires-secs 600 --raw\n<redacted invite token>\n' \
    >> "$ARTIFACTS/cli-transcript.log"
  redeem_invite "$invite" empty-model-user "$ARTIFACTS/empty-model-redeem.json"
  bearer="$(json_field "$ARTIFACTS/empty-model-redeem.json" session_token)"
  principal="$(json_field "$ARTIFACTS/empty-model-redeem.json" principal)"

  run_cli agent modify "$principal" \
    --add-capsule astrid-capsule-registry \
    --add-capsule astrid-capsule-openai-compat

  status="$(http_status POST /api/capsules/astrid-capsule-openai-compat/env/base_url "$bearer" \
    "{\"value\":\"$fake_base_url/empty-models\"}" \
    "$ARTIFACTS/empty-model-base-url-write.json")"
  assert_status "empty-model env base_url write" "$status" 204
  status="$(http_status POST /api/capsules/astrid-capsule-openai-compat/env/model "$bearer" \
    '{"value":"fake-empty-fallback"}' \
    "$ARTIFACTS/empty-model-fallback-write.json")"
  assert_status "empty-model env fallback write" "$status" 204
  local deadline=$((SECONDS + 45))
  until status="$(http_status GET /api/models "$bearer" "" "$ARTIFACTS/empty-model-catalog-models.json")" \
    && [[ "$status" == "200" ]] \
    && json_assert_model_list_contains "$ARTIFACTS/empty-model-catalog-models.json" \
      "openai-compat:fake-empty-fallback"; do
    if (( SECONDS >= deadline )); then
      cat "$ARTIFACTS/empty-model-catalog-models.json" >&2 2>/dev/null || true
      fail "empty-model catalog did not discover fallback model"
    fi
    sleep 1
  done
  assert_status "empty-model catalog fallback model list" "$status" 200
  json_assert_model_list_contains "$ARTIFACTS/empty-model-catalog-models.json" \
    "openai-compat:fake-empty-fallback"
  assert_model_list_count "$ARTIFACTS/empty-model-catalog-models.json" \
    "openai-compat:fake-empty-fallback" 1
  assert_model_list_count "$ARTIFACTS/empty-model-catalog-models.json" \
    "openai-compat:fake-echo" 0
}

assert_bounded_llm_error_surface() {
  local principal=$1
  local model_id=$2
  local label=$3
  local needle=$4
  local session
  session="$("$PYTHON" -c 'import uuid; print(uuid.uuid4())')"
  local out="$ARTIFACTS/llm-$label-run.txt"

  local rc=0
  bounded_principal_run "$principal" 20 "$out" --format json --session "$session" \
    "runtime harness should surface $label" || rc=$?
  if [[ "$rc" -eq 124 ]]; then
    cat "$out" >&2
    fail "$model_id run timed out instead of surfacing $label"
  fi
  if ! grep -qi "$needle" "$out"; then
    cat "$out" >&2
    fail "$model_id did not surface expected $label signal"
  fi
}

assert_fake_llm_request_model() {
  local log_file=$1
  local prompt_text=$2
  local expected_model=$3
  "$PYTHON" - "$log_file" "$prompt_text" "$expected_model" <<'PY'
import json
import sys

log_file = sys.argv[1]
prompt_text = sys.argv[2]
expected_model = sys.argv[3]
# The provider-qualified ID is an Astrid catalog key. The upstream
# OpenAI-compatible request must carry the provider-native model name.
matches = []

with open(log_file, encoding="utf-8") as handle:
    for line in handle:
        if not line.strip():
            continue
        entry = json.loads(line)
        if entry.get("method") != "POST" or entry.get("path") != "/v1/chat/completions":
            continue
        blob = json.dumps(entry.get("messages", []), sort_keys=True)
        if prompt_text in blob:
            matches.append(entry.get("model"))

if expected_model not in matches:
    raise SystemExit(
        f"expected prompt {prompt_text!r} to reach fake LLM as {expected_model!r}, got {matches!r}"
    )

unexpected = [model for model in matches if model != expected_model]
if unexpected:
    raise SystemExit(
        f"prompt {prompt_text!r} reached fake LLM through unexpected model(s): {unexpected!r}"
    )
PY
}

assert_principal_llm_attribution() {
  local user_prompt=$1
  local ops_prompt=$2

  note "checking fake LLM request attribution by principal model"
  assert_fake_llm_request_model "$ARTIFACTS/fake-openai.jsonl" "$user_prompt" "fake-slow"
  assert_fake_llm_request_model "$ARTIFACTS/fake-openai.jsonl" "$ops_prompt" "fake-toolish"
}

run_llm_provider_smoke() {
  local bearer=$1
  local principal=$2
  local models_file=$3
  local fake_base_url=$4
  local status target

  note "checking fake LLM provider failure handling"
  run_empty_model_catalog_smoke "$fake_base_url"

  for target in fake-error fake-malformed fake-timeout; do
    set_openai_model_env "$bearer" "$target" \
      "$ARTIFACTS/agent-openai-model-$target.json"
    status="$(http_status GET /api/models "$bearer" "" \
      "$ARTIFACTS/agent-models-$target.json")"
    assert_status "agent $target model list" "$status" 200
    json_assert_model_list_contains "$ARTIFACTS/agent-models-$target.json" \
      "openai-compat:$target"
    assert_model_list_count "$ARTIFACTS/agent-models-$target.json" \
      "openai-compat:$target" 1
    status="$(http_status PUT /api/models/active "$bearer" \
      "{\"id\":\"openai-compat:$target\"}" \
      "$ARTIFACTS/agent-set-active-model-$target.json")"
    assert_status "agent set $target active model" "$status" 200
    json_assert_model_id "$ARTIFACTS/agent-set-active-model-$target.json" \
      "openai-compat:$target"
    assert_bounded_llm_error_surface "$principal" "openai-compat:$target" "$target" \
      'fake upstream error\|502\|malformed\|invalid\|json\|timeout\|timed out\|deadline\|error'
  done

  set_openai_model_env "$bearer" fake-slow "$ARTIFACTS/agent-openai-model-restore.json"
  status="$(http_status GET /api/models "$bearer" "" "$models_file")"
  assert_status "agent restored model list" "$status" 200
  json_assert_model_list_contains "$models_file" "openai-compat:fake-slow"

  status="$(http_status PUT /api/models/active "$bearer" \
    '{"id":"openai-compat:fake-slow"}' \
    "$ARTIFACTS/agent-restore-active-model-fake-slow.json")"
  assert_status "agent restore fake-slow active model" "$status" 200
  json_assert_model_id "$ARTIFACTS/agent-restore-active-model-fake-slow.json" "openai-compat:fake-slow"
}
