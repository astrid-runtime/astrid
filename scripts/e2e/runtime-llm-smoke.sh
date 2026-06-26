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
  local status

  note "checking fake LLM provider failure handling"
  json_assert_model_list_contains "$models_file" "openai-compat:fake-error"
  json_assert_model_list_contains "$models_file" "openai-compat:fake-malformed"
  assert_model_list_count "$models_file" "openai-compat:duplicate-name" 1

  status="$(http_status PUT /api/models/active "$bearer" \
    '{"id":"openai-compat:fake-error"}' \
    "$ARTIFACTS/agent-set-active-model-fake-error.json")"
  assert_status "agent set fake-error active model" "$status" 200
  json_assert_model_id "$ARTIFACTS/agent-set-active-model-fake-error.json" "openai-compat:fake-error"
  assert_bounded_llm_error_surface "$principal" "openai-compat:fake-error" "fake-error" \
    'fake upstream error\|502\|error'

  status="$(http_status PUT /api/models/active "$bearer" \
    '{"id":"openai-compat:fake-malformed"}' \
    "$ARTIFACTS/agent-set-active-model-fake-malformed.json")"
  assert_status "agent set fake-malformed active model" "$status" 200
  json_assert_model_id "$ARTIFACTS/agent-set-active-model-fake-malformed.json" "openai-compat:fake-malformed"
  assert_bounded_llm_error_surface "$principal" "openai-compat:fake-malformed" "fake-malformed" \
    'malformed\|invalid\|json\|error'

  status="$(http_status PUT /api/models/active "$bearer" \
    '{"id":"openai-compat:fake-slow"}' \
    "$ARTIFACTS/agent-restore-active-model-fake-slow.json")"
  assert_status "agent restore fake-slow active model" "$status" 200
  json_assert_model_id "$ARTIFACTS/agent-restore-active-model-fake-slow.json" "openai-compat:fake-slow"
}
