#!/usr/bin/env bash
set -euo pipefail
CORE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT_DIR="$CORE_DIR/scripts/e2e"
CAPSULES_DIR="${ASTRID_E2E_CAPSULES_DIR:-$CORE_DIR/../capsules}"
ASTRID_HOME="${ASTRID_E2E_HOME:-$(mktemp -d "${TMPDIR:-/tmp}/astrid-runtime-e2e.XXXXXX")}"
ARTIFACTS="$ASTRID_HOME/artifacts"
REDACTED_UPLOAD="$ARTIFACTS/redacted-upload"
GATEWAY_HOST="${ASTRID_E2E_GATEWAY_HOST:-127.0.0.1}"
GATEWAY_PORT="${ASTRID_E2E_GATEWAY_PORT:-38756}"
GATEWAY="http://$GATEWAY_HOST:$GATEWAY_PORT"
PYTHON="${PYTHON:-python3}"
CORE_CAPSULES="${ASTRID_E2E_CORE_CAPSULES:-astrid-capsule-cli astrid-capsule-registry astrid-capsule-session astrid-capsule-identity astrid-capsule-prompt-builder astrid-capsule-react astrid-capsule-openai-compat}"
DAEMON_PID=""
SECONDARY_DAEMON_PID=""
SECONDARY_HOME=""
FAKE_PID=""
POISON_HOME=""
LAST_HTTP_OUT=""
REDACTION_SENTINELS=()
terminate_pid() {
  local pid=$1
  if [[ -n "$pid" ]]; then
    kill "$pid" 2>/dev/null || true
    for _ in {1..50}; do
      if ! kill -0 "$pid" 2>/dev/null; then
        wait "$pid" 2>/dev/null || true
        return
      fi
      sleep 0.1
    done
    kill -KILL "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi
}
cleanup() {
  local status=$?
  trap - EXIT INT TERM
  terminate_pid "$DAEMON_PID"
  terminate_pid "$SECONDARY_DAEMON_PID"
  terminate_pid "$FAKE_PID"
  if [[ -n "$SECONDARY_HOME" && -z "${ASTRID_E2E_KEEP_HOME:-}" && "$status" -eq 0 ]]; then
    rm -rf "$SECONDARY_HOME"
  elif [[ -n "$SECONDARY_HOME" ]]; then
    printf 'kept secondary ASTRID_HOME=%s\n' "$SECONDARY_HOME"
  fi
  if [[ "$status" -ne 0 && -d "$ASTRID_HOME/log" ]]; then mkdir -p "$ARTIFACTS/astrid-log" && cp -a "$ASTRID_HOME/log/." "$ARTIFACTS/astrid-log/" 2>/dev/null || true; fi
  if [[ "$status" -ne 0 ]]; then
    stage_redacted_upload || true
  fi
  if [[ -n "$POISON_HOME" && -z "${ASTRID_E2E_KEEP_HOME:-}" ]]; then
    rm -rf "$POISON_HOME"
  elif [[ -n "$POISON_HOME" ]]; then
    printf 'kept poisoned HOME=%s\n' "$POISON_HOME"
  fi
  if [[ -z "${ASTRID_E2E_KEEP_HOME:-}" && "$status" -eq 0 ]]; then
    rm -rf "$ASTRID_HOME"
  else
    printf 'kept ASTRID_HOME=%s\n' "$ASTRID_HOME"
  fi
  return "$status"
}
trap cleanup EXIT INT TERM
. "$SCRIPT_DIR/runtime-json-asserts.sh"
. "$SCRIPT_DIR/runtime-gateway-smoke.sh"
. "$SCRIPT_DIR/runtime-cli-smoke.sh"
. "$SCRIPT_DIR/runtime-multi-home-smoke.sh"
. "$SCRIPT_DIR/runtime-llm-smoke.sh"
note() { printf '\n==> %s\n' "$*"; }
fail() { printf 'error: %s\n' "$*" >&2; exit 1; }
run_cli() {
  printf '$ astrid %s\n' "$*" >> "$ARTIFACTS/cli-transcript.log"
  "$CORE_DIR/target/debug/astrid" "$@" \
    > >(tee -a "$ARTIFACTS/cli-transcript.log") \
    2> >(tee -a "$ARTIFACTS/cli-transcript.log" >&2)
}
run_principal_cli() {
  local principal=$1; shift
  printf '$ astrid --principal %s %s\n' "$principal" "$*" >> "$ARTIFACTS/cli-transcript.log"
  "$CORE_DIR/target/debug/astrid" --principal "$principal" "$@" \
    > >(tee -a "$ARTIFACTS/cli-transcript.log") \
    2> >(tee -a "$ARTIFACTS/cli-transcript.log" >&2)
}
http_status() {
  local method=$1
  local path=$2
  local bearer=$3
  local body=$4
  local out=$5
  local args=(
    --connect-timeout 2
    --max-time 25
    -sS
    -o "$out"
    -w "%{http_code}"
    -X "$method"
    "$GATEWAY$path"
  )
  if [[ -n "$bearer" ]]; then
    args+=(-H "Authorization: Bearer $bearer")
  fi
  if [[ -n "$body" ]]; then
    args+=(-H "Content-Type: application/json" -d "$body")
  fi
  LAST_HTTP_OUT="$out"
  curl "${args[@]}"
}
assert_status() {
  local label=$1
  local got=$2
  local want=$3
  if [[ "$got" != "$want" ]]; then
    if [[ -n "${LAST_HTTP_OUT:-}" && -f "$LAST_HTTP_OUT" ]]; then
      printf 'response body (%s):\n' "$LAST_HTTP_OUT" >&2
      sed -n '1,80p' "$LAST_HTTP_OUT" >&2 || true
    fi
    fail "$label expected HTTP $want, got $got"
  fi
}

redeem_invite() {
  local invite=$1
  local display_name=$2
  local out=$3
  local pubkey
  run_cli keypair generate --name "$display_name" --force --raw > "$ARTIFACTS/$display_name-pubkey.hex"
  pubkey="$(<"$ARTIFACTS/$display_name-pubkey.hex")"
  local status
  status="$(http_status POST /api/auth/redeem "" \
    "{\"token\":\"$invite\",\"public_key\":\"$pubkey\",\"display_name\":\"$display_name\"}" \
    "$out")"
  assert_status "$display_name redeem" "$status" 200
  mkdir -p "$ASTRID_HOME/keys"
  install -m 600 "$ASTRID_HOME/keys/local/$display_name.ed25519" \
    "$ASTRID_HOME/keys/$(json_field "$out" principal).key"
}

wait_for_http() {
  local url=$1
  local deadline=$((SECONDS + 30))
  until curl --connect-timeout 2 --max-time 5 -fsS "$url" >/dev/null 2>&1; do
    if (( SECONDS >= deadline )); then
      return 1
    fi
    sleep 1
  done
}

start_daemon() {
  local label=$1
  note "$label"
  printf '\n==> %s\n' "$label" >> "$ARTIFACTS/daemon.log"
  "$CORE_DIR/target/debug/astrid-daemon" >> "$ARTIFACTS/daemon.log" 2>&1 &
  DAEMON_PID=$!
  wait_for_http "$GATEWAY/healthz" || {
    tail -n 200 "$ARTIFACTS/daemon.log" >&2 || true
    fail "daemon did not become healthy"
  }
}

stop_daemon() {
  terminate_pid "$DAEMON_PID"
  DAEMON_PID=""
}

wait_for_fake_port() {
  local file=$1
  local deadline=$((SECONDS + 10))
  until grep -q '^PORT=' "$file" 2>/dev/null; do
    if (( SECONDS >= deadline )); then
      return 1
    fi
    sleep 0.2
  done
}

require_capsules() {
  local missing=()
  for capsule in $CORE_CAPSULES; do
    if [[ ! -d "$CAPSULES_DIR/$capsule" ]]; then
      missing+=("$CAPSULES_DIR/$capsule")
    fi
  done
  if ((${#missing[@]} > 0)); then
    printf 'missing required runtime capsule checkout(s):\n' >&2
    printf '  %s\n' "${missing[@]}" >&2
    printf 'Set ASTRID_E2E_CAPSULES_DIR or check out the capsule repos before running this harness.\n' >&2
    exit 2
  fi
}

register_redaction_sentinel() {
  local sentinel=$1
  [[ -n "$sentinel" ]] || return 0
  REDACTION_SENTINELS+=("$sentinel")
}

copy_dir_contents_if_exists() {
  local src=$1
  local dst=$2
  [[ -d "$src" ]] || return 0
  rm -rf "$dst"
  mkdir -p "$dst"
  cp -a "$src/." "$dst/" 2>/dev/null || true
}

stage_home_logs() {
  local home=$1
  local label=$2
  local log_dir
  local principal
  [[ -n "$home" ]] || return 0

  copy_dir_contents_if_exists "$home/log" "$REDACTED_UPLOAD/$label/daemon-log"
  [[ -d "$home/home" ]] || return 0
  while IFS= read -r -d '' log_dir; do
    principal="$(basename "$(dirname "$(dirname "$log_dir")")")"
    copy_dir_contents_if_exists "$log_dir" "$REDACTED_UPLOAD/$label/principal-logs/$principal"
  done < <(find "$home/home" -path '*/.local/log' -type d -print0 2>/dev/null)
}

redact_staged_upload() {
  [[ -d "$REDACTED_UPLOAD" ]] || return 0
  "$PYTHON" - "$REDACTED_UPLOAD" "${REDACTION_SENTINELS[@]}" <<'PY'
import os
import re
import sys

root = sys.argv[1]
sentinels = [s.encode() for s in sys.argv[2:] if s]
text_patterns = [
    (re.compile(r'ASTRID_E2E_[A-Z0-9_]*DO_NOT_LEAK_[A-Za-z0-9_]+'), r'<redacted-e2e-sentinel>'),
    (re.compile(r'("session_token"\s*:\s*")[^"]+(")'), r'\1<redacted-token>\2'),
    (re.compile(r'("token"\s*:\s*")[^"]+(")'), r'\1<redacted-token>\2'),
    (re.compile(r'(Authorization:\s*Bearer\s+)[A-Za-z0-9._~+/=-]+'), r'\1<redacted-token>'),
]

for dirpath, _, filenames in os.walk(root):
    for name in filenames:
        path = os.path.join(dirpath, name)
        try:
            with open(path, "rb") as handle:
                data = handle.read()
        except OSError:
            continue

        changed = False
        for sentinel in sentinels:
            if sentinel in data:
                data = data.replace(sentinel, b"<redacted-e2e-secret>")
                changed = True

        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            if changed:
                with open(path, "wb") as handle:
                    handle.write(data)
            continue

        redacted = text
        for pattern, replacement in text_patterns:
            redacted = pattern.sub(replacement, redacted)
        if changed or redacted != text:
            with open(path, "wb") as handle:
                handle.write(redacted.encode("utf-8"))
PY
}

scan_redacted_upload() {
  local sentinel
  [[ -d "$REDACTED_UPLOAD" ]] || return 0
  if grep -R --fixed-strings --binary-files=without-match -- "DO_NOT_LEAK" "$REDACTED_UPLOAD" >/dev/null 2>&1; then
    fail "sentinel marker leaked into redacted runtime artifact upload"
  fi
  for sentinel in "${REDACTION_SENTINELS[@]}"; do
    [[ -n "$sentinel" ]] || continue
    if grep -R --fixed-strings --binary-files=without-match -- "$sentinel" "$REDACTED_UPLOAD" >/dev/null 2>&1; then
      fail "sentinel secret leaked into redacted runtime artifact upload"
    fi
  done
}

stage_redacted_upload() {
  local entry
  local name

  [[ -d "$ARTIFACTS" ]] || return 0
  rm -rf "$REDACTED_UPLOAD"
  mkdir -p "$REDACTED_UPLOAD/artifacts"

  while IFS= read -r -d '' entry; do
    name="$(basename "$entry")"
    [[ "$name" == "redacted-upload" ]] && continue
    cp -a "$entry" "$REDACTED_UPLOAD/artifacts/"
  done < <(find "$ARTIFACTS" -mindepth 1 -maxdepth 1 -print0 2>/dev/null)

  stage_home_logs "$ASTRID_HOME" primary
  stage_home_logs "$SECONDARY_HOME" secondary
  redact_staged_upload
  scan_redacted_upload
}

redaction_check() {
  local sentinel=$1
  local targets=("$ARTIFACTS")
  local target
  local log_dir

  for target in "$ASTRID_HOME" "$SECONDARY_HOME"; do
    [[ -n "$target" ]] || continue
    [[ -d "$target/log" ]] && targets+=("$target/log")
    if [[ -d "$target/home" ]]; then
      while IFS= read -r -d '' log_dir; do
        targets+=("$log_dir")
      done < <(find "$target/home" -path '*/.local/log' -type d -print0 2>/dev/null)
    fi
  done

  for target in "${targets[@]}"; do
    if grep -R --fixed-strings --binary-files=without-match -- "$sentinel" "$target" >/dev/null 2>&1; then
      fail "sentinel secret leaked into runtime e2e logs/artifacts under $target"
    fi
  done
}

collect_audit_artifacts() {
  local user_bearer=$1
  local ops_bearer=$2
  local status

  status="$(http_status GET "/api/sys/audit?limit=1000" "$user_bearer" "" "$ARTIFACTS/agent-audit.json")"
  assert_status "agent scoped audit export" "$status" 200
  status="$(http_status GET "/api/sys/audit?limit=1000" "$ops_bearer" "" "$ARTIFACTS/operator-audit.json")"
  assert_status "operator scoped audit export" "$status" 200
}

main() {
  mkdir -p "$ASTRID_HOME/etc" "$ARTIFACTS"
  export ASTRID_HOME

  note "building Astrid binaries"
  if [[ -z "${ASTRID_E2E_SKIP_BUILD:-}" ]]; then
    cargo build -p astrid --bins
  fi

  require_capsules

  note "starting fake OpenAI-compatible server"
  local fake_port_file="$ARTIFACTS/fake-openai.port"
  "$PYTHON" "$SCRIPT_DIR/fake-openai-compat.py" \
    --host 127.0.0.1 \
    --port 0 \
    --log "$ARTIFACTS/fake-openai.jsonl" \
    > "$fake_port_file" \
    2> "$ARTIFACTS/fake-openai.stderr" &
  FAKE_PID=$!
  wait_for_fake_port "$fake_port_file" || fail "fake OpenAI-compatible server did not report a port"
  local fake_port
  fake_port="$(sed -n 's/^PORT=//p' "$fake_port_file" | head -n 1)"
  local fake_base_url="http://127.0.0.1:$fake_port"
  curl --connect-timeout 2 --max-time 5 -fsS "$fake_base_url/v1/models" >/dev/null
  note "writing gateway and local-egress config"
  cat > "$ASTRID_HOME/etc/gateway-http.toml" <<EOF
enabled = true
listen = "$GATEWAY_HOST:$GATEWAY_PORT"
session-lifetime-secs = 3600
redeem-rate-limit-secs = 0
EOF
  cat > "$ASTRID_HOME/config.toml" <<EOF
[logging]
directives = ["astrid_capsule::dispatcher=debug", "astrid_gateway::routes::sessions=debug", "astrid_capsule::engine::wasm::host::kv=debug", "astrid_events=debug"]
[http]
default_timeout_secs = 5
stream_connect_timeout_secs = 5
stream_read_timeout_secs = 3
header_deadline_secs = 5
[security.capsule_local_egress]
"astrid-capsule-openai-compat" = ["127.0.0.1:$fake_port"]
"openai-compat" = ["127.0.0.1:$fake_port"]
EOF

  POISON_HOME="$(mktemp -d "${TMPDIR:-/tmp}/astrid-runtime-poison-home.XXXXXX")"
  mkdir -p "$POISON_HOME/.astrid"
  cat > "$POISON_HOME/.astrid/config.toml" <<EOF
[security.capsule_local_egress]
"astrid-capsule-openai-compat" = ["127.0.0.1:9"]
"openai-compat" = ["127.0.0.1:9"]
EOF

  note "installing core capsule set"
  for capsule in $CORE_CAPSULES; do
    run_cli capsule install "$CAPSULES_DIR/$capsule"
  done

  note "configuring openai-compat for fake endpoint"
  local sentinel="ASTRID_E2E_SECRET_DO_NOT_LEAK_$RANDOM$RANDOM"
  register_redaction_sentinel "$sentinel"
  printf '$ astrid capsule config astrid-capsule-openai-compat --set base_url=<fake> --set model=fake-echo\n' \
    >> "$ARTIFACTS/cli-transcript.log"
  printf 'y\n' | "$CORE_DIR/target/debug/astrid" capsule config astrid-capsule-openai-compat \
    --set "base_url=$fake_base_url" \
    --set "model=fake-echo" \
    > "$ARTIFACTS/openai-config.out" \
    2> "$ARTIFACTS/openai-config.err"
  printf '$ astrid secret set api_key <redacted> --capsule astrid-capsule-openai-compat\n' \
    >> "$ARTIFACTS/cli-transcript.log"
  "$CORE_DIR/target/debug/astrid" secret set api_key "$sentinel" \
    --capsule astrid-capsule-openai-compat \
    > "$ARTIFACTS/openai-secret.out" \
    2> "$ARTIFACTS/openai-secret.err"
  run_cli secret list --agent default --format json > "$ARTIFACTS/default-secret-list.json"
  json_assert_secret_list_metadata "$ARTIFACTS/default-secret-list.json" \
    astrid-capsule-openai-compat api_key

  export HOME="$POISON_HOME"
  start_daemon "starting daemon"
  run_gateway_public_surface_smoke

  note "checking principal and capability isolation"
  run_cli group create ops-team --caps "capsule:install,invite:issue,invite:list,self:capsule:list"

  local ops_invite
  ops_invite="$("$CORE_DIR/target/debug/astrid" invite issue --group ops-team --max-uses 1 --expires-secs 600 --raw \
    2>> "$ARTIFACTS/cli-transcript.log")"
  printf '$ astrid invite issue --group ops-team --max-uses 1 --expires-secs 600 --raw\n<redacted invite token>\n' \
    >> "$ARTIFACTS/cli-transcript.log"
  redeem_invite "$ops_invite" operator-1 "$ARTIFACTS/operator-redeem.json"
  local ops_bearer
  local ops_principal
  local ops_group
  ops_bearer="$(json_field "$ARTIFACTS/operator-redeem.json" session_token)"
  ops_principal="$(json_field "$ARTIFACTS/operator-redeem.json" principal)"
  ops_group="$(json_field "$ARTIFACTS/operator-redeem.json" group)"
  [[ "$ops_group" == "ops-team" ]] || fail "operator-1 redeemed into $ops_group, expected ops-team"

  local status
  status="$(http_status POST /api/sys/invites "$ops_bearer" \
    '{"group":"agent","max_uses":1,"expires_secs":600}' \
    "$ARTIFACTS/operator-issued-invite.json")"
  assert_status "operator invite issue" "$status" 200
  status="$(http_status DELETE /api/sys/principals/default "$ops_bearer" "" \
    "$ARTIFACTS/operator-delete-default.json")"
  assert_status "operator delete default denied" "$status" 403
  status="$(http_status POST /api/auth/pair-device "$ops_bearer" \
    '{"expires_secs":120,"label":"operator second device"}' \
    "$ARTIFACTS/operator-pair-device-denied.json")"
  assert_status "operator pair-device denied" "$status" 403

  local agent_invite
  agent_invite="$("$CORE_DIR/target/debug/astrid" invite issue --group agent --max-uses 1 --expires-secs 600 --raw \
    2>> "$ARTIFACTS/cli-transcript.log")"
  printf '$ astrid invite issue --group agent --max-uses 1 --expires-secs 600 --raw\n<redacted invite token>\n' \
    >> "$ARTIFACTS/cli-transcript.log"
  redeem_invite "$agent_invite" regular-user "$ARTIFACTS/agent-redeem.json"
  local user_bearer
  local user_principal
  local user_group
  user_bearer="$(json_field "$ARTIFACTS/agent-redeem.json" session_token)"
  user_principal="$(json_field "$ARTIFACTS/agent-redeem.json" principal)"
  user_group="$(json_field "$ARTIFACTS/agent-redeem.json" group)"
  [[ "$user_group" == "agent" ]] || fail "regular-user redeemed into $user_group, expected agent"

  note "assigning prompt capsule set to isolated principals"
  local prompt_capsules=(
    --add-capsule astrid-capsule-registry \
    --add-capsule astrid-capsule-session \
    --add-capsule astrid-capsule-identity \
    --add-capsule astrid-capsule-prompt-builder \
    --add-capsule astrid-capsule-react \
    --add-capsule astrid-capsule-openai-compat
  )
  run_cli agent modify "$user_principal" "${prompt_capsules[@]}"
  run_cli agent modify "$ops_principal" "${prompt_capsules[@]}"

  note "checking default-only capsule surface isolation"
  local label bearer
  for pair in "agent:$user_bearer" "operator:$ops_bearer"; do
    label="${pair%%:*}"; bearer="${pair#*:}"
    status="$(http_status GET /api/capsules "$bearer" "" "$ARTIFACTS/$label-capsules.json")"; assert_status "$label capsule list" "$status" 200
    grep -q '"astrid-capsule-registry"' "$ARTIFACTS/$label-capsules.json" || fail "$label capsule list missed granted registry capsule"; ! grep -q '"astrid-capsule-cli"' "$ARTIFACTS/$label-capsules.json" || fail "$label saw default-only cli capsule"
    status="$(http_status GET /api/capsules/astrid-capsule-cli "$bearer" "" "$ARTIFACTS/$label-default-only-capsule.json")"; assert_status "$label default-only capsule detail hidden" "$status" 404
    status="$(http_status GET /api/capsules/astrid-capsule-cli/env "$bearer" "" "$ARTIFACTS/$label-default-only-env.json")"; assert_status "$label default-only capsule env hidden" "$status" 404
    status="$(http_status POST /api/capsules/astrid-capsule-cli/env/unused "$bearer" '{"value":"should-not-write"}' "$ARTIFACTS/$label-default-only-env-write.json")"; assert_status "$label default-only capsule env write hidden" "$status" 404
  done
  run_gateway_principal_surface_smoke agent "$user_bearer" 204
  run_gateway_principal_surface_smoke operator "$ops_bearer" 403
  status="$(http_status POST /api/auth/pair-device "$user_bearer" \
    '{"expires_secs":120,"label":"regular-user phone"}' \
    "$ARTIFACTS/agent-pair-device.json")"
  assert_status "agent pair-device issue" "$status" 200
  local pair_token
  local pair_principal
  pair_token="$(json_field "$ARTIFACTS/agent-pair-device.json" token)"
  pair_principal="$(json_field "$ARTIFACTS/agent-pair-device.json" principal)"
  [[ "$pair_principal" == "$user_principal" ]] || fail "pair token principal $pair_principal did not match $user_principal"
  local paired_pubkey
  paired_pubkey="$("$PYTHON" - <<'PY'
import secrets
print(secrets.token_hex(32))
PY
)"
  status="$(http_status POST /api/auth/pair-device/redeem "" \
    "{\"token\":\"$pair_token\",\"public_key\":\"$paired_pubkey\"}" \
    "$ARTIFACTS/agent-pair-device-redeem.json")"
  assert_status "agent pair-device redeem" "$status" 200
  local paired_principal
  local paired_bearer
  local paired_key_id
  paired_principal="$(json_field "$ARTIFACTS/agent-pair-device-redeem.json" principal)"
  paired_bearer="$(json_field "$ARTIFACTS/agent-pair-device-redeem.json" session_token)"
  paired_key_id="$(json_field "$ARTIFACTS/agent-pair-device-redeem.json" key_id)"
  [[ "$paired_principal" == "$user_principal" ]] || fail "paired device principal $paired_principal did not match $user_principal"
  status="$(http_status POST /api/auth/pair-device/redeem "" \
    "{\"token\":\"$pair_token\",\"public_key\":\"$paired_pubkey\"}" \
    "$ARTIFACTS/agent-pair-device-reuse-denied.json")"
  assert_status "pair token reuse denied" "$status" 502
  status="$(http_status GET /api/auth/me "$paired_bearer" "" "$ARTIFACTS/paired-me.json")"
  assert_status "paired auth/me" "$status" 200
  json_assert_field_equals "$ARTIFACTS/paired-me.json" principal "$user_principal"
  json_assert_field_equals "$ARTIFACTS/paired-me.json" device_key_id "$paired_key_id"
  status="$(http_status POST /api/auth/refresh "$paired_bearer" "" "$ARTIFACTS/paired-refresh.json")"
  assert_status "paired refresh" "$status" 200
  local refreshed_paired_bearer
  refreshed_paired_bearer="$(json_field "$ARTIFACTS/paired-refresh.json" session_token)"
  status="$(http_status GET /api/auth/me "$refreshed_paired_bearer" "" "$ARTIFACTS/paired-refresh-me.json")"
  assert_status "paired refresh auth/me" "$status" 200
  json_assert_field_equals "$ARTIFACTS/paired-refresh-me.json" principal "$user_principal"
  json_assert_field_equals "$ARTIFACTS/paired-refresh-me.json" device_key_id "$paired_key_id"
  status="$(http_status GET "/api/sys/principals/$user_principal/devices" "$user_bearer" "" \
    "$ARTIFACTS/agent-devices.json")"
  assert_status "agent device list" "$status" 200
  json_assert_device_list_contains "$ARTIFACTS/agent-devices.json" "$paired_key_id"
  status="$(http_status DELETE "/api/sys/principals/$user_principal/devices/$paired_key_id" "$user_bearer" "" \
    "$ARTIFACTS/agent-paired-device-revoke.json")"
  assert_status "agent paired-device revoke" "$status" 204
  status="$(http_status GET /api/auth/me "$paired_bearer" "" "$ARTIFACTS/paired-me-after-revoke.json")"
  assert_status "revoked paired bearer denied" "$status" 401
  status="$(http_status GET /api/auth/me "$refreshed_paired_bearer" "" \
    "$ARTIFACTS/paired-refresh-me-after-revoke.json")"
  assert_status "revoked refreshed paired bearer denied" "$status" 401

  status="$(http_status POST /api/auth/redeem "" \
    "{\"token\":\"$agent_invite\",\"public_key\":\"$paired_pubkey\",\"display_name\":\"reuse\"}" \
    "$ARTIFACTS/agent-invite-reuse-denied.json")"
  assert_status "invite token reuse denied" "$status" 502

  status="$(http_status GET /api/sys/principals "$user_bearer" "" "$ARTIFACTS/agent-principals.json")"
  assert_status "agent principal visibility" "$status" 200
  json_assert_principal_list_is_self_only "$ARTIFACTS/agent-principals.json" "$user_principal"
  status="$(http_status GET "/api/sys/principals/$ops_principal" "$user_bearer" "" \
    "$ARTIFACTS/agent-show-ops-denied.json")"
  assert_status "agent cross-principal principal detail hidden" "$status" 404
  status="$(http_status GET "/api/sys/principals/$user_principal" "$user_bearer" "" \
    "$ARTIFACTS/agent-show-self.json")"
  assert_status "agent principal self detail" "$status" 200
  json_assert_field_equals "$ARTIFACTS/agent-show-self.json" principal "$user_principal"
  status="$(http_status POST /api/sys/invites "$user_bearer" \
    '{"group":"agent","max_uses":1,"expires_secs":600}' \
    "$ARTIFACTS/agent-invite-denied.json")"
  assert_status "agent invite issue denied" "$status" 403
  status="$(http_status GET /api/auth/me "" "" "$ARTIFACTS/unauth-me.json")"
  assert_status "unauthenticated auth/me" "$status" 401
  status="$(http_status POST /api/auth/refresh "$user_bearer" "" "$ARTIFACTS/agent-refresh.json")"
  assert_status "agent refresh" "$status" 200
  local refresh_principal
  refresh_principal="$(json_field "$ARTIFACTS/agent-refresh.json" principal)"
  [[ "$refresh_principal" == "$user_principal" ]] || fail "refresh principal $refresh_principal did not match $user_principal"

  note "checking live capability grant and revoke"
  status="$(http_status GET /api/sys/status "$user_bearer" "" "$ARTIFACTS/agent-status-before-grant.json")"
  assert_status "agent status denied before grant" "$status" 403
  run_cli caps grant "$user_principal" system:status
  status="$(http_status GET /api/sys/status "$user_bearer" "" "$ARTIFACTS/agent-status-after-grant.json")"
  assert_status "agent status allowed after grant" "$status" 200
  run_cli caps revoke "$user_principal" system:status
  status="$(http_status GET /api/sys/status "$user_bearer" "" "$ARTIFACTS/agent-status-after-revoke.json")"
  assert_status "agent status denied after revoke" "$status" 403

  run_cli quota set --agent "$user_principal" --processes 4 --ipc-rate "1MB/s"
  status="$(http_status GET "/api/sys/principals/$user_principal/quotas" "$user_bearer" "" \
    "$ARTIFACTS/agent-quotas.json")"
  assert_status "agent quota self-read" "$status" 200
  status="$(http_status GET "/api/sys/principals/$ops_principal/quotas" "$user_bearer" "" \
    "$ARTIFACTS/agent-quotas-cross-principal-denied.json")"
  assert_status "agent cross-principal quota read denied" "$status" 403
  status="$(http_status GET "/api/sys/principals/$ops_principal/devices" "$user_bearer" "" \
    "$ARTIFACTS/agent-devices-cross-principal-denied.json")"
  assert_status "agent cross-principal devices read denied" "$status" 403

  note "checking per-principal capsule env isolation"
  status="$(http_status POST /api/capsules/astrid-capsule-openai-compat/env/model "" \
    '{"value":"fake-unauth"}' \
    "$ARTIFACTS/unauth-openai-env-write.json")"
  assert_status "unauthenticated env model write denied" "$status" 401
  status="$(http_status GET /api/capsules/astrid-capsule-openai-compat/env "$user_bearer" "" \
    "$ARTIFACTS/agent-openai-env-schema.json")"
  assert_status "agent env schema read" "$status" 200
  status="$(http_status POST /api/capsules/astrid-capsule-openai-compat/env/base_url "$user_bearer" \
    "{\"value\":\"$fake_base_url\"}" "$ARTIFACTS/agent-openai-base-url-write.json")"
  assert_status "agent env base_url write" "$status" 204
  status="$(http_status POST /api/capsules/astrid-capsule-openai-compat/env/base_url "$ops_bearer" \
    "{\"value\":\"$fake_base_url\"}" "$ARTIFACTS/operator-openai-base-url-write.json")"
  assert_status "operator env base_url write" "$status" 204
  status="$(http_status POST /api/capsules/astrid-capsule-openai-compat/env/model "$user_bearer" \
    '{"value":"fake-slow"}' \
    "$ARTIFACTS/agent-openai-env-write.json")"
  assert_status "agent env model write" "$status" 204
  status="$(http_status POST /api/capsules/astrid-capsule-openai-compat/env/model "$ops_bearer" \
    '{"value":"fake-toolish"}' \
    "$ARTIFACTS/operator-openai-env-write.json")"
  assert_status "operator env model write" "$status" 204
  json_assert_capsule_env_models "$ASTRID_HOME" astrid-capsule-openai-compat default "$user_principal" "$ops_principal" \
    fake-echo fake-slow fake-toolish

  status="$(http_status POST /api/capsules/astrid-capsule-openai-compat/env/model "$user_bearer" \
    '{"value":"fake-spoof","principal":"default"}' \
    "$ARTIFACTS/agent-openai-env-spoofed-principal-write.json")"
  assert_status "agent env body principal spoof ignored" "$status" 204
  json_assert_capsule_env_models "$ASTRID_HOME" astrid-capsule-openai-compat default "$user_principal" "$ops_principal" \
    fake-echo fake-spoof fake-toolish
  status="$(http_status POST /api/capsules/astrid-capsule-openai-compat/env/model "$user_bearer" \
    '{"value":"fake-slow"}' \
    "$ARTIFACTS/agent-openai-env-restore.json")"
  assert_status "agent env model restore" "$status" 204
  json_assert_capsule_env_models "$ASTRID_HOME" astrid-capsule-openai-compat default "$user_principal" "$ops_principal" \
    fake-echo fake-slow fake-toolish

  note "checking per-principal secret isolation"
  local user_secret="ASTRID_E2E_USER_SECRET_DO_NOT_LEAK_$RANDOM$RANDOM"
  local ops_secret="ASTRID_E2E_OPS_SECRET_DO_NOT_LEAK_$RANDOM$RANDOM"
  register_redaction_sentinel "$user_secret"
  register_redaction_sentinel "$ops_secret"
  status="$(http_status POST /api/capsules/astrid-capsule-openai-compat/env/api_key "$user_bearer" \
    "{\"value\":\"$user_secret\",\"principal\":\"default\"}" \
    "$ARTIFACTS/agent-openai-secret-spoofed-principal-write.json")"
  assert_status "agent secret body principal spoof ignored" "$status" 204
  status="$(http_status POST /api/capsules/astrid-capsule-openai-compat/env/api_key "$ops_bearer" \
    "{\"value\":\"$ops_secret\"}" \
    "$ARTIFACTS/operator-openai-secret-write.json")"
  assert_status "operator secret write" "$status" 204
  json_assert_secret_files_isolated "$ASTRID_HOME" astrid-capsule-openai-compat \
    "$sentinel" "$user_principal" "$user_secret" "$ops_principal" "$ops_secret"
  run_cli secret list --agent "$user_principal" --format json > "$ARTIFACTS/agent-secret-list.json"
  run_cli secret list --agent "$ops_principal" --format json > "$ARTIFACTS/operator-secret-list.json"
  json_assert_secret_list_metadata "$ARTIFACTS/agent-secret-list.json" \
    astrid-capsule-openai-compat api_key
  json_assert_secret_list_metadata "$ARTIFACTS/operator-secret-list.json" \
    astrid-capsule-openai-compat api_key
  run_cli_semantic_smoke "$user_principal" "$ops_principal"

  curl -sN --max-time 3 \
    -H "Authorization: Bearer $user_bearer" \
    "$GATEWAY/api/agent/stream" \
    > "$ARTIFACTS/agent-stream.sse" 2>&1 || true
  grep -q '^event: ready' "$ARTIFACTS/agent-stream.sse" \
    || fail "agent stream did not emit ready event"
  grep -q "\"principal\":\"$user_principal\"" "$ARTIFACTS/agent-stream.sse" \
    || fail "agent stream ready event did not carry caller principal"

  note "checking model discovery through registry capsule"
  local models_out="$ARTIFACTS/models-list.json"
  local deadline=$((SECONDS + 45))
  until run_cli capsule run astrid-capsule-registry models list --json > "$models_out" \
    && grep -q 'fake-echo' "$models_out"; do
    if (( SECONDS >= deadline )); then
      cat "$models_out" >&2 2>/dev/null || true
      fail "registry did not discover fake-echo via openai-compat"
    fi
    sleep 2
  done
  run_cli capsule run astrid-capsule-registry models set openai-compat:fake-echo

  note "checking per-principal active model isolation"
  status="$(http_status GET /api/models "$user_bearer" "" "$ARTIFACTS/agent-models.json")"
  assert_status "agent model list" "$status" 200
  json_assert_model_list_contains "$ARTIFACTS/agent-models.json" "openai-compat:fake-echo"
  json_assert_model_list_contains "$ARTIFACTS/agent-models.json" "openai-compat:fake-slow"
  status="$(http_status PUT /api/models/active "$user_bearer" \
    '{"id":"openai-compat:fake-slow"}' \
    "$ARTIFACTS/agent-set-active-model.json")"
  assert_status "agent set active model" "$status" 200
  json_assert_model_id "$ARTIFACTS/agent-set-active-model.json" "openai-compat:fake-slow"
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
  run_llm_provider_smoke "$user_bearer" "$user_principal" "$ARTIFACTS/agent-models.json" "$fake_base_url"

  run_multi_home_smoke "$fake_base_url" "$user_bearer" "$user_principal"

  note "checking per-principal session isolation"
  local user_session ops_session
  user_session="$("$PYTHON" -c 'import uuid; print(uuid.uuid4())')"
  ops_session="$("$PYTHON" -c 'import uuid; print(uuid.uuid4())')"
  local user_session_text="ASTRID_E2E_USER_SESSION_DO_NOT_LEAK_$RANDOM$RANDOM"
  local ops_session_text="ASTRID_E2E_OPS_SESSION_DO_NOT_LEAK_$RANDOM$RANDOM"
  local user_session_title="regular user e2e session"
  run_principal_cli "$user_principal" run --format json --session "$user_session" \
    "$user_session_text" > "$ARTIFACTS/agent-session-run.json"
  run_principal_cli "$ops_principal" run --format json --session "$ops_session" \
    "$ops_session_text" > "$ARTIFACTS/operator-session-run.json"
  assert_principal_llm_attribution "$user_session_text" "$ops_session_text"

  status="$(http_status GET "/api/agent/sessions?include_archived=true&limit=20" "$user_bearer" "" \
    "$ARTIFACTS/agent-sessions.json")"
  assert_status "agent session list" "$status" 200
  json_assert_session_list_scope "$ARTIFACTS/agent-sessions.json" "$user_session" "$ops_session"
  status="$(http_status GET "/api/agent/sessions?include_archived=true&limit=20" "$ops_bearer" "" \
    "$ARTIFACTS/operator-sessions.json")"
  assert_status "operator session list" "$status" 200
  json_assert_session_list_scope "$ARTIFACTS/operator-sessions.json" "$ops_session" "$user_session"
  status="$(http_status GET "/api/agent/sessions/$user_session/messages" "$user_bearer" "" \
    "$ARTIFACTS/agent-session-messages.json")"
  assert_status "agent session transcript" "$status" 200
  json_assert_session_messages_contains "$ARTIFACTS/agent-session-messages.json" "$user_session" "$user_session_text"
  status="$(http_status GET "/api/agent/sessions/$ops_session/messages" "$ops_bearer" "" \
    "$ARTIFACTS/operator-session-messages.json")"
  assert_status "operator session transcript" "$status" 200
  json_assert_session_messages_contains "$ARTIFACTS/operator-session-messages.json" "$ops_session" "$ops_session_text"
  status="$(http_status GET "/api/agent/sessions/$ops_session" "$user_bearer" "" \
    "$ARTIFACTS/agent-cross-session-get-hidden.json")"
  assert_status "agent cross-principal session get hidden" "$status" 404
  status="$(http_status GET "/api/agent/sessions/$ops_session/messages" "$user_bearer" "" \
    "$ARTIFACTS/agent-cross-session-messages-empty.json")"
  assert_status "agent cross-principal session transcript empty" "$status" 200
  json_assert_session_messages_empty "$ARTIFACTS/agent-cross-session-messages-empty.json" "$ops_session"
  status="$(http_status GET "/api/agent/sessions/search?q=$user_session_text&include_archived=true" "$user_bearer" "" \
    "$ARTIFACTS/agent-session-search-own.json")"
  assert_status "agent session search own" "$status" 200
  json_assert_session_search_scope "$ARTIFACTS/agent-session-search-own.json" "$user_session" "$ops_session"
  status="$(http_status GET "/api/agent/sessions/search?q=$ops_session_text&include_archived=true" "$user_bearer" "" \
    "$ARTIFACTS/agent-session-search-cross-hidden.json")"
  assert_status "agent session search cross-principal hidden" "$status" 200
  json_assert_session_search_scope "$ARTIFACTS/agent-session-search-cross-hidden.json" "-" "$ops_session"
  status="$(http_status PATCH "/api/agent/sessions/$user_session" "$user_bearer" \
    "{\"title\":\"$user_session_title\",\"session_id\":\"$ops_session\"}" \
    "$ARTIFACTS/agent-session-update.json")"
  assert_status "agent session update own" "$status" 200
  json_assert_session_summary "$ARTIFACTS/agent-session-update.json" "$user_session" "$user_session_title"
  status="$(http_status PATCH "/api/agent/sessions/$ops_session" "$user_bearer" \
    '{"title":"cross principal spoofed title"}' \
    "$ARTIFACTS/agent-cross-session-update-hidden.json")"
  assert_status "agent cross-principal session update hidden" "$status" 404
  status="$(http_status DELETE "/api/agent/sessions/$ops_session" "$user_bearer" "" \
    "$ARTIFACTS/agent-cross-session-delete-false.json")"
  assert_status "agent cross-principal session delete false" "$status" 200
  json_assert_deleted_flag "$ARTIFACTS/agent-cross-session-delete-false.json" false
  status="$(http_status GET "/api/agent/sessions/$ops_session" "$ops_bearer" "" \
    "$ARTIFACTS/operator-session-after-cross-attempts.json")"
  assert_status "operator session survived cross-principal attempts" "$status" 200
  json_assert_session_summary "$ARTIFACTS/operator-session-after-cross-attempts.json" "$ops_session" null

  note "checking prompt path through fake LLM"
  local run_out="$ARTIFACTS/run-output.txt"
  run_cli run --format json "say the word ping" > "$run_out"
  grep -qi 'ping\|fake echo' "$run_out" || {
    cat "$run_out" >&2
    fail "astrid run did not surface fake LLM output"
  }

  note "checking gateway prompt SSE opens for isolated regular principal"
  curl -sN --max-time 5 \
    -X POST "$GATEWAY/api/agent/prompt" \
    -H "Authorization: Bearer $user_bearer" \
    -H "Content-Type: application/json" \
    -d '{"text":"hello from gateway"}' \
    > "$ARTIFACTS/gateway-prompt.sse" 2>&1 || true
  if grep -q '^event: ready' "$ARTIFACTS/gateway-prompt.sse"; then
    note "gateway prompt emitted ready SSE event"
  elif grep -q '^event: error' "$ARTIFACTS/gateway-prompt.sse" \
    && grep -q 'agent loop not ready' "$ARTIFACTS/gateway-prompt.sse" \
    && grep -q 'unsatisfied_imports' "$ARTIFACTS/gateway-prompt.sse"; then
    note "gateway prompt returned bounded readiness error for incomplete prompt stack"
  else
    fail "gateway prompt did not emit a recognized bounded SSE result"
  fi

  note "checking restart persistence"
  stop_daemon
  start_daemon "restarting daemon against same ASTRID_HOME"
  status="$(http_status GET /api/auth/me "$user_bearer" "" "$ARTIFACTS/restart-agent-me.json")"
  assert_status "restart agent auth/me" "$status" 200
  json_assert_field_equals "$ARTIFACTS/restart-agent-me.json" principal "$user_principal"
  status="$(http_status POST /api/auth/refresh "$user_bearer" "" "$ARTIFACTS/restart-agent-refresh.json")"
  assert_status "restart agent refresh" "$status" 200
  local restart_user_bearer
  restart_user_bearer="$(json_field "$ARTIFACTS/restart-agent-refresh.json" session_token)"
  status="$(http_status GET /api/auth/me "$restart_user_bearer" "" "$ARTIFACTS/restart-agent-refresh-me.json")"
  assert_status "restart refreshed auth/me" "$status" 200
  json_assert_field_equals "$ARTIFACTS/restart-agent-refresh-me.json" principal "$user_principal"
  status="$(http_status GET /api/models/active "$restart_user_bearer" "" "$ARTIFACTS/restart-agent-active-model.json")"
  assert_status "restart agent active model" "$status" 200
  json_assert_model_id "$ARTIFACTS/restart-agent-active-model.json" "openai-compat:fake-slow"
  status="$(http_status GET /api/models/active "$ops_bearer" "" "$ARTIFACTS/restart-operator-active-model.json")"
  assert_status "restart operator active model" "$status" 200
  json_assert_model_id "$ARTIFACTS/restart-operator-active-model.json" "openai-compat:fake-toolish"
  status="$(http_status GET "/api/sys/principals/$user_principal/quotas" "$restart_user_bearer" "" \
    "$ARTIFACTS/restart-agent-quotas.json")"
  assert_status "restart agent quota self-read" "$status" 200
  status="$(http_status GET "/api/sys/principals/$ops_principal/quotas" "$restart_user_bearer" "" \
    "$ARTIFACTS/restart-agent-quotas-cross-principal-denied.json")"
  assert_status "restart cross-principal quota read denied" "$status" 403
  status="$(http_status GET /api/capsules/astrid-capsule-openai-compat/env "$restart_user_bearer" "" \
    "$ARTIFACTS/restart-agent-openai-env-schema.json")"
  assert_status "restart agent env schema read" "$status" 200
  json_assert_secret_files_isolated "$ASTRID_HOME" astrid-capsule-openai-compat \
    "$sentinel" "$user_principal" "$user_secret" "$ops_principal" "$ops_secret"
  run_cli secret list --agent "$user_principal" --format json > "$ARTIFACTS/restart-agent-secret-list.json"
  json_assert_secret_list_metadata "$ARTIFACTS/restart-agent-secret-list.json" \
    astrid-capsule-openai-compat api_key
  status="$(http_status GET "/api/agent/sessions?include_archived=true&limit=20" "$restart_user_bearer" "" \
    "$ARTIFACTS/restart-agent-sessions.json")"
  assert_status "restart agent session list" "$status" 200
  json_assert_session_list_scope "$ARTIFACTS/restart-agent-sessions.json" "$user_session" "$ops_session"
  status="$(http_status GET "/api/agent/sessions/$user_session" "$restart_user_bearer" "" \
    "$ARTIFACTS/restart-agent-session.json")"
  assert_status "restart agent session get" "$status" 200
  json_assert_session_summary "$ARTIFACTS/restart-agent-session.json" "$user_session" "$user_session_title"
  status="$(http_status GET "/api/agent/sessions/$user_session/messages" "$restart_user_bearer" "" \
    "$ARTIFACTS/restart-agent-session-messages.json")"
  assert_status "restart agent session transcript" "$status" 200
  json_assert_session_messages_contains "$ARTIFACTS/restart-agent-session-messages.json" \
    "$user_session" "$user_session_text"
  status="$(http_status GET "/api/agent/sessions/$ops_session" "$restart_user_bearer" "" \
    "$ARTIFACTS/restart-agent-cross-session-get-hidden.json")"
  assert_status "restart agent cross-principal session get hidden" "$status" 404
  status="$(http_status GET "/api/agent/sessions/$ops_session/messages" "$restart_user_bearer" "" \
    "$ARTIFACTS/restart-agent-cross-session-messages-empty.json")"
  assert_status "restart agent cross-principal session transcript empty" "$status" 200
  json_assert_session_messages_empty "$ARTIFACTS/restart-agent-cross-session-messages-empty.json" "$ops_session"

  note "collecting scoped audit artifacts"
  collect_audit_artifacts "$restart_user_bearer" "$ops_bearer"

  redaction_check "$sentinel"
  redaction_check "$user_secret"
  redaction_check "$ops_secret"
  stage_redacted_upload
  assert_poison_home_unused "$POISON_HOME"
  note "runtime e2e passed; artifacts at $ARTIFACTS"
}

main "$@"
