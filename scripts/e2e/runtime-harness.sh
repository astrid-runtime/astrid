#!/usr/bin/env bash
# Full-runtime Astrid smoke harness for CI.
#
# This script owns a temp ASTRID_HOME, builds real binaries, installs real
# capsule artifacts from local checkouts, points openai-compat at the local
# fake OpenAI-compatible server, and exercises the model/prompt path through
# the CLI plus gateway.

set -euo pipefail

CORE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT_DIR="$CORE_DIR/scripts/e2e"
CAPSULES_DIR="${ASTRID_E2E_CAPSULES_DIR:-$CORE_DIR/../capsules}"
ASTRID_HOME="${ASTRID_E2E_HOME:-$(mktemp -d "${TMPDIR:-/tmp}/astrid-runtime-e2e.XXXXXX")}"
ARTIFACTS="$ASTRID_HOME/artifacts"
GATEWAY_HOST="${ASTRID_E2E_GATEWAY_HOST:-127.0.0.1}"
GATEWAY_PORT="${ASTRID_E2E_GATEWAY_PORT:-38756}"
GATEWAY="http://$GATEWAY_HOST:$GATEWAY_PORT"
PYTHON="${PYTHON:-python3}"

# Keep this list explicit. Adding a shipped capsule to the core prompt/model
# story should be an intentional CI contract change.
CORE_CAPSULES="${ASTRID_E2E_CORE_CAPSULES:-astrid-capsule-cli astrid-capsule-registry astrid-capsule-session astrid-capsule-identity astrid-capsule-prompt-builder astrid-capsule-react astrid-capsule-openai-compat}"

DAEMON_PID=""
FAKE_PID=""
POISON_HOME=""

terminate_pid() {
  local pid=$1
  if [[ -n "$pid" ]]; then
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi
}

cleanup() {
  trap - EXIT INT TERM
  terminate_pid "$DAEMON_PID"
  terminate_pid "$FAKE_PID"
  if [[ -n "$POISON_HOME" && -z "${ASTRID_E2E_KEEP_HOME:-}" ]]; then
    rm -rf "$POISON_HOME"
  elif [[ -n "$POISON_HOME" ]]; then
    printf 'kept poisoned HOME=%s\n' "$POISON_HOME"
  fi
  if [[ -z "${ASTRID_E2E_KEEP_HOME:-}" ]]; then
    rm -rf "$ASTRID_HOME"
  else
    printf 'kept ASTRID_HOME=%s\n' "$ASTRID_HOME"
  fi
}
trap cleanup EXIT INT TERM

note() { printf '\n==> %s\n' "$*"; }
fail() { printf 'error: %s\n' "$*" >&2; exit 1; }

run_cli() {
  printf '$ astrid %s\n' "$*" >> "$ARTIFACTS/cli-transcript.log"
  "$CORE_DIR/target/debug/astrid" "$@" \
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
    --max-time 10
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
  curl "${args[@]}"
}

assert_status() {
  local label=$1
  local got=$2
  local want=$3
  if [[ "$got" != "$want" ]]; then
    fail "$label expected HTTP $want, got $got"
  fi
}

json_field() {
  local file=$1
  local field=$2
  "$PYTHON" - "$file" "$field" <<'PY'
import json
import sys

value = json.load(open(sys.argv[1], encoding="utf-8"))
for part in sys.argv[2].split("."):
    value = value[part]
print(value)
PY
}

json_assert_principal_list_is_self_only() {
  local file=$1
  local principal=$2
  "$PYTHON" - "$file" "$principal" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
principal = sys.argv[2]
principals = [entry["principal"] for entry in data.get("principals", [])]
if principal not in principals:
    raise SystemExit(f"{principal} missing from principal list: {principals}")
if "default" in principals and principal != "default":
    raise SystemExit(f"non-admin principal saw default in principal list: {principals}")
PY
}

json_assert_field_equals() {
  local file=$1
  local field=$2
  local expected=$3
  local found
  found="$(json_field "$file" "$field")"
  [[ "$found" == "$expected" ]] || fail "$field in $file was $found, expected $expected"
}

json_assert_model_id() {
  local file=$1
  local expected=$2
  "$PYTHON" - "$file" "$expected" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
expected = sys.argv[2]
found = data.get("id") if isinstance(data, dict) else None
if found != expected:
    raise SystemExit(f"expected model id {expected!r}, got {found!r}: {data!r}")
PY
}

json_assert_model_list_contains() {
  local file=$1
  local expected=$2
  "$PYTHON" - "$file" "$expected" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
expected = sys.argv[2]
if isinstance(data, dict) and isinstance(data.get("data"), list):
    data = data["data"]
ids = [entry.get("id") for entry in data if isinstance(entry, dict)]
if expected not in ids:
    raise SystemExit(f"expected {expected!r} in model ids {ids!r}")
PY
}

json_assert_capsule_env_models() {
  local home=$1
  local capsule=$2
  local default_principal=$3
  local user_principal=$4
  local ops_principal=$5
  local default_model=$6
  local user_model=$7
  local ops_model=$8
  "$PYTHON" - "$home" "$capsule" "$default_principal" "$user_principal" "$ops_principal" "$default_model" "$user_model" "$ops_model" <<'PY'
import json
import sys
from pathlib import Path

home = Path(sys.argv[1])
capsule = sys.argv[2]
default_principal = sys.argv[3]
user_principal = sys.argv[4]
ops_principal = sys.argv[5]
default_model = sys.argv[6]
user_model = sys.argv[7]
ops_model = sys.argv[8]

def read_env(principal: str) -> dict:
    path = home / "home" / principal / ".config" / "env" / f"{capsule}.env.json"
    if not path.exists():
        raise SystemExit(f"missing env file for {principal}: {path}")
    return json.loads(path.read_text(encoding="utf-8"))

default_env = read_env(default_principal)
user_env = read_env(user_principal)
ops_env = read_env(ops_principal)

if default_env.get("model") != default_model:
    raise SystemExit(f"default model drifted: {default_env!r}")
if user_env.get("model") != user_model:
    raise SystemExit(f"user model write missed or leaked: {user_env!r}")
if ops_env.get("model") != ops_model:
    raise SystemExit(f"ops model write missed or leaked: {ops_env!r}")
if user_env.get("model") == ops_env.get("model"):
    raise SystemExit(f"user and ops env models unexpectedly match: {user_env!r} / {ops_env!r}")
PY
}

json_assert_secret_list_metadata() {
  local file=$1
  local capsule=$2
  local key=$3
  "$PYTHON" - "$file" "$capsule" "$key" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
capsule = sys.argv[2]
key = sys.argv[3]
matches = [
    entry for entry in data
    if entry.get("capsule") == capsule and entry.get("key") == key
]
if len(matches) != 1:
    raise SystemExit(f"expected one secret metadata entry for {capsule}/{key}, got {matches!r}")
entry = matches[0]
if entry.get("storage") != "file":
    raise SystemExit(f"secret metadata did not report file storage: {entry!r}")
if entry.get("scope") != "agent":
    raise SystemExit(f"secret metadata did not report agent scope: {entry!r}")
for forbidden in ("value", "secret"):
    if forbidden in entry:
        raise SystemExit(f"secret metadata leaked {forbidden!r}: {entry!r}")
PY
}

json_assert_secret_files_isolated() {
  local home=$1
  local capsule=$2
  local default_secret=$3
  local user_principal=$4
  local user_secret=$5
  local ops_principal=$6
  local ops_secret=$7
  "$PYTHON" - "$home" "$capsule" "$default_secret" "$user_principal" "$user_secret" "$ops_principal" "$ops_secret" <<'PY'
import os
import stat
import sys
from pathlib import Path

home = Path(sys.argv[1])
capsule = sys.argv[2]
default_secret = sys.argv[3]
user_principal = sys.argv[4]
user_secret = sys.argv[5]
ops_principal = sys.argv[6]
ops_secret = sys.argv[7]

expected = {
    "default": default_secret,
    user_principal: user_secret,
    ops_principal: ops_secret,
}

for principal, value in expected.items():
    path = home / "secrets" / principal / capsule / "api_key"
    if not path.exists():
        raise SystemExit(f"missing secret file for {principal}: {path}")
    found = path.read_text(encoding="utf-8")
    if found != value:
        raise SystemExit(f"secret value for {principal} did not match its own sentinel")
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode != 0o600:
        raise SystemExit(f"secret file for {principal} has mode {mode:o}, expected 600")

if len(set(expected.values())) != len(expected):
    raise SystemExit("test sentinels must be distinct")
PY
}

json_assert_device_list_contains() {
  local file=$1
  local key_id=$2
  "$PYTHON" - "$file" "$key_id" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
key_id = sys.argv[2]
devices = data.get("devices", [])
ids = [device.get("key_id") for device in devices if isinstance(device, dict)]
if key_id not in ids:
    raise SystemExit(f"expected device {key_id!r} in {ids!r}")
PY
}

assert_poison_home_unused() {
  local home=$1
  local astrid_dir="$home/.astrid"
  local forbidden=(
    "$astrid_dir/run/system.sock"
    "$astrid_dir/run/system.token"
    "$astrid_dir/keys/gateway.ed25519"
    "$astrid_dir/home/regular-user"
    "$astrid_dir/home/operator-1"
    "$astrid_dir/secrets"
  )
  local path
  for path in "${forbidden[@]}"; do
    if [[ -e "$path" ]]; then
      fail "poisoned HOME was used unexpectedly: $path exists"
    fi
  done
}

redeem_invite() {
  local invite=$1
  local display_name=$2
  local out=$3
  local pubkey
  pubkey="$("$PYTHON" - <<'PY'
import secrets
print(secrets.token_hex(32))
PY
)"
  local status
  status="$(http_status POST /api/auth/redeem "" \
    "{\"token\":\"$invite\",\"public_key\":\"$pubkey\",\"display_name\":\"$display_name\"}" \
    "$out")"
  assert_status "$display_name redeem" "$status" 200
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

redaction_check() {
  local sentinel=$1
  if grep -R --fixed-strings "$sentinel" "$ARTIFACTS" >/dev/null 2>&1; then
    fail "sentinel secret leaked into runtime e2e artifacts"
  fi
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

  note "checking principal and capability isolation"
  run_cli group create ops-team --caps "capsule:install,invite:issue,invite:list"

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

  note "checking prompt path through fake LLM"
  local run_out="$ARTIFACTS/run-output.txt"
  run_cli run --format json "say the word ping" > "$run_out"
  grep -qi 'ping\|fake echo' "$run_out" || {
    cat "$run_out" >&2
    fail "astrid run did not surface fake LLM output"
  }

  note "checking gateway prompt SSE opens for isolated regular principal"
  run_cli agent modify "$user_principal" \
    --add-capsule astrid-capsule-registry \
    --add-capsule astrid-capsule-session \
    --add-capsule astrid-capsule-identity \
    --add-capsule astrid-capsule-prompt-builder \
    --add-capsule astrid-capsule-react \
    --add-capsule astrid-capsule-openai-compat
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

  redaction_check "$sentinel"
  redaction_check "$user_secret"
  redaction_check "$ops_secret"
  assert_poison_home_unused "$POISON_HOME"
  note "runtime e2e passed; artifacts at $ARTIFACTS"
}

main "$@"
