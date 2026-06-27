#!/usr/bin/env bash

expect_principal_cli_failure() {
  local principal=$1 label=$2
  shift 2
  if run_principal_cli "$principal" "$@" \
    > "$ARTIFACTS/$label.out" \
    2> "$ARTIFACTS/$label.err"; then
    cat "$ARTIFACTS/$label.out" >&2 || true
    cat "$ARTIFACTS/$label.err" >&2 || true
    fail "$label unexpectedly succeeded"
  fi
}

expect_principal_cli_success() {
  local principal=$1 label=$2
  shift 2
  if ! run_principal_cli "$principal" "$@" \
    > "$ARTIFACTS/$label.out" \
    2> "$ARTIFACTS/$label.err"; then
    cat "$ARTIFACTS/$label.out" >&2 || true
    cat "$ARTIFACTS/$label.err" >&2 || true
    fail "$label failed"
  fi
}

assert_principal_profile_absent() {
  local principal=$1
  local path="$ASTRID_HOME/etc/profiles/$principal.toml"
  [[ ! -e "$path" ]] || fail "denied principal create left profile behind: $path"
}

mint_admin_bearer() {
  local token pubkey status
  token="$("$CORE_DIR/target/debug/astrid" --principal default pair-device issue \
    --scope full \
    --label "runtime e2e admin adversarial device" \
    --expires-secs 120 \
    --raw 2>> "$ARTIFACTS/cli-transcript.log")"
  printf '$ astrid --principal default pair-device issue --scope full --label <e2e> --expires-secs 120 --raw\n<redacted pair token>\n' \
    >> "$ARTIFACTS/cli-transcript.log"
  pubkey="$("$PYTHON" - <<'PY'
import secrets
print(secrets.token_hex(32))
PY
)"
  status="$(http_status POST /api/auth/pair-device/redeem "" \
    "{\"token\":\"$token\",\"public_key\":\"$pubkey\"}" \
    "$ARTIFACTS/adversarial-admin-pair-redeem.json")"
  assert_status "admin pair-device redeem for adversarial checks" "$status" 200
  json_field "$ARTIFACTS/adversarial-admin-pair-redeem.json" session_token
}

json_assert_inheritance_and_clone_state() {
  local home=$1
  local source=$2
  local inherited=$3
  local cloned=$4
  local capsule=$5
  local expected_secret=$6
  "$PYTHON" - "$home" "$source" "$inherited" "$cloned" "$capsule" "$expected_secret" <<'PY'
import json
import re
import sys
from pathlib import Path

home = Path(sys.argv[1])
source = sys.argv[2]
inherited = sys.argv[3]
cloned = sys.argv[4]
capsule = sys.argv[5]
expected_secret = sys.argv[6]

def profile_array(path: Path, key: str) -> list[str]:
    if not path.exists():
        raise SystemExit(f"missing profile file: {path}")
    text = path.read_text(encoding="utf-8")
    match = re.search(rf"(?ms)^\s*{re.escape(key)}\s*=\s*\[(.*?)\]", text)
    if not match:
        return []
    return re.findall(r'"([^"]*)"', match.group(1))

def profile(principal: str) -> dict[str, list[str]]:
    path = home / "etc" / "profiles" / f"{principal}.toml"
    return {
        "groups": profile_array(path, "groups"),
        "capsules": profile_array(path, "capsules"),
    }

def env(principal: str) -> dict:
    path = home / "home" / principal / ".config" / "env" / f"{capsule}.env.json"
    if not path.exists():
        raise SystemExit(f"missing env file for {principal}: {path}")
    return json.loads(path.read_text(encoding="utf-8"))

def secret(principal: str) -> str:
    path = home / "secrets" / principal / capsule / "api_key"
    if not path.exists():
        raise SystemExit(f"missing secret file for {principal}: {path}")
    return path.read_text(encoding="utf-8")

source_profile = profile(source)
inherited_profile = profile(inherited)
cloned_profile = profile(cloned)

source_capsules = set(source_profile.get("capsules", []))
if capsule not in source_capsules:
    raise SystemExit(f"source profile did not include expected capsule grant: {source_profile!r}")

if inherited_profile.get("capsules", []):
    raise SystemExit(f"inherit-only create copied capsule grants: {inherited_profile!r}")
if inherited_profile.get("groups", []) != ["agent"]:
    raise SystemExit(f"inherit-only create should keep a clean agent profile: {inherited_profile!r}")

cloned_capsules = set(cloned_profile.get("capsules", []))
if not source_capsules.issubset(cloned_capsules):
    raise SystemExit(
        f"clone missed source capsule grants: source={source_profile!r} clone={cloned_profile!r}"
    )
if cloned_profile.get("groups") != source_profile.get("groups"):
    raise SystemExit(f"clone missed source groups: source={source_profile!r} clone={cloned_profile!r}")

for principal in (inherited, cloned):
    principal_env = env(principal)
    if principal_env.get("model") != "fake-slow":
        raise SystemExit(f"{principal} did not inherit source env model: {principal_env!r}")
    found_secret = secret(principal)
    if found_secret != expected_secret:
        raise SystemExit(f"{principal} secret did not match copied source sentinel")
PY
}

json_assert_http_create_did_not_inherit_or_clone() {
  local home=$1
  local created=$2
  local capsule=$3
  "$PYTHON" - "$home" "$created" "$capsule" <<'PY'
import re
import sys
from pathlib import Path

home = Path(sys.argv[1])
created = sys.argv[2]
capsule = sys.argv[3]
profile_path = home / "etc" / "profiles" / f"{created}.toml"
if not profile_path.exists():
    raise SystemExit(f"missing created profile: {profile_path}")

def profile_array(key: str) -> list[str]:
    text = profile_path.read_text(encoding="utf-8")
    match = re.search(rf"(?ms)^\s*{re.escape(key)}\s*=\s*\[(.*?)\]", text)
    if not match:
        return []
    return re.findall(r'"([^"]*)"', match.group(1))

groups = profile_array("groups")
if groups != ["agent"]:
    raise SystemExit(f"HTTP create clone/inherit smuggling changed groups: {groups!r}")
capsules = profile_array("capsules")
if capsules:
    raise SystemExit(f"HTTP create clone/inherit smuggling copied capsules: {capsules!r}")

env_path = home / "home" / created / ".config" / "env" / f"{capsule}.env.json"
if env_path.exists():
    raise SystemExit(f"HTTP create clone/inherit smuggling copied env: {env_path}")
secret_path = home / "secrets" / created / capsule / "api_key"
if secret_path.exists():
    raise SystemExit(f"HTTP create clone/inherit smuggling copied secret: {secret_path}")
PY
}

json_assert_adversarial_probe_report() {
  local path=$1
  "$PYTHON" - "$path" <<'PY'
import json
import sys
from pathlib import Path

data = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
expected = {
    "undeclared_publish_denied": True,
    "undeclared_subscribe_denied": True,
    "invalid_subscribe_denied": True,
}
for key, value in expected.items():
    if data.get(key) is not value:
        raise SystemExit(f"adversarial probe {key}={data.get(key)!r}, expected {value!r}: {data!r}")
PY
}

assert_no_adversarial_session_poison() {
  local path=$1
  if grep -q "ASTRID_ADVERSARIAL_POISON_SESSION" "$path"; then
    cat "$path" >&2 || true
    fail "adversarial capsule poisoned session list response"
  fi
}

wait_for_sse_ready() {
  local path=$1
  local deadline=$((SECONDS + 10))
  until grep -q '^event: ready' "$path" 2>/dev/null; do
    if (( SECONDS >= deadline )); then
      return 1
    fi
    sleep 0.1
  done
}

wait_for_approval_request_id() {
  local path=$1
  local deadline=$((SECONDS + 20))
  local python_bin="${PYTHON:-python3}"
  local request_id
  until request_id="$("$python_bin" - "$path" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
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
    if payload.get("type") != "approval_required":
        continue
    if payload.get("action") != "runtime-e2e-approval":
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

run_agent_request_http_guardrails() {
  local user_bearer=$1
  local user_principal=$2
  local status
  local python_bin="${PYTHON:-python3}"

  note "checking elicit-response HTTP guardrails"
  local elicit_request_id
  elicit_request_id="$("$python_bin" -c 'import uuid; print(uuid.uuid4())')"
  status="$(http_status GET /api/agent/requests "" "" "$ARTIFACTS/agent-requests-unauth.json")"
  assert_status "unauthenticated agent request stream denied" "$status" 401
  curl -sN --max-time 3 \
    -H "Authorization: Bearer $user_bearer" \
    "$GATEWAY/api/agent/requests" \
    > "$ARTIFACTS/agent-requests.sse" 2>&1 || true
  grep -q '^event: ready' "$ARTIFACTS/agent-requests.sse" \
    || fail "agent request stream did not emit ready event"
  grep -q "\"principal\":\"$user_principal\"" "$ARTIFACTS/agent-requests.sse" \
    || fail "agent request stream ready event did not carry caller principal"
  status="$(http_status POST /api/agent/elicit-response "" \
    "{\"request_id\":\"$elicit_request_id\",\"value\":\"unauth\"}" \
    "$ARTIFACTS/elicit-response-unauth.json")"
  assert_status "unauthenticated elicit response denied" "$status" 401
  status="$(http_status POST /api/agent/elicit-response "$user_bearer" \
    "{\"request_id\":\"$elicit_request_id\",\"value\":\"scalar\",\"values\":[\"array\"]}" \
    "$ARTIFACTS/elicit-response-ambiguous.json")"
  assert_status "ambiguous elicit response rejected" "$status" 400
  status="$(http_status POST /api/agent/elicit-response "$user_bearer" \
    "{\"request_id\":\"$elicit_request_id\",\"value\":\"answered\",\"principal\":\"default\"}" \
    "$ARTIFACTS/elicit-response-spoofed-principal.json")"
  assert_status "elicit response body principal ignored" "$status" 202
  status="$(http_status POST /api/agent/elicit-response "$user_bearer" \
    "{\"request_id\":\"$elicit_request_id\"}" \
    "$ARTIFACTS/elicit-response-cancel.json")"
  assert_status "elicit response cancel sentinel accepted" "$status" 202
  status="$(http_status POST /api/agent/approval-response "" \
    '{"request_id":"approval-unauth","decision":"approve"}' \
    "$ARTIFACTS/approval-response-unauth.json")"
  assert_status "unauthenticated approval response denied" "$status" 401
  status="$(http_status POST /api/agent/approval-response "$user_bearer" \
    '{"request_id":"approval-bad","decision":"maybe"}' \
    "$ARTIFACTS/approval-response-invalid.json")"
  assert_status "invalid approval response rejected" "$status" 400
  status="$(http_status POST /api/agent/approval-response "$user_bearer" \
    '{"request_id":"approval-spoof","decision":"deny","principal":"default"}' \
    "$ARTIFACTS/approval-response-spoofed-principal.json")"
  assert_status "approval response body principal ignored" "$status" 202
}

assert_artifact_lacks_text() {
  local path=$1
  local text=$2
  if grep -Fq "$text" "$path"; then
    cat "$path" >&2 || true
    fail "artifact $path leaked forbidden text: $text"
  fi
}

run_adversarial_capsule_smoke() {
  local user_bearer=$1
  local user_principal=$2
  local ops_bearer=$3
  local ops_principal=$4
  local status

  note "checking adversarial capsule host-call denial and response spoofing"

  run_principal_cli "$user_principal" capsule run astrid-capsule-adversarial adversarial \
    > "$ARTIFACTS/adversarial-capsule-probe.json"
  json_assert_adversarial_probe_report "$ARTIFACTS/adversarial-capsule-probe.json"

  status="$(http_status GET "/api/agent/sessions?include_archived=true&limit=20" "$user_bearer" "" \
    "$ARTIFACTS/adversarial-capsule-session-list.json")"
  assert_status "adversarial capsule session poison ignored" "$status" 200
  assert_no_adversarial_session_poison "$ARTIFACTS/adversarial-capsule-session-list.json"

  note "checking live approval responder principal isolation"
  local approval_sse="$ARTIFACTS/adversarial-approval-requests.sse"
  local approval_out="$ARTIFACTS/adversarial-approval-cli.txt"
  curl -sN --max-time 45 \
    -H "Authorization: Bearer $user_bearer" \
    "$GATEWAY/api/agent/requests" \
    > "$approval_sse" 2>&1 &
  local stream_pid=$!
  wait_for_sse_ready "$approval_sse" || {
    terminate_pid "$stream_pid"
    cat "$approval_sse" >&2 2>/dev/null || true
    fail "approval request stream did not become ready"
  }
  grep -q "\"principal\":\"$user_principal\"" "$approval_sse" || {
    terminate_pid "$stream_pid"
    fail "approval request stream ready event did not carry caller principal"
  }

  bounded_principal_cli "$user_principal" 20 "$approval_out" \
    capsule run astrid-capsule-adversarial adversarial-approval &
  local cli_pid=$!
  local approval_request_id
  approval_request_id="$(wait_for_approval_request_id "$approval_sse")" || {
    terminate_pid "$cli_pid"
    terminate_pid "$stream_pid"
    cat "$approval_sse" >&2 2>/dev/null || true
    fail "approval request stream did not forward adversarial approval request"
  }

  status="$(http_status POST /api/agent/approval-response "$ops_bearer" \
    "{\"request_id\":\"$approval_request_id\",\"decision\":\"approve\",\"reason\":\"wrong principal must not satisfy\"}" \
    "$ARTIFACTS/adversarial-approval-wrong-principal.json")"
  assert_status "wrong-principal approval response accepted but ignored by waiter" "$status" 202
  sleep 0.5
  if ! kill -0 "$cli_pid" 2>/dev/null; then
    wait "$cli_pid" || true
    terminate_pid "$stream_pid"
    cat "$approval_out" >&2 2>/dev/null || true
    fail "wrong-principal approval response satisfied the capsule approval waiter"
  fi

  status="$(http_status POST /api/agent/approval-response "$user_bearer" \
    "{\"request_id\":\"$approval_request_id\",\"decision\":\"approve\",\"reason\":\"runtime e2e approve\"}" \
    "$ARTIFACTS/adversarial-approval-user.json")"
  assert_status "same-principal approval response accepted" "$status" 202
  local approval_rc=0
  wait "$cli_pid" || approval_rc=$?
  terminate_pid "$stream_pid"
  if [[ "$approval_rc" -ne 0 ]]; then
    cat "$approval_out" >&2 2>/dev/null || true
    fail "adversarial approval command failed after same-principal response"
  fi
  grep -q '"approved":true' "$approval_out" \
    || fail "adversarial approval command did not report approved decision"

  note "checking live approval denial path"
  local denial_sse="$ARTIFACTS/adversarial-approval-deny-requests.sse"
  local denial_out="$ARTIFACTS/adversarial-approval-deny-cli.txt"
  curl -sN --max-time 45 \
    -H "Authorization: Bearer $user_bearer" \
    "$GATEWAY/api/agent/requests" \
    > "$denial_sse" 2>&1 &
  local denial_stream_pid=$!
  wait_for_sse_ready "$denial_sse" || {
    terminate_pid "$denial_stream_pid"
    cat "$denial_sse" >&2 2>/dev/null || true
    fail "approval deny request stream did not become ready"
  }
  bounded_principal_cli "$user_principal" 20 "$denial_out" \
    capsule run astrid-capsule-adversarial adversarial-approval &
  local denial_cli_pid=$!
  local denial_request_id
  denial_request_id="$(wait_for_approval_request_id "$denial_sse")" || {
    terminate_pid "$denial_cli_pid"
    terminate_pid "$denial_stream_pid"
    cat "$denial_sse" >&2 2>/dev/null || true
    fail "approval deny request stream did not forward adversarial approval request"
  }
  status="$(http_status POST /api/agent/approval-response "$user_bearer" \
    "{\"request_id\":\"$denial_request_id\",\"decision\":\"deny\",\"reason\":\"runtime e2e deny\"}" \
    "$ARTIFACTS/adversarial-approval-deny-user.json")"
  assert_status "same-principal approval denial response accepted" "$status" 202
  local denial_rc=0
  wait "$denial_cli_pid" || denial_rc=$?
  terminate_pid "$denial_stream_pid"
  if [[ "$denial_rc" -eq 0 ]]; then
    cat "$denial_out" >&2 2>/dev/null || true
    fail "adversarial approval command succeeded after same-principal deny"
  fi
  grep -q '"approved":false' "$denial_out" \
    || fail "adversarial approval command did not report denied decision"

  note "checking live approval timeout path"
  local timeout_sse="$ARTIFACTS/adversarial-approval-timeout-requests.sse"
  local timeout_out="$ARTIFACTS/adversarial-approval-timeout-cli.txt"
  curl -sN --max-time 75 \
    -H "Authorization: Bearer $user_bearer" \
    "$GATEWAY/api/agent/requests" \
    > "$timeout_sse" 2>&1 &
  local timeout_stream_pid=$!
  wait_for_sse_ready "$timeout_sse" || {
    terminate_pid "$timeout_stream_pid"
    cat "$timeout_sse" >&2 2>/dev/null || true
    fail "approval timeout request stream did not become ready"
  }
  bounded_principal_cli "$user_principal" 75 "$timeout_out" \
    capsule run astrid-capsule-adversarial adversarial-approval &
  local timeout_cli_pid=$!
  wait_for_approval_request_id "$timeout_sse" \
    > "$ARTIFACTS/adversarial-approval-timeout-request-id.txt" || {
    terminate_pid "$timeout_cli_pid"
    terminate_pid "$timeout_stream_pid"
    cat "$timeout_sse" >&2 2>/dev/null || true
    fail "approval timeout request stream did not forward adversarial approval request"
  }
  local timeout_rc=0
  wait "$timeout_cli_pid" || timeout_rc=$?
  terminate_pid "$timeout_stream_pid"
  if [[ "$timeout_rc" -eq 0 ]]; then
    cat "$timeout_out" >&2 2>/dev/null || true
    fail "adversarial approval command succeeded without a response"
  fi
  if [[ "$timeout_rc" -eq 124 ]]; then
    cat "$timeout_out" >&2 2>/dev/null || true
    fail "adversarial approval command exceeded the bounded timeout"
  fi
  grep -Eqi 'timed out|timeout|cancelled' "$timeout_out" \
    || fail "adversarial approval command did not report a timeout"

}

run_live_approval_cancel_smoke() {
  local user_bearer=$1
  local user_principal=$2
  local status
  local sse="$ARTIFACTS/adversarial-approval-cancel-requests.sse"
  local out="$ARTIFACTS/adversarial-approval-cancel-cli.txt"

  note "checking live approval cancellation on capsule unload"
  curl -sN --max-time 20 \
    -H "Authorization: Bearer $user_bearer" \
    "$GATEWAY/api/agent/requests" \
    > "$sse" 2>&1 &
  local stream_pid=$!
  wait_for_sse_ready "$sse" || {
    terminate_pid "$stream_pid"
    cat "$sse" >&2 2>/dev/null || true
    fail "approval cancel request stream did not become ready"
  }
  bounded_principal_cli "$user_principal" 12 "$out" \
    capsule run astrid-capsule-adversarial adversarial-approval &
  local cli_pid=$!
  wait_for_approval_request_id "$sse" > "$ARTIFACTS/adversarial-approval-cancel-request-id.txt" || {
    terminate_pid "$cli_pid"
    terminate_pid "$stream_pid"
    cat "$sse" >&2 2>/dev/null || true
    fail "approval cancel request stream did not forward adversarial approval request"
  }

  run_cli capsule remove astrid-capsule-adversarial --force
  terminate_pid "$stream_pid"

  local cancel_rc=0
  wait "$cli_pid" || cancel_rc=$?
  if [[ "$cancel_rc" -eq 0 ]]; then
    cat "$out" >&2 2>/dev/null || true
    fail "adversarial approval command succeeded after capsule unload cancellation"
  fi
  if [[ "$cancel_rc" -eq 124 ]]; then
    cat "$out" >&2 2>/dev/null || true
    fail "adversarial approval command hung after capsule unload cancellation"
  fi

  status="$(http_status GET /api/capsules "$user_bearer" "" \
    "$ARTIFACTS/adversarial-approval-cancel-capsules.json")"
  assert_status "adversarial capsule list after live cancel remove" "$status" 200
  json_assert_capsule_list_state "$ARTIFACTS/adversarial-approval-cancel-capsules.json" \
    astrid-capsule-adversarial absent
}

run_adversarial_principal_smoke() {
  local user_bearer=$1
  local user_principal=$2
  local ops_bearer=$3
  local ops_principal=$4
  local user_secret=$5

  note "checking adversarial principal create and wildcard escalation paths"

  local creator_invite
  run_cli group create agent-creators --caps "agent:create,self:agent:list"
  creator_invite="$("$CORE_DIR/target/debug/astrid" invite issue \
    --group agent-creators \
    --max-uses 1 \
    --expires-secs 600 \
    --raw 2>> "$ARTIFACTS/cli-transcript.log")"
  printf '$ astrid invite issue --group agent-creators --max-uses 1 --expires-secs 600 --raw\n<redacted invite token>\n' \
    >> "$ARTIFACTS/cli-transcript.log"
  redeem_invite "$creator_invite" creator-1 "$ARTIFACTS/creator-redeem.json"
  local creator_principal
  creator_principal="$(json_field "$ARTIFACTS/creator-redeem.json" principal)"

  expect_principal_cli_failure "$user_principal" adversarial-agent-create-denied \
    agent create e2e-regular-create-denied -y
  assert_principal_profile_absent e2e-regular-create-denied

  expect_principal_cli_success "$creator_principal" adversarial-agent-create-plain \
    agent create e2e-plain-created -y
  [[ -f "$ASTRID_HOME/etc/profiles/e2e-plain-created.toml" ]] \
    || fail "plain agent:create did not create e2e-plain-created profile"

  expect_principal_cli_failure "$creator_principal" adversarial-agent-inherit-denied \
    agent create e2e-inherit-denied --inherit-from "$user_principal" -y
  assert_principal_profile_absent e2e-inherit-denied

  run_cli caps grant "$creator_principal" agent:create:inherit
  expect_principal_cli_success "$creator_principal" adversarial-agent-inherit-allowed \
    agent create e2e-inherited --inherit-from "$user_principal" -y

  expect_principal_cli_failure "$creator_principal" adversarial-agent-clone-denied \
    agent create e2e-clone-denied --clone "$user_principal" -y
  assert_principal_profile_absent e2e-clone-denied

  run_cli caps grant "$creator_principal" agent:create:clone
  expect_principal_cli_success "$creator_principal" adversarial-agent-clone-allowed \
    agent create e2e-cloned --clone "$user_principal" -y

  json_assert_inheritance_and_clone_state "$ASTRID_HOME" "$user_principal" \
    e2e-inherited e2e-cloned astrid-capsule-openai-compat "$user_secret"

  local admin_bearer status
  admin_bearer="$(mint_admin_bearer)"

  status="$(http_status POST /api/sys/invites "$admin_bearer" \
    '{"group":"agent","max_uses":1,"expires_secs":600,"metadata":"e2e-http-revoke"}' \
    "$ARTIFACTS/http-invite-revoke-issue.json")"
  assert_status "admin HTTP invite issue for revoke" "$status" 200
  status="$(http_status GET /api/sys/invites "$admin_bearer" "" \
    "$ARTIFACTS/http-invite-list-before-revoke.json")"
  assert_status "admin HTTP invite list" "$status" 200
  json_assert_http_invite_metadata "$ARTIFACTS/http-invite-list-before-revoke.json" \
    e2e-http-revoke present
  local invite_fingerprint
  invite_fingerprint="$(invite_fingerprint_by_metadata "$ARTIFACTS/http-invite-list-before-revoke.json" \
    e2e-http-revoke)"
  status="$(http_status GET /api/sys/invites "$user_bearer" "" \
    "$ARTIFACTS/adversarial-user-invite-list-denied.json")"
  assert_status "regular principal invite list denied" "$status" 403
  status="$(http_status DELETE "/api/sys/invites/$invite_fingerprint" "$user_bearer" "" \
    "$ARTIFACTS/adversarial-user-invite-revoke-denied.json")"
  assert_status "regular principal invite revoke denied" "$status" 403
  status="$(http_status DELETE "/api/sys/invites/$invite_fingerprint" "$admin_bearer" "" \
    "$ARTIFACTS/http-invite-revoke.json")"
  assert_status "admin HTTP invite revoke" "$status" 204
  status="$(http_status GET /api/sys/invites "$admin_bearer" "" \
    "$ARTIFACTS/http-invite-list-after-revoke.json")"
  assert_status "admin HTTP invite list after revoke" "$status" 200
  json_assert_http_invite_metadata "$ARTIFACTS/http-invite-list-after-revoke.json" \
    e2e-http-revoke absent

  status="$(http_status POST /api/sys/principals "$admin_bearer" \
    '{"name":"e2e-http-lifecycle","groups":["agent"],"grants":[]}' \
    "$ARTIFACTS/http-principal-lifecycle-create.json")"
  assert_status "admin HTTP principal create" "$status" 200
  status="$(http_status PATCH /api/sys/principals/e2e-http-lifecycle "$admin_bearer" \
    '{"add_groups":["ops-team"],"remove_groups":[],"add_capsules":[],"remove_capsules":[]}' \
    "$ARTIFACTS/http-principal-lifecycle-patch.json")"
  assert_status "admin HTTP principal patch" "$status" 200
  status="$(http_status POST /api/sys/principals/e2e-http-lifecycle/disable "$admin_bearer" "" \
    "$ARTIFACTS/http-principal-lifecycle-disable.json")"
  assert_status "admin HTTP principal disable" "$status" 200
  status="$(http_status GET /api/sys/principals/e2e-http-lifecycle "$admin_bearer" "" \
    "$ARTIFACTS/http-principal-lifecycle-disabled-show.json")"
  assert_status "admin HTTP principal disabled show" "$status" 200
  json_assert_cli_agent_enabled "$ARTIFACTS/http-principal-lifecycle-disabled-show.json" \
    e2e-http-lifecycle false
  json_assert_cli_agent_show "$ARTIFACTS/http-principal-lifecycle-disabled-show.json" \
    e2e-http-lifecycle ops-team
  status="$(http_status POST /api/sys/principals/e2e-http-lifecycle/enable "$admin_bearer" "" \
    "$ARTIFACTS/http-principal-lifecycle-enable.json")"
  assert_status "admin HTTP principal enable" "$status" 200
  status="$(http_status GET /api/sys/principals/e2e-http-lifecycle "$admin_bearer" "" \
    "$ARTIFACTS/http-principal-lifecycle-enabled-show.json")"
  assert_status "admin HTTP principal enabled show" "$status" 200
  json_assert_cli_agent_enabled "$ARTIFACTS/http-principal-lifecycle-enabled-show.json" \
    e2e-http-lifecycle true
  status="$(http_status DELETE /api/sys/principals/e2e-http-lifecycle "$admin_bearer" "" \
    "$ARTIFACTS/http-principal-lifecycle-delete.json")"
  assert_status "admin HTTP principal delete" "$status" 204
  status="$(http_status GET /api/sys/principals/e2e-http-lifecycle "$admin_bearer" "" \
    "$ARTIFACTS/http-principal-lifecycle-deleted-show.json")"
  assert_status "deleted HTTP principal hidden" "$status" 404

  status="$(http_status POST /api/sys/principals "$admin_bearer" \
    "{\"name\":\"e2e-http-smuggle-clone\",\"groups\":[\"agent\"],\"grants\":[],\"inherit_from\":\"$user_principal\",\"clone_from\":\"$user_principal\",\"allow_admin_clone\":true}" \
    "$ARTIFACTS/http-principal-clone-smuggle-create.json")"
  assert_status "admin HTTP create ignores clone and inherit smuggling fields" "$status" 200
  json_assert_http_create_did_not_inherit_or_clone "$ASTRID_HOME" \
    e2e-http-smuggle-clone astrid-capsule-openai-compat
  status="$(http_status DELETE /api/sys/principals/e2e-http-smuggle-clone "$admin_bearer" "" \
    "$ARTIFACTS/http-principal-clone-smuggle-delete.json")"
  assert_status "admin HTTP clone smuggling cleanup" "$status" 204

  status="$(http_status POST /api/sys/groups "$user_bearer" \
    '{"name":"regular-group-create-denied","capabilities":["system:status"]}' \
    "$ARTIFACTS/adversarial-regular-group-create-denied.json")"
  assert_status "regular principal group create denied" "$status" 403

  status="$(http_status POST /api/sys/groups "$admin_bearer" \
    '{"name":"wildcard-denied","capabilities":["*"],"unsafe_admin":false}' \
    "$ARTIFACTS/adversarial-wildcard-group-denied.json")"
  assert_status "admin wildcard group create without unsafe denied" "$status" 403

  status="$(http_status POST /api/sys/groups "$admin_bearer" \
    '{"name":"wildcard-e2e","capabilities":["*"],"unsafe_admin":true}' \
    "$ARTIFACTS/adversarial-wildcard-group-allowed.json")"
  assert_status "admin wildcard group create with unsafe allowed" "$status" 200
  status="$(http_status GET /api/sys/groups "$admin_bearer" "" \
    "$ARTIFACTS/adversarial-admin-group-list.json")"
  assert_status "admin group list" "$status" 200
  json_assert_http_group "$ARTIFACTS/adversarial-admin-group-list.json" wildcard-e2e '*'
  status="$(http_status PATCH /api/sys/groups/wildcard-e2e "$admin_bearer" \
    '{"capabilities":["system:status"],"description":"patched by runtime e2e","unsafe_admin":false}' \
    "$ARTIFACTS/adversarial-wildcard-group-patch.json")"
  assert_status "admin group patch" "$status" 200
  status="$(http_status GET /api/sys/groups "$admin_bearer" "" \
    "$ARTIFACTS/adversarial-admin-group-list-after-patch.json")"
  assert_status "admin group list after patch" "$status" 200
  json_assert_http_group "$ARTIFACTS/adversarial-admin-group-list-after-patch.json" \
    wildcard-e2e system:status
  status="$(http_status GET /api/sys/groups "$user_bearer" "" \
    "$ARTIFACTS/adversarial-user-group-list-filtered.json")"
  assert_status "regular principal group list filtered" "$status" 200
  json_assert_http_group_names "$ARTIFACTS/adversarial-user-group-list-filtered.json" agent

  status="$(http_status POST "/api/sys/principals/$user_principal/caps" "$ops_bearer" \
    '{"capabilities":["system:status"],"unsafe_admin":false}' \
    "$ARTIFACTS/adversarial-operator-caps-grant-denied.json")"
  assert_status "operator without caps:grant denied" "$status" 403

  status="$(http_status POST "/api/sys/principals/e2e-plain-created/caps" "$admin_bearer" \
    '{"capabilities":["system:status"],"unsafe_admin":false}' \
    "$ARTIFACTS/adversarial-admin-caps-grant.json")"
  assert_status "admin caps grant allowed" "$status" 200

  status="$(http_status DELETE "/api/sys/principals/e2e-plain-created/caps" "$admin_bearer" \
    '{"capabilities":["system:status"]}' \
    "$ARTIFACTS/adversarial-admin-caps-revoke.json")"
  assert_status "admin caps revoke allowed" "$status" 204

  status="$(http_status POST "/api/sys/principals/$user_principal/caps" "$admin_bearer" \
    '{"capabilities":["*"],"unsafe_admin":false}' \
    "$ARTIFACTS/adversarial-wildcard-caps-denied.json")"
  assert_status "admin wildcard cap grant without unsafe denied" "$status" 403

  status="$(http_status DELETE /api/sys/groups/wildcard-e2e "$admin_bearer" "" \
    "$ARTIFACTS/adversarial-wildcard-group-delete.json")"
  assert_status "admin wildcard group cleanup" "$status" 204

  status="$(http_status GET "/api/sys/principals/$ops_principal?principal=$user_principal" \
    "$user_bearer" "" "$ARTIFACTS/adversarial-principal-query-spoof-hidden.json")"
  assert_status "principal query spoof does not widen visibility" "$status" 404
  assert_artifact_lacks_text "$ARTIFACTS/adversarial-principal-query-spoof-hidden.json" \
    "$ops_principal"
  assert_artifact_lacks_text "$ARTIFACTS/adversarial-principal-query-spoof-hidden.json" \
    "$user_principal"

  status="$(http_status GET "/api/sys/principals/e2e-unknown-principal?principal=$ops_principal" \
    "$user_bearer" "" "$ARTIFACTS/adversarial-principal-unknown-hidden.json")"
  assert_status "unknown principal remains hidden under query spoof" "$status" 404
  assert_artifact_lacks_text "$ARTIFACTS/adversarial-principal-unknown-hidden.json" \
    e2e-unknown-principal
  assert_artifact_lacks_text "$ARTIFACTS/adversarial-principal-unknown-hidden.json" \
    "$ops_principal"

  status="$(http_status GET /api/sys/principals/InvalidPrincipalId "$user_bearer" "" \
    "$ARTIFACTS/adversarial-principal-invalid-id.json")"
  assert_status "invalid principal id hidden with bounded error" "$status" 404
}

json_assert_http_group() {
  local file=$1 name=$2 cap=$3
  "$PYTHON" - "$file" "$name" "$cap" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
group = next((item for item in data.get("groups", []) if item.get("name") == sys.argv[2]), None)
if not group:
    raise SystemExit(f"group {sys.argv[2]!r} missing: {data!r}")
if sys.argv[3] not in group.get("capabilities", []):
    raise SystemExit(f"group missing capability {sys.argv[3]!r}: {group!r}")
PY
}

json_assert_http_group_names() {
  local file=$1
  shift
  "$PYTHON" - "$file" "$@" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
names = sorted(item.get("name") for item in data.get("groups", []))
want = sorted(sys.argv[2:])
if names != want:
    raise SystemExit(f"unexpected group visibility {names!r}, want {want!r}: {data!r}")
PY
}

json_assert_http_invite_metadata() {
  local file=$1 metadata=$2 expected=$3
  "$PYTHON" - "$file" "$metadata" "$expected" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
found = any(item.get("metadata") == sys.argv[2] for item in data.get("invites", []))
want = sys.argv[3] == "present"
if found is not want:
    raise SystemExit(f"invite metadata {sys.argv[2]!r} presence {found}, want {want}: {data!r}")
PY
}

invite_fingerprint_by_metadata() {
  local file=$1 metadata=$2
  "$PYTHON" - "$file" "$metadata" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
for item in data.get("invites", []):
    if item.get("metadata") == sys.argv[2]:
        print(item["token_fingerprint"])
        raise SystemExit(0)
raise SystemExit(f"invite metadata {sys.argv[2]!r} missing: {data!r}")
PY
}
