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

run_adversarial_capsule_smoke() {
  local user_bearer=$1
  local user_principal=$2
  local status

  note "checking adversarial capsule host-call denial and response spoofing"

  run_principal_cli "$user_principal" capsule run astrid-capsule-adversarial adversarial \
    > "$ARTIFACTS/adversarial-capsule-probe.json"
  json_assert_adversarial_probe_report "$ARTIFACTS/adversarial-capsule-probe.json"

  status="$(http_status GET "/api/agent/sessions?include_archived=true&limit=20" "$user_bearer" "" \
    "$ARTIFACTS/adversarial-capsule-session-list.json")"
  assert_status "adversarial capsule session poison ignored" "$status" 200
  assert_no_adversarial_session_poison "$ARTIFACTS/adversarial-capsule-session-list.json"
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
}
