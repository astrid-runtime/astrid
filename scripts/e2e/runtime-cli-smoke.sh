#!/usr/bin/env bash

run_cli_semantic_smoke() {
  local user_principal=$1 ops_principal=$2
  note "checking built-in CLI semantic read paths"

  run_cli agent list --format json > "$ARTIFACTS/cli-agent-list.json"
  json_assert_cli_agent_list "$ARTIFACTS/cli-agent-list.json" "$user_principal" "$ops_principal"
  run_cli agent show "$user_principal" --format json > "$ARTIFACTS/cli-agent-show-user.json"
  json_assert_cli_agent_show "$ARTIFACTS/cli-agent-show-user.json" "$user_principal" agent
  run_cli agent show "$ops_principal" --format json > "$ARTIFACTS/cli-agent-show-ops.json"
  json_assert_cli_agent_show "$ARTIFACTS/cli-agent-show-ops.json" "$ops_principal" ops-team
  run_cli agent create e2e-cli-lifecycle -y
  run_cli agent disable e2e-cli-lifecycle
  run_cli agent show e2e-cli-lifecycle --format json > "$ARTIFACTS/cli-agent-lifecycle-disabled.json"
  json_assert_cli_agent_enabled "$ARTIFACTS/cli-agent-lifecycle-disabled.json" e2e-cli-lifecycle false
  run_cli agent enable e2e-cli-lifecycle
  run_cli agent show e2e-cli-lifecycle --format json > "$ARTIFACTS/cli-agent-lifecycle-enabled.json"
  json_assert_cli_agent_enabled "$ARTIFACTS/cli-agent-lifecycle-enabled.json" e2e-cli-lifecycle true
  run_cli agent delete e2e-cli-lifecycle -y
  if run_cli agent show e2e-cli-lifecycle --format json > "$ARTIFACTS/cli-agent-lifecycle-deleted.json"; then
    fail "deleted agent e2e-cli-lifecycle remained visible"
  fi
  run_cli agent switch "$user_principal" > "$ARTIFACTS/cli-agent-switch-user.txt"
  run_cli agent current > "$ARTIFACTS/cli-agent-current-user.txt"
  grep -qx "$user_principal" "$ARTIFACTS/cli-agent-current-user.txt" || fail "agent current did not reflect switch"
  run_cli agent switch default > "$ARTIFACTS/cli-agent-switch-default.txt"

  run_cli group list --format json > "$ARTIFACTS/cli-group-list.json"
  json_assert_cli_group "$ARTIFACTS/cli-group-list.json" ops-team invite:issue
  run_cli group show ops-team --format json > "$ARTIFACTS/cli-group-show-ops.json"
  json_assert_cli_group "$ARTIFACTS/cli-group-show-ops.json" ops-team capsule:install
  run_cli group modify ops-team --add-caps system:status
  run_cli group show ops-team --format json > "$ARTIFACTS/cli-group-show-ops-after-add.json"
  json_assert_cli_group "$ARTIFACTS/cli-group-show-ops-after-add.json" ops-team system:status
  run_cli group modify ops-team --remove-caps system:status
  run_cli group show ops-team --format json > "$ARTIFACTS/cli-group-show-ops-after-remove.json"
  json_assert_cli_group_lacks_cap "$ARTIFACTS/cli-group-show-ops-after-remove.json" ops-team system:status

  run_cli caps show "$user_principal" --format json > "$ARTIFACTS/cli-caps-show-user.json"
  json_assert_cli_caps_show "$ARTIFACTS/cli-caps-show-user.json" "$user_principal" agent
  run_cli caps check "$ops_principal" invite:issue > "$ARTIFACTS/cli-caps-check-ops.txt"
  grep -q "allowed" "$ARTIFACTS/cli-caps-check-ops.txt" || fail "caps check did not allow ops invite:issue"

  local invite_token redeem_key pair_token pair_pubkey pair_key_id
  invite_token="$("$CORE_DIR/target/debug/astrid" invite issue --group agent --max-uses 1 \
    --expires-secs 600 --metadata e2e-cli-revoke --raw 2>> "$ARTIFACTS/cli-transcript.log")"
  printf '$ astrid invite issue --group agent --max-uses 1 --expires-secs 600 --metadata e2e-cli-revoke --raw\n<redacted invite token>\n' \
    >> "$ARTIFACTS/cli-transcript.log"
  run_cli invite list --json > "$ARTIFACTS/cli-invite-list-before-revoke.json"
  json_assert_invite_metadata "$ARTIFACTS/cli-invite-list-before-revoke.json" e2e-cli-revoke present
  printf '$ astrid invite revoke <redacted invite token>\n' >> "$ARTIFACTS/cli-transcript.log"
  "$CORE_DIR/target/debug/astrid" invite revoke "$invite_token" \
    > "$ARTIFACTS/cli-invite-revoke.txt" 2>> "$ARTIFACTS/cli-transcript.log"
  run_cli invite list --json > "$ARTIFACTS/cli-invite-list-after-revoke.json"
  json_assert_invite_metadata "$ARTIFACTS/cli-invite-list-after-revoke.json" e2e-cli-revoke absent
  run_cli keypair generate --name e2e-cli-redeem-key --force --raw \
    > "$ARTIFACTS/cli-invite-redeem-key.pub"
  redeem_key="$("$CORE_DIR/target/debug/astrid" invite issue --group agent --max-uses 1 \
    --expires-secs 600 --metadata e2e-cli-redeem --raw 2>> "$ARTIFACTS/cli-transcript.log")"
  printf '$ astrid invite issue --group agent --max-uses 1 --expires-secs 600 --metadata e2e-cli-redeem --raw\n<redacted invite token>\n' \
    >> "$ARTIFACTS/cli-transcript.log"
  printf '$ astrid invite redeem <redacted invite token> --keypair e2e-cli-redeem-key --display-name e2e-cli-redeemed\n' \
    >> "$ARTIFACTS/cli-transcript.log"
  "$CORE_DIR/target/debug/astrid" invite redeem "$redeem_key" --keypair e2e-cli-redeem-key \
    --display-name e2e-cli-redeemed > "$ARTIFACTS/cli-invite-redeem.txt" \
    2>> "$ARTIFACTS/cli-transcript.log"
  run_cli agent show e2e-cli-redeemed --format json > "$ARTIFACTS/cli-invite-redeemed-agent.json"
  json_assert_cli_agent_show "$ARTIFACTS/cli-invite-redeemed-agent.json" e2e-cli-redeemed agent
  run_cli agent delete e2e-cli-redeemed -y
  run_cli keypair delete e2e-cli-redeem-key --yes

  run_cli quota show --agent "$user_principal" --format json > "$ARTIFACTS/cli-quota-show-user.json"
  json_assert_cli_quota "$ARTIFACTS/cli-quota-show-user.json" "$user_principal" 4
  run_cli secret list --agent "$user_principal" --format json > "$ARTIFACTS/cli-secret-list-user.json"
  json_assert_secret_list_metadata "$ARTIFACTS/cli-secret-list-user.json" astrid-capsule-openai-compat api_key
  run_cli secret set e2e_cli_delete_marker e2e-value --agent "$user_principal"
  run_cli secret list --agent "$user_principal" --format json > "$ARTIFACTS/cli-secret-list-with-delete-marker.json"
  json_assert_secret_present "$ARTIFACTS/cli-secret-list-with-delete-marker.json" default e2e_cli_delete_marker
  run_cli secret delete e2e_cli_delete_marker --agent "$user_principal"
  run_cli secret list --agent "$user_principal" --format json > "$ARTIFACTS/cli-secret-list-after-delete.json"
  json_assert_secret_absent "$ARTIFACTS/cli-secret-list-after-delete.json" default e2e_cli_delete_marker
  run_cli keypair generate --name e2e-cli-key --force --raw > "$ARTIFACTS/cli-keypair-generated.pub"
  run_cli keypair list --json > "$ARTIFACTS/cli-keypair-list.json"
  json_assert_cli_keypair_list "$ARTIFACTS/cli-keypair-list.json" e2e-cli-key
  run_cli keypair show e2e-cli-key > "$ARTIFACTS/cli-keypair-show.txt"
  grep -q "public key (hex):" "$ARTIFACTS/cli-keypair-show.txt" || fail "keypair show missed public key"
  run_cli keypair pubkey e2e-cli-key > "$ARTIFACTS/cli-keypair-pubkey.txt"
  json_assert_cli_keypair_pubkey "$ARTIFACTS/cli-keypair-pubkey.txt"
  run_cli keypair delete e2e-cli-key --yes
  if run_cli keypair show e2e-cli-key > "$ARTIFACTS/cli-keypair-show-after-delete.txt"; then
    fail "deleted keypair e2e-cli-key remained visible"
  fi
  pair_token="$("$CORE_DIR/target/debug/astrid" pair-device issue --scope use-only \
    --label e2e-cli-pair --expires-secs 120 --raw 2>> "$ARTIFACTS/cli-transcript.log")"
  printf '$ astrid pair-device issue --scope use-only --label e2e-cli-pair --expires-secs 120 --raw\n<redacted pair token>\n' \
    >> "$ARTIFACTS/cli-transcript.log"
  pair_pubkey="$("$PYTHON" - <<'PY'
import secrets
print(secrets.token_hex(32))
PY
)"
  status="$(http_status POST /api/auth/pair-device/redeem "" \
    "{\"token\":\"$pair_token\",\"public_key\":\"$pair_pubkey\"}" \
    "$ARTIFACTS/cli-pair-device-redeem.json")"
  assert_status "CLI-issued pair token redeem" "$status" 200
  pair_key_id="$(json_field "$ARTIFACTS/cli-pair-device-redeem.json" key_id)"
  run_cli pair-device list --principal default --json > "$ARTIFACTS/cli-pair-device-list.json"
  json_assert_pair_device_list "$ARTIFACTS/cli-pair-device-list.json" "$pair_key_id" present
  run_cli pair-device revoke "$pair_key_id" --principal default
  run_cli pair-device list --principal default --json > "$ARTIFACTS/cli-pair-device-list-after-revoke.json"
  json_assert_pair_device_list "$ARTIFACTS/cli-pair-device-list-after-revoke.json" "$pair_key_id" absent

  run_cli capsule show astrid-capsule-openai-compat --format json \
    > "$ARTIFACTS/cli-capsule-show-openai-user.json"
  json_assert_cli_capsule_show "$ARTIFACTS/cli-capsule-show-openai-user.json" astrid-capsule-openai-compat
  run_cli capsule list > "$ARTIFACTS/cli-capsule-list.txt"
  grep -q "astrid-capsule-openai-compat" "$ARTIFACTS/cli-capsule-list.txt" || fail "capsule list missed openai-compat"
  run_cli capsule config astrid-capsule-openai-compat --agent "$user_principal" --show --format json \
    > "$ARTIFACTS/cli-capsule-config-openai-user.json"
  json_assert_cli_capsule_config "$ARTIFACTS/cli-capsule-config-openai-user.json" fake-slow

  run_cli version --format json > "$ARTIFACTS/cli-version.json"
  json_assert_cli_version "$ARTIFACTS/cli-version.json"
  run_cli config show --format json > "$ARTIFACTS/cli-config-show.json"
  json_assert_cli_config_show "$ARTIFACTS/cli-config-show.json"
  run_cli config path > "$ARTIFACTS/cli-config-path.txt"
  grep -q "$ASTRID_HOME" "$ARTIFACTS/cli-config-path.txt" || fail "config path did not include ASTRID_HOME"
  run_cli status > "$ARTIFACTS/cli-status.txt"
  grep -q "Astrid daemon" "$ARTIFACTS/cli-status.txt" || fail "status did not report running daemon"
  printf '$ astrid doctor\n' >> "$ARTIFACTS/cli-transcript.log"
  "$CORE_DIR/target/debug/astrid" doctor > "$ARTIFACTS/cli-doctor.txt" \
    2> >(tee -a "$ARTIFACTS/cli-transcript.log" >&2) || true
  sed -n '1,120p' "$ARTIFACTS/cli-doctor.txt" >> "$ARTIFACTS/cli-transcript.log"
  grep -q "ASTRID_HOME" "$ARTIFACTS/cli-doctor.txt" || fail "doctor did not inspect ASTRID_HOME"
}

json_assert_cli_agent_list() {
  local file=$1 user=$2 ops=$3
  "$PYTHON" - "$file" "$user" "$ops" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
principals = {entry.get("principal"): entry for entry in data}
for principal in sys.argv[2:]:
    entry = principals.get(principal)
    if not entry:
        raise SystemExit(f"missing principal {principal!r}: {list(principals)}")
    if entry.get("enabled") is not True:
        raise SystemExit(f"principal {principal!r} not enabled: {entry!r}")
PY
}

json_assert_cli_agent_show() {
  local file=$1 principal=$2 group=$3
  "$PYTHON" - "$file" "$principal" "$group" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
if data.get("principal") != sys.argv[2]:
    raise SystemExit(f"unexpected principal: {data!r}")
if sys.argv[3] not in data.get("groups", []):
    raise SystemExit(f"missing expected group {sys.argv[3]!r}: {data!r}")
PY
}

json_assert_cli_agent_enabled() {
  local file=$1 principal=$2 enabled=$3
  "$PYTHON" - "$file" "$principal" "$enabled" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
want = sys.argv[3].lower() == "true"
if data.get("principal") != sys.argv[2]:
    raise SystemExit(f"unexpected principal: {data!r}")
if data.get("enabled") is not want:
    raise SystemExit(f"unexpected enabled state: {data!r}")
PY
}

json_assert_cli_group() {
  local file=$1 name=$2 cap=$3
  "$PYTHON" - "$file" "$name" "$cap" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
if isinstance(data, list):
    data = next((entry for entry in data if entry.get("name") == sys.argv[2]), None)
if not data or data.get("name") != sys.argv[2]:
    raise SystemExit(f"group {sys.argv[2]!r} missing: {data!r}")
if sys.argv[3] not in data.get("capabilities", []):
    raise SystemExit(f"group missing capability {sys.argv[3]!r}: {data!r}")
PY
}

json_assert_cli_group_lacks_cap() {
  local file=$1 name=$2 cap=$3
  "$PYTHON" - "$file" "$name" "$cap" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
if isinstance(data, list):
    data = next((entry for entry in data if entry.get("name") == sys.argv[2]), None)
if not data or data.get("name") != sys.argv[2]:
    raise SystemExit(f"group {sys.argv[2]!r} missing: {data!r}")
if sys.argv[3] in data.get("capabilities", []):
    raise SystemExit(f"group still has capability {sys.argv[3]!r}: {data!r}")
PY
}

json_assert_invite_metadata() {
  local file=$1 metadata=$2 expected=$3
  "$PYTHON" - "$file" "$metadata" "$expected" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
found = any(item.get("metadata") == sys.argv[2] for item in data)
want = sys.argv[3] == "present"
if found is not want:
    raise SystemExit(f"invite metadata {sys.argv[2]!r} presence {found}, want {want}: {data!r}")
PY
}

json_assert_cli_caps_show() {
  local file=$1 principal=$2 group=$3
  "$PYTHON" - "$file" "$principal" "$group" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
if data.get("principal") != sys.argv[2]:
    raise SystemExit(f"unexpected caps principal: {data!r}")
if sys.argv[3] not in data.get("groups", []):
    raise SystemExit(f"missing caps group {sys.argv[3]!r}: {data!r}")
PY
}

json_assert_secret_absent() {
  local file=$1 capsule=$2 key=$3
  "$PYTHON" - "$file" "$capsule" "$key" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
for item in data:
    if item.get("capsule") == sys.argv[2] and item.get("key") == sys.argv[3]:
        raise SystemExit(f"secret was not deleted: {item!r}")
PY
}

json_assert_secret_present() {
  local file=$1 capsule=$2 key=$3
  "$PYTHON" - "$file" "$capsule" "$key" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
if not any(item.get("capsule") == sys.argv[2] and item.get("key") == sys.argv[3] for item in data):
    raise SystemExit(f"secret metadata entry missing for {sys.argv[2]!r}/{sys.argv[3]!r}: {data!r}")
PY
}

json_assert_cli_keypair_list() {
  local file=$1 name=$2
  "$PYTHON" - "$file" "$name" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
entry = next((item for item in data if item.get("name") == sys.argv[2]), None)
if not entry:
    raise SystemExit(f"keypair {sys.argv[2]!r} missing from list: {data!r}")
if entry.get("backend") != "file":
    raise SystemExit(f"unexpected keypair backend: {entry!r}")
if not entry.get("fingerprint"):
    raise SystemExit(f"keypair list missed fingerprint: {entry!r}")
PY
}

json_assert_pair_device_list() {
  local file=$1 key_id=$2 expected=$3
  "$PYTHON" - "$file" "$key_id" "$expected" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
found = any(item.get("key_id") == sys.argv[2] for item in data)
want = sys.argv[3] == "present"
if found is not want:
    raise SystemExit(f"pair device {sys.argv[2]!r} presence {found}, want {want}: {data!r}")
PY
}

json_assert_cli_keypair_pubkey() {
  local file=$1
  "$PYTHON" - "$file" <<'PY'
import re
import sys

text = open(sys.argv[1], encoding="utf-8").read().strip()
if not re.fullmatch(r"[0-9a-f]{64}", text):
    raise SystemExit(f"unexpected keypair public key output: {text!r}")
PY
}

json_assert_cli_quota() {
  local file=$1 principal=$2 processes=$3
  "$PYTHON" - "$file" "$principal" "$processes" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
if data.get("principal") != sys.argv[2]:
    raise SystemExit(f"unexpected quota principal: {data!r}")
if data.get("max_background_processes") != int(sys.argv[3]):
    raise SystemExit(f"unexpected process quota: {data!r}")
PY
}

json_assert_cli_capsule_show() {
  local file=$1 name=$2
  "$PYTHON" - "$file" "$name" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
if data.get("name") != sys.argv[2]:
    raise SystemExit(f"unexpected capsule: {data!r}")
manifest = data.get("manifest", "")
if 'name = "astrid-capsule-openai-compat"' not in manifest:
    raise SystemExit("capsule manifest body missing package identity")
PY
}

json_assert_cli_capsule_config() {
  local file=$1 model=$2
  "$PYTHON" - "$file" "$model" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
if data.get("model") != sys.argv[2]:
    raise SystemExit(f"unexpected capsule model config: {data!r}")
if "api_key" in data:
    raise SystemExit(f"capsule config leaked secret key metadata/value: {data!r}")
PY
}

json_assert_cli_version() {
  local file=$1
  "$PYTHON" - "$file" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
for key in ("version", "commit", "target"):
    if not data.get(key):
        raise SystemExit(f"version output missing {key}: {data!r}")
PY
}

json_assert_cli_config_show() {
  local file=$1
  "$PYTHON" - "$file" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
if not isinstance(data, dict):
    raise SystemExit(f"config output is not an object: {data!r}")
if "security" not in data:
    raise SystemExit(f"config output missing security section: {data!r}")
PY
}
