#!/usr/bin/env bash

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
if principals != [principal]:
    raise SystemExit(f"expected only {principal!r} in principal list, got {principals!r}")
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

json_assert_capsule_list_state() {
  local file=$1
  local capsule=$2
  local expected=$3
  "$PYTHON" - "$file" "$capsule" "$expected" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
capsule = sys.argv[2]
expected = sys.argv[3]
if isinstance(data, dict):
    capsules = data.get("capsules", [])
else:
    capsules = data
if not isinstance(capsules, list):
    raise SystemExit(f"expected capsule list, got {data!r}")
present = capsule in capsules
if expected == "present" and not present:
    raise SystemExit(f"expected {capsule!r} in capsule list {capsules!r}")
if expected == "absent" and present:
    raise SystemExit(f"expected {capsule!r} absent from capsule list {capsules!r}")
PY
}

json_assert_capsule_install_output() {
  local file=$1
  local phase=$2
  "$PYTHON" - "$file" "$phase" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
expected_phase = sys.argv[2]
if data.get("phase") != expected_phase:
    raise SystemExit(f"expected install phase {expected_phase!r}, got {data!r}")
for field in ("target_dir", "installed_version", "wasm_hash"):
    if not data.get(field):
        raise SystemExit(f"install output missed {field!r}: {data!r}")
if data.get("env_path") != "":
    raise SystemExit(f"storage-backed install exposed a native env path: {data!r}")
target_parts = str(data.get("target_dir", "")).replace("\\", "/").rstrip("/").split("/")
if len(target_parts) < 2 or target_parts[-2] != "astrid-capsule-registry":
    raise SystemExit(f"install target was not a digest-qualified registry cache: {data!r}")
digest = target_parts[-1]
if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
    raise SystemExit(f"install target cache generation was not a canonical digest: {data!r}")
PY
}

json_assert_capsule_show_durable_source() {
  local file=$1
  local capsule=$2
  "$PYTHON" - "$file" "$capsule" <<'PY'
import json
import sys
import uuid

data = json.load(open(sys.argv[1], encoding="utf-8"))
capsule = sys.argv[2]
if data.get("name") != capsule:
    raise SystemExit(f"expected capsule {capsule!r}, got {data!r}")
try:
    source_id = uuid.UUID(str(data.get("source", "")))
except ValueError as exc:
    raise SystemExit(f"capsule show exposed a non-canonical runtime source ID: {data!r}") from exc
if source_id.int == 0:
    raise SystemExit(f"capsule show exposed the reserved nil runtime source ID: {data!r}")
wasm_hash = str(data.get("wasm_hash", ""))
if len(wasm_hash) != 64 or any(ch not in "0123456789abcdef" for ch in wasm_hash):
    raise SystemExit(f"capsule show missed wasm_hash: {data!r}")
manifest = json.loads(data.get("manifest", ""))
if manifest.get("package", {}).get("name") != capsule:
    raise SystemExit(f"capsule manifest did not name {capsule!r}: {manifest!r}")
if data.get("contracts_status") != "daemon-registry":
    raise SystemExit(f"capsule show did not identify daemon registry authority: {data!r}")
PY
}

json_assert_audit_scope_and_events() {
  local file=$1
  local principal=$2
  shift 2
  "$PYTHON" - "$file" "$principal" "$@" <<'PY'
import json
import sys

path = sys.argv[1]
principal = sys.argv[2]
expected = sys.argv[3:]
data = json.load(open(path, encoding="utf-8"))
entries = data.get("entries", [])
if not isinstance(entries, list) or not entries:
    raise SystemExit(f"audit response has no entries: {data!r}")

for entry in entries:
    seen = entry.get("principal")
    if seen != principal:
        raise SystemExit(f"audit entry leaked cross-principal row for {principal!r}: {entry!r}")
    if entry.get("outcome") not in ("success", "failure"):
        raise SystemExit(f"audit entry has invalid outcome: {entry!r}")
    if not entry.get("method"):
        raise SystemExit(f"audit entry missed method: {entry!r}")
    if not entry.get("required_capability"):
        raise SystemExit(f"audit entry missed required_capability: {entry!r}")

def matches(spec: str, entry: dict) -> bool:
    method, outcome = spec.split(":", 1)
    return entry.get("method") == method and entry.get("outcome") == outcome

missing = [spec for spec in expected if not any(matches(spec, entry) for entry in entries)]
if missing:
    summary = [
        {
            "method": entry.get("method"),
            "outcome": entry.get("outcome"),
            "principal": entry.get("principal"),
            "required_capability": entry.get("required_capability"),
        }
        for entry in entries
    ]
    raise SystemExit(f"audit response missed expected events {missing!r}; saw {summary!r}")
PY
}

json_assert_session_list_scope() {
  local file=$1 expected=$2 forbidden=$3
  "$PYTHON" - "$file" "$expected" "$forbidden" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
expected = sys.argv[2]
forbidden = sys.argv[3]
sessions = data.get("sessions", [])
ids = [entry.get("session_id") for entry in sessions if isinstance(entry, dict)]
if expected not in ids:
    raise SystemExit(f"expected session {expected!r} in {ids!r}")
if forbidden in ids:
    raise SystemExit(f"forbidden cross-principal session {forbidden!r} appeared in {ids!r}")
PY
}

json_assert_session_summary() {
  local file=$1 expected_id=$2 expected_title=$3
  "$PYTHON" - "$file" "$expected_id" "$expected_title" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
expected_id = sys.argv[2]
expected_title = None if sys.argv[3] == "null" else sys.argv[3]
if data.get("session_id") != expected_id:
    raise SystemExit(f"expected session id {expected_id!r}, got {data!r}")
if data.get("title") != expected_title:
    raise SystemExit(f"expected title {expected_title!r}, got {data!r}")
PY
}

json_assert_session_messages_contains() {
  local file=$1 expected_id=$2 expected_text=$3
  "$PYTHON" - "$file" "$expected_id" "$expected_text" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
expected_id = sys.argv[2]
expected_text = sys.argv[3]
if data.get("session_id") != expected_id:
    raise SystemExit(f"expected transcript id {expected_id!r}, got {data!r}")
blob = json.dumps(data.get("messages", []), sort_keys=True)
if expected_text not in blob:
    raise SystemExit(f"expected transcript text {expected_text!r} not found in {blob!r}")
PY
}

json_assert_session_messages_empty() {
  local file=$1 expected_id=$2
  "$PYTHON" - "$file" "$expected_id" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
expected_id = sys.argv[2]
if data.get("session_id") != expected_id:
    raise SystemExit(f"expected transcript id {expected_id!r}, got {data!r}")
messages = data.get("messages")
if messages != []:
    raise SystemExit(f"expected empty cross-principal transcript, got {messages!r}")
PY
}

json_assert_session_search_scope() {
  local file=$1 expected=$2 forbidden=$3
  "$PYTHON" - "$file" "$expected" "$forbidden" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
expected = sys.argv[2]
forbidden = sys.argv[3]
results = data.get("results", [])
ids = [entry.get("session_id") for entry in results if isinstance(entry, dict)]
if expected != "-" and expected not in ids:
    raise SystemExit(f"expected search hit {expected!r} in {ids!r}")
if forbidden in ids:
    raise SystemExit(f"forbidden cross-principal search hit {forbidden!r} appeared in {ids!r}")
PY
}

assert_session_management_unavailable() {
  local label=$1 status=$2 out=$3
  LAST_HTTP_OUT="$out"
  assert_status "$label" "$status" 501
  "$PYTHON" - "$out" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
if data.get("error") != "not_implemented":
    raise SystemExit(f"session management missed not_implemented contract: {data!r}")
if "conversation-management verbs" not in data.get("reason", ""):
    raise SystemExit(f"session management missed bounded feature reason: {data!r}")
PY
}

json_assert_deleted_flag() {
  local file=$1 expected=$2
  "$PYTHON" - "$file" "$expected" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
expected = sys.argv[2].lower() == "true"
if data.get("deleted") is not expected:
    raise SystemExit(f"expected deleted={expected!r}, got {data!r}")
PY
}

json_assert_no_native_capsule_env() {
  local home=$1
  local capsule=$2
  local default_principal=$3
  local user_principal=$4
  local ops_principal=$5
  "$PYTHON" - "$home" "$capsule" "$default_principal" "$user_principal" "$ops_principal" <<'PY'
import sys
from pathlib import Path

home = Path(sys.argv[1])
capsule = sys.argv[2]
default_principal = sys.argv[3]
user_principal = sys.argv[4]
ops_principal = sys.argv[5]
for principal in (default_principal, user_principal, ops_principal):
    path = home / "home" / principal / ".config" / "env" / f"{capsule}.env.json"
    if path.exists():
        raise SystemExit(f"environment escaped governed storage into native alias path: {path}")
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
if entry.get("storage") != "secret-store":
    raise SystemExit(f"secret metadata did not report governed secret storage: {entry!r}")
if entry.get("scope") != "agent":
    raise SystemExit(f"secret metadata did not report agent scope: {entry!r}")
for forbidden in ("value", "secret"):
    if forbidden in entry:
        raise SystemExit(f"secret metadata leaked {forbidden!r}: {entry!r}")
PY
}

json_assert_secret_store_isolated() {
  local home=$1
  local capsule=$2
  local default_secret=$3
  local user_principal=$4
  local user_secret=$5
  local ops_principal=$6
  local ops_secret=$7
  "$PYTHON" - "$home" "$capsule" "$default_secret" "$user_principal" "$user_secret" "$ops_principal" "$ops_secret" <<'PY'
import sys
from pathlib import Path

home = Path(sys.argv[1])
capsule = sys.argv[2]
default_secret = sys.argv[3]
user_principal = sys.argv[4]
user_secret = sys.argv[5]
ops_principal = sys.argv[6]
ops_secret = sys.argv[7]

sentinels = {
    "default": default_secret,
    user_principal: user_secret,
    ops_principal: ops_secret,
}

for principal in sentinels:
    path = home / "secrets" / principal / capsule / "api_key"
    if path.exists():
        raise SystemExit(f"secret escaped governed storage into native alias path: {path}")

if len(set(sentinels.values())) != len(sentinels):
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
