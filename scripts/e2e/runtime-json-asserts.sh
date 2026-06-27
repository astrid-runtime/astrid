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
for field in ("target_dir", "installed_version", "wasm_hash", "env_path"):
    if not data.get(field):
        raise SystemExit(f"install output missed {field!r}: {data!r}")
if not str(data.get("target_dir", "")).endswith("/astrid-capsule-registry"):
    raise SystemExit(f"install target was not registry capsule: {data!r}")
PY
}

json_assert_capsule_show_archive_source() {
  local file=$1
  local capsule=$2
  local archive=$3
  "$PYTHON" - "$file" "$capsule" "$archive" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
capsule = sys.argv[2]
archive = sys.argv[3]
if data.get("name") != capsule:
    raise SystemExit(f"expected capsule {capsule!r}, got {data!r}")
if data.get("source") != archive:
    raise SystemExit(f"expected source {archive!r}, got {data!r}")
if not data.get("wasm_hash"):
    raise SystemExit(f"capsule show missed wasm_hash: {data!r}")
manifest = data.get("manifest", "")
if f'name = "{capsule}"' not in manifest:
    raise SystemExit(f"capsule manifest did not name {capsule!r}: {manifest!r}")
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
