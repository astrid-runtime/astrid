#!/usr/bin/env bash

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

json_assert_principal_lacks_group() {
  local file=$1 principal=$2 forbidden_group=$3
  "$PYTHON" - "$file" "$principal" "$forbidden_group" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
if data.get("principal") != sys.argv[2]:
    raise SystemExit(f"unexpected principal: {data!r}")
if sys.argv[3] in data.get("groups", []):
    raise SystemExit(f"forbidden group {sys.argv[3]!r} present: {data!r}")
PY
}

json_assert_http_forbidden_reason() {
  local file=$1 expected=$2
  "$PYTHON" - "$file" "$expected" <<'PY'
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
if data.get("error") != "forbidden":
    raise SystemExit(f"unexpected forbidden response: {data!r}")
reason = data.get("reason")
if not isinstance(reason, str) or sys.argv[2] not in reason:
    raise SystemExit(f"forbidden reason missing {sys.argv[2]!r}: {data!r}")
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
