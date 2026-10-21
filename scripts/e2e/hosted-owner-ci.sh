#!/usr/bin/env bash
# Public, disposable test authority. Never a product bootstrap or user default.
# The caller owns the home, working directory, command timeout and daemon lifecycle.

configure_hosted_owner_ci() {
  local fixture=$1
  shift
  local source
  source="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/fixtures/hosted-owner-ci-keys.json"
  python3 - "$source" "$fixture" <<'PY'
import json
import os
import pathlib
import sys
import time

keys = json.loads(pathlib.Path(sys.argv[1]).read_text())
root = pathlib.Path(sys.argv[2])
if not root.is_absolute():
    raise SystemExit("CI enrollment requires an absolute, caller-owned fixture directory")
root.mkdir(mode=0o700)  # Exclusive: do not adopt or overwrite an existing fixture.
for role in ("owner", "deployment"):
    seed = bytes.fromhex(keys[role]["seed_hex"])
    public = bytes.fromhex(keys[role]["public_key_hex"])
    if len(seed) != 32 or len(public) != 32:
        raise SystemExit("invalid disposable Ed25519 fixture")
    fd = os.open(root / f"{role}.key", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(seed)
if (keys["owner"]["seed_hex"] == keys["deployment"]["seed_hex"]
        or keys["owner"]["public_key_hex"] == keys["deployment"]["public_key_hex"]):
    raise SystemExit("CI signer roles must be independent")
policy = {"deployment_key": list(bytes.fromhex(keys["deployment"]["public_key_hex"])),
          "generation": 1, "expires_at": int(time.time()) + 21600}
(root / "policy.json").write_text(json.dumps(policy))
(root / "owner-public.txt").write_text(keys["owner"]["public_key_hex"])
PY
  [[ $? -eq 0 ]] || return 1
  "$@" owner configure --policy "$fixture/policy.json" --target-default \
    > "$fixture/configured.json" || return
}

provision_hosted_owner_ci() {
  local fixture=$1 owner_public expiry
  shift
  owner_public=$(cat "$fixture/owner-public.txt") || return
  expiry=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["expires_at"])' \
    "$fixture/policy.json") || return
  "$@" owner prepare --owner-public-key "$owner_public" \
    > "$fixture/genesis.json" || return
  "$@" owner challenge --genesis "$fixture/genesis.json" --expires-at "$expiry" \
    > "$fixture/challenge.json" || return
  python3 - "$fixture/configured.json" "$fixture/challenge.json" <<'PY'
import json
import sys

configured, challenge = (json.load(open(path)) for path in sys.argv[1:])
for field in ("policy", "installation", "artifact"):
    if challenge[field] != configured[field]:
        raise SystemExit(f"CI challenge changed configured {field}")
PY
  [[ $? -eq 0 ]] || return 1
  "$@" owner sign-owner --challenge "$fixture/challenge.json" \
    --signing-key "$fixture/owner.key" > "$fixture/owner-signed.json" || return
  "$@" owner authorize --envelope "$fixture/owner-signed.json" \
    --signing-key "$fixture/deployment.key" > "$fixture/authorized.json" || return
  "$@" owner provision --envelope "$fixture/authorized.json" \
    > "$fixture/completion.json" || return
  "$@" owner inspect > "$fixture/inspection.json" || return
  python3 - "$fixture/completion.json" "$fixture/inspection.json" <<'PY'
import json
import sys

completion, inspection = (json.load(open(path)) for path in sys.argv[1:])
if completion.get("status") != "enrolled" or inspection.get("enrollment") != "enrolled":
    raise SystemExit("real native CI enrollment did not complete")
if inspection.get("completion") != completion.get("completion"):
    raise SystemExit("CI inspection lost the exact enrollment completion")
PY
}

assert_unenrolled_hosted_owner_ci() {
  local fixture=$1
  shift
  mkdir -m 700 "$fixture" || return
  "$@" owner inspect > "$fixture/before.json" || return
  "$@" agent list --format json > "$fixture/agents-before.json" || return
  local operation
  for operation in create claim delete; do
    local target=ci-no-owner
    [[ "$operation" != claim ]] || target=default
    local args=(agent "$operation" "$target")
    [[ "$operation" == claim ]] || args+=(-y)
    if "$@" "${args[@]}" > "$fixture/$operation.stdout" \
      2> "$fixture/$operation.stderr"; then
      printf 'unenrolled %s unexpectedly succeeded\n' "$operation" >&2
      return 1
    fi
    if [[ "$operation" == delete ]]; then
      grep -Fq 'ownership mutation requires an enrolled authority' \
        "$fixture/$operation.stderr" || return
    else
      grep -Fq 'principal creation requires a current user delegation' \
        "$fixture/$operation.stderr" || return
    fi
  done
  "$@" owner inspect > "$fixture/after.json" || return
  "$@" agent list --format json > "$fixture/agents-after.json" || return
  python3 - "$fixture" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
before, after = (json.loads((root / f"{name}.json").read_text()) for name in ("before", "after"))
if before.get("enrollment") != "unenrolled" or before != after:
    raise SystemExit("denied CLI mutation changed public enrollment state")
if json.loads((root / "agents-before.json").read_text()) != json.loads((root / "agents-after.json").read_text()):
    raise SystemExit("denied CLI mutation changed the principal roster")
PY
}
