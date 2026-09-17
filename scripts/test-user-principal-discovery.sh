#!/usr/bin/env bash
# Real CLI/daemon journey, isolated from the operator's runtime and credentials.
# Optional second argument seeds a packed released home, then upgrades in place.
set -euo pipefail
if [[ $# -lt 1 || $# -gt 2 || "$1" != /* || ! -x "$1" ]]; then
    echo 'usage: test-user-principal-discovery.sh /absolute/candidate/astrid [/absolute/released/astrid]' >&2
    exit 2
fi
cli=$1
released=${2:-}
if [[ -n "$released" && ( "$released" != /* || ! -x "$released" ) ]]; then
    echo 'usage: test-user-principal-discovery.sh /absolute/candidate/astrid [/absolute/released/astrid]' >&2
    exit 2
fi
test_root=$(mktemp -d /tmp/astrid-user-discovery.XXXXXX)
export ASTRID_HOME="$test_root/runtime"
export ASTRID_PRINCIPAL=default
unset ASTRID_RUN_DIR ASTRID_ENFORCED_DISTRO ASTRID_CLIENT_CONFIG_PATH
mkdir -m 700 "$ASTRID_HOME"
cd "$test_root"
stop_cli=$cli
cleanup() {
    local result=$?
    trap - EXIT
    if ! "$stop_cli" stop > cleanup.log 2>&1; then
        echo "Disposable runtime cleanup failed: $test_root/cleanup.log" >&2
        result=1
    fi
    echo "Retained test evidence: $test_root"
    exit "$result"
}
trap cleanup EXIT

assert_mine() {
    local file=$1
    shift
    python3 - "$file" "$@" <<'PY'
import json
import sys

path = sys.argv[1]
expected = sorted(sys.argv[2:])
rows = json.load(open(path))
got = sorted(row["principal"] for row in rows)
assert got == expected, (got, rows)
assert all(row.get("owner_uid") for row in rows), rows
PY
}

refuse_child_directory() {
    if "$cli" --principal discovery-child agent list --mine --format json > child.log 2>&1; then
        echo 'Agent without human delegation obtained a user directory' >&2
        exit 1
    fi
    grep -q 'user delegation' child.log
}

refuse_child_claim() {
    if "$cli" --principal discovery-child agent claim discovery-peer > child-claim.log 2>&1; then
        echo 'Undelegated principal claimed another identity' >&2
        exit 1
    fi
    # Named claim reuses agent:create, so a child is denied before the
    # handler. Kernel tests pin the delegation string for callers that
    # hold the capability. Either public denial is required.
    grep -Eq 'user delegation|missing capability' child-claim.log
}


use_child() {
    local prefix=$1
    local bin=$2
    "$bin" --principal discovery-child agent show discovery-child --format json > "$prefix-show.json"
    "$bin" --principal discovery-child quota show --agent discovery-child --format json > "$prefix-quota.json"
    "$bin" --principal discovery-child capsule list > "$prefix-capsules.txt"
    python3 -c "import json,sys; show=json.load(open(sys.argv[1])); quota=json.load(open(sys.argv[2])); assert show['principal']=='discovery-child', show; assert show.get('enabled') is True, show; assert quota['max_storage_bytes']==2*1024*1024*1024, quota" "$prefix-show.json" "$prefix-quota.json"
}

hash_keys() {
    local out=$1
    shift
    local principal
    for principal in "$@"; do
        shasum -a 256 "$ASTRID_HOME/keys/$principal.key"
    done > "$out"
}

if [[ -n "$released" ]]; then
    stop_cli=$released
    "$released" --version > released-version.txt
    shasum -a 256 "$released" "$cli" > upgrade-inputs.sha256
    "$released" start > released-start.log 2>&1
    "$released" agent create discovery-child > released-create-child.log 2>&1
    "$released" agent create discovery-peer > released-create-peer.log 2>&1
    "$released" quota set --agent discovery-child --storage 2GiB > released-quota.log 2>&1
    use_child released-use "$released"
    hash_keys principal-keys.before.sha256 default discovery-child discovery-peer
    "$released" stop > released-stop.log 2>&1
    python3 -c 'import os,sys; names=sorted(os.listdir(sys.argv[1])); assert names==["astrid.volume"], names' "$ASTRID_HOME"
    stop_cli=$cli
    "$cli" start > start.log 2>&1
    hash_keys principal-keys.after.sha256 default discovery-child discovery-peer
    cmp principal-keys.before.sha256 principal-keys.after.sha256
    use_child upgraded-use "$cli"
    cmp released-use-show.json upgraded-use-show.json
    cmp released-use-quota.json upgraded-use-quota.json
    "$cli" agent list --mine --format json > before.json
    # Bound local-operator upgrade assigns packed leftovers at candidate start.
    # Named claim remains for deferred hosted/shared leftovers, not this path.
    assert_mine before.json default discovery-child discovery-peer
    refuse_child_directory
    refuse_child_claim
    "$cli" stop > stop.log 2>&1
    "$cli" start > restart.log 2>&1
    "$cli" agent list --mine --format json > after.json
    cmp before.json after.json
    use_child upgraded-restart-use "$cli"
    cmp released-use-show.json upgraded-restart-use-show.json
    cmp released-use-quota.json upgraded-restart-use-quota.json
    echo 'PASS: packed released-to-candidate upgrade preserved keys/use and assigned leftover principals to the local operator without named claim'
else
    "$cli" start > start.log 2>&1
    "$cli" agent create discovery-child > create.log 2>&1
    "$cli" agent list --mine --format json > before.json
    assert_mine before.json default discovery-child
    refuse_child_directory
    "$cli" stop > stop.log 2>&1
    "$cli" start > restart.log 2>&1
    "$cli" agent list --mine --format json > after.json
    cmp before.json after.json
    echo 'PASS: real authenticated directory, delegated-user requirement, restart persistence'
fi
