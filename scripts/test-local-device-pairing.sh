#!/usr/bin/env bash
# Real local pairing API, never direct profile mutation or a live application home.
set -euo pipefail
if [[ $# != 1 || "$1" != /* || ! -x "$1" ]]; then
    echo 'usage: test-local-device-pairing.sh /absolute/candidate/astrid' >&2
    exit 2
fi
cli=$1
umask 077
test_root=$(mktemp -d /tmp/astrid-local-pairing.XXXXXX)
export ASTRID_HOME="$test_root/runtime"
export ASTRID_PRINCIPAL=default
unset ASTRID_RUN_DIR ASTRID_ENFORCED_DISTRO ASTRID_CLIENT_CONFIG_PATH
mkdir "$ASTRID_HOME"
cd "$test_root"
cleanup() {
    local result=$?
    trap - EXIT
    if ! "$cli" stop > cleanup.log 2>&1; then
        echo "Disposable runtime cleanup failed: $test_root/cleanup.log" >&2
        result=1
    fi
    echo "Retained test evidence: $test_root"
    exit "$result"
}
trap cleanup EXIT
"$cli" start > start.log 2>&1
"$cli" keypair generate --name native-ui --raw > public-key.txt
public_key=$(<public-key.txt)
"$cli" pair-device issue --scope use-only --label native-ui --raw > pair-token.txt
"$cli" pair-device redeem --public-key "$public_key" < pair-token.txt > paired.json
"$cli" pair-device list --json > devices.json
python3 - <<'PY'
import json
paired = json.load(open('paired.json'))
devices = json.load(open('devices.json'))
assert paired['principal'] == 'default', paired
matches = [device for device in devices if device['key_id'] == paired['key_id']]
assert len(matches) == 1, devices
assert matches[0]['label'] == 'native-ui', matches
PY
if "$cli" pair-device redeem --public-key "$public_key" < pair-token.txt > replay.log 2>&1; then
    echo 'Single-use token replay was accepted' >&2
    exit 1
fi
key_id=$(python3 -c 'import json; print(json.load(open("paired.json"))["key_id"])')
"$cli" pair-device revoke "$key_id" > revoke.log 2>&1
"$cli" pair-device list --json > revoked.json
python3 - <<'PY'
import json
key_id = json.load(open('paired.json'))['key_id']
assert not any(device['key_id'] == key_id for device in json.load(open('revoked.json')))
token = open('pair-token.txt').read().strip()
for name in ['paired.json', 'devices.json', 'replay.log', 'revoke.log', 'revoked.json']:
    assert token not in open(name).read(), f'token exposed in {name}'
PY
echo 'PASS: real key generation, token issuance/redemption, single-use refusal and revocation'
