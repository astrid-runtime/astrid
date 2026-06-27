#!/usr/bin/env bash

run_admin_pair_device_cross_principal_smoke() {
  local user_bearer=$1
  local user_principal=$2
  local admin_bearer=$3
  local status token pubkey key_id paired_bearer

  note "checking admin cross-principal pair-device list/revoke"
  status="$(http_status POST /api/auth/pair-device "$user_bearer" \
    '{"expires_secs":120,"label":"admin revoke target","scope":"use-only"}' \
    "$ARTIFACTS/admin-pair-device-target.json")"
  assert_status "agent pair-device issue for admin revoke" "$status" 200
  token="$(json_field "$ARTIFACTS/admin-pair-device-target.json" token)"
  pubkey="$("$PYTHON" - <<'PY'
import secrets
print(secrets.token_hex(32))
PY
)"
  status="$(http_status POST /api/auth/pair-device/redeem "" \
    "{\"token\":\"$token\",\"public_key\":\"$pubkey\"}" \
    "$ARTIFACTS/admin-pair-device-target-redeem.json")"
  assert_status "admin revoke target pair-token redeem" "$status" 200
  key_id="$(json_field "$ARTIFACTS/admin-pair-device-target-redeem.json" key_id)"
  paired_bearer="$(json_field "$ARTIFACTS/admin-pair-device-target-redeem.json" session_token)"

  status="$(http_status GET "/api/sys/principals/$user_principal/devices" "$admin_bearer" "" \
    "$ARTIFACTS/admin-cross-principal-devices.json")"
  assert_status "admin cross-principal device list" "$status" 200
  json_assert_device_list_contains "$ARTIFACTS/admin-cross-principal-devices.json" "$key_id"
  status="$(http_status DELETE "/api/sys/principals/$user_principal/devices/$key_id" \
    "$admin_bearer" "" "$ARTIFACTS/admin-cross-principal-device-revoke.json")"
  assert_status "admin cross-principal device revoke" "$status" 204
  status="$(http_status GET /api/auth/me "$paired_bearer" "" \
    "$ARTIFACTS/admin-revoked-paired-me.json")"
  assert_status "admin-revoked paired bearer denied" "$status" 401
}
