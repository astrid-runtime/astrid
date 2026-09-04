#!/usr/bin/env bash
set -euo pipefail
umask 077

REQUIRED_TEAM_ID=9BDSL5BJAP
NOTARY_PROFILE_NAME=astrid-fskit
P12_PATH=
P8_PATH=
SIGNING_KEYCHAIN=
KEYCHAIN_PASSWORD=
NOTARY_MODE=
RESTORE_KEYCHAINS=()

cleanup() {
  local status=$?
  trap - EXIT
  set +e
  if [[ "${#RESTORE_KEYCHAINS[@]}" -gt 0 ]]; then
    security list-keychains -s "${RESTORE_KEYCHAINS[@]}" >/dev/null 2>&1
  fi
  if [[ -n "$SIGNING_KEYCHAIN" ]]; then
    if [[ -f "$SIGNING_KEYCHAIN" ]]; then
      security delete-keychain "$SIGNING_KEYCHAIN" >/dev/null 2>&1
    fi
  fi
  if [[ -n "$P12_PATH" ]]; then
    rm -f "$P12_PATH"
  fi
  if [[ -n "$P8_PATH" ]]; then
    rm -f "$P8_PATH"
  fi
  exit "$status"
}
trap cleanup EXIT

require_team() {
  [[ -n "${ASTRID_MACOS_DEVELOPMENT_TEAM_ID:-}" ]] || {
    echo "set ASTRID_MACOS_DEVELOPMENT_TEAM_ID" >&2
    return 1
  }
  [[ "$ASTRID_MACOS_DEVELOPMENT_TEAM_ID" == "$REQUIRED_TEAM_ID" ]] || {
    echo "ASTRID_MACOS_DEVELOPMENT_TEAM_ID does not match team $REQUIRED_TEAM_ID" >&2
    return 1
  }
}

require_developer_id() {
  [[ -n "${ASTRID_MACOS_DEVELOPER_ID_P12:-}" ]] || {
    echo "ASTRID_MACOS_DEVELOPER_ID_P12 is required for Developer ID signing" >&2
    return 1
  }
  [[ -n "${ASTRID_MACOS_DEVELOPER_ID_P12_PASSWORD:-}" ]] || {
    echo "ASTRID_MACOS_DEVELOPER_ID_P12_PASSWORD is required for Developer ID signing" >&2
    return 1
  }
}

write_developer_id_p12() {
  P12_PATH="$RUNNER_TEMP/astrid-developer-id.p12.$$"
  printf '%s' "$ASTRID_MACOS_DEVELOPER_ID_P12" |
    python3 -c 'import base64, sys; sys.stdout.buffer.write(base64.b64decode(sys.stdin.read()))' \
      >"$P12_PATH"
  chmod 0600 "$P12_PATH"
}

prepare_notary_input() {
  local apple_id=${ASTRID_MACOS_NOTARY_APPLE_ID:-}
  local app_password=${ASTRID_MACOS_NOTARY_APP_PASSWORD:-}
  local key_id=${ASTRID_FSKIT_NOTARY_KEY_ID:-}
  local issuer_id=${ASTRID_FSKIT_NOTARY_ISSUER_ID:-}
  local key=${ASTRID_FSKIT_NOTARY_KEY:-}

  if [[ -n "$apple_id" || -n "$app_password" ]]; then
    [[ -n "$apple_id" && -n "$app_password" ]] || {
      echo "both ASTRID_MACOS_NOTARY_APPLE_ID and ASTRID_MACOS_NOTARY_APP_PASSWORD are required" >&2
      return 1
    }
    export ASTRID_FSKIT_NOTARY_PROFILE="$NOTARY_PROFILE_NAME"
    NOTARY_MODE=apple-id
  elif [[ -n "$key_id" || -n "$issuer_id" || -n "$key" ]]; then
    [[ -n "$key_id" && -n "$issuer_id" && -n "$key" ]] || {
      echo "ASTRID_MACOS_NOTARY_KEY_ID, ASTRID_MACOS_NOTARY_ISSUER_ID, and ASTRID_MACOS_NOTARY_KEY are required together" >&2
      return 1
    }
    unset ASTRID_FSKIT_NOTARY_PROFILE
    P8_PATH="$RUNNER_TEMP/astrid-notary.p8.$$"
    printf '%s' "$key" >"$P8_PATH"
    chmod 0600 "$P8_PATH"
    export ASTRID_FSKIT_NOTARY_KEY_PATH="$P8_PATH"
    NOTARY_MODE=api-key
  else
    echo "Apple-ID notary credentials or a complete App Store Connect API key are required" >&2
    return 1
  fi
}

create_signing_keychain() {
  local keychain_password
  local keychain_path
  local original_keychain

  keychain_password="$(openssl rand -hex 32)"
  KEYCHAIN_PASSWORD="$keychain_password"
  keychain_path="$RUNNER_TEMP/astrid-signing-$$.keychain"
  while IFS= read -r original_keychain; do
    [[ -n "$original_keychain" ]] || continue
    RESTORE_KEYCHAINS+=("$original_keychain")
  done < <(security list-keychains -d user | sed -e $'s/^[[:space:]]*//' -e 's/^"//' -e 's/"$//')

  SIGNING_KEYCHAIN="$keychain_path"
  security create-keychain -p "$keychain_password" "$keychain_path"
  security unlock-keychain -p "$keychain_password" "$keychain_path"
  security list-keychains -s "$SIGNING_KEYCHAIN" "${RESTORE_KEYCHAINS[@]}" >/dev/null
}

import_developer_id() {
  security import "$P12_PATH" \
    -k "$SIGNING_KEYCHAIN" \
    -P "$ASTRID_MACOS_DEVELOPER_ID_P12_PASSWORD" \
    -T /usr/bin/codesign
  security set-key-partition-list -S apple-tool:,apple: \
    -k "$KEYCHAIN_PASSWORD" "$SIGNING_KEYCHAIN" >/dev/null
  security find-identity -v -p codesigning "$SIGNING_KEYCHAIN" |
    grep -Eq '[[:space:]]1 valid identit(y|ies)'
  rm -f "$P12_PATH"
  P12_PATH=
}

MODE=notary-build
if [[ "${1:-}" == "--identity-only" ]]; then
  MODE=identity-only
  shift
fi
if [[ "$MODE" == identity-only ]]; then
  [[ $# -gt 0 ]] || {
    echo "usage: import_macos_signing.sh [--identity-only] command [arguments]" >&2
    exit 2
  }
else
  [[ $# -eq 0 ]] || {
    echo "usage: import_macos_signing.sh [--identity-only] command [arguments]" >&2
    exit 2
  }
fi

require_team
export ASTRID_FSKIT_DEVELOPMENT_TEAM="$ASTRID_MACOS_DEVELOPMENT_TEAM_ID"
require_developer_id
[[ "$(uname -s)" == Darwin ]] || {
  echo "Developer ID signing requires macOS" >&2
  exit 1
}
: "${RUNNER_TEMP:?set RUNNER_TEMP}"
command -v python3 >/dev/null 2>&1 || {
  echo "python3 is required to decode the Developer ID identity" >&2
  exit 1
}
command -v security >/dev/null 2>&1 || {
  echo "security is required to manage the signing keychain" >&2
  exit 1
}
command -v xcrun >/dev/null 2>&1 || {
  echo "xcrun is required for macOS signing" >&2
  exit 1
}

write_developer_id_p12
create_signing_keychain
import_developer_id

if [[ "$MODE" == notary-build ]]; then
  prepare_notary_input
  if [[ "$NOTARY_MODE" == apple-id ]]; then
    xcrun notarytool store-credentials "$NOTARY_PROFILE_NAME" \
      --keychain "$SIGNING_KEYCHAIN" \
      --apple-id "$ASTRID_MACOS_NOTARY_APPLE_ID" \
      --password "$ASTRID_MACOS_NOTARY_APP_PASSWORD" \
      --team-id "$ASTRID_MACOS_DEVELOPMENT_TEAM_ID" >/dev/null
  elif [[ "$NOTARY_MODE" != api-key ]]; then
    echo "notary input did not select Apple-ID or the API-key fallback" >&2
    exit 1
  fi
  SCRIPT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
  "$SCRIPT_ROOT/scripts/build-macos-fskit.sh"
else
  "$@"
fi
