#!/usr/bin/env bash
set -euo pipefail
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH

usage() {
  cat >&2 <<'EOF'
usage: manage-macos-fskit.sh install|update|enable|status|check-process|uninstall|validate
environment: ASTRID_FSKIT_APP_DEST, ASTRID_FSKIT_BIN_DIR
EOF
}

if [[ "$(uname -s)" != Darwin ]]; then
  echo "the AstridFS lifecycle manager requires macOS" >&2
  exit 1
fi

[[ $# -eq 1 ]] || {
  usage
  exit 2
}
COMMAND=$1
MANAGER_DIR="$(cd "$(dirname "$0")" && pwd)"
if [[ -d "$MANAGER_DIR/AstridFS.app" ]]; then
  RELEASE_ROOT="$MANAGER_DIR"
elif [[ -d "$MANAGER_DIR/../native/macos/AstridFSKit" ]]; then
  RELEASE_ROOT="$(cd "$MANAGER_DIR/.." && pwd)"
else
  RELEASE_ROOT="$(cd "$MANAGER_DIR/.." && pwd)"
fi
SOURCE_APP="$RELEASE_ROOT/AstridFS.app"
DESTINATION_APP="${ASTRID_FSKIT_APP_DEST:-/Applications/AstridFS.app}"
VALIDATOR="$RELEASE_ROOT/scripts/validate-macos-fskit.sh"
EXTENSION_IDENTIFIER=org.astrid.runtime.fs.AppEx
APP_IDENTIFIER=org.astrid.runtime.fs
COMPANION_IDENTIFIER=org.astrid.runtime.fs.storage-provider-fskit
CODE_SIGN_TEAM=9BDSL5BJAP
APP_EXECUTABLE="$DESTINATION_APP/Contents/MacOS/AstridFS"
if [[ ! -x "$VALIDATOR" ]]; then
  VALIDATOR="$MANAGER_DIR/validate-macos-fskit.sh"
fi

validate_app() {
  [[ -x "$VALIDATOR" ]] || {
    echo "missing validator: $VALIDATOR" >&2
    exit 1
  }
  "$VALIDATOR" "$1"
}

extension_record() {
  /usr/bin/pluginkit -m -A -D -v -i "$EXTENSION_IDENTIFIER"
}

extension_is_elected() {
  local extension_path records elected_record elected_info elected_path
  local installed_short version_token expected_prefix
  extension_path="$DESTINATION_APP/Contents/Extensions/AstridFSAppEx.appex"
  records="$(extension_record)" || return 1
  elected_record="$(printf '%s\n' "$records" | /usr/bin/awk -F '\t' '
    $1 ~ /^\+[[:space:]]*/ {
      elected = $0
      count++
    }
    END {
      if (count != 1) {
        exit 1
      }
      print elected
    }')" || return 1
  IFS=$'\t' read -r elected_info _ _ elected_path <<<"$elected_record"
  [[ "$elected_path" == "$extension_path" ]] || return 1
  expected_prefix="+    $EXTENSION_IDENTIFIER("
  case "$elected_info" in
    "$expected_prefix"*) ;;
    *) return 1 ;;
  esac
  version_token="${elected_info#"$expected_prefix"}"
  version_token="${version_token%)}"
  [[ "$version_token" != "$elected_info" && -n "$version_token" ]] || return 1
  installed_short="$(plutil -extract CFBundleShortVersionString raw -expect string \
    "$extension_path/Contents/Info.plist")"
  # PlugInKit's parenthetical binds to the extension's short version only.
  [[ "$version_token" == "$installed_short" ]]
}

require_extension_elected() {
  if extension_is_elected; then
    return 0
  fi
  echo "AstridFS is installed but macOS has not elected $EXTENSION_IDENTIFIER from $DESTINATION_APP." >&2
  echo "Open System Settings > General > Login Items & Extensions > File System Extensions, enable AstridFS, then rerun this command." >&2
  extension_record >&2 || true
  return 1
}

companion_path() {
  if [[ -x "$RELEASE_ROOT/astrid-storage-provider-fskit" ]]; then
    printf '%s\n' "$RELEASE_ROOT/astrid-storage-provider-fskit"
    return
  fi
  echo "missing co-installed astrid-storage-provider-fskit beside AstridFS.app" >&2
  return 1
}

companion_target() {
  if [[ -n "${ASTRID_FSKIT_BIN_DIR:-}" ]]; then
    printf '%s\n' "$ASTRID_FSKIT_BIN_DIR/astrid-storage-provider-fskit"
  elif command -v astrid >/dev/null 2>&1; then
    printf '%s\n' "$(dirname "$(command -v astrid)")/astrid-storage-provider-fskit"
  else
    printf '%s\n' "/usr/local/bin/astrid-storage-provider-fskit"
  fi
}

validate_companion() {
  local companion=$1 app_version provider_output provider_version request_id
  /usr/bin/codesign --verify --strict --verbose=2 "$companion"
  provider_output="$(/usr/bin/codesign --display --verbose=4 "$companion" 2>&1)"
  grep -Fx "Identifier=$COMPANION_IDENTIFIER" <<<"$provider_output" >/dev/null
  grep -Fx "TeamIdentifier=$CODE_SIGN_TEAM" <<<"$provider_output" >/dev/null
  app_version="$(plutil -extract CFBundleShortVersionString raw -expect string \
    "$SOURCE_APP/Contents/Info.plist")"
  request_id="$(/usr/bin/uuidgen)" || {
    echo "unable to generate a request ID for the FSKit companion probe" >&2
    return 1
  }
  provider_output="$(printf '%s\n' \
    "{\"protocol_version\":1,\"request_id\":\"$request_id\",\"acting_principal_hint\":\"default\",\"operation\":{\"operation\":\"status\",\"selector\":{\"kind\":\"native-path\",\"value\":\"/\"}}}" \
    | "$companion" --astrid-provider-stdio-v1)" || {
    echo "the FSKit companion failed its provider identity probe" >&2
    return 1
  }
  provider_version="$(sed -nE 's/.*"name":"astrid-storage-provider-fskit","version":"([^"]+)".*/\1/p' \
    <<<"$provider_output" | head -n 1)"
  [[ "$provider_version" == "$app_version" ]] || {
    echo "FSKit companion version $provider_version does not match AstridFS $app_version" >&2
    return 1
  }
}

app_process_matches() {
  local pid=$1 process_path loaded_path signature installed_version
  process_path="$(/bin/ps -p "$pid" -o comm=)" || return 1
  [[ "$process_path" == "$APP_EXECUTABLE" ]] || return 1
  loaded_path="$(/usr/sbin/lsof -p "$pid" -a -d txt -Fn \
    | /usr/bin/sed -n 's/^n//p' | /usr/bin/head -n 1)"
  [[ "$loaded_path" == "$APP_EXECUTABLE" ]] || return 1
  signature="$(/usr/bin/codesign --display --verbose=4 "$process_path" 2>&1)"
  grep -Fx "Identifier=$APP_IDENTIFIER" <<<"$signature" >/dev/null
  grep -Fx "TeamIdentifier=$CODE_SIGN_TEAM" <<<"$signature" >/dev/null
  installed_version="$(plutil -extract CFBundleShortVersionString raw -expect string \
    "$DESTINATION_APP/Contents/Info.plist")"
  [[ -n "$installed_version" ]]
  if [[ -n "${ASTRID_FSKIT_EXPECTED_VERSION:-}" ]]; then
    [[ "$installed_version" == "$ASTRID_FSKIT_EXPECTED_VERSION" ]]
  fi
}

check_app_processes() {
  local pid pids
  pids="$(/usr/bin/pgrep -x AstridFS)" || {
    echo "AstridFS is not running at $APP_EXECUTABLE" >&2
    return 1
  }
  while IFS= read -r pid; do
    app_process_matches "$pid" || {
      echo "AstridFS PID $pid does not match $APP_EXECUTABLE, $APP_IDENTIFIER, team $CODE_SIGN_TEAM, and the installed Astrid version" >&2
      return 1
    }
  done <<<"$pids"
  printf 'AstridFS process identity verified: %s\n' "$(printf '%s\n' "$pids" | paste -sd, -)"
}

TRANSACTION_ACTIVE=0
APP_ACTIVATED=0
APP_BACKED_UP=0
COMPANION_ACTIVATED=0
COMPANION_BACKED_UP=0
APP_STAGE=
APP_BACKUP=
APP_TRANSACTION=
COMPANION_STAGE=
COMPANION_BACKUP=
COMPANION_TRANSACTION=
COMPANION_TARGET=

rollback_install() {
  local failed=0
  if [[ "$APP_ACTIVATED" -eq 1 ]]; then
    /bin/rm -rf "$DESTINATION_APP" || failed=1
  fi
  if [[ "$APP_BACKED_UP" -eq 1 ]]; then
    /bin/mv "$APP_BACKUP" "$DESTINATION_APP" || failed=1
  fi
  if [[ "$COMPANION_ACTIVATED" -eq 1 ]]; then
    /bin/rm -f "$COMPANION_TARGET" || failed=1
  fi
  if [[ "$COMPANION_BACKED_UP" -eq 1 ]]; then
    /bin/mv "$COMPANION_BACKUP" "$COMPANION_TARGET" || failed=1
  fi
  if [[ "$failed" -eq 0 ]]; then
    [[ -z "$APP_TRANSACTION" ]] || /bin/rm -rf "$APP_TRANSACTION" || failed=1
    [[ -z "$COMPANION_TRANSACTION" ]] || /bin/rm -rf "$COMPANION_TRANSACTION" || failed=1
  fi
  [[ "$failed" -eq 0 ]]
}

transaction_exit() {
  local status=$?
  trap - EXIT HUP INT TERM
  if [[ "$TRANSACTION_ACTIVE" -eq 1 ]]; then
    if rollback_install; then
      echo "AstridFS update failed; the previous app and companion were restored." >&2
    else
      echo "AstridFS update failed and rollback was incomplete; restore $APP_BACKUP and $COMPANION_BACKUP manually." >&2
    fi
  fi
  exit "$status"
}

install_app() {
  [[ -d "$SOURCE_APP" ]] || {
    echo "missing release app: $SOURCE_APP" >&2
    exit 1
  }
  validate_app "$SOURCE_APP"
  local companion_source
  companion_source="$(companion_path)"
  validate_companion "$companion_source"
  COMPANION_TARGET="$(companion_target)"
  [[ ! -L "$DESTINATION_APP" && ! -L "$COMPANION_TARGET" ]] || {
    echo "refusing to replace a redirected AstridFS app or companion" >&2
    return 1
  }
  local app_parent companion_parent
  app_parent="$(/usr/bin/dirname "$DESTINATION_APP")"
  companion_parent="$(/usr/bin/dirname "$COMPANION_TARGET")"
  /bin/mkdir -p "$app_parent" "$companion_parent"
  APP_TRANSACTION="$(/usr/bin/mktemp -d "$app_parent/.AstridFS.update.XXXXXX")"
  if ! COMPANION_TRANSACTION="$(/usr/bin/mktemp -d "$companion_parent/.astrid-fskit.update.XXXXXX")"; then
    /bin/rm -rf "$APP_TRANSACTION"
    return 1
  fi
  APP_STAGE="$APP_TRANSACTION/new"
  APP_BACKUP="$APP_TRANSACTION/previous"
  COMPANION_STAGE="$COMPANION_TRANSACTION/new"
  COMPANION_BACKUP="$COMPANION_TRANSACTION/previous"
  TRANSACTION_ACTIVE=1
  trap transaction_exit EXIT
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM
  /usr/bin/ditto "$SOURCE_APP" "$APP_STAGE"
  validate_app "$APP_STAGE"
  /usr/bin/install -m 0755 "$companion_source" "$COMPANION_STAGE"
  if [[ -e "$DESTINATION_APP" ]]; then
    /bin/mv "$DESTINATION_APP" "$APP_BACKUP"
    APP_BACKED_UP=1
  fi
  /bin/mv "$APP_STAGE" "$DESTINATION_APP"
  APP_ACTIVATED=1
  validate_app "$DESTINATION_APP"
  if [[ -e "$COMPANION_TARGET" ]]; then
    [[ -f "$COMPANION_TARGET" ]] || {
      echo "existing FSKit companion is not a regular file" >&2
      return 1
    }
    /bin/mv "$COMPANION_TARGET" "$COMPANION_BACKUP"
    COMPANION_BACKED_UP=1
  fi
  /bin/mv "$COMPANION_STAGE" "$COMPANION_TARGET"
  COMPANION_ACTIVATED=1
  [[ -x "$COMPANION_TARGET" ]]

  TRANSACTION_ACTIVE=0
  trap - EXIT HUP INT TERM
  if ! /bin/rm -rf "$APP_TRANSACTION" || ! /bin/rm -rf "$COMPANION_TRANSACTION"; then
    echo "AstridFS was updated, but a previous-version backup could not be removed." >&2
  fi
  return 0
}

case "$COMMAND" in
  install|update)
    install_app
    ;;
  enable)
    validate_app "$DESTINATION_APP"
    open -gj "$DESTINATION_APP"
    for _ in {1..30}; do
      if extension_is_elected && check_app_processes; then
        echo "AstridFS is elected for CLI-controlled mounts."
        exit 0
      fi
      sleep 1
    done
    require_extension_elected
    check_app_processes
    ;;
  check-process)
    validate_app "$DESTINATION_APP"
    check_app_processes
    ;;
  status)
    validate_app "$DESTINATION_APP"
    require_extension_elected
    echo "AstridFS is installed, signed, notarized, and elected at $DESTINATION_APP"
    if /sbin/mount | grep -Fq astridfs; then
      /sbin/mount | grep -F astridfs
    else
      echo "No active astridfs mounts."
    fi
    ;;
  uninstall)
    validate_app "$DESTINATION_APP"
    if /sbin/mount | grep -Fq astridfs; then
      echo "unmount every Astrid filesystem before uninstalling AstridFS" >&2
      exit 1
    fi
    osascript - "$DESTINATION_APP" <<'APPLESCRIPT'
on run arguments
  tell application "Finder" to delete POSIX file (item 1 of arguments)
end run
APPLESCRIPT
    [[ ! -e "$DESTINATION_APP" ]] || {
      echo "AstridFS was not removed" >&2
      exit 1
    }
    rm -f "$(companion_target)"
    ;;
  validate)
    if [[ -d "$DESTINATION_APP" ]]; then
      validate_app "$DESTINATION_APP"
    else
      validate_app "$SOURCE_APP"
    fi
    ;;
  *)
    usage
    exit 2
    ;;
esac
