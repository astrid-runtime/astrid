#!/usr/bin/env bash
set -euo pipefail
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH

usage() {
  cat >&2 <<'EOF'
usage: manage-macos-fskit.sh install|update|enable|status|uninstall|validate
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

companion_path() {
  if [[ -x "$RELEASE_ROOT/astrid-storage-provider-fskit" ]]; then
    printf '%s\n' "$RELEASE_ROOT/astrid-storage-provider-fskit"
    return
  fi
  local companion
  companion="$(command -v astrid-storage-provider-fskit || true)"
  [[ -n "$companion" && -x "$companion" ]] || {
    echo "missing co-installed astrid-storage-provider-fskit" >&2
    return 1
  }
  printf '%s\n' "$companion"
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
    open "$DESTINATION_APP"
    echo "AstridFS launched. Enable AstridFS in System Settings when macOS prompts you."
    ;;
  status)
    validate_app "$DESTINATION_APP"
    echo "AstridFS is installed, signed, and notarized at $DESTINATION_APP"
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
