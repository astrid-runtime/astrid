#!/usr/bin/env bash
set -euo pipefail

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

install_companion() {
  local source target
  source="$(companion_path)"
  target="$(companion_target)"
  if [[ -e "$target" && "$source" -ef "$target" ]]; then
    return
  fi
  mkdir -p "$(dirname "$target")"
  local stage="${target}.new.$$"
  rm -f "$stage"
  if ! install -m 0755 "$source" "$stage"; then
    rm -f "$stage"
    return 1
  fi
  mv -f "$stage" "$target"
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

install_app() {
  [[ -d "$SOURCE_APP" ]] || {
    echo "missing release app: $SOURCE_APP" >&2
    exit 1
  }
  validate_app "$SOURCE_APP"
  mkdir -p "$(dirname "$DESTINATION_APP")"
  local stage backup
  stage="${DESTINATION_APP}.new.$$"
  backup="${DESTINATION_APP}.previous.$$"
  rm -rf "$stage"
  ditto "$SOURCE_APP" "$stage"
  validate_app "$stage"
  if [[ -e "$DESTINATION_APP" ]]; then
    mv "$DESTINATION_APP" "$backup"
    if ! mv "$stage" "$DESTINATION_APP"; then
      mv "$backup" "$DESTINATION_APP"
      exit 1
    fi
    if ! validate_app "$DESTINATION_APP"; then
      rm -rf "$DESTINATION_APP"
      mv "$backup" "$DESTINATION_APP"
      exit 1
    fi
    rm -rf "$backup"
  else
    mv "$stage" "$DESTINATION_APP"
    validate_app "$DESTINATION_APP"
  fi
  install_companion
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
