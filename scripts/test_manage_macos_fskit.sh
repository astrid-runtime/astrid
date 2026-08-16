#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != Darwin ]]; then
  echo "macOS FSKit lifecycle tests require macOS" >&2
  exit 1
fi

TEST_ROOT="$(mktemp -d)"
trap 'rm -rf "$TEST_ROOT"' EXIT
RELEASE="$TEST_ROOT/release"
DESTINATION="$TEST_ROOT/Applications/AstridFS.app"
BIN_DIR="$TEST_ROOT/bin"
TARGET="$BIN_DIR/astrid-storage-provider-fskit"
FAILURE_LOG="$TEST_ROOT/companion-failure.log"
/bin/mkdir -p "$RELEASE/macos" "$RELEASE/AstridFS.app" "$DESTINATION" "$BIN_DIR"
/bin/cp scripts/manage-macos-fskit.sh "$RELEASE/macos/manage-macos-fskit.sh"
/bin/chmod 0755 "$RELEASE/macos/manage-macos-fskit.sh"
/usr/bin/printf 'new-app\n' > "$RELEASE/AstridFS.app/version"
/usr/bin/printf 'old-app\n' > "$DESTINATION/version"
/usr/bin/printf 'new-companion\n' > "$RELEASE/astrid-storage-provider-fskit"
/bin/chmod 0755 "$RELEASE/astrid-storage-provider-fskit"
/usr/bin/printf 'old-companion\n' > "$TARGET"
/bin/chmod 0755 "$TARGET"

/bin/cat > "$RELEASE/macos/validate-macos-fskit.sh" <<'VALIDATOR'
#!/usr/bin/env bash
set -euo pipefail
[[ -d "$1" && -f "$1/version" ]]
if [[ "$1" == "$TEST_DESTINATION" && "${TEST_FAIL_COMPANION_ACTIVATION:-0}" == 1 ]]; then
  /usr/bin/find "$(/usr/bin/dirname "$TEST_COMPANION_TARGET")" \
    -path '*/.astrid-fskit.update.*/new' -delete
fi
VALIDATOR
/bin/chmod 0755 "$RELEASE/macos/validate-macos-fskit.sh"

if TEST_DESTINATION="$DESTINATION" \
  TEST_COMPANION_TARGET="$TARGET" \
  TEST_FAIL_COMPANION_ACTIVATION=1 \
  ASTRID_FSKIT_APP_DEST="$DESTINATION" \
  ASTRID_FSKIT_BIN_DIR="$BIN_DIR" \
  "$RELEASE/macos/manage-macos-fskit.sh" update >"$FAILURE_LOG" 2>&1; then
  echo "injected companion activation failure unexpectedly succeeded" >&2
  exit 1
fi
/usr/bin/grep -Fq "the previous app and companion were restored" "$FAILURE_LOG"
[[ "$(<"$DESTINATION/version")" == old-app ]]
[[ "$(<"$TARGET")" == old-companion ]]
[[ -z "$(find "$TEST_ROOT" \( -name '.AstridFS.update.*' -o -name '.astrid-fskit.update.*' \) -print -quit)" ]]

TEST_DESTINATION="$DESTINATION" \
  TEST_COMPANION_TARGET="$TARGET" \
  ASTRID_FSKIT_APP_DEST="$DESTINATION" \
  ASTRID_FSKIT_BIN_DIR="$BIN_DIR" \
  "$RELEASE/macos/manage-macos-fskit.sh" update
[[ "$(<"$DESTINATION/version")" == new-app ]]
[[ "$(<"$TARGET")" == new-companion ]]
[[ -x "$TARGET" ]]
[[ -z "$(find "$TEST_ROOT" \( -name '.AstridFS.update.*' -o -name '.astrid-fskit.update.*' \) -print -quit)" ]]
