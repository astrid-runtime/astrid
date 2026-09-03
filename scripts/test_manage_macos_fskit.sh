#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != Darwin ]]; then
  echo "macOS FSKit lifecycle tests require macOS" >&2
  exit 1
fi

TEST_ROOT="$(mktemp -d)"
RELEASE="$TEST_ROOT/release"
DESTINATION="$TEST_ROOT/Applications/AstridFS.app"
BIN_DIR="$TEST_ROOT/bin"
TARGET="$BIN_DIR/astrid-storage-provider-fskit"
AD_HOC_COMPANION="$TEST_ROOT/ad-hoc-companion"
FAILURE_LOG="$TEST_ROOT/companion-failure.log"
/bin/mkdir -p \
  "$RELEASE/macos" \
  "$RELEASE/AstridFS.app/Contents" \
  "$DESTINATION" \
  "$BIN_DIR"

trap '/bin/rm -rf "$TEST_ROOT"' EXIT

/bin/cp scripts/manage-macos-fskit.sh "$RELEASE/macos/manage-macos-fskit.sh"
/bin/chmod 0755 "$RELEASE/macos/manage-macos-fskit.sh"
/bin/cat > "$RELEASE/AstridFS.app/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleShortVersionString</key>
  <string>1.2.3</string>
</dict>
</plist>
PLIST
/usr/bin/plutil -lint "$RELEASE/AstridFS.app/Contents/Info.plist"
/usr/bin/printf 'new-app\n' > "$RELEASE/AstridFS.app/version"
/usr/bin/printf 'old-app\n' > "$DESTINATION/version"
/bin/cat > "$TEST_ROOT/companion.c" <<'C'
#include <stdio.h>

int main(void) {
  (void)puts("{\"protocol_version\":1,\"provider\":{\"name\":\"astrid-storage-provider-fskit\",\"version\":\"1.2.3\"}}");
  return 0;
}
C
/usr/bin/clang -O2 -o "$AD_HOC_COMPANION" "$TEST_ROOT/companion.c"
/usr/bin/codesign --force --identifier org.astrid.runtime.fs.storage-provider-fskit \
  --sign - "$AD_HOC_COMPANION"
/usr/bin/codesign --verify --strict "$AD_HOC_COMPANION"
/usr/bin/printf 'old-companion\n' > "$TARGET"
/bin/chmod 0755 "$TARGET"
/usr/bin/printf 'old-companion\n' > "$RELEASE/astrid-storage-provider-fskit"
/bin/chmod 0755 "$RELEASE/astrid-storage-provider-fskit"

/bin/cat > "$RELEASE/macos/validate-macos-fskit.sh" <<'VALIDATOR'
#!/usr/bin/env bash
set -euo pipefail
[[ -d "$1" && -f "$1/version" ]]
VALIDATOR
/bin/chmod 0755 "$RELEASE/macos/validate-macos-fskit.sh"

assert_unchanged_installation() {
  [[ "$(<"$DESTINATION/version")" == old-app ]]
  [[ "$(<"$TARGET")" == old-companion ]]
}

refuse_update() {
  local description=$1
  if ASTRID_FSKIT_APP_DEST="$DESTINATION" \
    ASTRID_FSKIT_BIN_DIR="$BIN_DIR" \
    "$RELEASE/macos/manage-macos-fskit.sh" update >"$FAILURE_LOG" 2>&1; then
    echo "$description unexpectedly passed lifecycle validation" >&2
    exit 1
  fi
  assert_unchanged_installation
}

if ASTRID_FSKIT_APP_DEST="$DESTINATION" \
  ASTRID_FSKIT_BIN_DIR="$BIN_DIR" \
  "$RELEASE/macos/manage-macos-fskit.sh" update >"$FAILURE_LOG" 2>&1; then
  echo "an unsigned companion unexpectedly passed lifecycle validation" >&2
  exit 1
fi
assert_unchanged_installation

/bin/cp "$AD_HOC_COMPANION" "$RELEASE/astrid-storage-provider-fskit"
# The manager accepts only an Apple-issued 9BDSL5BJAP identity, so local
# coverage stops at rejection; update/rollback proof remains runner-only.
refuse_update "an ad-hoc companion without an Apple team identifier"

/usr/bin/codesign --force --identifier org.astrid.wrong.companion \
  --sign - "$RELEASE/astrid-storage-provider-fskit"
refuse_update "a companion with the wrong identifier"

[[ -z "$(find "$TEST_ROOT" \( -name '.AstridFS.update.*' -o -name '.astrid-fskit.update.*' \) -print -quit)" ]]
