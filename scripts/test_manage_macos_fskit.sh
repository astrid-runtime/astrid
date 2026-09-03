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
FAKE_PLUGINKIT="$TEST_ROOT/pluginkit"
FAKE_PGREP="$TEST_ROOT/pgrep"
BASH_ENV_FILE="$TEST_ROOT/bash-env"
/bin/mkdir -p \
  "$RELEASE/macos" \
  "$RELEASE/AstridFS.app/Contents" \
  "$DESTINATION/Contents/Extensions/AstridFSAppEx.appex/Contents" \
  "$BIN_DIR"

trap '/bin/rm -rf "$TEST_ROOT"' EXIT

/bin/cp scripts/manage-macos-fskit.sh "$RELEASE/macos/manage-macos-fskit.sh"
/bin/chmod 0755 "$RELEASE/macos/manage-macos-fskit.sh"
/bin/cat > "$FAKE_PLUGINKIT" <<'PLUGINKIT'
#!/usr/bin/env bash
set -euo pipefail
printf '+    org.astrid.runtime.fs.AppEx(%s)\tignored\tignored\t%s\n' \
  "${ASTRID_TEST_PLUGINKIT_VERSION:?}" "${ASTRID_TEST_PLUGINKIT_PATH:?}"
PLUGINKIT
/bin/chmod 0755 "$FAKE_PLUGINKIT"
/bin/cat > "$FAKE_PGREP" <<'PGREP'
#!/usr/bin/env bash
exit 1
PGREP
/bin/chmod 0755 "$FAKE_PGREP"
/bin/cat > "$BASH_ENV_FILE" <<'BASH_ENV'
open() { :; }
sleep() { :; }
BASH_ENV

# Exercise the manager's real PlugInKit parser with a deterministic temporary
# record. The command copy keeps all production paths intact while redirecting
# only the host tools that would otherwise require a live FSKit installation.
/usr/bin/sed \
  -e "s|/usr/bin/pluginkit|$FAKE_PLUGINKIT|g" \
  -e "s|/usr/bin/pgrep|$FAKE_PGREP|g" \
  -e 's|for _ in {1..30}|for _ in {1..1}|' \
  "$RELEASE/macos/manage-macos-fskit.sh" > "$TEST_ROOT/manage-macos-fskit.sh"
/bin/mv "$TEST_ROOT/manage-macos-fskit.sh" "$RELEASE/macos/manage-macos-fskit.sh"
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
/bin/cat > "$DESTINATION/Contents/Extensions/AstridFSAppEx.appex/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleShortVersionString</key>
  <string>1.0</string>
  <key>CFBundleVersion</key>
  <string>600</string>
</dict>
</plist>
PLIST
/usr/bin/plutil -lint "$DESTINATION/Contents/Extensions/AstridFSAppEx.appex/Contents/Info.plist"
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

if ASTRID_TEST_PLUGINKIT_VERSION=600 \
  ASTRID_TEST_PLUGINKIT_PATH="$DESTINATION/Contents/Extensions/AstridFSAppEx.appex" \
  ASTRID_FSKIT_APP_DEST="$DESTINATION" \
  BASH_ENV="$BASH_ENV_FILE" \
  "$RELEASE/macos/manage-macos-fskit.sh" status >"$FAILURE_LOG" 2>&1; then
  echo "a PlugInKit build-version parenthetical unexpectedly passed election validation" >&2
  exit 1
fi
/usr/bin/grep -Fq "has not elected" "$FAILURE_LOG" || {
  echo "build-version parenthetical refusal did not explain the election mismatch" >&2
  exit 1
}

if ASTRID_TEST_PLUGINKIT_VERSION=1.0 \
  ASTRID_TEST_PLUGINKIT_PATH="$DESTINATION/Contents/Extensions/AstridFSAppEx.appex" \
  ASTRID_FSKIT_APP_DEST="$DESTINATION" \
  BASH_ENV="$BASH_ENV_FILE" \
  "$RELEASE/macos/manage-macos-fskit.sh" enable >"$FAILURE_LOG" 2>&1; then
  echo "enable unexpectedly passed without a bound AstridFS process" >&2
  exit 1
fi
/usr/bin/grep -Fq "AstridFS is not running at" "$FAILURE_LOG" || {
  echo "enable without a bound process did not fail closed" >&2
  exit 1
}

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
