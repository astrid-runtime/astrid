#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != Darwin ]]; then
  echo "FSKit artifacts can be validated only on macOS" >&2
  exit 1
fi

if [[ $# -ne 1 ]]; then
  echo "usage: $0 AstridFS.app" >&2
  exit 2
fi

APP_PATH=$1
EXTENSION_PATH="$APP_PATH/Contents/Extensions/AstridFSAppEx.appex"
APP_BINARY="$APP_PATH/Contents/MacOS/AstridFS"
EXTENSION_BINARY="$EXTENSION_PATH/Contents/MacOS/AstridFSAppEx"
APP_IDENTIFIER=org.astrid.runtime.fs
EXTENSION_IDENTIFIER=org.astrid.runtime.fs.AppEx
CODE_SIGN_TEAM=9BDSL5BJAP

[[ -d "$APP_PATH" && -d "$EXTENSION_PATH" ]]
[[ -f "$APP_PATH/Contents/Info.plist" && -f "$EXTENSION_PATH/Contents/Info.plist" ]]
[[ -x "$APP_BINARY" && -x "$EXTENSION_BINARY" ]]

[[ "$(plutil -extract CFBundleIdentifier raw -expect string "$APP_PATH/Contents/Info.plist")" == "$APP_IDENTIFIER" ]]
[[ "$(plutil -extract CFBundleIdentifier raw -expect string "$EXTENSION_PATH/Contents/Info.plist")" == "$EXTENSION_IDENTIFIER" ]]
[[ "$(plutil -extract LSUIElement raw -expect bool "$APP_PATH/Contents/Info.plist")" == true ]]
APP_VERSION="$(plutil -extract CFBundleVersion raw -expect string "$APP_PATH/Contents/Info.plist")"
EXTENSION_VERSION="$(plutil -extract CFBundleVersion raw -expect string "$EXTENSION_PATH/Contents/Info.plist")"
APP_RELEASE_VERSION="$(plutil -extract CFBundleShortVersionString raw -expect string "$APP_PATH/Contents/Info.plist")"
EXTENSION_RELEASE_VERSION="$(plutil -extract CFBundleShortVersionString raw -expect string "$EXTENSION_PATH/Contents/Info.plist")"
[[ -n "$APP_VERSION" && "$APP_VERSION" == "$EXTENSION_VERSION" ]]
[[ -n "$APP_RELEASE_VERSION" && "$APP_RELEASE_VERSION" == "$EXTENSION_RELEASE_VERSION" ]]
if [[ -n "${ASTRID_FSKIT_EXPECTED_VERSION:-}" && "$APP_RELEASE_VERSION" != "$ASTRID_FSKIT_EXPECTED_VERSION" ]]; then
  echo "AstridFS version $APP_RELEASE_VERSION does not match expected Astrid $ASTRID_FSKIT_EXPECTED_VERSION" >&2
  exit 1
fi

codesign --verify --deep --strict --verbose=2 "$APP_PATH"
codesign --verify --deep --strict --verbose=2 "$EXTENSION_PATH"
signature="$(codesign --display --verbose=4 "$APP_PATH" 2>&1)"
grep -Fx "Identifier=$APP_IDENTIFIER" <<<"$signature" >/dev/null
grep -Fx "TeamIdentifier=$CODE_SIGN_TEAM" <<<"$signature" >/dev/null
signature="$(codesign --display --verbose=4 "$EXTENSION_PATH" 2>&1)"
grep -Fx "Identifier=$EXTENSION_IDENTIFIER" <<<"$signature" >/dev/null
grep -Fx "TeamIdentifier=$CODE_SIGN_TEAM" <<<"$signature" >/dev/null
ENTITLEMENTS="$(codesign --display --entitlements - "$EXTENSION_PATH" 2>/dev/null)"
grep -Fq "com.apple.developer.fskit.fsmodule" <<<"$ENTITLEMENTS"
xcrun stapler validate "$APP_PATH"
spctl -a -vvv -t exec "$APP_PATH"
