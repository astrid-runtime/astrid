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
EXTENSION_PATH="$APP_PATH/Contents/PlugIns/AstridFSAppEx.app"
APP_BINARY="$APP_PATH/Contents/MacOS/AstridFS"
EXTENSION_BINARY="$EXTENSION_PATH/Contents/MacOS/AstridFSAppEx"

[[ -d "$APP_PATH" && -d "$EXTENSION_PATH" ]]
[[ -f "$APP_PATH/Contents/Info.plist" && -f "$EXTENSION_PATH/Contents/Info.plist" ]]
[[ -x "$APP_BINARY" && -x "$EXTENSION_BINARY" ]]

codesign --verify --deep --strict --verbose=2 "$APP_PATH"
codesign --verify --deep --strict --verbose=2 "$EXTENSION_PATH"
ENTITLEMENTS="$(codesign --display --entitlements - "$EXTENSION_PATH" 2>/dev/null)"
grep -Fq "com.apple.developer.fskit.fsmodule" <<<"$ENTITLEMENTS"
xcrun stapler validate "$APP_PATH"
spctl -a -vvv -t exec "$APP_BINARY"
