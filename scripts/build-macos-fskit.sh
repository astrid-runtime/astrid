#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != Darwin ]]; then
  echo "FSKit app builds require macOS" >&2
  exit 1
fi

: "${ASTRID_FSKIT_DEVELOPMENT_TEAM:?set ASTRID_FSKIT_DEVELOPMENT_TEAM to the Apple team identifier}"

OUTPUT_ROOT="${ASTRID_FSKIT_OUTPUT_ROOT:-$PWD/target/macos-fskit}"
CONFIGURATION="${ASTRID_FSKIT_CONFIGURATION:-Release}"

scripts/check-macos-fskit.sh
mkdir -p "$OUTPUT_ROOT"

xcodebuild \
  -project native/macos/AstridFSKit/AstridFS.xcodeproj \
  -scheme AstridFS \
  -configuration "$CONFIGURATION" \
  -derivedDataPath "$OUTPUT_ROOT/DerivedData" \
  DEVELOPMENT_TEAM="$ASTRID_FSKIT_DEVELOPMENT_TEAM" \
  CODE_SIGN_STYLE=Automatic \
  build

APP_PATH="$OUTPUT_ROOT/DerivedData/Build/Products/$CONFIGURATION/AstridFS.app"
if [[ ! -d "$APP_PATH" ]]; then
  echo "signed FSKit app was not produced at $APP_PATH" >&2
  exit 1
fi

codesign --verify --deep --strict "$APP_PATH"
echo "$APP_PATH"
