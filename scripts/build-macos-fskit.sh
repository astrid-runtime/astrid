#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != Darwin ]]; then
  echo "FSKit app builds require macOS" >&2
  exit 1
fi

: "${ASTRID_FSKIT_DEVELOPMENT_TEAM:?set ASTRID_FSKIT_DEVELOPMENT_TEAM to the Apple team identifier}"
CODE_SIGN_IDENTITY="${ASTRID_FSKIT_CODE_SIGN_IDENTITY:-Developer ID Application}"

OUTPUT_ROOT="${ASTRID_FSKIT_OUTPUT_ROOT:-$PWD/target/macos-fskit}"
CONFIGURATION="${ASTRID_FSKIT_CONFIGURATION:-Release}"
SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)"
BUILD_VERSION="$(git rev-list --count HEAD)"
ARCHS="${ASTRID_FSKIT_ARCHS:-$(uname -m)}"

scripts/check-macos-fskit.sh
mkdir -p "$OUTPUT_ROOT"
DERIVED_DATA="$OUTPUT_ROOT/DerivedData"
rm -rf "$DERIVED_DATA"

SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
xcodebuild \
  -project native/macos/AstridFSKit/AstridFS.xcodeproj \
  -scheme AstridFS \
  -configuration "$CONFIGURATION" \
  -derivedDataPath "$DERIVED_DATA" \
  DEVELOPMENT_TEAM="$ASTRID_FSKIT_DEVELOPMENT_TEAM" \
  CODE_SIGN_IDENTITY="$CODE_SIGN_IDENTITY" \
  CODE_SIGN_STYLE=Manual \
  CURRENT_PROJECT_VERSION="$BUILD_VERSION" \
  ARCHS="$ARCHS" \
  ONLY_ACTIVE_ARCH=NO \
  COMPILER_INDEX_STORE_ENABLE=NO \
  OTHER_CODE_SIGN_FLAGS="--timestamp --options runtime" \
  build

APP_PATH="$OUTPUT_ROOT/DerivedData/Build/Products/$CONFIGURATION/AstridFS.app"
if [[ ! -d "$APP_PATH" ]]; then
  echo "signed FSKit app was not produced at $APP_PATH" >&2
  exit 1
fi

EXTENSION_PATH="$APP_PATH/Contents/Extensions/AstridFSAppEx.appex"
if [[ ! -d "$EXTENSION_PATH" ]]; then
  echo "FSKit app extension was not produced at $EXTENSION_PATH" >&2
  exit 1
fi

APP_BINARY="$APP_PATH/Contents/MacOS/AstridFS"
EXTENSION_BINARY="$EXTENSION_PATH/Contents/MacOS/AstridFSAppEx"
APP_VERSION="$(plutil -extract CFBundleVersion raw -expect string "$APP_PATH/Contents/Info.plist")"
EXTENSION_VERSION="$(plutil -extract CFBundleVersion raw -expect string "$EXTENSION_PATH/Contents/Info.plist")"
if [[ "$APP_VERSION" != "$BUILD_VERSION" || "$EXTENSION_VERSION" != "$BUILD_VERSION" ]]; then
  echo "FSKit bundle versions do not match source revision" >&2
  exit 1
fi
APP_ARCHITECTURES="$(lipo -archs "$APP_BINARY")"
EXTENSION_ARCHITECTURES="$(lipo -archs "$EXTENSION_BINARY")"
if [[ "$APP_ARCHITECTURES" != "$ARCHS" || "$EXTENSION_ARCHITECTURES" != "$ARCHS" ]]; then
  echo "FSKit bundle architectures do not match $ARCHS" >&2
  exit 1
fi

codesign --verify --deep --strict --verbose=2 "$APP_PATH"
codesign --verify --deep --strict --verbose=2 "$EXTENSION_PATH"
ENTITLEMENTS="$(codesign --display --entitlements - "$EXTENSION_PATH" 2>/dev/null || true)"
if ! grep -Fq "com.apple.developer.fskit.fsmodule" <<<"$ENTITLEMENTS"; then
  echo "FSKit extension lacks the required fskit.fsmodule entitlement" >&2
  exit 1
fi

if [[ "${ASTRID_FSKIT_NOTARIZE:-0}" == 1 ]]; then
  NOTARY_ZIP="$OUTPUT_ROOT/AstridFS-notary.zip"
  ditto -c -k --keepParent "$APP_PATH" "$NOTARY_ZIP"
  if [[ -n "${ASTRID_FSKIT_NOTARY_PROFILE:-}" ]]; then
    xcrun notarytool submit "$NOTARY_ZIP" \
      --keychain-profile "$ASTRID_FSKIT_NOTARY_PROFILE" --wait
  elif [[ -n "${ASTRID_FSKIT_NOTARY_KEY_PATH:-}" ]]; then
    : "${ASTRID_FSKIT_NOTARY_KEY_ID:?set ASTRID_FSKIT_NOTARY_KEY_ID}"
    : "${ASTRID_FSKIT_NOTARY_ISSUER_ID:?set ASTRID_FSKIT_NOTARY_ISSUER_ID}"
    xcrun notarytool submit "$NOTARY_ZIP" \
      --key "$ASTRID_FSKIT_NOTARY_KEY_PATH" \
      --key-id "$ASTRID_FSKIT_NOTARY_KEY_ID" \
      --issuer "$ASTRID_FSKIT_NOTARY_ISSUER_ID" --wait
  else
    echo "notarization requested but no keychain profile or API key was supplied" >&2
    exit 1
  fi
  xcrun stapler staple "$APP_PATH"
  xcrun stapler validate "$APP_PATH"
  rm -f "$NOTARY_ZIP"
fi

echo "$APP_PATH"
