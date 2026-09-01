#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != Darwin ]]; then
  echo "FSKit checks require macOS" >&2
  exit 1
fi

SDK_PATH="$(xcrun --sdk macosx --show-sdk-path)"
SDK_VERSION="$(xcrun --sdk macosx --show-sdk-version)"
if [[ "${SDK_VERSION%%.*}" -lt 26 ]]; then
  echo "Astrid's path-backed FSKit provider requires the macOS 26 SDK" >&2
  exit 1
fi
ARCHS="${ASTRID_FSKIT_ARCHS:-$(uname -m)}"
case "$ARCHS" in
  x86_64|arm64) ;;
  *)
    echo "ASTRID_FSKIT_ARCHS must be x86_64 or arm64" >&2
    exit 2
    ;;
esac

swiftc \
  -typecheck \
  -target "$ARCHS-apple-macosx26.0" \
  -sdk "$SDK_PATH" \
  -parse-as-library \
  native/macos/AstridFSKit/AstridFSAppEx/*.swift

swiftc \
  -typecheck \
  -target "$ARCHS-apple-macosx26.0" \
  -sdk "$SDK_PATH" \
  -parse-as-library \
  native/macos/AstridFSKit/AstridFS/AstridFSApp.swift

plutil -lint \
  native/macos/AstridFSKit/AstridFSAppEx/Info.plist \
  native/macos/AstridFSKit/AstridFSAppEx/AstridFSAppEx.entitlements \
  native/macos/AstridFSKit/AstridFS/AstridFS.entitlements

APP_SOURCE=native/macos/AstridFSKit/AstridFS/AstridFSApp.swift
PROJECT=native/macos/AstridFSKit/AstridFS.xcodeproj/project.pbxproj
grep -Fq 'application.setActivationPolicy(.prohibited)' "$APP_SOURCE"
if grep -RqE 'WindowGroup|MenuBarExtra|NSWindow|NSMenu' native/macos/AstridFSKit/AstridFS; then
  echo "the FSKit containing app must not define a window or menu-bar scene" >&2
  exit 1
fi
if [[ "$(grep -Fc 'INFOPLIST_KEY_LSUIElement = YES;' "$PROJECT")" -ne 2 ]]; then
  echo "both FSKit app configurations must set LSUIElement" >&2
  exit 1
fi

if [[ "${ASTRID_FSKIT_VALIDATE_PROJECT:-0}" == 1 ]]; then
  DERIVED_DATA="${ASTRID_FSKIT_DERIVED_DATA:-${RUNNER_TEMP:-/tmp}/astrid-fskit-derived}"
  ASTRID_VERSION="$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -n 1)"
  SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)" \
    CURRENT_PROJECT_VERSION="$(git rev-list --count HEAD)" \
    MARKETING_VERSION="$ASTRID_VERSION" \
  xcodebuild \
    -project native/macos/AstridFSKit/AstridFS.xcodeproj \
    -scheme AstridFS \
    -configuration Debug \
    -derivedDataPath "$DERIVED_DATA" \
    ARCHS="$ARCHS" \
    ONLY_ACTIVE_ARCH=NO \
    CODE_SIGNING_ALLOWED=NO \
    build
  APP="$DERIVED_DATA/Build/Products/Debug/AstridFS.app"
  EXTENSION="$APP/Contents/Extensions/AstridFSAppEx.appex"
  [[ "$(plutil -extract LSUIElement raw -expect bool "$APP/Contents/Info.plist")" == true ]]
  [[ "$(plutil -extract CFBundleShortVersionString raw -expect string "$APP/Contents/Info.plist")" == "$ASTRID_VERSION" ]]
  [[ "$(plutil -extract CFBundleShortVersionString raw -expect string "$EXTENSION/Contents/Info.plist")" == "$ASTRID_VERSION" ]]
fi
