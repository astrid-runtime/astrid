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

swiftc \
  -typecheck \
  -target "$(uname -m)-apple-macosx26.0" \
  -sdk "$SDK_PATH" \
  -parse-as-library \
  native/macos/AstridFSKit/AstridFSAppEx/*.swift

plutil -lint \
  native/macos/AstridFSKit/AstridFSAppEx/Info.plist \
  native/macos/AstridFSKit/AstridFSAppEx/AstridFSAppEx.entitlements \
  native/macos/AstridFSKit/AstridFS/AstridFS.entitlements

if [[ "${ASTRID_FSKIT_VALIDATE_PROJECT:-0}" == 1 ]]; then
  DERIVED_DATA="${ASTRID_FSKIT_DERIVED_DATA:-${RUNNER_TEMP:-/tmp}/astrid-fskit-derived}"
  xcodebuild \
    -project native/macos/AstridFSKit/AstridFS.xcodeproj \
    -scheme AstridFS \
    -configuration Debug \
    -derivedDataPath "$DERIVED_DATA" \
    CODE_SIGNING_ALLOWED=NO \
    build
fi
