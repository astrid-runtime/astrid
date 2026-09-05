#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
CHECK_SCRIPT="$REPO_ROOT/scripts/check-macos-fskit.sh"
SANDBOX="$(mktemp -d)"
trap 'rm -rf "$SANDBOX"' EXIT
CAPTURE_FILE="$SANDBOX/xcodebuild.env"
export CAPTURE_FILE

cat > "$SANDBOX/xcodebuild" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail

current_arg=""
marketing_arg=""
derived_data=""
building=false

while (($#)); do
  case "$1" in
    CURRENT_PROJECT_VERSION=*)
      current_arg="${1#*=}"
      ;;
    MARKETING_VERSION=*)
      marketing_arg="${1#*=}"
      ;;
    -derivedDataPath)
      shift
      derived_data="$1"
      ;;
    build)
      building=true
      ;;
  esac
  shift
done

[[ "$building" == true ]]

{
  printf 'CURRENT_PROJECT_VERSION_ARG=%q\n' "$current_arg"
  printf 'MARKETING_VERSION_ARG=%q\n' "$marketing_arg"
  printf 'CURRENT_PROJECT_VERSION_ENV=%q\n' "${CURRENT_PROJECT_VERSION-}"
  printf 'MARKETING_VERSION_ENV=%q\n' "${MARKETING_VERSION-}"
  printf 'SOURCE_DATE_EPOCH_ENV=%q\n' "${SOURCE_DATE_EPOCH-}"
  printf 'SOURCE_DATE_EPOCH_ARG=%q\n' "$(printf '%s\n' "$@" | grep -F 'SOURCE_DATE_EPOCH=' || true)"
} > "$CAPTURE_FILE"

if [[ -z "$marketing_arg" ]]; then
  marketing_arg="${MARKETING_VERSION-}"
fi
if [[ -z "$current_arg" ]]; then
  current_arg="${CURRENT_PROJECT_VERSION-}"
fi

[[ -n "$derived_data" ]]
[[ -n "$current_arg" ]]
[[ -n "$marketing_arg" ]]

app_dir="$derived_data/Build/Products/Debug/AstridFS.app"
extension_dir="$app_dir/Contents/Extensions/AstridFSAppEx.appex"
mkdir -p "$app_dir/Contents/Extensions"

for plist in "$app_dir/Contents/Info.plist" "$extension_dir/Contents/Info.plist"; do
  mkdir -p "$(dirname "$plist")"
  cat > "$plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleShortVersionString</key>
  <string>$marketing_arg</string>
  <key>LSUIElement</key>
  <true/>
</dict>
</plist>
PLIST
done
MOCK
chmod +x "$SANDBOX/xcodebuild"

validation_block="$(awk '/^if \[\[ "\$\{ASTRID_FSKIT_VALIDATE_PROJECT:-0\}" == 1 \]\]; then$/,/^fi$/' "$CHECK_SCRIPT")"
[[ -n "$validation_block" ]]

run_validation() {
  local block="$1"
  (
    export PATH="$SANDBOX:$PATH"
    export ASTRID_FSKIT_VALIDATE_PROJECT=1
    export ASTRID_FSKIT_DERIVED_DATA="$SANDBOX/project-derived"
    unset RUNNER_TEMP
    ARCHS="$(uname -m)"
    cd "$REPO_ROOT"
    eval "$block"
  )
}

settings_are_xcodebuild_args() {
  local capture
  capture="$(cat "$CAPTURE_FILE")"
  eval "$capture"

  [[ -n "$CURRENT_PROJECT_VERSION_ARG" ]]
  [[ -n "$MARKETING_VERSION_ARG" ]]
  [[ -z "$CURRENT_PROJECT_VERSION_ENV" ]]
  [[ -z "$MARKETING_VERSION_ENV" ]]
  [[ -n "$SOURCE_DATE_EPOCH_ENV" ]]
  [[ -z "$SOURCE_DATE_EPOCH_ARG" ]]
}

run_validation "$validation_block"
settings_are_xcodebuild_args

[[ "$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$REPO_ROOT/Cargo.toml" | head -n 1)" == "2026.9.0" ]]
[[ "$(plutil -extract CFBundleShortVersionString raw -expect string \
  "$SANDBOX/project-derived/Build/Products/Debug/AstridFS.app/Contents/Info.plist")" == "2026.9.0" ]]
[[ "$(plutil -extract CFBundleShortVersionString raw -expect string \
  "$SANDBOX/project-derived/Build/Products/Debug/AstridFS.app/Contents/Extensions/AstridFSAppEx.appex/Contents/Info.plist")" == "2026.9.0" ]]

env_only_block="$(printf '%s\n' "$validation_block" |
  perl -0pe 's/^[ \t]+CURRENT_PROJECT_VERSION=.*\\\n//mg;
             s/^[ \t]+MARKETING_VERSION=.*\\\n//mg;
             s/^([ \t]+)xcodebuild \\\n/$1CURRENT_PROJECT_VERSION="$(git rev-list --count HEAD)" \\\n$1MARKETING_VERSION="$ASTRID_VERSION" \\\n$1xcodebuild \\\n/mg')"
[[ "$env_only_block" != "$validation_block" ]]

if run_validation "$env_only_block" && settings_are_xcodebuild_args; then
  echo "regression failed: env-only build settings were accepted" >&2
  exit 1
fi

echo "check-macos-fskit build-settings regression passed"
