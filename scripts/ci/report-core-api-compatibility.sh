#!/usr/bin/env bash

set -euo pipefail

IFS=',' read -ra excludes <<< "${INTERNAL_EXCLUDES:-}"
exclude_args=()
for package in "${excludes[@]}"; do
  if [[ -n "$package" ]]; then
    exclude_args+=(--exclude "$package")
  fi
done

set +e
cargo semver-checks check-release \
  --manifest-path Cargo.toml \
  --baseline-rev "$BASE_SHA" \
  --all-features \
  "${exclude_args[@]}" 2>&1 | tee internal-semver-checks.log
status=${PIPESTATUS[0]}
set -e

case "$status" in
  0)
    echo "result=success" >> "$GITHUB_OUTPUT"
    ;;
  100)
    echo "result=findings" >> "$GITHUB_OUTPUT"
    echo "::warning title=Core Rust API change::Review the advisory cargo-semver-checks findings. Core library compatibility requires maintainer judgment and is not a merge blocker."
    ;;
  *)
    echo "result=error" >> "$GITHUB_OUTPUT"
    echo "::error title=Internal Rust API check failed::cargo-semver-checks could not complete (exit $status); this is a tool, build, or infrastructure failure, not an advisory API finding."
    exit "$status"
    ;;
esac
