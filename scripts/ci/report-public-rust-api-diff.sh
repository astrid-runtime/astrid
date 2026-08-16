#!/usr/bin/env bash

set -euo pipefail

cat >> "$GITHUB_STEP_SUMMARY" <<'EOF'
### Core Rust API item diff

Core library diffs are report-only because these crates are implementation details whose compatibility requires maintainer judgment. Tool, compiler, and workflow failures remain blocking.
EOF

packages=$(cargo metadata --locked --format-version 1 --no-deps \
  | jq -r '.packages[]
    | select(.publish == null)
    | select(any(.targets[]; any(.kind[]; . == "lib")))
    | [.name, .manifest_path] | @tsv')

while IFS=$'\t' read -r package manifest_path; do
  # A crate introduced by this PR has no manifest at the base SHA;
  # cargo-public-api cannot diff against a baseline where the package does not
  # exist, and the entire API is additive anyway.
  rel_manifest="${manifest_path#"$GITHUB_WORKSPACE/"}"
  if ! git cat-file -e "$BASE_SHA:$rel_manifest" 2>/dev/null; then
    echo "$package is new in this PR (no baseline at $BASE_SHA); skipping diff."
    continue
  fi
  echo "::group::cargo public-api $package"
  cargo +nightly-2026-06-29 public-api \
    --package "$package" \
    --all-features \
    -ss \
    diff \
    --force \
    "$BASE_SHA..HEAD"
  echo "::endgroup::"
done <<< "$packages"
