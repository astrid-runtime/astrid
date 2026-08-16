#!/usr/bin/env bash

set -euo pipefail

readonly scratch=/tmp/astrid-openapi
mkdir -p "$scratch"
cp crates/astrid-gateway/examples/print-openapi.rs "$scratch/print-openapi.rs"
cp Cargo.lock "$scratch/Cargo.lock"

generate_spec() {
  local ref="$1"
  local out="$2"

  git reset --hard
  git clean -fd -e .openapi-target
  git checkout "$ref"
  mkdir -p crates/astrid-gateway/examples
  cp "$scratch/print-openapi.rs" crates/astrid-gateway/examples/print-openapi.rs
  if [[ ! -f Cargo.lock ]]; then
    cp "$scratch/Cargo.lock" Cargo.lock
  fi

  cargo run --locked -p astrid-gateway --example print-openapi > "$out"
}

generate_spec "$BASE_SHA" "$scratch/base.json"
generate_spec "$HEAD_SHA" "$scratch/head.json"

if diff -u "$scratch/base.json" "$scratch/head.json"; then
  exit 0
fi
if [[ "$OPENAPI_CONTRACT_CHANGE" == "true" ]]; then
  echo "OpenAPI contract changed and was acknowledged by commit marker."
  exit 0
fi
echo "::error::OpenAPI contract changed without an API-CONTRACT-CHANGE: marker in a commit message."
exit 1
