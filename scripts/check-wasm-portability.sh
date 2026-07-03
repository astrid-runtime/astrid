#!/usr/bin/env bash
set -euo pipefail

# Regression guard for the browser host profile: the kernel's pure-semantics
# crates must keep compiling for wasm32-unknown-unknown. This is a compile-only
# check (`cargo check`, no build/test) — it proves the dependency graph and
# feature gating stay wasm-clean without paying the linker cost.
#
# getrandom 0.3/0.4 (reached via uuid/rand/surrealkv) require BOTH the
# `wasm_js` cargo feature (wired in the crates' Cargo.toml under
# `[target.'cfg(target_family = "wasm")'.dependencies]`) AND this build-time
# cfg selecting the browser RNG backend. The cfg is scoped to this script so
# native builds never see it.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

TARGET="wasm32-unknown-unknown"

CRATES=(
  astrid-types
  astrid-core
  astrid-crypto
  astrid-capabilities
  astrid-audit
  astrid-events
  astrid-config
  astrid-approval
)

if ! rustup target list --installed 2>/dev/null | grep -qx "$TARGET"; then
  echo "error: rust target $TARGET is not installed (run: rustup target add $TARGET)" >&2
  exit 1
fi

export RUSTFLAGS='--cfg getrandom_backend="wasm_js"'

for crate in "${CRATES[@]}"; do
  echo "==> cargo check --target $TARGET -p $crate"
  cargo check --target "$TARGET" -p "$crate"
done

echo "All wasm32-unknown-unknown portability checks passed."
