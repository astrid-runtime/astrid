#!/usr/bin/env bash
# Sync host/astrid-capsule.wit from the canonical unicity-astrid/wit
# submodule (at contracts/) into the kernel's in-tree wit/ directory.
#
# Why this exists: astrid-capsule is published to crates.io.
# wasmtime::component::bindgen!{path: "../../wit"} reads the file at
# build time, and cargo package can only bundle files inside the
# crate's directory tree — so the WIT file has to physically live at
# core/wit/astrid-capsule.wit. The canonical source of truth is
# contracts/host/astrid-capsule.wit; this script copies it across, and
# the wit-sync CI job runs --check on every push to fail on drift.
#
# Usage:
#   scripts/sync-host-wit.sh           # copy submodule → wit/
#   scripts/sync-host-wit.sh --check   # verify in sync, exit 1 if not

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/contracts/host/astrid-capsule.wit"
DST="$ROOT/wit/astrid-capsule.wit"

if [[ ! -f "$SRC" ]]; then
  echo "sync-host-wit: source not found: $SRC" >&2
  echo "sync-host-wit: run 'git submodule update --init --recursive' from the repo root" >&2
  exit 1
fi

if [[ "${1:-}" == "--check" ]]; then
  if ! diff -q "$SRC" "$DST" >/dev/null 2>&1; then
    echo "sync-host-wit: $DST is out of sync with $SRC" >&2
    echo "sync-host-wit: run scripts/sync-host-wit.sh to fix" >&2
    diff "$SRC" "$DST" >&2 || true
    exit 1
  fi
  echo "sync-host-wit: in sync"
  exit 0
fi

cp "$SRC" "$DST"
echo "sync-host-wit: $DST ← $SRC"
