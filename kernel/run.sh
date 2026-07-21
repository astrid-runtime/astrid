#!/usr/bin/env bash
# Build the ring-0 kernel, wrap it into a UEFI image, boot it under QEMU with
# the frozen machine contract, and assert the serial evidence.
set -euo pipefail
exec cargo run -p ktest --release --manifest-path "$(dirname "$0")/Cargo.toml" "$@"
