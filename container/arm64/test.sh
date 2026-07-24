#!/usr/bin/env bash
set -euo pipefail

export ASTRID_OCI_TEST_PLATFORM=linux/arm64
export ASTRID_OCI_TEST_ARCHITECTURE=arm64
export ASTRID_OCI_TEST_LABEL=arm64

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(CDPATH='' cd -- "$SCRIPT_DIR/../.." && pwd)
exec "$REPO_ROOT/container/amd64/test.sh" "$@"
