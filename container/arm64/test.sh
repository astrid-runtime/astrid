#!/usr/bin/env bash
set -euo pipefail

export ASTRID_OCI_TEST_PLATFORM=linux/arm64
export ASTRID_OCI_TEST_ARCHITECTURE=arm64
export ASTRID_OCI_TEST_LABEL=arm64

exec container/amd64/test.sh "$@"
