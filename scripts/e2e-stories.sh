#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

printf '%s\n' \
  "scripts/e2e-stories.sh is a compatibility wrapper; running scripts/e2e/runtime-harness.sh" \
  >&2

exec "$SCRIPT_DIR/e2e/runtime-harness.sh" "$@"
