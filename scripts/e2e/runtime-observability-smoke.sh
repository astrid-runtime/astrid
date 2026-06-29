#!/usr/bin/env bash

ASTRID_E2E_LOG_SCAN_LIMIT_BYTES="${ASTRID_E2E_LOG_SCAN_LIMIT_BYTES:-10485760}"

assert_runtime_log_contract() {
  local paths=()
  while (($# > 0)) && [[ "$1" != "--" ]]; do
    paths+=("$1")
    shift
  done
  [[ "${1:-}" == "--" ]] && shift

  "$PYTHON" - "${paths[@]}" -- "$@" <<'PY'
import os
import sys
from pathlib import Path

separator = sys.argv.index("--")
paths = [Path(path) for path in sys.argv[1:separator]]
forbidden_values = [value for value in sys.argv[separator + 1:] if value]
limit = int(os.environ.get("ASTRID_E2E_LOG_SCAN_LIMIT_BYTES", "10485760"))
expected = {"Kernel booted successfully", "astrid-gateway listening"}
forbidden_static = ("DO_NOT_LEAK", "Authorization: Bearer", "session_token")

def log_files():
    for path in paths:
        if path.is_file():
            yield path
        elif path.is_dir():
            for entry in sorted(path.rglob("*")):
                if entry.is_file():
                    yield entry

files = list(log_files())
if not files:
    raise SystemExit(f"daemon logs missing: {[str(path) for path in paths]!r}")

scanned = 0
found = set()
for path in files:
    if path.is_file():
        size = path.stat().st_size
        if scanned + size > limit:
            raise SystemExit(
                f"daemon log scan exceeded {limit} bytes before {path}"
            )
        scanned += size
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                for needle in expected:
                    if needle in line:
                        found.add(needle)
                for needle in forbidden_static:
                    if needle in line:
                        raise SystemExit(f"daemon log leaked sensitive marker: {needle!r}")
                for forbidden in forbidden_values:
                    if forbidden in line:
                        raise SystemExit("daemon log leaked a runtime token or bearer value")

missing = expected - found
if missing:
    raise SystemExit(
        "daemon log missing expected runtime evidence: "
        + ", ".join(repr(item) for item in sorted(missing))
    )
PY
}

if [[ "${1:-}" == "--self-test" ]]; then
  PYTHON="${PYTHON:-python3}"
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  printf 'Kernel booted successfully\n' > "$tmp/daemon.log"
  printf 'astrid-gateway listening\n' > "$tmp/gateway.log"
  ASTRID_E2E_LOG_SCAN_LIMIT_BYTES=4096 assert_runtime_log_contract "$tmp" --

  printf 'Kernel booted successfully\nastrid-gateway listening\n' > "$tmp/too-large.log"
  if ASTRID_E2E_LOG_SCAN_LIMIT_BYTES=8 assert_runtime_log_contract "$tmp" -- 2>/dev/null; then
    echo "expected oversized log scan to fail" >&2
    exit 1
  fi
  echo "self-test passed"
fi
