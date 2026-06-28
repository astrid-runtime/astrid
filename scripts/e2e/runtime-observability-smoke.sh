#!/usr/bin/env bash

assert_runtime_log_contract() {
  local paths=()
  while (($# > 0)) && [[ "$1" != "--" ]]; do
    paths+=("$1")
    shift
  done
  [[ "${1:-}" == "--" ]] && shift

  "$PYTHON" - "${paths[@]}" -- "$@" <<'PY'
import sys
from pathlib import Path

separator = sys.argv.index("--")
paths = [Path(path) for path in sys.argv[1:separator]]
forbidden_values = [value for value in sys.argv[separator + 1:] if value]

chunks = []
for path in paths:
    if path.is_file():
        chunks.append(path.read_text(encoding="utf-8", errors="replace"))
    elif path.is_dir():
        for entry in sorted(path.rglob("*")):
            if entry.is_file():
                chunks.append(entry.read_text(encoding="utf-8", errors="replace"))

if not chunks:
    raise SystemExit(f"daemon logs missing: {[str(path) for path in paths]!r}")

text = "\n".join(chunks)
for needle in ("Kernel booted successfully", "astrid-gateway listening"):
    if needle not in text:
        raise SystemExit(f"daemon log missing expected runtime evidence: {needle!r}")

for needle in ("DO_NOT_LEAK", "Authorization: Bearer", "session_token"):
    if needle in text:
        raise SystemExit(f"daemon log leaked sensitive marker: {needle!r}")

for forbidden in forbidden_values:
    if forbidden in text:
        raise SystemExit("daemon log leaked a runtime token or bearer value")
PY
}
