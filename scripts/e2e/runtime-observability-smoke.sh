#!/usr/bin/env bash

assert_runtime_log_contract() {
  local daemon_log=$1
  shift

  "$PYTHON" - "$daemon_log" "$@" <<'PY'
import sys
from pathlib import Path

log = Path(sys.argv[1])
if not log.exists():
    raise SystemExit(f"daemon log missing: {log}")

text = log.read_text(encoding="utf-8", errors="replace")
for needle in ("Kernel booted successfully", "astrid-gateway listening"):
    if needle not in text:
        raise SystemExit(f"daemon log missing expected runtime evidence: {needle!r}")

for needle in ("DO_NOT_LEAK", "Authorization: Bearer", "session_token"):
    if needle in text:
        raise SystemExit(f"daemon log leaked sensitive marker: {needle!r}")

for forbidden in [value for value in sys.argv[2:] if value]:
    if forbidden in text:
        raise SystemExit("daemon log leaked a runtime token or bearer value")
PY
}
