#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLAUDE_ASTRID="$SCRIPT_DIR/claude-astrid"

pass=0
fail=0
report() {
  if [[ $1 -eq 0 ]]; then
    pass=$((pass + 1))
    echo "  PASS: $2"
  else
    fail=$((fail + 1))
    echo "  FAIL: $2"
  fi
}

echo "=== T1: shell tool roundtrip ==="
out=$("$CLAUDE_ASTRID" -p 'Use the shell.run_shell_command tool to run "echo hello-from-astrid". Print only the tool output, nothing else.' 2>&1) || true
echo "$out" | grep -q "hello-from-astrid"
report $? "shell tool returns expected output"

echo "=== T2: astrid headless mode still works ==="
out=$(astrid -p 'echo' 2>&1) || true
[[ -n "$out" ]]
report $? "astrid -p still runs (any output)"

echo ""
echo "Total: $((pass + fail)). Pass: $pass. Fail: $fail."
exit $fail
