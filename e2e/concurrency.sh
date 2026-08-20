#!/usr/bin/env bash
# astrid#1231 — evidence that run-loop workers serve concurrently, and that all
# of them die.
#
# Runs the concurrency fixture twice against an isolated runtime home: once with
# bind_workers=1 (the serial baseline this issue reports) and once with N. The
# fixture blocks WORK_MS per request, so the difference is unmistakable.
#
# Deliberately asserts COMPLETION SPREAD rather than absolute wall-clock: a
# shared runner can be slow without being serial, and "all five finished within
# one request-time of each other" is the property under test.
#
# Usage:  ASTRID_BIN=/path/to/astrid ./e2e/concurrency.sh
set -euo pipefail

PROJECT_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
ASTRID=${ASTRID_BIN:-"$PROJECT_ROOT/target/debug/astrid"}
FIXTURE_DIR="$PROJECT_ROOT/e2e/fixtures/astrid-capsule-concurrency"
PORT=18231
CLIENTS=5
WORK_MS=500

command -v python3 >/dev/null || { echo "concurrency: python3 required" >&2; exit 1; }
[[ -x $ASTRID ]] || { echo "concurrency: no astrid binary at $ASTRID" >&2; exit 1; }

E2E_ROOT=$(mktemp -d /tmp/astrid-concurrency.XXXXXX)
export ASTRID_HOME="$E2E_ROOT/home"
DAEMON_UP=0

cleanup() {
  if [[ $DAEMON_UP == 1 ]]; then "$ASTRID" stop >/dev/null 2>&1 || true; fi
  rm -rf "$E2E_ROOT"
}
trap cleanup EXIT

# Fire CLIENTS connections at once; print each one's elapsed milliseconds.
burst() {
  python3 - "$PORT" "$CLIENTS" <<'PY'
import socket, sys, threading, time
port, n = int(sys.argv[1]), int(sys.argv[2])
out = [None] * n
def one(i):
    t0 = time.monotonic()
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=30)
        s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        while s.recv(4096):
            pass
        s.close()
        out[i] = int((time.monotonic() - t0) * 1000)
    except Exception as e:                      # noqa: BLE001 - reported, not raised
        out[i] = -1
        print(f"client {i} failed: {e}", file=sys.stderr)
threads = [threading.Thread(target=one, args=(i,)) for i in range(n)]
for t in threads: t.start()
for t in threads: t.join()
print(" ".join(str(v) for v in out))
PY
}

run_with_workers() {
  local workers=$1
  rm -rf "$ASTRID_HOME"
  "$ASTRID" start >/dev/null 2>&1
  DAEMON_UP=1
  sleep 1

  # bind_workers comes from the manifest; rewrite it per run so one fixture
  # proves both the baseline and the result.
  sed -i.bak "s/^bind_workers = .*/bind_workers = $workers/" "$FIXTURE_DIR/Capsule.toml"
  "$ASTRID" capsule install "$FIXTURE_DIR" --principal default --yes >/dev/null 2>&1
  sleep 3   # let every worker reach accept()

  burst

  "$ASTRID" stop >/dev/null 2>&1 || true
  DAEMON_UP=0
  sleep 1
}

echo "astrid#1231: serial baseline (bind_workers = 1)"
SERIAL=$(run_with_workers 1)
echo "  elapsed ms: $SERIAL"

echo "astrid#1231: concurrent (bind_workers = $CLIENTS)"
PARALLEL=$(run_with_workers "$CLIENTS")
echo "  elapsed ms: $PARALLEL"

echo "astrid#1231: asserting"
python3 - "$WORK_MS" "$SERIAL" "$PARALLEL" <<'PY'
import sys
work = int(sys.argv[1])
serial = [int(v) for v in sys.argv[2].split()]
parallel = [int(v) for v in sys.argv[3].split()]

assert all(v > 0 for v in serial), f"a baseline client failed: {serial}"
assert all(v > 0 for v in parallel), f"a concurrent client failed: {parallel}"

# Serial: each client waits for those ahead of it, so the spread across
# completions is at least (n-1) request-times.
serial_spread = max(serial) - min(serial)
assert serial_spread >= work, (
    f"baseline did not serialize (spread {serial_spread}ms < {work}ms) — "
    f"the fixture may not be blocking: {serial}"
)

# Concurrent: every client is served at once, so they finish together. One
# request-time of slack absorbs a slow runner without admitting a serial run.
parallel_spread = max(parallel) - min(parallel)
assert parallel_spread < work, (
    f"requests still serialized with concurrent workers "
    f"(spread {parallel_spread}ms >= {work}ms): {parallel}"
)

print(f"  baseline spread   {serial_spread}ms  (>= {work}ms, serialized)")
print(f"  concurrent spread {parallel_spread}ms  (<  {work}ms, parallel)")
PY

echo "astrid#1231: asserting every worker died"
# The daemon is stopped. If any worker survived it still holds the shared
# listener and still ACCEPTS — the failure mode that matters, because a stale
# worker keeps serving with whatever policy it last loaded.
#
# Tested by connecting, not by binding. A bind probe is confounded by TIME_WAIT:
# the client connections above leave lingering entries for ~30-60s, so a bind
# without SO_REUSEADDR fails on a port that has no listener at all. "Is anything
# still serving?" is the actual property, and a refused connect answers it.
sleep 2
if python3 -c "
import socket, sys
try:
    socket.create_connection(('127.0.0.1', $PORT), timeout=2).close()
    sys.exit(1)          # something accepted — a worker is still alive
except (ConnectionRefusedError, socket.timeout, OSError):
    sys.exit(0)          # refused — nothing is listening
"; then
  echo "  connect refused on $PORT — no worker survived the stop"
else
  echo "  FAIL: something still accepts on $PORT after daemon stop" >&2
  exit 1
fi

git -C "$PROJECT_ROOT" checkout -- "$FIXTURE_DIR/Capsule.toml" 2>/dev/null || true
rm -f "$FIXTURE_DIR/Capsule.toml.bak"
echo "astrid#1231: PASS"
