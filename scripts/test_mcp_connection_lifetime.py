"""Real anonymous transport lifecycle; not authenticated Oracle/tool proof."""
import json
import os
from pathlib import Path
import selectors
import subprocess
import sys
import tempfile
import time

binary = str(Path(sys.argv[1]).resolve())
root = Path(tempfile.mkdtemp(prefix="mcp-life.", dir="/tmp"))
env = os.environ.copy()
for key in list(env):
    if key.startswith("ASTRID_"):
        del env[key]
env["ASTRID_HOME"] = str(root)
clients = []
persistent = os.environ.get("MCP_PROBE_PERSISTENT") == "1"
direct = os.environ.get("MCP_PROBE_DIRECT") == "1"
print("root", root, flush=True)

def call(proc, number, method, params=None):
    message = {"jsonrpc": "2.0", "id": number, "method": method}
    if params is not None:
        message["params"] = params
    proc.stdin.write(json.dumps(message) + "\n")
    proc.stdin.flush()
    with selectors.DefaultSelector() as selector:
        selector.register(proc.stdout, selectors.EVENT_READ)
        if not selector.select(30):
            raise TimeoutError(method)
        line = proc.stdout.readline()
    result = json.loads(line)
    assert result.get("id") == number, result
    # Astrid does not implement ping; its method-not-found reply still proves
    # the same live transport processed this request after the quiet interval.
    assert "error" not in result or (method == "ping" and
        result["error"].get("code") == -32601), result
    print(method, number, "PASS", flush=True)

try:
    subprocess.run([binary, "--principal", "default", "start", *([] if persistent else ["--ephemeral"])],
        cwd=root, env=env, check=True, timeout=60)
    daemon_pid = int((root / "run/system.pid").read_text().splitlines()[0])
    if not direct:
        subprocess.run([binary, "--principal", "anonymous", "mcp", "ready", "--format", "json"],
            cwd=root, env=env, check=True, timeout=60, stdout=subprocess.DEVNULL)
    for session in ("session-one", "session-two"):
        client_env = env | {"ASTRID_SESSION_ID": session, "ASTRID_HOST": "codex"}
        log = (root.parent / (root.name + "-" + session + ".log")).open("w")
        proc = subprocess.Popen([binary, "--principal", "anonymous", "mcp", "serve" if direct else "attach"],
            cwd=root, env=client_env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=log, text=True)
        clients.append(proc)
        call(proc, 1, "initialize", {"protocolVersion": "2026-07-28", "capabilities": {},
            "clientInfo": {"name": session, "version": "1"}})
        proc.stdin.write('{"jsonrpc":"2.0","method":"notifications/initialized"}\n')
        proc.stdin.flush()
    print("two sessions initialized; quiet interval begins", flush=True)
    time.sleep(float(os.environ.get("MCP_PROBE_QUIET_SECONDS", "125")))
    for proc in clients:
        call(proc, 2, "ping")
    clients[0].stdin.close()
    clients[0].wait(timeout=10)
    time.sleep(35)
    call(clients[1], 3, "ping")
    clients[1].stdin.close()
    clients[1].wait(timeout=10)
    if persistent:
        time.sleep(40)
        os.kill(daemon_pid, 0)
        subprocess.run([binary, "--principal", "default", "status"], cwd=root,
            env=env, check=True, timeout=15, stdout=subprocess.DEVNULL)
        print("PASS: explicit persistent daemon survives final MCP disconnect", flush=True)
        sys.exit(0)
    deadline = time.monotonic() + 70
    while time.monotonic() < deadline:
        if sorted(p.name for p in root.iterdir()) == ["astrid.volume"]:
            print("PASS: last session closed, runtime retired to exactly astrid.volume", flush=True)
            break
        time.sleep(1)
    else:
        raise AssertionError([p.name for p in root.iterdir()])
finally:
    for proc in clients:
        if proc.poll() is None:
            proc.terminate()
            proc.wait(timeout=10)
    subprocess.run([binary, "--principal", "default", "stop"], cwd=root, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
