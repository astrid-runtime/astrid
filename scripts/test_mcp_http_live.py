#!/usr/bin/env python3
"""Explicit opt-in rehearsal against an installed broker and read-only tool.

Starts only the candidate HTTP frontend, never replaces installed binaries or
plugin configuration. The supplied runtime should already be running. The
operator selects the tool and its arguments; no capsule installation occurs.
"""

import argparse
import concurrent.futures
import json
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import tempfile
import urllib.error
import urllib.request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--runtime-home", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--principal", required=True)
    parser.add_argument("--tool", required=True)
    parser.add_argument("--arguments", default="{}")
    args = parser.parse_args()
    arguments = json.loads(args.arguments)
    env = dict(os.environ, ASTRID_HOME=str(args.runtime_home.resolve()))
    run_dir = Path(env.get("ASTRID_RUN_DIR", args.runtime_home / "run"))
    with socket.socket(socket.AF_UNIX) as probe:
        probe.settimeout(3)
        probe.connect(str(run_dir / "system.sock"))
    with tempfile.TemporaryDirectory(prefix="astrid-http-") as scratch:
        token = secrets.token_hex(32)
        token_path = Path(scratch) / "token"
        token_path.touch(mode=0o600)
        token_path.write_text(token)
        with (Path(scratch) / "server.log").open("w+") as log:
            process = subprocess.Popen([
                str(args.binary.resolve()), "--principal", args.principal,
                "mcp", "http", "--listen", "127.0.0.1:0",
                "--token-file", str(token_path), "--workspace", str(args.workspace.resolve()),
            ], cwd=args.runtime_home, env=env, stdout=log, stderr=subprocess.PIPE, text=True)
            try:
                # A bounded reader prevents a failed startup from hanging CI.
                def ready():
                    output = []
                    for line in process.stderr:
                        output.append(line)
                        match = re.search(r"ready at (http://127\.0\.0\.1:\d+/mcp)", line)
                        if match:
                            return match[1]
                    raise RuntimeError("HTTP startup failed: " + "".join(output)[-2000:])

                executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
                try:
                    url = executor.submit(ready).result(timeout=90)
                finally:
                    executor.shutdown(wait=False)

                def call(method, params, credential=token):
                    params = dict(params, _meta={
                        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                        "io.modelcontextprotocol/clientInfo": {"name": "http-rehearsal", "version": "1"},
                        "io.modelcontextprotocol/clientCapabilities": {},
                    })
                    headers = {
                        "Content-Type": "application/json",
                        "Accept": "application/json, text/event-stream",
                        "Authorization": "Bearer " + credential,
                        "MCP-Protocol-Version": "2026-07-28", "Mcp-Method": method,
                    }
                    if "name" in params:
                        headers["Mcp-Name"] = params["name"]
                    request = urllib.request.Request(url, data=json.dumps({
                        "jsonrpc": "2.0", "id": 1, "method": method, "params": params,
                    }).encode(), headers=headers)
                    with urllib.request.urlopen(request, timeout=65) as response:
                        assert response.headers.get("Mcp-Session-Id") is None
                        result = json.load(response)
                    assert "error" not in result, result
                    return result["result"]

                try:
                    call("tools/list", {}, "wrong")
                    raise AssertionError("wrong bearer accepted")
                except urllib.error.HTTPError as error:
                    assert error.code == 401, error.code
                tools = call("tools/list", {})["tools"]
                assert any(tool["name"] == args.tool for tool in tools), tools
                result = call("tools/call", {"name": args.tool, "arguments": arguments})
                assert not result.get("isError"), result
                assert result.get("content"), result
                print(json.dumps({"principal": args.principal, "tool_count": len(tools),
                                  "tool": args.tool, "result": result}, indent=2))
            finally:
                process.terminate()
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                    raise AssertionError("HTTP frontend did not shut down cleanly")
                process.stderr.close()
                assert process.returncode == 0, f"HTTP shutdown exit: {process.returncode}"


if __name__ == "__main__":
    main()
