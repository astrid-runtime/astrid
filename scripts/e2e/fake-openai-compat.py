#!/usr/bin/env python3
"""Tiny OpenAI-compatible test server for Astrid runtime e2e.

It implements only the protocol surface Astrid needs in CI:

- GET /v1/models
- POST /v1/chat/completions
- streaming SSE chat completions
- JSONL request logging with authorization headers redacted

The server binds loopback only by default and prints its selected port to
stdout as `PORT=<port>` so shell harnesses can allocate port 0 safely.
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


MODELS = [
    {"id": "fake-echo", "object": "model", "owned_by": "astrid-e2e"},
    {"id": "fake-slow", "object": "model", "owned_by": "astrid-e2e"},
    {"id": "fake-timeout", "object": "model", "owned_by": "astrid-e2e"},
    {"id": "fake-error", "object": "model", "owned_by": "astrid-e2e"},
    {"id": "fake-malformed", "object": "model", "owned_by": "astrid-e2e"},
    {"id": "fake-toolish", "object": "model", "owned_by": "astrid-e2e"},
    {"id": "duplicate-name", "object": "model", "owned_by": "astrid-e2e-a"},
    {"id": "duplicate-name", "object": "model", "owned_by": "astrid-e2e-b"},
]


class State:
    def __init__(self, log_path: Path) -> None:
        self.log_path = log_path
        self.lock = threading.Lock()
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, entry: dict[str, Any]) -> None:
        line = json.dumps(entry, sort_keys=True) + "\n"
        with self.lock:
            with self.log_path.open("a", encoding="utf-8") as handle:
                handle.write(line)


def redact_headers(handler: BaseHTTPRequestHandler) -> dict[str, str]:
    headers: dict[str, str] = {}
    for key, value in handler.headers.items():
        if key.lower() == "authorization":
            headers[key] = "<redacted>"
        else:
            headers[key] = value
    return headers


class Handler(BaseHTTPRequestHandler):
    server_version = "AstridFakeOpenAI/1.0"

    @property
    def state(self) -> State:
        return self.server.state  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args: Any) -> None:
        sys.stderr.write("fake-openai: " + fmt % args + "\n")

    def do_GET(self) -> None:
        if self.path == "/v1/models":
            models = MODELS
        elif self.path == "/empty-models/v1/models":
            models = []
        else:
            self.send_error(404, "not found")
            return

        self.state.log(
            {
                "method": "GET",
                "path": self.path,
                "headers": redact_headers(self),
                "model_count": len(models),
            }
        )
        self.send_json({"object": "list", "data": models})

    def do_POST(self) -> None:
        if self.path != "/v1/chat/completions":
            self.send_error(404, "not found")
            return

        raw = self.rfile.read(int(self.headers.get("content-length", "0") or "0"))
        try:
            body = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            self.send_error(400, "invalid JSON")
            return

        model = str(body.get("model") or "fake-echo")
        self.state.log(
            {
                "method": "POST",
                "path": self.path,
                "headers": redact_headers(self),
                "model": model,
                "stream": bool(body.get("stream")),
                "messages": body.get("messages", []),
            }
        )

        if model == "fake-error":
            self.send_json({"error": {"message": "fake upstream error"}}, status=502)
            return
        if model == "fake-malformed":
            self.send_response(200)
            self.send_header("content-type", "text/event-stream")
            self.end_headers()
            self.wfile.write(b"data: {not-json}\n\n")
            self.wfile.flush()
            return
        if model == "fake-timeout":
            self.send_response(200)
            self.send_header("content-type", "text/event-stream")
            self.send_header("cache-control", "no-cache")
            self.end_headers()
            time.sleep(6)
            return

        if bool(body.get("stream")):
            self.send_stream(model, body)
            return

        self.send_json(
            {
                "id": "chatcmpl-fake",
                "object": "chat.completion",
                "model": model,
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": completion_text(model, body),
                        },
                        "finish_reason": "stop",
                    }
                ],
            }
        )

    def send_json(self, value: Any, status: int = 200) -> None:
        payload = json.dumps(value).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def send_stream(self, model: str, body: dict[str, Any]) -> None:
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.send_header("cache-control", "no-cache")
        self.end_headers()

        if model == "fake-slow":
            time.sleep(2)

        for token in completion_text(model, body).split(" "):
            event = {
                "id": "chatcmpl-fake",
                "object": "chat.completion.chunk",
                "model": model,
                "choices": [
                    {
                        "index": 0,
                        "delta": {"content": token + " "},
                        "finish_reason": None,
                    }
                ],
            }
            self.wfile.write(b"data: " + json.dumps(event).encode("utf-8") + b"\n\n")
            self.wfile.flush()
        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()


def completion_text(model: str, body: dict[str, Any]) -> str:
    messages = body.get("messages") or []
    last = ""
    if isinstance(messages, list) and messages:
        content = messages[-1].get("content", "")
        if isinstance(content, str):
            last = content
    if model == "fake-toolish":
        return '{"tool_calls":[{"name":"fake_tool","arguments":{"echo":true}}]}'
    return f"fake echo: {last}".strip()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--log", required=True, type=Path)
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    server.state = State(args.log)  # type: ignore[attr-defined]
    print(f"PORT={server.server_address[1]}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
