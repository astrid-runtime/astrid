from __future__ import annotations

import json
import os


PREPARE_ONLY = os.environ.get("PREPARE_ONLY", "")

include = [
    {"target": "x86_64-apple-darwin", "os": "macos-latest", "archive": "tar.gz", "libc": "native"},
    {"target": "aarch64-apple-darwin", "os": "macos-latest", "archive": "tar.gz", "libc": "native"},
]
if PREPARE_ONLY != "true":
    include.extend([
        {"target": "x86_64-pc-windows-msvc", "os": "windows-latest", "archive": "tar.gz", "libc": "native"},
        {"target": "x86_64-unknown-linux-gnu", "os": "ubuntu-latest", "archive": "tar.gz", "libc": "gnu"},
        {"target": "aarch64-unknown-linux-gnu", "os": "ubuntu-latest", "archive": "tar.gz", "libc": "gnu"},
        {"target": "x86_64-unknown-linux-musl", "os": "ubuntu-latest", "archive": "tar.gz", "libc": "musl", "platform": "linux/amd64", "image": "docker.io/library/rust@sha256:e98196986adced5602f6e21c54babdbf2a8700400c7a78868324a3630e0c5d15"},
        {"target": "aarch64-unknown-linux-musl", "os": "ubuntu-24.04-arm", "archive": "tar.gz", "libc": "musl", "platform": "linux/arm64", "image": "docker.io/library/rust@sha256:594694ee6b07747b63b5c265be2616b62e814180b66227e2c18c6ee85e4136be"},
    ])
print(json.dumps({"include": include}, separators=(",", ":")))
