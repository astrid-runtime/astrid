# astrid-cli

[![Crates.io](https://img.shields.io/crates/v/astrid-cli)](https://crates.io/crates/astrid-cli)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](../../LICENSE-MIT)
[![MSRV: 1.94](https://img.shields.io/badge/MSRV-1.94-blue)](https://www.rust-lang.org)

**The terminal frontend for the Astrid OS.**

In the OS model, this is a shell. It does not run agents, call LLMs, enforce security policy, or own state. It spawns the kernel daemon as a background process, connects over a Unix domain socket, and renders streaming events in a ratatui TUI. Kill the CLI. Reconnect. Pick up where you left off. The daemon owns the session. The CLI is disposable.

## Architecture

Three companion binaries work together:

| Binary | Crate | Role |
|---|---|---|
| `astrid` | astrid-cli | Terminal frontend (TUI, REPL, capsule management) |
| `astrid-daemon` | astrid-daemon | Background kernel process (boots kernel, loads capsules, serves IPC) |
| `astrid-build` | astrid-build | Capsule compiler and packager (Rust, MCP) |

The CLI discovers companion binaries in the same directory as itself, falling back to `PATH`. It never links the kernel directly — all communication is over the Unix domain socket via length-prefixed JSON.

## Quick start

```bash
cargo install --path crates/astrid-cli
cargo install --path crates/astrid-daemon
cargo install --path crates/astrid-build

astrid init
astrid chat
```

## Commands

### Chat & sessions

| Command | Description |
|---|---|
| `astrid` | Start an interactive chat session (default command) |
| `astrid chat` | Same as above. `--session <UUID>` to resume a specific session. |
| `astrid session list` | List persisted sessions |
| `astrid session info <ID>` | Show session details |
| `astrid session delete <ID>` | Delete a session |

### Daemon lifecycle

| Command | Description |
|---|---|
| `astrid start` | Start a persistent daemon (detached, no TUI). Survives CLI disconnect. |
| `astrid status` | Show daemon PID, uptime, connected clients, loaded capsules. |
| `astrid stop` | Gracefully shut down the running daemon. |

When you run `astrid chat` without a running daemon, an **ephemeral** daemon is spawned automatically. It shuts down on idle after the last client disconnects. Use `astrid start` for a persistent daemon that serves multiple frontends (CLI, Discord, web).

### Capsule management

| Command | Description |
|---|---|
| `astrid capsule install <source>` | Install from local path, GitHub URL, or registry. `--workspace` for workspace-level. |
| `astrid capsule update [target]` | Update one or all capsules from their original source. |
| `astrid capsule list` | List installed capsules with capability metadata. `-v` for full details. |
| `astrid capsule deps` | Print the capsule dependency graph. |

### Build & init

| Command | Description |
|---|---|
| `astrid build [path]` | Compile and package a capsule. Delegates to `astrid-build`. |
| `astrid init` | Initialize a workspace in the current directory. |

## Daemon connection flow

1. Check for existing daemon (socket probe at `~/.astrid/run/system.sock`)
2. If running → connect and perform handshake
3. If not running → spawn `astrid-daemon --ephemeral`, poll readiness sentinel, connect
4. If stale socket (connection refused) → clean up, respawn

## Global flags

| Flag | Description |
|---|---|
| `-v, --verbose` | Enable debug-level logging |
| `--format json` | Switch to NDJSON output for scripting. Interactive prompts are auto-denied. |

## Development

```bash
cargo test -p astrid-cli
```

## License

Dual MIT/Apache-2.0. See [LICENSE-MIT](../../LICENSE-MIT) and [LICENSE-APACHE](../../LICENSE-APACHE).
