# astrid-daemon

[![Crates.io](https://img.shields.io/crates/v/astrid-daemon)](https://crates.io/crates/astrid-daemon)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](../../LICENSE-MIT)
[![MSRV: 1.94](https://img.shields.io/badge/MSRV-1.94-blue)](https://www.rust-lang.org)

**The background kernel process for the Astrid OS.**

In the OS model, this is the kernel running as a daemon. It boots the kernel, loads capsules via auto-discovery, binds a Unix domain socket, and serves IPC requests from frontends (CLI, Discord, web, etc.). All state — sessions, capabilities, audit logs, VFS — lives here.

## How it runs

The daemon is typically spawned automatically by the CLI (`astrid chat` or `astrid start`). It can also be started directly for headless or multi-frontend deployments.

### Spawned by CLI (typical)

```bash
# Ephemeral — auto-shuts down on idle after last client disconnects
astrid

# Persistent — stays running after CLI disconnects
astrid start
```

### Started directly

```bash
# Persistent mode (default)
astrid-daemon --workspace /path/to/project

# Ephemeral mode
astrid-daemon --ephemeral --workspace /path/to/project

# With verbose logging
astrid-daemon --verbose
```

## Flags

| Flag | Default | Description |
|---|---|---|
| `-s, --session <UUID>` | `00000000-...` (system) | Session ID to bind the daemon to |
| `-w, --workspace <PATH>` | Current directory | Workspace root directory |
| `--ephemeral` | `false` | Auto-shutdown on idle after last client disconnects |
| `-v, --verbose` | `false` | Enable debug-level logging |

## Lifecycle

1. Resolves `~/.astrid/` home directory, initializes logging to `~/.astrid/log/`.
2. Boots the kernel: event bus, KV store, capability store, audit log, VFS, MCP servers.
3. Binds Unix socket at `~/.astrid/run/system.sock`, generates session token at `~/.astrid/run/system.token`.
4. Loads all capsules from `~/.astrid/home/{principal}/.local/capsules/` and `.astrid/capsules/` (workspace).
5. Verifies a compatible Unix socket uplink is loaded (required for the socket accept loop).
6. Writes readiness sentinel at `~/.astrid/run/system.ready` — CLI polls for this.
7. Waits for SIGTERM/SIGINT, then shuts down gracefully (drains capsules, cleans up socket/token/readiness files).

## Management API

Frontends send `KernelRequest` messages over the socket to manage the daemon:

| Request | Description |
|---|---|
| `GetStatus` | Returns PID, uptime, connected clients, loaded capsules |
| `Shutdown { reason }` | Graceful shutdown |
| `ListCapsules` | List loaded capsule names |
| `ReloadCapsules` | Hot-reload capsules from disk |
| `GetCommands` | List registered slash commands |
| `GetCapsuleMetadata` | Capsule manifests, providers, interceptors |

## Development

```bash
cargo build -p astrid-daemon
cargo test -p astrid-daemon
```

## License

Dual MIT/Apache-2.0. See [LICENSE-MIT](../../LICENSE-MIT) and [LICENSE-APACHE](../../LICENSE-APACHE).
