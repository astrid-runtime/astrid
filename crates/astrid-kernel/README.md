# astrid-kernel

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](../../LICENSE-MIT)
[![MSRV: 1.94](https://img.shields.io/badge/MSRV-1.94-blue)](https://www.rust-lang.org)

**The microkernel.**

In the OS model, this is `init`. It boots every subsystem, binds the Unix socket, mounts the VFS overlay, opens the audit log, and starts the IPC bus. No business logic lives here. No cognitive loops, no LLM calls, no tool implementations. The kernel routes bytes between capsules and enforces system-wide invariants. Frontends (CLI, Discord, web) connect over the Unix socket and drive the same `Kernel` instance.

## What it owns

The `Kernel` struct holds every system-wide resource: `EventBus`, `CapsuleRegistry`, `SecureMcpClient`, `CapabilityStore`, `OverlayVfs`, `SurrealKvStore`, `AuditLog`, `AllowanceStore`, `SessionToken`, and an `IdentityStore`. All fields are `pub`. One struct, one owner, no ambient state.

## Boot sequence

`Kernel::new(session_id, workspace_root)` runs the full boot:

1. Resolve `~/.astrid/` (or `$ASTRID_HOME`). Open persistent KV store.
2. Initialize the MCP process manager with workspace-scoped sandboxing.
3. Bootstrap the capability store (ed25519 key pair) and chain-linked audit log.
4. Mount the copy-on-write VFS overlay. Writes land in a session-scoped `TempDir`. The real workspace is read-only until explicit commit.
5. Bind `~/.astrid/run/system.sock` (parent directory 0o700). Generate a 256-bit CSPRNG session token and write it to `~/.astrid/run/system.token` (a 0o600 file).
6. Create the identity store. Bootstrap the CLI root user idempotently.
7. Spawn four background tasks: kernel management router, connection tracker, idle monitor, capsule health monitor.
8. Spawn the `EventDispatcher` to route IPC events to capsule interceptors.

Requires a multi-threaded tokio runtime. The constructor asserts this at the top and panics on single-threaded runtimes because `block_in_place` would deadlock.

## Management API

The kernel router listens on `astrid.v1.request.*` and handles requests like `ListCapsules`, `GetCommands`, `GetCapsuleMetadata`, `ReloadCapsules`, and `InstallCapsule`. Mutating operations are rate-limited with a sliding-window limiter (e.g. `ReloadCapsules` capped at 5/min). Read-only operations are unlimited.

`ApproveCapability` is defined in the protocol but not yet implemented (it returns an error).

## Daemon lifetime

Ephemeral daemons use authenticated client lifecycle leases and shut down when
the final client disconnects. Lease accounting uses a synchronous, non-lossy
observer rather than the bounded broadcast queue used for ordinary events.
Persistent daemons remain running unless the operator explicitly configures
`ASTRID_IDLE_TIMEOUT_SECS`.

## Socket security

- Stale sockets are detected via `connect()` probe. Connection refused = stale, safe to remove. Successful connect = live kernel, boot aborted.
- Symlinks at the socket path are unconditionally removed before bind.
- Socket path length is validated against the platform `sun_path` limit (104 bytes macOS, 108 bytes Linux).
- The session token has no `/tmp` fallback. Writing a secret under a world-listable directory would undermine the authentication it provides.

## Development

```bash
cargo test -p astrid-kernel
```

## License

Dual MIT/Apache-2.0. See [LICENSE-MIT](../../LICENSE-MIT) and [LICENSE-APACHE](../../LICENSE-APACHE).
