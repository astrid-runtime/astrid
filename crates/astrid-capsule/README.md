# astrid-capsule

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](../../LICENSE-MIT)
[![MSRV: 1.94](https://img.shields.io/badge/MSRV-1.94-blue)](https://www.rust-lang.org)

**The process runtime.**

Capsules are processes in the OS model. This crate reads a `Capsule.toml` manifest, provisions the correct execution engines, enforces per-capsule security boundaries, resolves dependency ordering, and manages the full lifecycle from load to unload. The manifest is the source of truth. No code is required to register tools, interceptors, or cron jobs.

## Three engines, one capsule

A single manifest can run multiple engines simultaneously under one lifecycle:

- **`WasmEngine`** - Extism/Wasmtime sandbox. Full host ABI access via syscalls. 64 MB memory ceiling (1024 WASM pages).
- **`McpHostEngine`** - Native stdio subprocess bridged through `SecureMcpClient`. Binary hash verification, capability gating.
- **`StaticEngine`** - Context files and commands loaded into memory without booting a VM.

The `CompositeCapsule` owns a `Vec<Box<dyn ExecutionEngine>>` and fans lifecycle calls across all engines. Load, unload, tool invocation, interceptor dispatch, and health checks all iterate the engine list.

## Manifest-first security

`ManifestSecurityGate` intercepts every sensitive host call: HTTP requests, filesystem reads/writes, process spawns, socket binds, identity operations. Anything not declared in `[capabilities]` is denied.

The gate resolves VFS scheme prefixes (`cwd://`, `home://`) to canonical physical paths at construction time. Path traversal via `..` is rejected before the check reaches `starts_with`. Wildcard `"*"` in `fs_read`/`fs_write` is confined to the canonical workspace root, so `*` does not mean "the entire filesystem."

Identity operations use a hierarchical capability model: `admin > link > resolve`. Having `"admin"` implies all lower levels.

## Dependency ordering

`toposort_manifests` uses Kahn's algorithm to order capsule loads. Edges are derived from `requires`/`provides` capability declarations, not package names. Capabilities use typed prefixes (`topic:`, `tool:`, `llm:`, `uplink:`) with single-segment wildcard matching (`topic:llm.stream.*` matches `topic:llm.stream.anthropic`).

Unsatisfied requirements are logged as warnings and treated as met. The capsule still loads. Cycles are detected and return a `CycleError` with the involved capsule names.

## Event dispatch

`EventDispatcher` subscribes to the global `EventBus` and routes events to capsule interceptors. Both IPC events (matched by topic) and lifecycle events (matched by `event_type()`) are dispatched. Per-capsule semaphores (default 4 permits) prevent a single capsule from flooding the bus. All dispatch is fire-and-forget.

## File watcher

A hot-reload file watcher exists (`watcher.rs`) that debounces filesystem events and verifies changes via BLAKE3 hashing. It is currently dead code, tracked by #296 for integration into the kernel lifecycle.

## Key types

| Type | Role |
|---|---|
| `CapsuleManifest` | Deserialized `Capsule.toml`. Source of truth for engine provisioning and security. |
| `Capsule` (trait) | Unified interface: `load`, `unload`, `tools`, `invoke_interceptor`, `check_health`. |
| `CompositeCapsule` | Concrete impl. Owns engines, fans out lifecycle calls. |
| `CapsuleLoader` | Factory. Translates manifest + directory into a `CompositeCapsule`. |
| `CapsuleRegistry` | In-memory store indexed by `CapsuleId`. Tracks uplinks and WASM session mappings. |
| `CapsuleSecurityGate` | Trait for gating sensitive host calls. `ManifestSecurityGate` for production. |
| `EventDispatcher` | Subscribes to `EventBus`, routes to interceptors. |

## Development

```bash
cargo test -p astrid-capsule
```

## License

Dual MIT/Apache-2.0. See [LICENSE-MIT](../../LICENSE-MIT) and [LICENSE-APACHE](../../LICENSE-APACHE).
