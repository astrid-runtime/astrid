# astrid-capabilities

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](../../LICENSE-MIT)
[![MSRV: 1.94](https://img.shields.io/badge/MSRV-1.94-blue)](https://www.rust-lang.org)

**The agent cannot forge the token. It cannot replay an old one. It cannot talk its way past the check.**

In the OS model, capability tokens are the kernel's access control mechanism. An agent that wants to call `mcp://filesystem:read_file` needs a signed token granting `Permission::Invoke` on a matching resource pattern. No token, no access. The token is Ed25519-signed by the runtime key, linked to the approval audit entry that created it, optionally time-bounded, and scoped to session or persistent storage. The agent has no way to mint, modify, or extend them.

## How tokens work

When a human approves an action with "Allow Always", the security interceptor (`astrid-approval`) calls into this crate to mint a `CapabilityToken`. The token is signed, stored, and returned as proof. On subsequent calls, the interceptor finds the token and skips the approval prompt.

`ResourcePattern` uses compiled glob matching via `globset`. Patterns like `mcp://filesystem:*` match any tool on that server. `file:///home/user/**` matches any file under that directory. Exact URIs skip glob compilation for speed. Path traversal (`..`) is rejected at pattern creation and again at match time. Defense in depth.

**Dual-tier storage.** Session tokens live in memory via `RwLock<HashMap>`. Persistent tokens survive restarts through the `KvStore` injected by the host; native Astrid injects the authoritative principal store. The legacy standalone SurrealKV constructor remains only for API compatibility during migration. Both tiers share revocation and single-use tracking. Revocation persists to KV before updating in-memory state, so a crash between the two cannot resurrect a revoked token.

**Replay protection.** Single-use tokens are marked consumed atomically under a write lock. `mark_used` checks, persists, and inserts in one critical section to prevent TOCTOU races. State survives process restart via KV.

**Tamper detection on read.** Persistent tokens are re-validated (expiry + signature) on every `get()`, `find_capability()`, and `has_capability()` call. A token tampered on disk fails signature verification and is silently skipped. Session tokens skip this check because they were validated at `add()` time and live in trusted memory.

**Clock-skew tolerance.** Configurable window (default 30 seconds) via `validate_with_skew`. A token that expired 10 seconds ago still passes with the default tolerance.

## Resource pattern examples

| Pattern | Matches |
|---|---|
| `mcp://filesystem:read_file` | Exactly that one tool |
| `mcp://filesystem:*` | Any tool on the `filesystem` server |
| `mcp://*:read_*` | Any `read_` tool on any server |
| `file:///home/user/**` | Any file under `/home/user` |

## Usage

```toml
[dependencies]
astrid-capabilities = { workspace = true }
```

```rust
use astrid_capabilities::{
    CapabilityToken, CapabilityStore, ResourcePattern, TokenScope, AuditEntryId,
};
use astrid_core::Permission;
use astrid_crypto::KeyPair;

let runtime_key = KeyPair::generate();
let pattern = ResourcePattern::new("mcp://filesystem:*").unwrap();

let token = CapabilityToken::create(
    pattern,
    vec![Permission::Invoke],
    TokenScope::Session,
    runtime_key.key_id(),
    AuditEntryId::new(),
    &runtime_key,
    None, // no TTL
);

let store = CapabilityStore::in_memory();
store.add(token).unwrap();
assert!(store.has_capability("mcp://filesystem:read_file", Permission::Invoke));
```

This crate also defines `DirHandle` and `FileHandle`, the opaque UUID-based handles used by `astrid-vfs`. You cannot construct a path to a directory you have not been granted.

## Development

```bash
cargo test -p astrid-capabilities
```

## License

Dual MIT/Apache-2.0. See [LICENSE-MIT](../../LICENSE-MIT) and [LICENSE-APACHE](../../LICENSE-APACHE).
