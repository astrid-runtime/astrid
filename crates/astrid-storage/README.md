# astrid-storage

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](../../LICENSE-MIT)
[![MSRV: 1.94](https://img.shields.io/badge/MSRV-1.94-blue)](https://www.rust-lang.org)

**The persistence layer. Disk for the OS.**

An operating system needs disk. Astrid has a raw key-value contract projected onto typed, durable per-principal roots, plus an optional query engine. The legacy SurrealKV reader remains available only during the migration window.

## Why two tiers

Capsules and kernel services need fast, isolated byte storage. Some optional
services need relations, graph traversal, or richer queries. Forcing both
shapes through one interface wastes either simplicity or power, so the crate
keeps the principal-state KV contract separate from the optional query engine.

| Deployment | KV backend | DB backend |
|---|---|---|
| Dev / single-agent | Durable principal store | SurrealDB (embedded, SurrealKV) |
| Production / multi-node | Durable principal store plus future placement execution | Deployment-selected query service |

Distributed placement for the principal store remains implementation work; it
is not exposed as a runtime backend selector.

## Namespace isolation

Every KV operation is scoped to a namespace. WASM guests receive a `ScopedKvStore` bound to `wasm:{capsule_id}` and never see the raw key structure. The kernel uses `system:*` namespaces for internal state.

Empty namespaces, empty keys, and names containing null bytes are rejected before reaching the storage engine. The native runtime maps host-stamped `{principal}:capsule:{id}` namespaces onto one typed root per validated principal; kernel namespaces remain under a separate system owner.

## Secret storage

The `SecretStore` trait provides synchronous credential storage (called from synchronous Extism host functions that bridge to async via `block_on`). Three implementations:

- `KvSecretStore` stores secrets in the KV tier with a `__secret:` key prefix. Works everywhere. No OS-level encryption at rest.
- `KeychainSecretStore` (`keychain` feature) uses the OS keychain via the `keyring` crate. Per-capsule isolation via service name scoping.
- `FallbackSecretStore` (`keychain` feature) probes the keychain once at construction. If accessible, all operations go to keychain. If not, all go to KV. No per-operation fallback that could scatter secrets across both backends.

The `build_secret_store` convenience constructor picks the best available backend.

## Identity

`IdentityStore` manages users and cross-platform identity links. A Discord user, a Telegram user, and a CLI user can all resolve to the same `AstridUserId`. Platform names are normalized (case, whitespace). Path-injection characters (`/`, `\0`) in platform names, user IDs, and display names are rejected before key construction.

## Feature flags

| Feature | Enables |
|---|---|
| `legacy-surrealkv` | Legacy `SurrealKvStore` reader and migrator |
| `kv` | Compatibility alias for `legacy-surrealkv`; runtime KV is unconditional |
| `db` | `Database` (SurrealDB query engine) |
| `keychain` | `KeychainSecretStore` + `FallbackSecretStore` |
| `full` | `kv` + `db` |

The KV contract is never feature-gated. `KvStore`, `MemoryKvStore`,
`ScopedKvStore`, `KvSecretStore`, and the principal-store adapter are always
available. The old `kv` name remains only so existing dependent manifests keep
building; only the transition dependency is optional.

## Usage

```toml
[dependencies]
astrid-storage = { workspace = true, features = ["full"] }
```

```rust
use std::sync::Arc;
use astrid_storage::kv::{MemoryKvStore, ScopedKvStore};

let store = Arc::new(MemoryKvStore::new());
let scoped = ScopedKvStore::new(store, "wasm:my-plugin")?;

scoped.set("config", b"{}".to_vec()).await?;
scoped.set_json("prefs", &serde_json::json!({"key": "value"})).await?;
let loaded: serde_json::Value = scoped.get_json("prefs").await?.unwrap();
```

## Development

```bash
cargo test -p astrid-storage --all-features
```

## License

Dual MIT/Apache-2.0. See [LICENSE-MIT](../../LICENSE-MIT) and [LICENSE-APACHE](../../LICENSE-APACHE).
