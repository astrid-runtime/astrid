# astrid-storage

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](../../LICENSE-MIT)
[![MSRV: 1.94](https://img.shields.io/badge/MSRV-1.94-blue)](https://www.rust-lang.org)

**The persistence layer. Disk for the OS.**

An operating system needs disk. Astrid has a raw key-value contract projected
onto typed, durable per-principal roots. The legacy SurrealKV reader remains
available only during the migration window.

## Storage model

Capsules and kernel services need fast, isolated byte storage. The native
object store supplies that contract directly; query services belong above this
crate rather than inside its persistence substrate.

| Deployment | KV backend |
|---|---|
| Dev / single-agent | Durable principal store |
| Production / multi-node | Durable principal store plus future placement execution |

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

The `build_secret_store` convenience constructor is always KV-backed and never
probes the OS keychain. Signed distributions that explicitly opt into the
`keychain` feature may call `build_keychain_secret_store` instead.

## Identity

`IdentityStore` manages users and cross-platform identity links. A Discord user, a Telegram user, and a CLI user can all resolve to the same `AstridUserId`. Platform names are normalized (case, whitespace). Path-injection characters (`/`, `\0`) in platform names, user IDs, and display names are rejected before key construction.

## Feature flags

| Feature | Enables |
|---|---|
| `legacy-surrealkv` | Legacy `SurrealKvStore` reader and migrator |
| `keychain` | `KeychainSecretStore` + `FallbackSecretStore` |
| `full` | Legacy compatibility features |

The KV contract is never feature-gated. `KvStore`, `MemoryKvStore`,
`ScopedKvStore`, `KvSecretStore`, and the principal-store adapter are always
available. The old `kv` name remains only so existing dependent manifests keep
building; only the transition dependency is optional.

## Usage

```toml
[dependencies]
astrid-storage = { workspace = true }
```

Enable `legacy-surrealkv` only in a binary responsible for importing an
existing SurrealKV store. New deployments and ordinary consumers do not need
the transition dependency.

```rust
use std::sync::Arc;
use astrid_storage::kv::{MemoryKvStore, ScopedKvStore};

let store = Arc::new(MemoryKvStore::new());
let scoped = ScopedKvStore::new(store, "wasm:my-plugin")?;

scoped.set("config", b"{}".to_vec()).await?;
scoped.set_json("prefs", &serde_json::json!({"key": "value"})).await?;
let loaded: serde_json::Value = scoped.get_json("prefs").await?.unwrap();
```

## Performance

Performance values are evidence artifacts, not crate API documentation. Run
the manual **Storage benchmark evidence** workflow to produce content-bound
reports for Linux, macOS, and Windows from the same exact revision and workload
configuration. The report records the code revision, tree state, executable,
arguments, host environment, cache policy, and raw samples.

Historical device-local results remain useful for diagnosing regressions, but
they are not portable release numbers. The full methodology, cross-platform CI
contract, historical baselines, raw samples, and content-bound evidence
envelopes live in
[`../../docs/astrid-storage-performance.md`](../../docs/astrid-storage-performance.md)
and [`../../docs/benchmarks/storage-io/`](../../docs/benchmarks/storage-io/).

## Development

```bash
cargo test -p astrid-storage --all-features
```

## License

Dual MIT/Apache-2.0. See [LICENSE-MIT](../../LICENSE-MIT) and [LICENSE-APACHE](../../LICENSE-APACHE).
