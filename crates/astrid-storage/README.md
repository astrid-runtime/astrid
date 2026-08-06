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

The `build_secret_store` convenience constructor picks the best available backend.

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

The current dense physical-catalogue implementation was measured from clean
commit `ce756e1e` on an M2 Ultra/APFS host. Each reported median covers three
runs over a deterministic 512 MiB incompressible corpus, with one-MiB reads, four
principals, and a governed one-GiB object-cache budget. Native comparisons are
same-run substrate measurements; the verified-read comparator reads and
BLAKE3-verifies the same bytes.

| Operation | Median result | Interpretation |
|---|---:|---|
| Astrid staging write | 4,443.2 MiB/s | native-speed acknowledgement path |
| Native warm verified read | 1,596.8 MiB/s | read plus BLAKE3 |
| Astrid warm verified read | 1,778.5 MiB/s | 0.898× native elapsed time |
| Astrid first verified read | 518.2 MiB/s | process-local evidence cold |
| Astrid post-reopen verified read | 404.3 MiB/s | evidence rebuilt after reopen |
| Unique publication | 179.5 MiB/s | asynchronous authoritative admission |
| Duplicate publication | 256.5 MiB/s | exact same-content admission |
| Four-principal shared publication | 380.9 MiB/s aggregate | 2.122× single-principal throughput |
| Four-principal warm verified read | 6,285.1 MiB/s aggregate | 3.534× single-principal throughput |
| Populated reopen | 1.276 s | dense physical-catalogue recovery |
| Direct-catalogue activation | 2.243 s | one-time migration of the populated store |

The current bounded bulk-ingest checkpoint at clean commit `02968196` split
the same 512 MiB corpus into 128 independently fingerprinted 4 MiB sources.
Workers now carry engine-bound prepared batches through a bounded channel to
one authoritative appender. Against exact parent `279c9342`, eight-worker first
ingest holds at 388.3 MiB/s and scaling at 2.105 times the serial path while
making both memory bounds observable: 4,207,436 bytes single-worker and a
58,853,269-byte median with eight workers. The operator-only phase matrix
measures 250.7 ms in the parallel pipeline versus 1,067.7 ms in root
publication, including 979.1 ms of exact closure validation.
These phase totals are diagnostics, not guest-visible dedup signals. The
earlier source-change invariant still applies: unchanged re-ingest reads no
source bytes and a changed token reads only its source partition. At 388.3
MiB/s, one TiB extrapolates to about 45 minutes; closure validation is now the
dominant measured first-ingest cost.

Unique random content appended 1.013715 physical bytes per logical byte,
including authenticated representation metadata. Republishing the identical
512 MiB appended 18,032 bytes (0.003359%): exact deduplication plus the new
principal root and catalogue metadata. Strict small-file seals measured 71.6
files/s versus 230.2 native write-and-sync operations/s, so ordinary hosted
close remains the native-speed staging boundary while publication proceeds in
the background. The dense map uses 903.0 representation-metadata bytes per new
object, 19.7% below the preceding canonical binary map, while preserving
legacy-root recovery and logical identities.

These are engine and APFS-substrate measurements, not mounted-provider results
or corpus-wide compression claims. The full methodology, historical baselines,
raw samples, and content-bound evidence envelope live in
[`../../docs/astrid-storage-performance.md`](../../docs/astrid-storage-performance.md)
and [`../../docs/benchmarks/storage-io/`](../../docs/benchmarks/storage-io/).

## Development

```bash
cargo test -p astrid-storage --all-features
```

## License

Dual MIT/Apache-2.0. See [LICENSE-MIT](../../LICENSE-MIT) and [LICENSE-APACHE](../../LICENSE-APACHE).
