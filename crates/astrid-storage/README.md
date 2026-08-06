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

The current contiguous-adoption implementation was measured from clean commit
`6384aaec` on an M2 Ultra/APFS host. Each reported median covers three
runs over a deterministic 512 MiB incompressible corpus, with one-MiB reads, four
principals, and a governed one-GiB object-cache budget. Native comparisons are
same-run substrate measurements; the verified-read comparator reads and
BLAKE3-verifies the same bytes.

| Operation | Median result | Interpretation |
|---|---:|---|
| Astrid staging write | 5,080.8 MiB/s | acknowledgement path |
| Verified copy fallback | 674.7 MiB/s | forced full-data fallback, no clone |
| Native warm verified read | 1,660.7 MiB/s | read plus BLAKE3 |
| Astrid warm verified read | 1,774.6 MiB/s | 0.936× native elapsed time |
| Astrid first verified read | 625.6 MiB/s | process-local evidence cold |
| Astrid post-reopen verified read | 488.5 MiB/s | evidence rebuilt after reopen |
| Unique publication | 270.4 MiB/s | asynchronous contiguous admission |
| Duplicate publication | 295.8 MiB/s | supplied preimage is reverified before reuse |
| Eight-worker first ingest | 1,212.1 MiB/s | 4.449× single-worker throughput |
| Four-principal shared publication | 935.8 MiB/s aggregate | 3.461× single-principal throughput |
| Four-principal warm verified read | 6,325.5 MiB/s aggregate | 3.565× single-principal throughput |
| Populated reopen | 1.561 s | revalidates the contiguous representation |

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

The following clean checkpoint, `a4a492b5`, carries staging-earned closure
evidence into publication without weakening the authoritative root check.
Eight-worker first ingest reaches 1,251.0 MiB/s, 3.22 times the prior
checkpoint, while exact closure validation falls from 979.1 ms to 0.146 ms.
Physical-map work remains flat, and the median eight-worker pending-memory bound
is 67,303,811 bytes. Missing or cyclic closure, failed admission, reclaimed
staged objects, and parent-before-child staging across batches take the normal
fail-closed validation path. On this warm 512 MiB corpus, one TiB extrapolates
to about 14 minutes; this is not a larger-than-memory or mounted-provider claim.

Unique random content appended 1.000971 authoritative bytes per logical byte,
including the contiguous blob and authenticated representation metadata.
Republishing the identical 512 MiB appended 8,387 bytes (0.001562%): exact
deduplication plus the new principal root and catalogue metadata. The unique
publication added 61,042 bytes of representation metadata, or 1,034.6 bytes
per newly inserted object; the raw 512 MiB payload is not misreported as
metadata. Strict small-file seals measured 70.5 files/s versus 197.3 native
write-and-sync operations/s, so ordinary hosted
close remains the native-speed staging boundary while publication proceeds in
the background.

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
