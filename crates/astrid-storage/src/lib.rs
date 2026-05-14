//! Astrid Storage — unified persistence layer.
//!
//! Provides two tiers of storage for the Astrid runtime:
//!
//! # Tier 1: Raw Key-Value ([`KvStore`])
//!
//! Direct byte-level `get`/`set`/`delete` backed by **`SurrealKV`** — an embedded,
//! versioned, ACID-compliant LSM-tree KV store. Zero query overhead.
//!
//! Primary use case: WASM guest storage with scoped namespaces per plugin.
//!
//! Enable with the **`kv`** feature.
//!
//! # Tier 2: Query Engine ([`Database`])
//!
//! Full **`SurrealDB`** with `SurrealQL` — document-graph database supporting
//! relations, graph traversal, computed fields, and complex queries.
//!
//! Primary use case: system stores (approval, audit, capabilities, memory).
//!
//! Enable with the **`db`** feature.
//!
//! # Scaling
//!
//! | Deployment | KV backend | DB backend |
//! |------------|------------|------------|
//! | Dev / single-agent | `SurrealKV` (embedded) | `SurrealDB` (embedded, `SurrealKV`) |
//! | Production / multi-node | `SurrealKV` (embedded) | `SurrealDB` (over `TiKV`, Raft) |
//!
//! Same API at both tiers. Scaling is a config change, not a code change.
//!
//! # Feature Flags
//!
//! - **`kv`** — `SurrealKV` raw key-value store
//! - **`db`** — `SurrealDB` full query engine
//! - **`full`** — Both `kv` and `db`

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![deny(unreachable_pub)]
#![deny(clippy::unwrap_used)]
#![cfg_attr(test, allow(clippy::unwrap_used))]

pub mod error;
pub mod identity;
pub mod kv;
pub mod secret;

#[cfg(feature = "db")]
pub mod db;

pub use error::{StorageError, StorageResult};
pub use identity::{IdentityError, IdentityStore, KvIdentityStore};
pub use kv::{KvEntry, KvStore, MemoryKvStore, ScopedKvStore};
pub use secret::{
    FileSecretStore, KvSecretStore, SecretStore, SecretStoreError, build_secret_store,
};

#[cfg(feature = "keychain")]
pub use secret::{FallbackSecretStore, KeychainSecretStore};

#[cfg(feature = "kv")]
pub use kv::SurrealKvStore;

#[cfg(feature = "db")]
pub use db::Database;
