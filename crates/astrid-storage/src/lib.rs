//! Astrid Storage — unified persistence layer.
//!
//! Provides two tiers of storage for the Astrid runtime:
//!
//! # Tier 1: Raw Key-Value ([`KvStore`])
//!
//! Direct byte-level `get`/`set`/`delete` over an injected backend. Native
//! Astrid uses the durable principal store; `SurrealKV` remains available only
//! as a legacy migration reader and differential-test oracle.
//!
//! Primary use case: WASM guest storage with scoped namespaces per plugin.
//!
//! # Tier 2: Query Engine ([`Database`])
//!
//! Full **`SurrealDB`** with `SurrealQL` — document-graph database supporting
//! relations, graph traversal, computed fields, and complex queries.
//!
//! Primary use case: optional relational and query-heavy services.
//!
//! Enable with the **`db`** feature.
//!
//! # Scaling
//!
//! | Deployment | KV backend | DB backend |
//! |------------|------------|------------|
//! | Dev / single-agent | Durable principal store | `SurrealDB` (embedded, `SurrealKV`) |
//! | Production / multi-node | Durable principal store plus future placement execution | Deployment-selected query service |
//!
//! Both tiers retain stable interfaces, but distributed placement for the
//! principal store remains separate implementation work rather than a backend
//! setting.
//!
//! # Feature Flags
//!
//! - **`legacy-surrealkv`** — legacy `SurrealKV` reader and migrator
//! - **`kv`** — compatibility alias for `legacy-surrealkv`; runtime KV is
//!   unconditional
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
#[cfg(not(target_family = "wasm"))]
pub mod principal_state;
pub mod secret;

#[cfg(feature = "db")]
pub mod db;

pub use error::{StorageError, StorageResult};
pub use identity::{IdentityError, IdentityStore, KvIdentityStore};
pub use kv::{
    KvEntry, KvPrincipalResolver, KvQuotaResolver, KvStore, MemoryKvStore, PrincipalKvStore,
    ScopedKvStore, TreeKvStore,
};
pub use secret::{
    DenySecretStore, FileSecretStore, KvSecretStore, ReadThroughSecretStore, SecretStore,
    SecretStoreError, build_secret_store,
};

#[cfg(feature = "keychain")]
pub use secret::{FallbackSecretStore, KeychainSecretStore};

#[cfg(feature = "legacy-surrealkv")]
pub use kv::SurrealKvStore;
#[cfg(not(target_family = "wasm"))]
pub use principal_state::{
    Blake3ObjectIdentityV1, StateOwner, StateOwnerCodecV1, StateOwnerResolver, open_runtime_kv,
};

#[cfg(feature = "db")]
pub use db::Database;
