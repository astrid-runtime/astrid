#![deny(unreachable_pub)]

//! Core runtime management for User-Space Capsules in Astrid OS.
//!
//! Core capsule runtime implementing the "Manifest-First" architecture.
//! It provides the definition for `Capsule.toml`
//! manifests, handles discovery, and routes execution to the appropriate
//! environments (WASM sandboxes or legacy host processes).

pub mod capsule;
pub mod context;
pub mod discovery;
pub mod dispatcher;
pub mod engine;
pub mod error;
pub mod fuel_ledger;
pub mod loader;
pub mod manifest;
pub mod principal_class;
pub mod profile_cache;
pub mod registry;
pub mod schema_catalog;
pub mod security;
pub mod topic;
pub mod toposort;
pub(crate) mod watcher;

pub use engine::wasm::limits::CapsuleRuntimeLimits;
pub use fuel_ledger::{FuelLedger, FuelRateLimiter};
