#![deny(unreachable_pub)]

//! Core runtime management for User-Space Capsules in Astrid OS.
//!
//! Core capsule runtime implementing the "Manifest-First" architecture.
//! It provides the definition for `Capsule.toml`
//! manifests, handles discovery, and routes execution to the appropriate
//! environments (WASM sandboxes or legacy host processes).

pub mod access;
pub mod audit_sink;
pub mod capsule;
pub mod context;
// Manifest discovery is std::fs-heavy and native-only; an alternate host
// (e.g. a browser WebAssembly build) supplies capsules by other means.
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub mod discovery;
pub mod dispatcher;
pub mod engine;
// The loader constructs the Wasmtime/process-backed engines, so it is
// native-only. An alternate host wires its own engines into `CompositeCapsule`.
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub mod loader;
pub mod memory_ledger;

// Engine-agnostic capsule types live in `astrid-capsule-types` so the browser
// WebAssembly host can share them without pulling Wasmtime. Re-exported here at
// their original paths so kernel and every other consumer compile unchanged.
pub use astrid_capsule_types::error;
pub use astrid_capsule_types::fuel_ledger;
pub use astrid_capsule_types::manifest;
pub mod principal_class;
pub mod profile_cache;
pub mod readiness;
pub mod registry;
pub mod schema_catalog;
pub mod security;
pub mod tool_discovery;
pub mod topic;
pub mod toposort;
// The manifest watcher drives hot-reload via the native `notify` crate; an
// alternate host has no OS filesystem-watch facility.
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub(crate) mod watcher;

pub use access::CapsuleAccessResolver;
pub use astrid_capsule_types::limits::{CapsuleRuntimeLimits, HttpLimits};
pub use audit_sink::{HostAuditEvent, HostAuditOutcome, HostAuditSink};
pub use fuel_ledger::{FuelLedger, FuelRateLimiter};
pub use memory_ledger::MemoryLedger;
// `StoreMemoryMeter` is the Wasmtime `ResourceLimiter`; native-only.
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub use memory_ledger::StoreMemoryMeter;
pub use tool_discovery::{ToolDescriptor, describe_loaded_capsule, tools_missing_execute_route};
