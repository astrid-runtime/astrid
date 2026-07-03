#![deny(unreachable_pub)]

//! Engine-agnostic capsule types shared by all Astrid capsule engines.
//!
//! The kernel routes on these pure data types — the capsule manifest, the
//! capsule id, the fuel/memory ledgers, and the resource/HTTP limits — while
//! the capsule *engines* (the native Wasmtime host today, a browser WebAssembly
//! host tomorrow) own the execution machinery. Keeping the types in their own
//! wasm-clean crate (no `wasmtime`, no `tokio`) lets every engine depend on the
//! shared vocabulary without pulling one engine's runtime.

pub mod capsule;
pub mod error;
pub mod fuel_ledger;
pub mod limits;
pub mod manifest;
pub mod memory_ledger;

pub use capsule::CapsuleId;
pub use error::{CapsuleError, CapsuleResult};
pub use fuel_ledger::{FuelLedger, FuelRateLimiter};
pub use limits::{CapsuleRuntimeLimits, HttpLimits};
pub use memory_ledger::MemoryLedger;
