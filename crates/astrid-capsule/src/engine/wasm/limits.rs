//! Tokio-backed constructors for the engine-agnostic capsule runtime limits.
//!
//! The pure limit types ([`CapsuleRuntimeLimits`], [`HttpLimits`]) and the
//! host-derived default resolvers live in `astrid-capsule-types` so the browser
//! WebAssembly host can share them without pulling `tokio`. They are re-exported
//! here at their original paths (`crate::engine::wasm::limits::*`) so the rest
//! of the Wasmtime engine compiles unchanged.
//!
//! The one piece that cannot move is building the actual `tokio::sync::Semaphore`
//! gates from a [`CapsuleRuntimeLimits`]: that depends on tokio, which the
//! engine-agnostic crate must not depend on. It stays here as the
//! [`CapsuleRuntimeLimitsExt`] extension trait.

use std::sync::Arc;

use tokio::sync::Semaphore;

pub use astrid_capsule_types::limits::{
    CapsuleRuntimeLimits, HttpLimits, host_blocking_concurrency_default,
    host_instance_pool_size_default, host_io_concurrency_default,
};

/// Tokio-backed constructors for [`CapsuleRuntimeLimits`]. Kept in the Wasmtime
/// engine crate because they build `tokio::sync::Semaphore` gates, which the
/// engine-agnostic `astrid-capsule-types` crate must not pull.
pub trait CapsuleRuntimeLimitsExt {
    /// Build the blocking host-call semaphore sized to this limit.
    fn blocking_semaphore(self) -> Arc<Semaphore>;

    /// Build the async-I/O host-call semaphore sized to this limit.
    fn io_semaphore(self) -> Arc<Semaphore>;
}

impl CapsuleRuntimeLimitsExt for CapsuleRuntimeLimits {
    fn blocking_semaphore(self) -> Arc<Semaphore> {
        Arc::new(Semaphore::new(self.blocking_concurrency))
    }

    fn io_semaphore(self) -> Arc<Semaphore> {
        Arc::new(Semaphore::new(self.io_concurrency))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semaphores_match_resolved_counts() {
        let r = CapsuleRuntimeLimits::resolve(Some(3), Some(11), None);
        assert_eq!(r.blocking_semaphore().available_permits(), 3);
        assert_eq!(r.io_semaphore().available_permits(), 11);
    }
}
