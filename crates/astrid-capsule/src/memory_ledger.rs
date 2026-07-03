//! The per-Store memory limiter that feeds the shared peak-memory ledger.
//!
//! The engine-agnostic [`MemoryLedger`] (the shared per-principal high-water
//! accounting) lives in `astrid-capsule-types`; it is re-exported here at its
//! original path so consumers compile unchanged. [`StoreMemoryMeter`] is the
//! Wasmtime `ResourceLimiter` that enforces the per-invocation byte ceiling and
//! records each invoking principal's peak into that ledger, so it stays in the
//! Wasmtime engine crate.

use astrid_core::PrincipalId;

pub use astrid_capsule_types::MemoryLedger;

/// Per-Store memory limiter: enforces the per-invocation byte ceiling **and**
/// records the invoking principal's peak into the shared [`MemoryLedger`].
///
/// Replaces a plain `wasmtime::StoreLimits` as the `HostState` limiter field. A
/// pooled Store is leased by different principals, so the ceiling and the
/// attributee are re-targeted per invocation via [`set`](Self::set); for a
/// run-loop's dedicated Store they are set once to the owner at build.
pub struct StoreMemoryMeter {
    /// Linear-memory byte ceiling for the current invocation (the principal's
    /// `max_memory_bytes` quota). A grow beyond it is denied — the same cap the
    /// old `StoreLimits::memory_size` enforced.
    max_memory_bytes: usize,
    /// Principal to attribute growth to (the invoking principal; the owner for a
    /// run-loop's dedicated Store).
    principal: PrincipalId,
    /// Shared peak ledger.
    ledger: MemoryLedger,
}

impl StoreMemoryMeter {
    /// Build a meter capped at `max_memory_bytes`, attributing growth to
    /// `principal`, recording into `ledger`.
    #[must_use]
    pub fn new(max_memory_bytes: usize, principal: PrincipalId, ledger: MemoryLedger) -> Self {
        Self {
            max_memory_bytes,
            principal,
            ledger,
        }
    }

    /// Re-target for a new invocation: the principal's memory ceiling and the
    /// principal to attribute peak growth to. Called at invocation SET, since a
    /// pooled Store crosses principals.
    pub fn set(&mut self, max_memory_bytes: usize, principal: PrincipalId) {
        self.max_memory_bytes = max_memory_bytes;
        self.principal = principal;
    }
}

impl wasmtime::ResourceLimiter for StoreMemoryMeter {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        // Enforce the per-invocation byte ceiling (what `StoreLimits` did).
        if desired > self.max_memory_bytes {
            return Ok(false);
        }
        if let Some(max) = maximum
            && desired > max
        {
            return Ok(false);
        }
        // Attribute the new high-water size to the invoking principal.
        self.ledger
            .record_peak(&self.principal, u64::try_from(desired).unwrap_or(u64::MAX));
        Ok(true)
    }

    fn table_growing(
        &mut self,
        _current: usize,
        _desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        // Tables are unbounded here, matching the prior `StoreLimits` (which set
        // only `memory_size`). Only linear memory is metered.
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn meter_enforces_ceiling_and_records_peak() {
        use wasmtime::ResourceLimiter;

        let ledger = MemoryLedger::default();
        let p = PrincipalId::new("carol").unwrap();
        let mut meter = StoreMemoryMeter::new(64 * 1024, p.clone(), ledger.clone());

        // Within the cap: allowed and recorded.
        assert!(meter.memory_growing(0, 16 * 1024, None).unwrap());
        assert_eq!(ledger.peak(&p), 16 * 1024);

        // Growing further raises the peak.
        assert!(meter.memory_growing(16 * 1024, 48 * 1024, None).unwrap());
        assert_eq!(ledger.peak(&p), 48 * 1024);

        // Beyond the ceiling: denied, peak unchanged.
        assert!(!meter.memory_growing(48 * 1024, 128 * 1024, None).unwrap());
        assert_eq!(ledger.peak(&p), 48 * 1024);

        // Re-target to a new principal + cap; the old principal's peak persists.
        let q = PrincipalId::new("dave").unwrap();
        meter.set(256 * 1024, q.clone());
        assert!(meter.memory_growing(0, 200 * 1024, None).unwrap());
        assert_eq!(ledger.peak(&q), 200 * 1024);
        assert_eq!(ledger.peak(&p), 48 * 1024);
    }
}
