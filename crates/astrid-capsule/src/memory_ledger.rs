//! The per-Store memory limiter that feeds the shared peak-memory ledger.
//!
//! The engine-agnostic [`MemoryLedger`] (the shared per-principal high-water
//! accounting) lives in `astrid-capsule-types`; it is re-exported here at its
//! original path so consumers compile unchanged. [`StoreMemoryMeter`] is the
//! Wasmtime `ResourceLimiter` that enforces the per-invocation byte ceiling and
//! records each invoking principal's peak into that ledger, so it stays in the
//! Wasmtime engine crate.

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
use astrid_core::PrincipalId;

pub use astrid_capsule_types::MemoryLedger;

/// Per-Store memory limiter: enforces the per-invocation byte ceiling **and**
/// records the invoking principal's peak into the shared [`MemoryLedger`].
///
/// Replaces a plain `wasmtime::StoreLimits` as the `HostState` limiter field. A
/// pooled Store is leased by different principals, so the ceiling and the
/// attributee are re-targeted per invocation via [`set`](Self::set); for a
/// run-loop's dedicated Store they are set once to the owner at build.
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub struct StoreMemoryMeter {
    /// Linear-memory byte ceiling for the current invocation (the principal's
    /// `max_memory_bytes` quota). A grow beyond it is denied — the same cap the
    /// old `StoreLimits::memory_size` enforced.
    max_memory_bytes: usize,
    /// Principal to attribute growth to (the invoking principal; the owner for a
    /// run-loop's dedicated Store).
    principal: PrincipalId,
    /// Conservative element ceiling derived from `max_memory_bytes`.
    max_table_elements: usize,
    /// Shared peak ledger.
    ledger: MemoryLedger,
}

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
impl StoreMemoryMeter {
    /// Build a meter capped at `max_memory_bytes`, attributing growth to
    /// `principal`, recording into `ledger`.
    #[must_use]
    pub fn new(max_memory_bytes: usize, principal: PrincipalId, ledger: MemoryLedger) -> Self {
        Self {
            max_memory_bytes,
            principal,
            max_table_elements: table_element_limit(max_memory_bytes),
            ledger,
        }
    }

    /// Re-target for a new invocation: the principal's memory ceiling and the
    /// principal to attribute peak growth to. Called at invocation SET, since a
    /// pooled Store crosses principals.
    pub fn set(&mut self, max_memory_bytes: usize, principal: PrincipalId) {
        self.max_memory_bytes = max_memory_bytes;
        self.max_table_elements = table_element_limit(max_memory_bytes);
        self.principal = principal;
    }
}

/// Conservative host bytes accounted per table element.
const TABLE_ELEMENT_SLOT_BYTES: usize = 32;

fn table_element_limit(max_memory_bytes: usize) -> usize {
    (max_memory_bytes / TABLE_ELEMENT_SLOT_BYTES).max(1)
}

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
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
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        if desired > self.max_table_elements {
            return Ok(false);
        }
        if let Some(max) = _maximum
            && desired > max
        {
            return Ok(false);
        }
        Ok(true)
    }
}

#[cfg(all(test, not(all(target_arch = "wasm32", target_os = "unknown"))))]
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

    #[test]
    fn table_growth_cannot_bypass_the_memory_ceiling() {
        use wasmtime::ResourceLimiter;

        let ledger = MemoryLedger::default();
        let principal = PrincipalId::new("carol").unwrap();
        let mut meter = StoreMemoryMeter::new(64 * 1024, principal.clone(), ledger.clone());

        // 64 KiB / 32-byte conservative slots = 2048 elements.
        assert!(meter.table_growing(0, 2_048, None).unwrap());
        assert!(
            !meter.table_growing(2_048, 2_049, None).unwrap(),
            "table growth must not become an unbounded host-memory side channel"
        );

        meter.set(32 * 1024, principal);
        assert!(meter.table_growing(0, 1_024, None).unwrap());
        assert!(!meter.table_growing(1_024, 1_025, None).unwrap());
        assert!(!meter.table_growing(0, 2, Some(1)).unwrap());
    }
}
