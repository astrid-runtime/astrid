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
    /// Aggregate admitted linear-memory bytes across every memory in this
    /// Store. WebAssembly memories do not shrink, so a Store whose quota is
    /// lowered below this value must be discarded before its next invocation.
    current_memory_bytes: usize,
    /// Delta admitted by the latest `memory_growing` callback. Wasmtime calls
    /// `memory_grow_failed` if the actual allocation then fails; retaining the
    /// delta lets that callback roll exact current accounting back.
    pending_growth_bytes: usize,
    /// Whether this Store is principal-affine and therefore owns an exact
    /// reservation in the shared current-resident ledger.
    track_current: bool,
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
            current_memory_bytes: 0,
            pending_growth_bytes: 0,
            track_current: false,
            ledger,
        }
    }

    /// Re-target for a new invocation: the principal's memory ceiling and the
    /// principal to attribute peak growth to. Called at invocation SET, since a
    /// pooled Store crosses principals.
    pub fn set(&mut self, max_memory_bytes: usize, principal: PrincipalId) {
        debug_assert!(
            !self.track_current || self.principal == principal,
            "a principal-affine Store must never change owner"
        );
        // A prior admitted growth with no failure callback completed.
        self.pending_growth_bytes = 0;
        self.max_memory_bytes = max_memory_bytes;
        self.principal = principal;
    }

    /// Permanently bind a newly constructed Store to one principal before
    /// component initialization. All admitted growth then reserves against the
    /// principal's aggregate resident-memory quota until this meter drops.
    pub(crate) fn bind_resident(&mut self, max_memory_bytes: usize, principal: PrincipalId) {
        debug_assert_eq!(self.current_memory_bytes, 0);
        debug_assert!(!self.track_current);
        self.max_memory_bytes = max_memory_bytes;
        self.principal = principal;
        self.track_current = true;
    }

    /// Current admitted linear-memory size for residency/quota revalidation.
    #[must_use]
    pub(crate) fn current_memory_bytes(&self) -> usize {
        self.current_memory_bytes
    }

    /// Whether a resident Store or its principal's cross-capsule aggregate no
    /// longer fits a freshly lowered quota.
    #[must_use]
    pub(crate) fn resident_memory_exceeds(&self, max_memory_bytes: usize) -> bool {
        self.track_current
            && (self.current_memory_bytes > max_memory_bytes
                || self.ledger.current(&self.principal)
                    > u64::try_from(max_memory_bytes).unwrap_or(u64::MAX))
    }
}

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
impl wasmtime::ResourceLimiter for StoreMemoryMeter {
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        // No failure callback for the preceding admission means it completed.
        self.pending_growth_bytes = 0;
        if let Some(max) = maximum
            && desired > max
        {
            return Ok(false);
        }
        let Some(additional) = desired.checked_sub(current) else {
            return Ok(false);
        };
        let Some(next_total) = self.current_memory_bytes.checked_add(additional) else {
            return Ok(false);
        };
        // This is an aggregate per-Store ceiling, including components that
        // declare more than one linear memory.
        if next_total > self.max_memory_bytes {
            return Ok(false);
        }
        if self.track_current
            && additional > 0
            && !self.ledger.try_reserve_current(
                &self.principal,
                u64::try_from(additional).unwrap_or(u64::MAX),
                u64::try_from(self.max_memory_bytes).unwrap_or(u64::MAX),
            )
        {
            return Ok(false);
        }
        // Attribute the Store's aggregate high-water size to the invoking
        // principal. For free checkout this intentionally remains an upper
        // bound when the Store inherited earlier allocations.
        self.ledger.record_peak(
            &self.principal,
            u64::try_from(next_total).unwrap_or(u64::MAX),
        );
        self.current_memory_bytes = next_total;
        self.pending_growth_bytes = additional;
        Ok(true)
    }

    fn memory_grow_failed(&mut self, _error: wasmtime::Error) -> wasmtime::Result<()> {
        let failed = std::mem::take(&mut self.pending_growth_bytes);
        let Some(next_total) = self.current_memory_bytes.checked_sub(failed) else {
            debug_assert!(false, "failed growth exceeded admitted Store memory");
            return Ok(());
        };
        self.current_memory_bytes = next_total;
        if self.track_current {
            self.ledger
                .release_current(&self.principal, u64::try_from(failed).unwrap_or(u64::MAX));
        }
        Ok(())
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

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
impl Drop for StoreMemoryMeter {
    fn drop(&mut self) {
        if self.track_current {
            self.ledger.release_current(
                &self.principal,
                u64::try_from(self.current_memory_bytes).unwrap_or(u64::MAX),
            );
        }
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
        assert_eq!(meter.current_memory_bytes(), 16 * 1024);

        // Growing further raises the peak.
        assert!(meter.memory_growing(16 * 1024, 48 * 1024, None).unwrap());
        assert_eq!(ledger.peak(&p), 48 * 1024);
        assert_eq!(meter.current_memory_bytes(), 48 * 1024);

        // Beyond the ceiling: denied, peak unchanged.
        assert!(!meter.memory_growing(48 * 1024, 128 * 1024, None).unwrap());
        assert_eq!(ledger.peak(&p), 48 * 1024);
        assert_eq!(meter.current_memory_bytes(), 48 * 1024);

        // Re-target to a new principal + cap; the old principal's peak persists.
        let q = PrincipalId::new("dave").unwrap();
        meter.set(256 * 1024, q.clone());
        assert!(meter.memory_growing(48 * 1024, 200 * 1024, None).unwrap());
        assert_eq!(ledger.peak(&q), 200 * 1024);
        assert_eq!(ledger.peak(&p), 48 * 1024);
    }

    #[test]
    fn meter_caps_the_aggregate_of_multiple_memories_and_rolls_back_failures() {
        use wasmtime::ResourceLimiter;

        let ledger = MemoryLedger::default();
        let alice = PrincipalId::new("alice").unwrap();
        let mut meter = StoreMemoryMeter::new(64 * 1024, PrincipalId::default(), ledger.clone());
        meter.bind_resident(64 * 1024, alice.clone());

        assert!(meter.memory_growing(0, 40 * 1024, None).unwrap());
        assert!(
            !meter.memory_growing(0, 30 * 1024, None).unwrap(),
            "two memories must share one Store ceiling"
        );
        assert_eq!(ledger.current(&alice), 40 * 1024);

        assert!(meter.memory_growing(40 * 1024, 48 * 1024, None).unwrap());
        assert_eq!(ledger.current(&alice), 48 * 1024);
        meter
            .memory_grow_failed(wasmtime::Error::msg("synthetic allocation failure"))
            .unwrap();
        assert_eq!(meter.current_memory_bytes(), 40 * 1024);
        assert_eq!(ledger.current(&alice), 40 * 1024);
    }

    #[test]
    fn resident_meters_share_one_principal_current_memory_ceiling() {
        use wasmtime::ResourceLimiter;

        let ledger = MemoryLedger::default();
        let alice = PrincipalId::new("alice").unwrap();
        let mut first = StoreMemoryMeter::new(64 * 1024, PrincipalId::default(), ledger.clone());
        first.bind_resident(64 * 1024, alice.clone());
        assert!(first.memory_growing(0, 40 * 1024, None).unwrap());
        assert_eq!(ledger.current(&alice), 40 * 1024);

        let mut second = StoreMemoryMeter::new(64 * 1024, PrincipalId::default(), ledger.clone());
        second.bind_resident(64 * 1024, alice.clone());
        assert!(!second.memory_growing(0, 30 * 1024, None).unwrap());
        assert_eq!(ledger.current(&alice), 40 * 1024);

        drop(first);
        assert_eq!(ledger.current(&alice), 0);
        assert!(second.memory_growing(0, 30 * 1024, None).unwrap());
        assert_eq!(ledger.current(&alice), 30 * 1024);
        drop(second);
        assert_eq!(ledger.current(&alice), 0);
    }
}
