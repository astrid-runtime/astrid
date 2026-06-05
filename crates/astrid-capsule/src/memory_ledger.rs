//! Shared per-principal peak-memory accounting ledger + the per-Store limiter
//! that feeds it.
//!
//! Records the high-water linear-memory size each invoking principal grows a
//! Store to. Like [`FuelLedger`](crate::FuelLedger) the [`MemoryLedger`] is
//! kernel-owned and cloned into every `WasmEngine`, so a principal's peak is the
//! max across every capsule it drives — the substrate that fills
//! `ResourceUsage::memory_bytes_peak_total`.
//!
//! **Attribution under pooling.** A capsule's pooled Stores are shared across
//! principals under free checkout, and grown linear memory persists across
//! leases (wasmtime cannot shrink a linear memory). The attributable signal is
//! therefore "the largest memory any of this principal's invocations GREW a
//! Store to": the principal that caused the growth owns the peak; one that
//! reuses an already-grown Store without growing is not charged (memory growth
//! is the only event the limiter sees). For a run-loop capsule's dedicated
//! Store the attributee is the owner, set once.
//!
//! KNOWN IMPRECISION (telemetry-only, no deny path): growth records the
//! ABSOLUTE new size, so a principal that grows an already-grown pooled Store —
//! even by one page — is attributed that absolute high-water, which may include
//! linear memory a *prior* leaseholder allocated. The peak is thus an upper
//! bound on a principal's own footprint: never below its true peak, never above
//! its `max_memory_bytes` ceiling, but possibly inflated by inherited pooled
//! memory. Acceptable while this is operator-facing telemetry; revisit (e.g.
//! per-lease baseline deltas) before it ever gates a budget decision.
//!
//! **Concurrency + growth.** Same shape as [`FuelLedger`]: a sharded
//! [`DashMap`] of per-principal [`AtomicU64`], so concurrent invocations record
//! lock-free per principal. One entry per distinct principal, capped at
//! [`MAX_PRINCIPALS`] (the `astrid#827` lesson, since this map gains no deny
//! path that would prune it): at capacity a new principal evicts the
//! lowest-peak entry — but only if it is itself a bigger user — so a flood of
//! ephemeral sub-agent principals cannot grow the map without limit, and the
//! biggest memory users (the interesting telemetry) are the ones retained.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use astrid_core::PrincipalId;
use dashmap::DashMap;

/// Cap on distinct principals tracked. A flood of ephemeral sub-agent
/// principals must not grow the ledger without bound — the lesson of the
/// `chain_locks` / fuel-ledger churn (`astrid#827`). When full, recording a
/// *new* principal first evicts the entry with the lowest recorded peak, so the
/// ledger retains the biggest memory users (the interesting telemetry) instead
/// of growing or dropping arbitrarily. Sized generously: real deployments have
/// far fewer concurrent principals, so the cap only bites under adversarial
/// ephemeral churn.
const MAX_PRINCIPALS: usize = 4096;

/// Shared, cloneable handle to the per-principal peak-memory ledger.
///
/// Cloning is an `Arc` bump; every clone observes the same map, so the kernel
/// hands one clone to each `WasmEngine` and they all record into the same
/// per-principal high-water marks.
#[derive(Clone, Default)]
pub struct MemoryLedger {
    inner: Arc<DashMap<PrincipalId, AtomicU64>>,
}

impl MemoryLedger {
    /// Raise `principal`'s recorded peak to `bytes` if it exceeds the current
    /// high-water mark (else no-op).
    ///
    /// Lock-free in steady state: once a principal has an entry the common path
    /// takes a shard *read* guard and a `Relaxed` compare-exchange max. Only the
    /// first observation of a never-seen principal takes a shard write guard.
    /// `Relaxed` is correct — a monotonic high-water mark with no ordering
    /// dependency on other memory.
    pub fn record_peak(&self, principal: &PrincipalId, bytes: u64) {
        if bytes == 0 {
            return;
        }
        if let Some(counter) = self.inner.get(principal) {
            Self::raise_to(&counter, bytes);
            return;
        }
        // New principal. Bound the map (`astrid#827` lesson): if at capacity,
        // evict the lowest-peak entry — but ONLY if this newcomer's peak is
        // strictly above it. Evicting a bigger user to record a smaller one
        // would defeat the goal of keeping the biggest memory users (the
        // interesting telemetry) and let a flood of small, ephemeral
        // sub-agent principals thrash the real ones out. If the newcomer is
        // not bigger, drop it. A benign race may let the size briefly exceed
        // the cap under concurrent new inserts — bounded by the number of
        // concurrent inserters, never unbounded.
        if self.inner.len() >= MAX_PRINCIPALS && !self.evict_lowest_if_below(bytes) {
            return;
        }
        Self::raise_to(&self.inner.entry(principal.clone()).or_default(), bytes);
    }

    /// At capacity, remove the entry with the smallest recorded peak — but only
    /// when `threshold` exceeds it, so a smaller newcomer never displaces a
    /// bigger user. Returns `true` if there is now room to insert (an entry was
    /// evicted, or — racing — the map dipped empty), `false` if the newcomer
    /// should be dropped.
    ///
    /// `O(n)` over the map, but only on the rare new-principal-while-at-capacity
    /// path; `n` is bounded by [`MAX_PRINCIPALS`] and each probe is a `Relaxed`
    /// load, so the scan is microseconds. The iterator's shard guards are
    /// dropped before the `remove`, so it cannot deadlock against a concurrent
    /// `record_peak`.
    fn evict_lowest_if_below(&self, threshold: u64) -> bool {
        let mut victim: Option<PrincipalId> = None;
        let mut lowest = u64::MAX;
        for entry in &*self.inner {
            let peak = entry.value().load(Ordering::Relaxed);
            if peak <= lowest {
                lowest = peak;
                victim = Some(entry.key().clone());
            }
        }
        let Some(key) = victim else {
            // Map raced empty — there is room.
            return true;
        };
        if threshold <= lowest {
            // The newcomer is no bigger than our smallest user; keep the
            // bigger one and drop the newcomer.
            return false;
        }
        self.inner.remove(&key);
        true
    }

    /// Relaxed atomic max: raise `counter` to `bytes` if larger. The closure
    /// returns `None` (no write) when `bytes` is not larger, so `fetch_update`
    /// returns `Err` and we ignore it — lock-free and uncontended per principal.
    fn raise_to(counter: &AtomicU64, bytes: u64) {
        let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
            (bytes > v).then_some(bytes)
        });
    }

    /// Read `principal`'s peak linear-memory high-water mark in bytes, or `0` if
    /// it has never grown a Store. A snapshot via a shard read guard + a single
    /// `Relaxed` load, the same ordering the record path uses.
    #[must_use]
    pub fn peak(&self, principal: &PrincipalId) -> u64 {
        self.inner
            .get(principal)
            .map_or(0, |counter| counter.load(Ordering::Relaxed))
    }
}

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
    fn record_peak_keeps_the_high_water_mark() {
        let ledger = MemoryLedger::default();
        let p = PrincipalId::default();
        assert_eq!(ledger.peak(&p), 0);

        ledger.record_peak(&p, 1000);
        assert_eq!(ledger.peak(&p), 1000);

        // A lower observation does not lower the peak.
        ledger.record_peak(&p, 500);
        assert_eq!(ledger.peak(&p), 1000);

        // A higher one raises it.
        ledger.record_peak(&p, 4096);
        assert_eq!(ledger.peak(&p), 4096);

        // Zero is ignored.
        ledger.record_peak(&p, 0);
        assert_eq!(ledger.peak(&p), 4096);
    }

    #[test]
    fn ledger_is_per_principal_and_shared_across_clones() {
        let ledger = MemoryLedger::default();
        let a = PrincipalId::new("alice").unwrap();
        let b = PrincipalId::new("bob").unwrap();

        ledger.record_peak(&a, 2048);
        // A clone observes the same map (shared Arc).
        let clone = ledger.clone();
        clone.record_peak(&b, 8192);

        assert_eq!(ledger.peak(&a), 2048);
        assert_eq!(ledger.peak(&b), 8192);
        assert_eq!(clone.peak(&a), 2048);
    }

    #[test]
    fn ledger_is_bounded_and_evicts_the_lowest_peak() {
        let ledger = MemoryLedger::default();
        // Fill to capacity; principal `pi` gets peak `i + 1`, so peaks are all
        // distinct and the lowest is `p0` (peak 1).
        for i in 0..MAX_PRINCIPALS {
            let p = PrincipalId::new(format!("p{i}")).unwrap();
            ledger.record_peak(&p, (i as u64) + 1);
        }
        assert_eq!(ledger.inner.len(), MAX_PRINCIPALS);
        let lowest = PrincipalId::new("p0").unwrap();
        assert_eq!(ledger.peak(&lowest), 1);

        // One more NEW principal at a high peak evicts the lowest (`p0`) and the
        // map stays bounded.
        let newcomer = PrincipalId::new("newcomer").unwrap();
        ledger.record_peak(&newcomer, 1_000_000);
        assert!(ledger.inner.len() <= MAX_PRINCIPALS, "stays bounded");
        assert_eq!(ledger.peak(&newcomer), 1_000_000, "newcomer recorded");
        assert_eq!(ledger.peak(&lowest), 0, "lowest-peak principal evicted");

        // A NEW principal whose peak is NOT above the current lowest must be
        // DROPPED rather than evict a bigger user (else a flood of small
        // ephemeral principals would thrash out the real ones). After the
        // eviction above the smallest retained user is `p1` (peak 2); a
        // newcomer at peak 2 (== the lowest) must not displace it.
        let p1 = PrincipalId::new("p1").unwrap();
        assert_eq!(ledger.peak(&p1), 2, "p1 is now the lowest retained user");
        let smaller = PrincipalId::new("smaller").unwrap();
        ledger.record_peak(&smaller, 2);
        assert_eq!(
            ledger.peak(&smaller),
            0,
            "smaller newcomer dropped, not recorded"
        );
        assert_eq!(ledger.peak(&p1), 2, "existing bigger user retained");
    }

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
