//! Shared per-principal CPU accounting ledger.
//!
//! Accumulates the wasmtime fuel (exact deterministic guest-instruction count)
//! each principal burns inside pooled interceptor calls. A single
//! [`FuelLedger`] is owned by the kernel and cloned into every capsule's
//! `WasmEngine`, so a principal driving N capsules has its CPU **summed
//! cross-capsule into one per-principal total** — not fragmented into N
//! independent per-capsule sub-totals as it was when the ledger lived on each
//! engine.
//!
//! **Concurrency.** The map is sharded ([`DashMap`]) and each principal's
//! counter is an [`AtomicU64`], so concurrent interceptor invocations on the
//! hot path increment lock-free per principal. This is deliberate: a single
//! process-wide `Mutex` here would re-serialise every interceptor call across
//! all capsules and re-introduce the orchestration concurrency cliff that
//! astrid#813/#817 removed.
//!
//! **Scope today: TELEMETRY.** [`charge`](FuelLedger::charge) is the only
//! mutator and there is no read/deny path yet — the windowed-rate deny/throttle
//! enforcement is the follow-up that consumes this aggregate (it is why the
//! ledger had to become cross-capsule first). The run-loop CPU bound remains
//! enforced separately by the epoch-interrupt mechanism, not by this ledger.
//!
//! **Growth.** One entry per distinct [`PrincipalId`], never evicted —
//! monotonic for the process lifetime. Ephemeral sub-agents get distinct
//! principal ids, so the map grows with the number of principals ever seen.
//! Acceptable while this is telemetry; bound it (LRU / windowed pruning) before
//! it gains the read+deny path, so a flood of ephemeral principals can't grow
//! it without limit. (Inherited, not introduced: the old per-engine `HashMap`
//! was equally unbounded.)
//!
//! **Default-principal collapse.** When an invocation has no caller principal
//! the writer keys under [`PrincipalId::default()`] (the literal `"default"`).
//! In single-tenant deployments effectively all interceptor CPU sums into that
//! one bucket, so the future per-principal budget only *discriminates* once
//! more than one principal is present — the aggregate is correct either way,
//! but a single-user budget is really a whole-instance budget.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use astrid_core::PrincipalId;
use dashmap::DashMap;

/// Shared, cloneable handle to the per-principal CPU fuel ledger.
///
/// Cloning is cheap (an `Arc` bump) and every clone observes the same map, so
/// the kernel hands one clone to each `WasmEngine` and they all accumulate into
/// the same per-principal totals. See the module docs for concurrency and scope.
#[derive(Clone, Default)]
pub struct FuelLedger {
    inner: Arc<DashMap<PrincipalId, AtomicU64>>,
}

impl FuelLedger {
    /// Attribute `fuel` guest-instructions to `principal`, summing into its
    /// cross-capsule total.
    ///
    /// Lock-free in steady state: once a principal has an entry, the common
    /// path takes a shard *read* guard and a relaxed *saturating* add. Only the
    /// first charge for a never-seen principal takes a shard write guard to
    /// insert the counter. `Relaxed` is correct — this is a monotonic counter
    /// with no ordering dependency on other memory.
    ///
    /// The add **saturates** at `u64::MAX` rather than wrapping (a plain
    /// `fetch_add` wraps): a runaway burner pins at the ceiling instead of
    /// silently resetting the total toward zero, preserving the "monotonic for
    /// the process lifetime" guarantee the module docs promise. This mirrors the
    /// old per-engine ledger and [`FuelRateLimiter`]'s window arithmetic.
    pub fn charge(&self, principal: &PrincipalId, fuel: u64) {
        if fuel == 0 {
            return;
        }
        // Fast path: principal already present — read guard + saturating add, no
        // clone, no shard write lock.
        if let Some(counter) = self.inner.get(principal) {
            Self::saturating_add(&counter, fuel);
            return;
        }
        // Slow path: first charge for this principal. `entry` write-locks only
        // this principal's shard; `or_default` races are resolved by DashMap.
        Self::saturating_add(&self.inner.entry(principal.clone()).or_default(), fuel);
    }

    /// Saturating relaxed atomic add: pins at `u64::MAX` instead of wrapping.
    /// Still lock-free — a `Relaxed` compare-exchange loop, uncontended per
    /// principal. The closure always returns `Some`, so `fetch_update` can never
    /// return `Err` here.
    fn saturating_add(counter: &AtomicU64, fuel: u64) {
        let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
            Some(v.saturating_add(fuel))
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pid(s: &str) -> PrincipalId {
        PrincipalId::new(s).expect("valid principal id")
    }

    #[test]
    fn charge_sums_per_principal() {
        let ledger = FuelLedger::default();
        let a = pid("alice");
        ledger.charge(&a, 100);
        ledger.charge(&a, 50);
        assert_eq!(
            ledger.inner.get(&a).unwrap().load(Ordering::Relaxed),
            150,
            "repeat charges accumulate"
        );
    }

    #[test]
    fn distinct_principals_are_independent() {
        let ledger = FuelLedger::default();
        let (a, b) = (pid("alice"), pid("bob"));
        ledger.charge(&a, 100);
        ledger.charge(&b, 7);
        assert_eq!(ledger.inner.get(&a).unwrap().load(Ordering::Relaxed), 100);
        assert_eq!(ledger.inner.get(&b).unwrap().load(Ordering::Relaxed), 7);
    }

    #[test]
    fn clones_share_one_aggregate() {
        // The whole point of PR1: a clone handed to a second "engine" charges
        // into the same per-principal total (cross-capsule aggregation).
        let engine_a = FuelLedger::default();
        let engine_b = engine_a.clone();
        let p = pid("alice");
        engine_a.charge(&p, 40);
        engine_b.charge(&p, 2);
        assert_eq!(
            engine_a.inner.get(&p).unwrap().load(Ordering::Relaxed),
            42,
            "two engines sharing one ledger sum cross-capsule"
        );
    }

    #[test]
    fn zero_charge_is_a_noop() {
        let ledger = FuelLedger::default();
        let p = pid("alice");
        ledger.charge(&p, 0);
        assert!(
            ledger.inner.get(&p).is_none(),
            "a zero charge must not even create an entry"
        );
    }

    #[test]
    fn charge_saturates_instead_of_wrapping() {
        // The total is documented monotonic for the process lifetime; a charge
        // past u64::MAX must pin at the ceiling, never wrap back toward zero (a
        // plain `fetch_add` would wrap).
        let ledger = FuelLedger::default();
        let p = pid("alice");
        ledger.charge(&p, u64::MAX);
        ledger.charge(&p, 10);
        assert_eq!(
            ledger.inner.get(&p).unwrap().load(Ordering::Relaxed),
            u64::MAX,
            "saturating add pins at u64::MAX"
        );
    }
}
