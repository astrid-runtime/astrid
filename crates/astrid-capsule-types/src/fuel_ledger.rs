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
use std::time::Duration;
// `web_time::Instant` IS `std::time::Instant` on native targets (pure
// re-export, same type identity for callers); on wasm32-unknown-unknown it
// reads the JS performance clock instead of panicking like `std`'s.
use web_time::Instant;

use astrid_core::PrincipalId;
use dashmap::DashMap;
use parking_lot::Mutex;

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

    /// Read `principal`'s cumulative cross-capsule fuel total, or `0` if the
    /// principal has never been charged.
    ///
    /// Cheap: a DashMap shard *read* guard plus a single `Relaxed` atomic load —
    /// the same ordering the [`charge`](FuelLedger::charge) hot path uses, and
    /// correct for the read side because this is a monotonic counter with no
    /// happens-before dependency on other memory. (The shard read guard is a
    /// lightweight read-lock, not strictly lock-free, but distinct principals
    /// live on distinct shards and never contend.) The value is a snapshot:
    /// concurrent charges may land immediately after the load, so a reader sees
    /// a total that is correct-as-of-read, never torn.
    #[must_use]
    pub fn total(&self, principal: &PrincipalId) -> u64 {
        self.inner
            .get(principal)
            .map_or(0, |counter| counter.load(Ordering::Relaxed))
    }
}

/// One principal's sliding 1-second CPU-fuel window.
///
/// `(window_start, fuel_in_window)` is the exact analogue of the
/// `(Instant, usize)` cell `astrid-events`' `IpcRateLimiter` keeps per
/// `(capsule, principal)` — here it is per *principal*, summed cross-capsule
/// (the [`FuelLedger`] is the total; this window is the *rate*). Has no
/// `Default` deliberately: a fresh window must be stamped with a real `now`,
/// not `Instant`'s (absent) zero, so [`FuelRateLimiter::record`] always
/// constructs it explicitly.
struct FuelWindow {
    /// Start of the current 1-second window. Rolled forward whenever a call
    /// observes the window is `>= 1s` stale.
    window_start: Instant,
    /// Fuel charged to this principal since `window_start`. Saturating, so a
    /// runaway burner pins at `u64::MAX` rather than wrapping back under budget.
    fuel_in_window: u64,
}

/// Length of the rate window. One second, matching the
/// `max_cpu_fuel_per_sec` budget unit and the `IpcRateLimiter` window.
const WINDOW: Duration = Duration::from_secs(1);

/// Map-size threshold above which [`FuelRateLimiter::maybe_prune`] becomes
/// eligible to run. Below this the map is small enough to leave alone. Mirrors
/// the `> 1000` guard in `astrid-events`' `IpcRateLimiter`.
const PRUNE_THRESHOLD: usize = 1000;

/// Minimum spacing between prune passes. A prune walks the whole map, so it is
/// throttled to at most once per minute (the `astrid-events` cadence).
const PRUNE_INTERVAL: Duration = Duration::from_secs(60);

/// Shared, cloneable per-principal CPU-**rate** limiter — the deny side of the
/// CPU budget, layered on top of the telemetry-only [`FuelLedger`].
///
/// Where [`FuelLedger`] keeps a monotonic *total* per principal, this keeps a
/// rolling 1-second *rate* per principal and answers a single question on the
/// hot path — [`over_budget`](FuelRateLimiter::over_budget) — that the
/// interceptor consults *before* admitting a call. [`record`](
/// FuelRateLimiter::record) feeds it the exact post-hoc fuel from the same
/// invocation, the same way `charge` feeds the ledger.
///
/// **Fail-OPEN, by construction.** The per-principal cell is a
/// [`parking_lot::Mutex`] — **non-poisoning** — and every time computation is
/// `saturating_*`, so the window math has no panic and no error path: a thread
/// that panicked elsewhere cannot poison a cell and turn this into a
/// deny-everything brick. Liveness wins on the rate axis. (The orthogonal
/// *exemption* axis fails CLOSED — see `resolve_exemption` — so an
/// unidentifiable principal is bounded, not exempt; only the window arithmetic
/// fails open, and it structurally cannot fail.)
///
/// **Concurrency.** Sharded [`DashMap`] keyed by principal, each cell its own
/// `Mutex`, so distinct principals never contend. This deliberately does not
/// reintroduce a single process-wide lock (the astrid#813/#817 cliff).
///
/// **Growth.** Like the ledger the map grows with distinct principals, but
/// unlike the ledger it is *bounded*: [`maybe_prune`](
/// FuelRateLimiter::maybe_prune) lazily drops principals whose window has gone
/// stale, so a flood of ephemeral sub-agent principals cannot grow it without
/// limit.
#[derive(Clone)]
pub struct FuelRateLimiter {
    /// Per-principal rolling window. Each cell guarded by a non-poisoning
    /// `parking_lot::Mutex`; distinct principals live on distinct DashMap
    /// shards and never contend.
    inner: Arc<DashMap<PrincipalId, Mutex<FuelWindow>>>,
    /// Timestamp of the last prune pass, throttling prunes to once per
    /// [`PRUNE_INTERVAL`]. `try_lock`'d, never blocked on, so a prune in flight
    /// never stalls a `record`.
    last_prune: Arc<Mutex<Instant>>,
}

impl Default for FuelRateLimiter {
    fn default() -> Self {
        Self {
            inner: Arc::new(DashMap::new()),
            // `Instant` has no zero; stamp with a real `now` so the first prune
            // is correctly throttled.
            last_prune: Arc::new(Mutex::new(Instant::now())),
        }
    }
}

impl FuelRateLimiter {
    /// Roll `window` forward if it is `>= 1s` stale relative to `now`, resetting
    /// the in-window fuel. Pure helper over a held cell guard.
    fn roll(window: &mut FuelWindow, now: Instant) {
        if now.saturating_duration_since(window.window_start) >= WINDOW {
            window.window_start = now;
            window.fuel_in_window = 0;
        }
    }

    /// Is `principal` over its 1-second CPU-fuel budget *right now*?
    ///
    /// The gate the interceptor consults before admitting a call. Returns
    /// `false` (admit) for:
    /// - `max_fuel_per_sec == 0` — 0 means **unlimited**, never deny-all;
    /// - a *cold* principal with no window yet — first call is always admitted,
    ///   and it is `record` (post-hoc), not this read, that creates the entry;
    /// - any principal whose rolled window is still at or under budget.
    ///
    /// Rolls the window first (so a principal that was over budget a second ago
    /// SELF-HEALS — there is no permanent brick), then compares
    /// `fuel_in_window > max_fuel_per_sec`. The comparison is strict: spending
    /// *exactly* the budget is allowed, only *exceeding* it denies.
    #[must_use]
    pub fn over_budget(
        &self,
        principal: &PrincipalId,
        max_fuel_per_sec: u64,
        now: Instant,
    ) -> bool {
        // 0 = unlimited. Never deny-all on a zero budget.
        if max_fuel_per_sec == 0 {
            return false;
        }
        // Cold principal: no window yet => admit. Do NOT create an entry here;
        // entry creation is `record`'s job, on the post-hoc feed.
        let Some(cell) = self.inner.get(principal) else {
            return false;
        };
        let mut window = cell.lock();
        Self::roll(&mut window, now);
        window.fuel_in_window > max_fuel_per_sec
    }

    /// Attribute `fuel` to `principal`'s current 1-second window (post-hoc, from
    /// the exact wasmtime fuel the call burned).
    ///
    /// Mirrors [`FuelLedger::charge`]'s zero-noop. Creates the principal's
    /// window on first non-zero charge, rolls it, then `saturating_add`s the
    /// fuel (a runaway pins at `u64::MAX`, never wraps under budget). Finally
    /// runs the lazy prune so the map stays bounded.
    pub fn record(&self, principal: &PrincipalId, fuel: u64, now: Instant) {
        if fuel == 0 {
            return;
        }
        // Fast path: principal already has a window — a shard *read* guard plus
        // the cell lock, no shard write lock and no `PrincipalId` clone. This is
        // the steady-state path (a principal is recorded once per invocation,
        // far more often than it is first seen) and mirrors the
        // [`FuelLedger::charge`] hot path.
        if let Some(cell) = self.inner.get(principal) {
            let mut window = cell.lock();
            Self::roll(&mut window, now);
            window.fuel_in_window = window.fuel_in_window.saturating_add(fuel);
        } else {
            // Slow path: first charge for this principal. `entry` write-locks
            // only this principal's shard; concurrent first-inserts are resolved
            // by DashMap.
            let cell = self.inner.entry(principal.clone()).or_insert_with(|| {
                Mutex::new(FuelWindow {
                    window_start: now,
                    fuel_in_window: 0,
                })
            });
            let mut window = cell.lock();
            Self::roll(&mut window, now);
            window.fuel_in_window = window.fuel_in_window.saturating_add(fuel);
        }
        self.maybe_prune(now);
    }

    /// Lazily drop principals whose window has gone stale, bounding map growth.
    ///
    /// Only eligible above [`PRUNE_THRESHOLD`] entries and at most once per
    /// [`PRUNE_INTERVAL`]. The idiom is ported from `astrid-events`'
    /// `IpcRateLimiter` (its `> 1000` / `> 60s` lazy prune) but uses
    /// non-poisoning `parking_lot` locks: `try_lock` on `last_prune` so a prune
    /// in flight never blocks a `record`, and `try_lock` on each cell inside
    /// `retain` so we never deadlock against a window lock a concurrent
    /// `record`/`over_budget` is holding — a cell we cannot lock is simply
    /// *kept* (a live, contended principal is never pruned). All time math is
    /// `saturating_duration_since`.
    fn maybe_prune(&self, now: Instant) {
        if self.inner.len() <= PRUNE_THRESHOLD {
            return;
        }
        let Some(mut last) = self.last_prune.try_lock() else {
            return;
        };
        if now.saturating_duration_since(*last) < PRUNE_INTERVAL {
            return;
        }
        *last = now;
        self.inner.retain(|_, cell| {
            // Keep any cell we cannot lock (a concurrent holder => live).
            // Keep any cell whose window is still fresh (< 1s stale).
            match cell.try_lock() {
                Some(window) => now.saturating_duration_since(window.window_start) < WINDOW,
                None => true,
            }
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
    fn total_sums_charges_and_defaults_to_zero() {
        let ledger = FuelLedger::default();
        let a = pid("alice");
        ledger.charge(&a, 100);
        ledger.charge(&a, 50);
        assert_eq!(ledger.total(&a), 150, "total returns the cumulative sum");
        assert_eq!(
            ledger.total(&pid("absent")),
            0,
            "a never-charged principal reads as zero, not an error"
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

    // ── FuelRateLimiter (PR2: the deny side) ─────────────────────────────
    //
    // All tests inject a synthetic `now: Instant` so they exercise the
    // window roll deterministically with NO real sleep (a 1.1s real-clock
    // variant is provided once, `#[ignore]`d, as a belt-and-braces check that
    // the wall clock agrees with the injected-clock logic).

    const BUDGET: u64 = 1_000;

    #[test]
    fn rate_over_budget_after_recording_past_budget() {
        let rl = FuelRateLimiter::default();
        let p = pid("alice");
        let t0 = Instant::now();
        // Spend the budget exactly: still admitted (strict `>`), one more unit
        // tips it over.
        rl.record(&p, BUDGET, t0);
        assert!(
            !rl.over_budget(&p, BUDGET, t0),
            "spending exactly the budget is allowed"
        );
        rl.record(&p, 1, t0);
        assert!(
            rl.over_budget(&p, BUDGET, t0),
            "one unit past the budget must deny within the same window"
        );
    }

    #[test]
    fn rate_under_budget_is_admitted() {
        let rl = FuelRateLimiter::default();
        let p = pid("alice");
        let t0 = Instant::now();
        rl.record(&p, BUDGET / 2, t0);
        assert!(
            !rl.over_budget(&p, BUDGET, t0),
            "a principal under budget must be admitted"
        );
    }

    #[test]
    fn rate_cold_principal_is_admitted() {
        // A principal with no window yet (never recorded) is always admitted,
        // and the read must NOT create an entry (entry creation is record's
        // job).
        let rl = FuelRateLimiter::default();
        let p = pid("ghost");
        let t0 = Instant::now();
        assert!(
            !rl.over_budget(&p, BUDGET, t0),
            "a cold principal must be admitted"
        );
        assert!(
            rl.inner.get(&p).is_none(),
            "over_budget must not create a window for a cold principal"
        );
    }

    #[test]
    fn rate_window_self_heals_across_the_second() {
        // The security-critical anti-brick property: a principal that blew its
        // budget does NOT stay denied forever. Advancing `now` past the 1s
        // window rolls it and the principal is admitted again — proving the
        // deny is a rate throttle, not a permanent ban.
        let rl = FuelRateLimiter::default();
        let p = pid("alice");
        let t0 = Instant::now();
        rl.record(&p, BUDGET * 10, t0);
        assert!(
            rl.over_budget(&p, BUDGET, t0),
            "way over budget within the window must deny"
        );
        let t1 = t0 + Duration::from_millis(1_001);
        assert!(
            !rl.over_budget(&p, BUDGET, t1),
            "after the window rolls, the principal must be admitted again (no permanent brick)"
        );
    }

    #[test]
    fn rate_zero_budget_is_always_admitted() {
        // 0 = unlimited; even an astronomically over-spent principal is never
        // denied on a zero budget (must not become deny-all).
        let rl = FuelRateLimiter::default();
        let p = pid("unbounded");
        let t0 = Instant::now();
        rl.record(&p, u64::MAX, t0);
        assert!(
            !rl.over_budget(&p, 0, t0),
            "a zero (unlimited) budget must never deny"
        );
    }

    #[test]
    fn rate_distinct_principals_have_independent_windows() {
        let rl = FuelRateLimiter::default();
        let (a, b) = (pid("alice"), pid("bob"));
        let t0 = Instant::now();
        // Alice blows her budget; Bob is untouched.
        rl.record(&a, BUDGET * 5, t0);
        assert!(rl.over_budget(&a, BUDGET, t0), "alice over budget");
        assert!(
            !rl.over_budget(&b, BUDGET, t0),
            "bob's window is independent of alice's"
        );
        rl.record(&b, BUDGET / 4, t0);
        assert!(!rl.over_budget(&b, BUDGET, t0), "bob still under budget");
    }

    #[test]
    fn rate_zero_record_is_a_noop() {
        // Mirror FuelLedger: a zero charge does not even create a window.
        let rl = FuelRateLimiter::default();
        let p = pid("alice");
        rl.record(&p, 0, Instant::now());
        assert!(
            rl.inner.get(&p).is_none(),
            "a zero record must not create a window entry"
        );
    }

    #[test]
    fn rate_clones_share_one_map() {
        // Like the ledger, a cloned handle observes the same windows, so the
        // engine clone the loader hands each capsule rate-limits the same
        // principal cross-capsule.
        let a = FuelRateLimiter::default();
        let b = a.clone();
        let p = pid("alice");
        let t0 = Instant::now();
        a.record(&p, BUDGET, t0);
        b.record(&p, 1, t0);
        assert!(
            a.over_budget(&p, BUDGET, t0),
            "two handles sharing one map sum cross-capsule into one window"
        );
    }

    #[test]
    fn rate_lazy_prune_caps_the_map() {
        // Fill the map past the prune threshold with STALE windows, then drive a
        // record at a `now` more than PRUNE_INTERVAL after the synthetic
        // last_prune so the prune fires and drops the stale entries.
        let rl = FuelRateLimiter::default();
        let base = Instant::now();
        // last_prune is stamped at construction (~base); force it well into the
        // past so the next record is prune-eligible.
        *rl.last_prune.lock() = base;
        // Insert > PRUNE_THRESHOLD stale principals, all windowed at `base`.
        for i in 0..(PRUNE_THRESHOLD + 50) {
            rl.inner.insert(
                pid(&format!("ghost-{i}")),
                Mutex::new(FuelWindow {
                    window_start: base,
                    fuel_in_window: 1,
                }),
            );
        }
        assert!(
            rl.inner.len() > PRUNE_THRESHOLD,
            "map seeded over threshold"
        );
        // A record far past PRUNE_INTERVAL: the stale (base-windowed) entries
        // are now > 1s stale and get retained-out; only the fresh "live"
        // principal recorded at `now` survives.
        let now = base + Duration::from_secs(120);
        rl.record(&pid("live"), BUDGET, now);
        // All ghost windows started at `base`, now 120s stale => pruned. `live`
        // is fresh.
        assert!(
            rl.inner.len() < PRUNE_THRESHOLD,
            "lazy prune must drop stale windows and bound the map (len = {})",
            rl.inner.len()
        );
        assert!(
            rl.inner.contains_key(&pid("live")),
            "the freshly-recorded principal survives the prune"
        );
    }

    #[test]
    #[ignore = "real-clock variant; the deterministic injected-now tests are the contract"]
    fn rate_window_self_heals_real_clock() {
        let rl = FuelRateLimiter::default();
        let p = pid("alice");
        let t0 = Instant::now();
        rl.record(&p, BUDGET * 10, t0);
        assert!(rl.over_budget(&p, BUDGET, Instant::now()));
        std::thread::sleep(Duration::from_millis(1_100));
        assert!(
            !rl.over_budget(&p, BUDGET, Instant::now()),
            "after a real second the window must reset"
        );
    }
}
