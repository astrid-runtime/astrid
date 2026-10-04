//! Cooperative execution-rate accounting. Unlike a fixed-window counter,
//! excess work remains owed across window boundaries and task cancellation.
//!
//! Each identity starts with one second of burst capacity. Work is charged at
//! a scheduler boundary, so simultaneous in-flight execution can overshoot;
//! callers must bound those boundaries and stop resuming while debt remains.
//! This is not an instruction-level hard ceiling or complete host CPU meter.

use dashmap::DashMap;
use parking_lot::Mutex;
use std::hash::Hash;
use std::num::NonZeroU64;
use std::sync::Arc;
use std::time::Duration;
use web_time::Instant;

#[cfg(test)]
mod tests;

// Fixed-point fuel credit: nanosecond resolution avoids rounding a tiny
// scheduling slice into a free slice. This is a unit conversion, not a quota.
const NANOS_PER_SECOND: i128 = 1_000_000_000;

// Housekeeping only, not an execution/identity limit. Match FuelRateLimiter's
// lazy scan policy so small ledgers avoid a full-map walk on the hot path.
const PRUNE_THRESHOLD: usize = 1_000;
const PRUNE_INTERVAL: Duration = Duration::from_mins(1);

struct Balance {
    credit: i128,
    updated: Instant,
    rate: NonZeroU64,
}

/// Shared debt for one authority domain, keyed by principal or accountable user.
/// Clones share balances; constructing one per capsule would defeat aggregation.
pub struct ExecutionRate<K> {
    balances: Arc<DashMap<K, Mutex<Balance>>>,
    last_prune: Arc<Mutex<Instant>>,
}

impl<K> Clone for ExecutionRate<K> {
    fn clone(&self) -> Self {
        Self {
            balances: Arc::clone(&self.balances),
            last_prune: Arc::clone(&self.last_prune),
        }
    }
}

impl<K: Eq + Hash> Default for ExecutionRate<K> {
    fn default() -> Self {
        Self {
            balances: Arc::new(DashMap::new()),
            last_prune: Arc::new(Mutex::new(Instant::now())),
        }
    }
}

impl<K: Clone + Eq + Hash> ExecutionRate<K> {
    /// Charge observed work exactly once, including work in a task that will
    /// subsequently be cancelled. Returning does not erase excess consumption.
    /// The rate is supplied by trusted operator policy, never by a guest.
    #[must_use]
    pub fn charge(&self, key: &K, rate: NonZeroU64, fuel: u64, now: Instant) -> Duration {
        self.maybe_prune(key, now);
        if fuel == 0 {
            return self.delay(key, rate, now);
        }
        if let Some(entry) = self.balances.get(key) {
            return entry.lock().charge(rate, fuel, now);
        }
        // Only insertion takes this lock. Match the scan's lock order
        // (maintenance then shard), and preserve its clock across eviction.
        let last_prune = self.last_prune.lock();
        let entry = self.balances.entry(key.clone()).or_insert_with(|| {
            Mutex::new(Balance {
                credit: i128::from(rate.get()) * NANOS_PER_SECOND,
                // A delayed sample may arrive after this identity was pruned.
                // Do not restart its clock before the completed cleanup scan.
                updated: now.max(*last_prune),
                rate,
            })
        });
        drop(last_prune);
        entry.lock().charge(rate, fuel, now)
    }

    fn maybe_prune(&self, active: &K, now: Instant) {
        if self.balances.len() <= PRUNE_THRESHOLD {
            return;
        }
        let Some(mut last) = self.last_prune.try_lock() else {
            return;
        };
        if now.saturating_duration_since(*last) < PRUNE_INTERVAL {
            return;
        }
        *last = now;
        // No map/cell guard is held by this caller. Retain serializes eviction
        // with charge/delay via the shard guard; a detached balance cannot be
        // charged after removal. Never erase debt or partially spent credit.
        self.balances.retain(|key, cell| {
            if key == active {
                return true;
            }
            let Some(mut balance) = cell.try_lock() else {
                return true;
            };
            let rate = balance.rate;
            balance.refresh(rate, now);
            balance.credit < i128::from(rate.get()) * NANOS_PER_SECOND
        });
    }

    /// Recheck shared debt after waiting. Another principal may have charged
    /// more work in the meantime, so a previously returned delay is not a permit.
    #[must_use]
    pub fn delay(&self, key: &K, rate: NonZeroU64, now: Instant) -> Duration {
        let Some(entry) = self.balances.get(key) else {
            return Duration::ZERO;
        };
        let mut balance = entry.lock();
        balance.refresh(rate, now);
        balance.recheck_delay()
    }
}

impl Balance {
    fn charge(&mut self, rate: NonZeroU64, fuel: u64, now: Instant) -> Duration {
        self.refresh(rate, now);
        // Saturation fails closed: accumulated debt can never wrap into credit.
        self.credit = self
            .credit
            .saturating_sub(i128::from(fuel) * NANOS_PER_SECOND);
        self.recheck_delay()
    }

    fn refresh(&mut self, rate: NonZeroU64, now: Instant) {
        // A stale timestamp must not move the accounting clock backwards and
        // let a later caller earn the same time twice.
        let elapsed = now.saturating_duration_since(self.updated);
        let refill = elapsed
            .as_nanos()
            .saturating_mul(u128::from(self.rate.get()));
        let refill = i128::try_from(refill).unwrap_or(i128::MAX);
        self.credit = self
            .credit
            .saturating_add(refill)
            .min(i128::from(rate.get()) * NANOS_PER_SECOND);
        self.updated = self.updated.max(now);
        self.rate = rate;
    }

    fn recheck_delay(&self) -> Duration {
        if self.credit >= 0 {
            return Duration::ZERO;
        }
        let nanos = self
            .credit
            .unsigned_abs()
            .div_ceil(u128::from(self.rate.get()));
        // Wake at least once per accounting second to recheck shared policy;
        // the debt itself is NOT capped or reset. Also avoids Instant overflow
        // for enormous debt at very small configured rates.
        Duration::from_nanos(nanos.min(1_000_000_000) as u64)
    }
}
