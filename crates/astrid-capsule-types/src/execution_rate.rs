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

struct Balance {
    credit: i128,
    updated: Instant,
    rate: NonZeroU64,
}

/// Shared debt for one authority domain, keyed by principal or accountable user.
/// Clones share balances; constructing one per capsule would defeat aggregation.
pub struct ExecutionRate<K> {
    balances: Arc<DashMap<K, Mutex<Balance>>>,
}

impl<K> Clone for ExecutionRate<K> {
    fn clone(&self) -> Self {
        Self {
            balances: Arc::clone(&self.balances),
        }
    }
}

impl<K: Eq + Hash> Default for ExecutionRate<K> {
    fn default() -> Self {
        Self {
            balances: Arc::new(DashMap::new()),
        }
    }
}

impl<K: Clone + Eq + Hash> ExecutionRate<K> {
    /// Charge observed work exactly once, including work in a task that will
    /// subsequently be cancelled. Returning does not erase excess consumption.
    /// The rate is supplied by trusted operator policy, never by a guest.
    #[must_use]
    pub fn charge(&self, key: &K, rate: NonZeroU64, fuel: u64, now: Instant) -> Duration {
        let entry = self.balances.entry(key.clone()).or_insert_with(|| {
            Mutex::new(Balance {
                credit: i128::from(rate.get()) * NANOS_PER_SECOND,
                updated: now,
                rate,
            })
        });
        let mut balance = entry.lock();
        balance.refresh(rate, now);
        // Saturation fails closed: accumulated debt can never wrap into credit.
        balance.credit = balance
            .credit
            .saturating_sub(i128::from(fuel) * NANOS_PER_SECOND);
        balance.recheck_delay()
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
