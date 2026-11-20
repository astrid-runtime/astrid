//! IPC rate limiter for publish events.
//!
//! Buckets are keyed by `(capsule_uuid, principal)` so two principals sharing
//! a single capsule instance cannot starve each other's throughput budget. The
//! per-principal ceiling is supplied by the caller (from
//! `PrincipalProfile::quotas::max_ipc_throughput_bytes`) and is applied
//! independently per bucket.

use std::sync::atomic::{AtomicUsize, Ordering};

use astrid_core::principal::PrincipalId;
use dashmap::mapref::entry::Entry;
use uuid::Uuid;

/// Composite bucket key: per-capsule **and** per-principal.
///
/// The rate limiter buckets traffic so Alice flooding from capsule `X` does
/// not consume Bob's budget on the same capsule `X`.
pub type RateLimiterKey = (Uuid, PrincipalId);

/// Absolute upper bound on a single IPC payload.
///
/// This is a `DoS` guard, not a per-principal dial — even a generous profile
/// should not allow one-shot allocations above this size. Deliberately kept
/// hardcoded so a malformed profile cannot raise it.
pub const MAX_IPC_PAYLOAD_BYTES: usize = 5 * 1024 * 1024;

/// Simple token-bucket rate limiter for IPC publish events.
///
/// One bucket per `(capsule_uuid, principal)` key. Each bucket carries a
/// `(window_start, bytes_sent)` pair; when the window is older than 1 second
/// it resets.
#[derive(Debug)]
pub struct IpcRateLimiter {
    state: std::sync::OnceLock<dashmap::DashMap<RateLimiterKey, (web_time::Instant, usize)>>,
    last_prune: std::sync::Mutex<web_time::Instant>,
    bucket_count: AtomicUsize,
}

impl IpcRateLimiter {
    /// Create a new IPC rate limiter. Bucket storage is allocated on the first
    /// quota check that passes the hard payload cap.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: std::sync::OnceLock::new(),
            last_prune: std::sync::Mutex::new(web_time::Instant::now()),
            bucket_count: AtomicUsize::new(0),
        }
    }

    /// Check whether a capsule + principal may publish a payload of
    /// `size_bytes`, given a per-principal throughput ceiling of
    /// `max_throughput_bytes_per_sec`.
    ///
    /// # Errors
    ///
    /// Returns an error string if the payload exceeds
    /// [`MAX_IPC_PAYLOAD_BYTES`] or if adding it would push the bucket over
    /// `max_throughput_bytes_per_sec` within the current 1-second window.
    pub fn check_quota(
        &self,
        capsule_uuid: Uuid,
        principal: &PrincipalId,
        size_bytes: usize,
        max_throughput_bytes_per_sec: usize,
    ) -> Result<(), String> {
        // Hard limit on payload size to prevent OOM, independent of the
        // per-principal throughput dial.
        if size_bytes > MAX_IPC_PAYLOAD_BYTES {
            return Err("Payload too large".to_string());
        }

        let state = self.state.get_or_init(dashmap::DashMap::new);
        let now = web_time::Instant::now();

        // Count updates are covered by the insertion shard guard or the
        // prune mutex. This avoids locking every shard just to count buckets.
        // The relaxed count only gates cleanup; quota authority remains under
        // the bucket's write guard.
        if self.bucket_count.load(Ordering::Relaxed) > 1000
            && let Ok(mut last) = self.last_prune.try_lock()
            && now.saturating_duration_since(*last).as_secs() > 60
        {
            *last = now;
            let mut removed = 0_usize;
            state.retain(|_, v| {
                let keep = now.saturating_duration_since(v.0).as_secs() < 1;
                if !keep {
                    removed = removed.saturating_add(1);
                }
                keep
            });
            // Insertions publish their count before releasing the shard guard,
            // so every removed bucket is already included in this subtraction.
            let previous = self.bucket_count.fetch_sub(removed, Ordering::Relaxed);
            debug_assert!(previous >= removed);
        }

        let key: RateLimiterKey = (capsule_uuid, principal.clone());
        let mut entry = match state.entry(key) {
            Entry::Occupied(entry) => entry.into_ref(),
            Entry::Vacant(entry) => {
                let entry = entry.insert((now, 0));
                self.bucket_count.fetch_add(1, Ordering::Relaxed);
                entry
            },
        };

        // Reset window if more than 1 second has passed
        if now.saturating_duration_since(entry.0).as_secs() >= 1 {
            entry.0 = now;
            entry.1 = 0;
        }

        if entry.1.saturating_add(size_bytes) > max_throughput_bytes_per_sec {
            return Err("Rate limit exceeded".to_string());
        }

        entry.1 = entry.1.saturating_add(size_bytes);

        Ok(())
    }
}

impl Default for IpcRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pid(name: &str) -> PrincipalId {
        PrincipalId::new(name).expect("valid principal")
    }

    const ONE_MIB: usize = 1024 * 1024;
    const TEN_MIB: usize = 10 * 1024 * 1024;

    #[test]
    fn payload_above_hard_cap_rejected_regardless_of_profile() {
        let rl = IpcRateLimiter::new();
        // Even with a huge profile quota, the hard payload cap still fires.
        let err = rl
            .check_quota(
                Uuid::new_v4(),
                &pid("alice"),
                MAX_IPC_PAYLOAD_BYTES + 1,
                usize::MAX,
            )
            .expect_err("payload > 5 MiB must reject");
        assert!(err.contains("Payload too large"));
    }

    #[test]
    fn single_principal_honors_profile_ceiling() {
        let rl = IpcRateLimiter::new();
        let cap = Uuid::new_v4();
        let p = pid("alice");

        // 1 MiB cap: first 1 MiB send OK, next byte fails.
        rl.check_quota(cap, &p, ONE_MIB, ONE_MIB)
            .expect("first send fits");
        let err = rl
            .check_quota(cap, &p, 1, ONE_MIB)
            .expect_err("next byte should bust the 1 MiB cap");
        assert!(err.contains("Rate limit exceeded"));
    }

    #[test]
    fn two_principals_have_independent_buckets() {
        let rl = IpcRateLimiter::new();
        let cap = Uuid::new_v4();
        let alice = pid("alice");
        let bob = pid("bob");

        // Alice saturates her 1 MiB bucket.
        rl.check_quota(cap, &alice, ONE_MIB, ONE_MIB)
            .expect("alice fills her bucket");
        assert!(
            rl.check_quota(cap, &alice, 1, ONE_MIB).is_err(),
            "alice must be rate-limited now"
        );

        // Bob on the same capsule is untouched.
        rl.check_quota(cap, &bob, ONE_MIB, TEN_MIB)
            .expect("bob unaffected");
        rl.check_quota(cap, &bob, ONE_MIB, TEN_MIB)
            .expect("bob unaffected still");
    }

    #[test]
    fn same_principal_on_two_capsules_has_independent_buckets() {
        let rl = IpcRateLimiter::new();
        let cap_a = Uuid::new_v4();
        let cap_b = Uuid::new_v4();
        let p = pid("alice");

        rl.check_quota(cap_a, &p, ONE_MIB, ONE_MIB)
            .expect("cap_a fills");
        assert!(rl.check_quota(cap_a, &p, 1, ONE_MIB).is_err());

        // Same principal on a different capsule is independent — capsule_uuid
        // is part of the key, intentional for per-capsule isolation.
        rl.check_quota(cap_b, &p, ONE_MIB, ONE_MIB)
            .expect("cap_b independent");
    }

    #[test]
    fn window_resets_after_one_second() {
        // Sleeping 1s in a unit test is ugly; this test uses a tiny quota so
        // it only needs to demonstrate reset behavior once.
        let rl = IpcRateLimiter::new();
        let cap = Uuid::new_v4();
        let p = pid("slow");

        rl.check_quota(cap, &p, 100, 100).expect("initial fits");
        assert!(rl.check_quota(cap, &p, 1, 100).is_err(), "at cap");

        std::thread::sleep(std::time::Duration::from_millis(1100));
        rl.check_quota(cap, &p, 100, 100)
            .expect("after window reset, fresh budget");
    }
}

#[cfg(test)]
mod initialization_tests;

#[cfg(all(test, unix))]
mod profile_tests;
