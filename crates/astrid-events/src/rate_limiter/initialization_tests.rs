use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::time::Duration;

use super::{IpcRateLimiter, MAX_IPC_PAYLOAD_BYTES};
use astrid_core::PrincipalId;
use uuid::Uuid;
use web_time::Instant;

#[test]
fn hard_cap_rejection_does_not_allocate_buckets() {
    let limiter = IpcRateLimiter::new();
    let principal = PrincipalId::new("alice").unwrap();
    assert!(limiter.state.get().is_none());
    assert_eq!(
        limiter.check_quota(
            Uuid::nil(),
            &principal,
            MAX_IPC_PAYLOAD_BYTES + 1,
            usize::MAX
        ),
        Err("Payload too large".to_owned())
    );
    assert!(limiter.state.get().is_none());
}

#[test]
fn concurrent_first_checks_share_one_bucket() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<IpcRateLimiter>();
    let limiter = Arc::new(IpcRateLimiter::new());
    let barrier = Barrier::new(16);
    let principal = PrincipalId::new("alice").unwrap();
    std::thread::scope(|scope| {
        for _ in 0..16 {
            let (limiter, barrier, principal) = (&limiter, &barrier, &principal);
            scope.spawn(move || {
                barrier.wait();
                limiter.check_quota(Uuid::nil(), principal, 0, 0).unwrap();
            });
        }
    });
    assert_eq!(limiter.state.get().unwrap().len(), 1);
    assert_eq!(limiter.bucket_count.load(Ordering::Relaxed), 1);
}

#[test]
fn concurrent_quota_is_atomic_and_isolated_by_principal_and_capsule() {
    let limiter = Arc::new(IpcRateLimiter::new());
    let keys = [
        (Uuid::from_u128(1), PrincipalId::new("alice").unwrap()),
        (Uuid::from_u128(1), PrincipalId::new("bob").unwrap()),
        (Uuid::from_u128(2), PrincipalId::new("alice").unwrap()),
        (Uuid::from_u128(2), PrincipalId::new("bob").unwrap()),
    ];
    // A future window avoids depending on host scheduling during this race.
    // Production uses saturating elapsed time, so it cannot reset these keys.
    let future = Instant::now().checked_add(Duration::from_hours(1)).unwrap();
    let state = limiter.state.get_or_init(dashmap::DashMap::new);
    for key in &keys {
        limiter.check_quota(key.0, &key.1, 0, usize::MAX).unwrap();
        *state.get_mut(key).unwrap() = (future, 0);
    }
    let admitted = std::array::from_fn::<_, 4, _>(|_| AtomicUsize::new(0));
    let barrier = Barrier::new(16);
    std::thread::scope(|scope| {
        for worker in 0..16 {
            let (limiter, barrier, admitted, keys) = (&limiter, &barrier, &admitted, &keys);
            scope.spawn(move || {
                let index = worker % keys.len();
                let (capsule, principal) = &keys[index];
                barrier.wait();
                for _ in 0..128 {
                    if limiter.check_quota(*capsule, principal, 1, 128).is_ok() {
                        admitted[index].fetch_add(1, Ordering::Relaxed);
                    }
                }
            });
        }
    });
    for count in admitted {
        assert_eq!(count.load(Ordering::Relaxed), 128);
    }
    for key in &keys {
        assert_eq!(state.get(key).unwrap().1, 128);
    }
}

#[test]
fn crossing_size_threshold_does_not_delay_prune_or_reset_live_quotas() {
    let limiter = IpcRateLimiter::new();
    let now = Instant::now();
    let expired = now.checked_sub(Duration::from_mins(2)).unwrap();
    let last = now.checked_sub(Duration::from_secs(61)).unwrap();
    *limiter.last_prune.lock().unwrap() = last;
    let principal = PrincipalId::new("alice").unwrap();
    let state = limiter.state.get_or_init(dashmap::DashMap::new);
    for index in 0..1000 {
        let key = (Uuid::from_u128(index), principal.clone());
        limiter.check_quota(key.0, &key.1, 0, usize::MAX).unwrap();
        *state.get_mut(&key).unwrap() = (expired, 1);
    }
    let live = Uuid::from_u128(1000);
    limiter.check_quota(live, &principal, 100, 100).unwrap();
    assert_eq!(state.len(), 1001, "1000 entries must not trigger prune");
    state.get_mut(&(live, principal.clone())).unwrap().0 =
        now.checked_add(Duration::from_hours(1)).unwrap();
    assert_eq!(*limiter.last_prune.lock().unwrap(), last);
    assert_eq!(
        limiter.check_quota(live, &principal, 1, 100),
        Err("Rate limit exceeded".to_owned())
    );
    assert_eq!(state.len(), 1, "stale keys should be removed at 1001");
    assert_eq!(limiter.bucket_count.load(Ordering::Relaxed), state.len());
    assert_eq!(state.get(&(live, principal)).unwrap().1, 100);
    assert!(*limiter.last_prune.lock().unwrap() > last);
}

#[test]
fn prune_interval_does_not_allow_an_early_prune() {
    let limiter = IpcRateLimiter::new();
    // Future timestamp makes the no-prune decision independent of scheduling.
    let last = Instant::now().checked_add(Duration::from_hours(1)).unwrap();
    *limiter.last_prune.lock().unwrap() = last;
    let expired = Instant::now().checked_sub(Duration::from_mins(2)).unwrap();
    let principal = PrincipalId::new("alice").unwrap();
    let state = limiter.state.get_or_init(dashmap::DashMap::new);
    for index in 0..1001 {
        let key = (Uuid::from_u128(index), principal.clone());
        limiter.check_quota(key.0, &key.1, 0, usize::MAX).unwrap();
        *state.get_mut(&key).unwrap() = (expired, 1);
    }
    limiter
        .check_quota(Uuid::from_u128(1001), &principal, 0, 0)
        .unwrap();
    assert_eq!(state.len(), 1002);
    assert_eq!(limiter.bucket_count.load(Ordering::Relaxed), state.len());
    assert_eq!(*limiter.last_prune.lock().unwrap(), last);
}

#[test]
fn concurrent_insertions_and_pruning_keep_the_bucket_count_exact() {
    let limiter = IpcRateLimiter::new();
    let principal = PrincipalId::new("alice").unwrap();
    for index in 0..1001 {
        limiter
            .check_quota(Uuid::from_u128(index), &principal, 0, 0)
            .unwrap();
    }
    let state = limiter.state.get().unwrap();
    let expired = Instant::now().checked_sub(Duration::from_mins(2)).unwrap();
    for mut entry in state.iter_mut() {
        entry.0 = expired;
    }
    *limiter.last_prune.lock().unwrap() = expired;
    let barrier = Barrier::new(16);
    std::thread::scope(|scope| {
        for worker in 0_u128..16 {
            let (limiter, barrier, principal) = (&limiter, &barrier, &principal);
            scope.spawn(move || {
                barrier.wait();
                for index in 0_u128..128 {
                    let key = worker
                        .checked_mul(128)
                        .unwrap()
                        .checked_add(index)
                        .unwrap()
                        .checked_add(1001)
                        .unwrap();
                    // Rejected quota attempts still create exactly one bucket,
                    // preserving the original limiter's accounting semantics.
                    assert!(
                        limiter
                            .check_quota(Uuid::from_u128(key), principal, 1, 0)
                            .is_err()
                    );
                }
            });
        }
    });
    assert_eq!(limiter.bucket_count.load(Ordering::Relaxed), state.len());
    // The race may legitimately expire buckets on a delayed runner. Seed a
    // fresh threshold-sized group with cleanup disabled before the second
    // prune, so this assertion does not depend on the race finishing in 1s.
    *limiter.last_prune.lock().unwrap() =
        Instant::now().checked_add(Duration::from_hours(1)).unwrap();
    for index in 0_u128..1001 {
        let key = Uuid::from_u128(index.checked_add(10_000).unwrap());
        limiter.check_quota(key, &principal, 0, 0).unwrap();
    }
    assert!(state.len() > 1000);
    // Force another real prune after the race and verify the count again.
    for mut entry in state.iter_mut() {
        entry.0 = expired;
    }
    *limiter.last_prune.lock().unwrap() = expired;
    limiter
        .check_quota(Uuid::from_u128(u128::MAX), &principal, 0, 0)
        .unwrap();
    assert_eq!(state.len(), 1);
    assert_eq!(limiter.bucket_count.load(Ordering::Relaxed), 1);
}
