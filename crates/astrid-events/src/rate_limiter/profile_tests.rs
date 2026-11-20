//! Opt-in release-mode profiling; no allocation observer or production hook.
use std::hint::black_box;
use std::sync::Arc;
use std::time::Duration;

use astrid_core::PrincipalId;
use nix::sys::resource::{UsageWho, getrusage};
use nix::sys::time::TimeValLike as _;
use uuid::Uuid;

use super::IpcRateLimiter;

fn cpu_micros() -> i64 {
    let usage = getrusage(UsageWho::RUSAGE_SELF).unwrap();
    usage
        .user_time()
        .num_microseconds()
        .checked_add(usage.system_time().num_microseconds())
        .unwrap()
}

#[test]
#[ignore = "Opt-in native release profile; not a CI timing gate"]
fn mature_quota_profile() {
    for (workers, split, count, extra_buckets) in [
        (1, false, 500_000, 0),
        (4, false, 100_000, 0),
        (16, false, 25_000, 0),
        (4, true, 100_000, 0),
        (16, true, 25_000, 0),
        (1, false, 500_000, 1000),
    ] {
        let limiter = Arc::new(IpcRateLimiter::new());
        let principal = PrincipalId::new("rate-bench").unwrap();
        let keys = (0_u128..workers)
            .map(|index| {
                Uuid::from_u128(if split {
                    index.checked_add(1).unwrap()
                } else {
                    1
                })
            })
            .collect::<Vec<_>>();
        for key in &keys {
            limiter
                .check_quota(*key, &principal, 0, usize::MAX)
                .unwrap();
        }
        for extra in 0_u128..extra_buckets {
            let key = Uuid::from_u128(extra.checked_add(10_000).unwrap());
            limiter.check_quota(key, &principal, 0, usize::MAX).unwrap();
        }
        // Exercise the real mature path immediately, without a
        // minute-long sleep or exposing a clock setter in the library API.
        *limiter.last_prune.lock().unwrap() = web_time::Instant::now()
            .checked_sub(Duration::from_mins(2))
            .unwrap();
        let cpu_before = cpu_micros();
        let started = std::time::Instant::now();
        std::thread::scope(|scope| {
            for key in &keys {
                let (limiter, principal) = (&limiter, &principal);
                scope.spawn(move || {
                    for _ in 0..count {
                        black_box(limiter)
                            .check_quota(
                                black_box(*key),
                                black_box(principal),
                                black_box(1),
                                usize::MAX,
                            )
                            .unwrap();
                    }
                });
            }
        });
        let wall = started.elapsed();
        let cpu = cpu_micros().checked_sub(cpu_before).unwrap();
        println!(
            "{}",
            serde_json::json!({"workers":workers,"split":split,"count":count,"extra_buckets":extra_buckets,
                "cpu_micros":cpu,"wall_ns":u64::try_from(wall.as_nanos()).unwrap()})
        );
    }
}
