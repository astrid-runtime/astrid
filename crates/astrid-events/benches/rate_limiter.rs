//! Public IPC quota paths with the normal allocator and no allocation logging.
//! `cargo bench -p astrid-events --bench rate_limiter -- hot 1000000 1`
//! Modes: idle constructors, first checks on preconstructed limiters, lifecycle
//! construction/check/drop, hot same-key traffic, split-key traffic, rejection.
//! Count is objects for idle/first and operations per worker otherwise. Hot
//! traffic includes scoped worker startup/join; its buckets are prewarmed.
#![deny(unsafe_code)]

use std::error::Error;
use std::hint::black_box;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Instant;

use astrid_core::PrincipalId;
use astrid_events::rate_limiter::{IpcRateLimiter, MAX_IPC_PAYLOAD_BYTES};
use uuid::Uuid;

type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Idle,
    First,
    Lifecycle,
    Hot,
    Split,
    Reject,
    Throttled,
}

fn requests(
    limiter: &IpcRateLimiter,
    id: Uuid,
    principal: &PrincipalId,
    count: usize,
) -> Result<()> {
    for _ in 0..count {
        limiter.check_quota(
            black_box(id),
            black_box(principal),
            black_box(1),
            usize::MAX,
        )?;
    }
    Ok(())
}

fn hot(
    limiter: &Arc<IpcRateLimiter>,
    keys: &[Uuid],
    principal: &PrincipalId,
    count: usize,
) -> Result<()> {
    if keys.len() == 1 {
        return requests(limiter, keys[0], principal, count);
    }
    std::thread::scope(|scope| {
        let workers = keys
            .iter()
            .map(|id| scope.spawn(move || requests(limiter, *id, principal, count)))
            .collect::<Vec<_>>();
        for worker in workers {
            worker.join().map_err(|_| "quota worker panicked")??;
        }
        Ok(())
    })
}

#[cfg(unix)]
fn counters() -> Result<(Option<u64>, Option<u64>)> {
    use nix::sys::resource::{UsageWho, getrusage};
    use nix::sys::time::TimeValLike as _;
    let usage = getrusage(UsageWho::RUSAGE_SELF)?;
    let micros = usage
        .user_time()
        .num_microseconds()
        .checked_add(usage.system_time().num_microseconds())
        .ok_or("CPU overflow")?;
    let cpu = u64::try_from(micros)?
        .checked_mul(1000)
        .ok_or("CPU overflow")?;
    let rss = u64::try_from(usage.max_rss())?;
    let rss = if cfg!(target_os = "macos") {
        Some(rss)
    } else if cfg!(target_os = "linux") {
        Some(rss.checked_mul(1024).ok_or("RSS overflow")?)
    } else {
        None
    };
    Ok((Some(cpu), rss))
}

#[cfg(not(unix))]
fn counters() -> Result<(Option<u64>, Option<u64>)> {
    Ok((None, None))
}

fn arguments() -> Result<(String, Mode, usize, usize)> {
    let args = std::env::args()
        .skip(1)
        .filter(|arg| arg != "--bench")
        .collect::<Vec<_>>();
    let args = if args.is_empty() {
        vec!["hot".to_owned(), "1000000".to_owned(), "1".to_owned()]
    } else {
        args
    };
    if args.len() != 3 {
        return Err("usage: rate_limiter <idle|first|lifecycle|hot|split|reject|throttled> <count> <workers>".into());
    }
    let mode = match args[0].as_str() {
        "idle" => Mode::Idle,
        "first" => Mode::First,
        "lifecycle" => Mode::Lifecycle,
        "hot" => Mode::Hot,
        "split" => Mode::Split,
        "reject" => Mode::Reject,
        "throttled" => Mode::Throttled,
        _ => return Err("unknown rate-limiter workload".into()),
    };
    let count = args[1].parse::<NonZeroUsize>()?.get();
    let workers = args[2].parse::<NonZeroUsize>()?.get();
    if !matches!(mode, Mode::Hot | Mode::Split) && workers != 1 {
        return Err("this mode requires one worker".into());
    }
    Ok((args[0].clone(), mode, count, workers))
}

fn main() -> Result<()> {
    let (name, mode, count, workers) = arguments()?;
    let principal = PrincipalId::new("rate-bench")?;
    let limiter = Arc::new(IpcRateLimiter::new());
    let keys = (0..workers)
        .map(|index| {
            let value = if mode == Mode::Split {
                u128::try_from(index)?
                    .checked_add(1)
                    .ok_or("key overflow")?
            } else {
                1
            };
            Ok(Uuid::from_u128(value))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut held = Vec::with_capacity(if matches!(mode, Mode::Idle | Mode::First) {
        count
    } else {
        0
    });
    if mode == Mode::First {
        for _ in 0..count {
            held.push(Arc::new(IpcRateLimiter::new()));
        }
    }
    if matches!(mode, Mode::Hot | Mode::Split) {
        for id in &keys {
            limiter.check_quota(*id, &principal, 0, usize::MAX)?;
        }
    }
    let (cpu_before, _) = counters()?;
    let started = Instant::now();
    run(mode, count, &limiter, &keys, &principal, &mut held)?;
    let wall = started.elapsed();
    let (cpu_after, rss) = counters()?;
    let cpu = match (cpu_before, cpu_after) {
        (Some(before), Some(after)) => {
            Some(after.checked_sub(before).ok_or("CPU counter reversed")?)
        },
        _ => None,
    };
    println!(
        "{}",
        serde_json::json!({"mode":name,"count":count,"workers":workers,"cpu_ns":cpu,"wall_ns":u64::try_from(wall.as_nanos())?,"process_lifetime_peak_rss_bytes":rss,"held_limiters":held.len()})
    );
    black_box(held);
    Ok(())
}

fn run(
    mode: Mode,
    count: usize,
    limiter: &Arc<IpcRateLimiter>,
    keys: &[Uuid],
    principal: &PrincipalId,
    held: &mut Vec<Arc<IpcRateLimiter>>,
) -> Result<()> {
    match mode {
        Mode::Idle => {
            for _ in 0..count {
                held.push(black_box(Arc::new(IpcRateLimiter::new())));
            }
        },
        Mode::First => {
            for item in held.iter() {
                item.check_quota(keys[0], principal, 1, usize::MAX)?;
            }
        },
        Mode::Lifecycle => {
            for _ in 0..count {
                let item = Arc::new(IpcRateLimiter::new());
                item.check_quota(keys[0], principal, 1, usize::MAX)?;
                black_box(item);
            }
        },
        Mode::Hot | Mode::Split => hot(limiter, keys, principal, count)?,
        Mode::Throttled => {
            for _ in 0..count {
                if limiter.check_quota(keys[0], principal, 1, 0).is_ok() {
                    return Err("zero quota admitted a byte".into());
                }
            }
        },
        Mode::Reject => {
            for _ in 0..count {
                if limiter
                    .check_quota(
                        keys[0],
                        principal,
                        MAX_IPC_PAYLOAD_BYTES
                            .checked_add(1)
                            .ok_or("payload overflow")?,
                        usize::MAX,
                    )
                    .is_ok()
                {
                    return Err("oversize payload was admitted".into());
                }
            }
        },
    }
    Ok(())
}
