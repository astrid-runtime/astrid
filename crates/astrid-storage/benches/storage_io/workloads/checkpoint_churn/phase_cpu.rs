//! Flat process CPU/RSS rows at checkpoint-churn phase boundaries.
//!
//! One `getrusage(RUSAGE_SELF)` per mark. User+system cover all threads during
//! the interval. Peak RSS is the cumulative lifetime high-water mark at phase
//! end (macOS/iOS bytes, Linux KiB→bytes); other Unix leave it `None`. Non-Unix
//! rows are explicit `Unavailable`, never fake zeroes.

use std::error::Error;
#[cfg(any(unix, test))]
use std::time::Duration;

use crate::report::{ProcessPhaseRecord, ProcessPhaseStatus, Report};

type CaptureResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

#[cfg(any(unix, test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ProcessCpuTimes {
    pub(super) user: Duration,
    pub(super) system: Duration,
}

#[cfg(unix)]
struct Snapshot {
    cpu: ProcessCpuTimes,
    peak_rss_bytes: Option<u64>,
}

/// Previous CPU snapshot plus outer sample index; marks push flat report rows.
pub(super) struct PhaseTimer {
    sample_index: usize,
    #[cfg(unix)]
    previous_cpu: ProcessCpuTimes,
}

impl PhaseTimer {
    pub(super) fn start(sample_index: usize) -> CaptureResult<Self> {
        Ok(Self {
            sample_index,
            #[cfg(unix)]
            previous_cpu: capture()?.cpu,
        })
    }

    pub(super) fn mark(&mut self, phase: &'static str, report: &mut Report) -> CaptureResult<()> {
        #[cfg(unix)]
        let status = {
            let snapshot = capture()?;
            let delta = checked_delta(self.previous_cpu, snapshot.cpu)?;
            self.previous_cpu = snapshot.cpu;
            ProcessPhaseStatus::Measured {
                user_cpu_nanoseconds: delta.user.as_nanos(),
                system_cpu_nanoseconds: delta.system.as_nanos(),
                process_lifetime_peak_rss_bytes: snapshot.peak_rss_bytes,
            }
        };
        #[cfg(not(unix))]
        let status = ProcessPhaseStatus::Unavailable {
            reason: "process CPU/RSS phase counters require Unix getrusage(RUSAGE_SELF)",
        };
        report.record_process_phase(ProcessPhaseRecord {
            sample_index: self.sample_index,
            phase,
            status,
        });
        Ok(())
    }
}

#[cfg(unix)]
fn capture() -> CaptureResult<Snapshot> {
    use nix::sys::resource::{UsageWho, getrusage};
    let usage = getrusage(UsageWho::RUSAGE_SELF)
        .map_err(|error| format!("getrusage(RUSAGE_SELF) failed: {error}"))?;
    Ok(Snapshot {
        cpu: ProcessCpuTimes {
            user: duration_from_timeval(usage.user_time())?,
            system: duration_from_timeval(usage.system_time())?,
        },
        peak_rss_bytes: peak_rss_bytes(usage.max_rss())?,
    })
}

#[cfg(any(unix, test))]
pub(super) fn checked_delta(
    before: ProcessCpuTimes,
    after: ProcessCpuTimes,
) -> Result<ProcessCpuTimes, String> {
    let user = after.user.checked_sub(before.user).ok_or_else(|| {
        format!(
            "process user CPU went backwards: before={:?} after={:?}",
            before.user, after.user
        )
    })?;
    let system = after.system.checked_sub(before.system).ok_or_else(|| {
        format!(
            "process system CPU went backwards: before={:?} after={:?}",
            before.system, after.system
        )
    })?;
    Ok(ProcessCpuTimes { user, system })
}

#[cfg(unix)]
fn duration_from_timeval(time: nix::sys::time::TimeVal) -> CaptureResult<Duration> {
    let seconds = u64::try_from(time.tv_sec())
        .map_err(|_| "getrusage returned negative CPU timeval seconds")?;
    let microseconds = u32::try_from(time.tv_usec())
        .map_err(|_| "getrusage returned negative or oversized CPU timeval microseconds")?;
    let nanos = microseconds
        .checked_mul(1_000)
        .ok_or("getrusage CPU timeval microsecond overflow")?;
    Ok(Duration::new(seconds, nanos))
}

#[cfg(unix)]
fn peak_rss_bytes(max_rss: libc::c_long) -> CaptureResult<Option<u64>> {
    if cfg!(any(target_os = "macos", target_os = "ios")) {
        Ok(Some(
            u64::try_from(max_rss).map_err(|_| "getrusage returned negative ru_maxrss")?,
        ))
    } else if cfg!(target_os = "linux") {
        let kib = u64::try_from(max_rss).map_err(|_| "getrusage returned negative ru_maxrss")?;
        Ok(Some(
            kib.checked_mul(1024)
                .ok_or("ru_maxrss KiB to bytes overflow")?,
        ))
    } else {
        Ok(None)
    }
}
