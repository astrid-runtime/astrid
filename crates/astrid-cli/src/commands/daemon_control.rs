//! Orphaned-daemon detection and termination for `astrid stop`/`astrid restart`.
//!
//! When the daemon socket exists but `SocketClient::connect()` fails (a hung
//! or half-dead daemon), deleting the socket file is not enough: the orphaned
//! process keeps holding the singleton lock on `run/system.lock` (and thus the
//! state-db lock), so the next `astrid start` dies with "Database … is already
//! locked by another process". This module reads the PID the daemon recorded
//! at boot (`run/system.pid`) and, if that process is still alive, signals it
//! (SIGTERM, then SIGKILL after a grace window) so the lock is released before
//! the socket/readiness/PID files are cleaned up.
//!
//! The PID is untrusted on-disk state: it may be missing, garbage, stale
//! (pointing at a recycled PID owned by an unrelated process), or already dead.
//! Every read tolerates that — a missing/garbage PID file means "no orphan to
//! kill", and a dead PID means "already gone". We never escalate to a PID we
//! cannot confirm is a live process.

use std::path::Path;
use std::time::{Duration, Instant};

/// How long to wait for a signalled daemon to exit before escalating /
/// giving up. Kept just above the kernel's own graceful-shutdown budget so a
/// daemon mid-shutdown gets a fair chance to release the lock cleanly.
pub(crate) const GRACE: Duration = Duration::from_secs(3);

/// Poll interval while waiting for a signalled process to exit.
const POLL: Duration = Duration::from_millis(100);

/// Read and parse the daemon PID from `pid_path`.
///
/// Returns `None` when the file is absent, unreadable, or does not contain a
/// single positive integer — all of which mean "no recorded daemon to signal".
/// Trailing/leading whitespace (e.g. a trailing newline) is tolerated.
pub(crate) fn read_pid_file(pid_path: &Path) -> Option<u32> {
    let contents = std::fs::read_to_string(pid_path).ok()?;
    parse_pid(&contents)
}

/// Parse a PID from raw file contents. Pure helper, split out for testing.
///
/// Accepts a single base-10 integer, ignoring surrounding whitespace. A zero
/// PID is rejected: `kill(0, …)` targets the caller's own process group, never
/// a child, so a `0` recorded in the file must never be signalled.
pub(crate) fn parse_pid(contents: &str) -> Option<u32> {
    let trimmed = contents.trim();
    let pid: u32 = trimmed.parse().ok()?;
    if pid == 0 { None } else { Some(pid) }
}

/// Check whether a process with `pid` is currently alive.
///
/// Uses `kill(pid, 0)` semantics: signal 0 performs error checking without
/// delivering a signal. A successful call (or `EPERM`, meaning the process
/// exists but is owned by another user) is treated as "alive"; `ESRCH` ("no
/// such process") is "dead". A zero/invalid PID is "dead" (nothing to signal).
#[cfg(unix)]
#[must_use]
pub(crate) fn is_process_alive(pid: u32) -> bool {
    let Ok(raw) = i32::try_from(pid) else {
        return false;
    };
    if raw <= 0 {
        return false;
    }
    let target = nix::unistd::Pid::from_raw(raw);
    // `kill(pid, 0)` succeeds when we may signal the process, and fails with
    // `EPERM` when the process exists but is owned by another user — both mean
    // "alive". Only `ESRCH` ("no such process", and anything else we can't act
    // on) is "dead".
    !matches!(
        nix::sys::signal::kill(target, None),
        Err(e) if e != nix::errno::Errno::EPERM
    )
}

#[cfg(not(unix))]
#[must_use]
pub(crate) fn is_process_alive(_pid: u32) -> bool {
    false
}

/// Send a signal to `pid`, mapping the outcome to a bool.
///
/// Returns `true` if the signal was delivered, `false` if the process was
/// already gone (`ESRCH`) or the PID is invalid. Other errors (e.g. `EPERM`)
/// also return `false` — we could not act on the process.
#[cfg(unix)]
fn signal(pid: u32, sig: nix::sys::signal::Signal) -> bool {
    let Ok(raw) = i32::try_from(pid) else {
        return false;
    };
    if raw <= 0 {
        return false;
    }
    nix::sys::signal::kill(nix::unistd::Pid::from_raw(raw), sig).is_ok()
}

#[cfg(not(unix))]
fn signal(_pid: u32, _sig: ()) -> bool {
    false
}

/// Outcome of an orphan-kill attempt, for caller-side messaging.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KillOutcome {
    /// No live process was recorded (missing/garbage/stale-dead PID) — nothing
    /// to do.
    NotRunning,
    /// The process exited after SIGTERM within the grace window.
    TermExited,
    /// The process survived SIGTERM and was escalated to SIGKILL, after which
    /// it exited.
    KilledExited,
    /// The process did not exit even after SIGKILL within the grace window.
    /// The caller should surface this — the lock may still be held.
    StillAlive,
}

/// Terminate an orphaned daemon identified by the PID in `pid_path`.
///
/// 1. Read the recorded PID; if absent/garbage/dead → [`KillOutcome::NotRunning`].
/// 2. Send `SIGTERM` and poll up to [`GRACE`] for the process to exit.
/// 3. If still alive, escalate to `SIGKILL` and poll again up to [`GRACE`].
///
/// This is the orphan path for `astrid stop`: the daemon is unreachable over
/// the socket, so a clean shutdown request is impossible. Liveness is checked
/// via the recorded PID, never via the lock directly (the CLI does not open the
/// state db), so the function is self-contained and unit-testable against any
/// PID.
pub(crate) async fn terminate_orphan(pid_path: &Path) -> KillOutcome {
    let Some(pid) = read_pid_file(pid_path) else {
        return KillOutcome::NotRunning;
    };
    if !is_process_alive(pid) {
        return KillOutcome::NotRunning;
    }

    // Politely ask it to exit; it may be wedged but still able to handle the
    // signal handler and release the lock.
    #[cfg(unix)]
    let _ = signal(pid, nix::sys::signal::Signal::SIGTERM);
    if wait_for_exit(pid, GRACE).await {
        return KillOutcome::TermExited;
    }

    // Escalate. A truly wedged process (e.g. stuck in uninterruptible IO) may
    // still survive this, but SIGKILL is the strongest tool we have and frees
    // the lock the moment the kernel reaps the process.
    #[cfg(unix)]
    let _ = signal(pid, nix::sys::signal::Signal::SIGKILL);
    if wait_for_exit(pid, GRACE).await {
        KillOutcome::KilledExited
    } else {
        KillOutcome::StillAlive
    }
}

/// Poll until `pid` is no longer alive or `budget` elapses. Returns `true` if
/// the process exited within the budget.
async fn wait_for_exit(pid: u32, budget: Duration) -> bool {
    let deadline = Instant::now()
        .checked_add(budget)
        .unwrap_or_else(Instant::now);
    loop {
        if !is_process_alive(pid) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(POLL).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_pid_accepts_plain_integer() {
        assert_eq!(parse_pid("12345"), Some(12345));
    }

    #[test]
    fn parse_pid_tolerates_trailing_newline_and_whitespace() {
        assert_eq!(parse_pid("12345\n"), Some(12345));
        assert_eq!(parse_pid("  678  "), Some(678));
    }

    #[test]
    fn parse_pid_rejects_zero() {
        // `kill(0, …)` hits the caller's own group — never signal a recorded 0.
        assert_eq!(parse_pid("0"), None);
    }

    #[test]
    fn parse_pid_rejects_garbage() {
        assert_eq!(parse_pid(""), None);
        assert_eq!(parse_pid("not-a-pid"), None);
        assert_eq!(parse_pid("-1"), None);
        assert_eq!(parse_pid("12.5"), None);
    }

    #[test]
    fn read_pid_file_missing_is_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("system.pid");
        assert_eq!(read_pid_file(&path), None);
    }

    #[test]
    fn read_pid_file_round_trips_written_pid() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("system.pid");
        std::fs::write(&path, "424242").unwrap();
        assert_eq!(read_pid_file(&path), Some(424242));
    }

    #[test]
    fn read_pid_file_garbage_is_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("system.pid");
        std::fs::write(&path, "garbage\n").unwrap();
        assert_eq!(read_pid_file(&path), None);
    }

    #[cfg(unix)]
    #[test]
    fn current_process_is_alive() {
        // Our own PID must register as alive.
        assert!(is_process_alive(std::process::id()));
    }

    #[cfg(unix)]
    #[test]
    fn nonexistent_pid_is_dead() {
        // A PID that is essentially never assigned. The kernel's pid_max on
        // Linux/macOS is well below this; even if recycled it would be ours to
        // not own. `is_process_alive` must report dead (ESRCH).
        // Use a high but valid i32 PID that no real process will hold in test.
        assert!(!is_process_alive(0)); // zero rejected outright
        // A very high PID is overwhelmingly unlikely to be live in CI.
        assert!(!is_process_alive(2_000_000_000));
    }

    #[tokio::test]
    async fn terminate_orphan_missing_pidfile_is_notrunning() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("system.pid");
        assert_eq!(terminate_orphan(&path).await, KillOutcome::NotRunning);
    }

    #[tokio::test]
    async fn terminate_orphan_dead_pid_is_notrunning() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("system.pid");
        std::fs::write(&path, "2000000000").unwrap();
        assert_eq!(terminate_orphan(&path).await, KillOutcome::NotRunning);
    }
}
