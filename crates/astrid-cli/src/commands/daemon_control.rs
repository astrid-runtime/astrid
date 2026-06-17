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
//! kill", and a dead PID means "already gone".
//!
//! Liveness alone is NOT sufficient to signal: a recycled PID may now belong to
//! an unrelated process, and killing it would be a serious fail-open. So the
//! daemon also records its canonicalized executable path in the PID file, and
//! we signal ONLY when the live process's executable matches it. If the
//! recorded exe is absent (old single-line file or a daemon that couldn't
//! resolve its own path), the live exe is unreadable, or the two differ, we
//! refuse to signal ([`KillOutcome::Unverified`]) — a stuck lock is recoverable;
//! killing the wrong process is not.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// How long to wait for a signalled daemon to exit before escalating /
/// giving up. Kept just above the kernel's own graceful-shutdown budget so a
/// daemon mid-shutdown gets a fair chance to release the lock cleanly.
pub(crate) const GRACE: Duration = Duration::from_secs(3);

/// Poll interval while waiting for a signalled process to exit.
const POLL: Duration = Duration::from_millis(100);

/// Read and parse the daemon PID (and recorded executable path) from `pid_path`.
///
/// Returns `None` when the file is absent, unreadable, or its first line is not
/// a single positive integer — all of which mean "no recorded daemon to
/// signal". The optional second line is the daemon's canonicalized executable
/// path, used to verify the live process's identity before signalling; it is
/// `None` for legacy single-line files or daemons that couldn't resolve their
/// own path.
pub(crate) fn read_pid_file(pid_path: &Path) -> Option<(u32, Option<PathBuf>)> {
    let contents = std::fs::read_to_string(pid_path).ok()?;
    parse_pid_file(&contents)
}

/// Parse the PID-file body: first line = PID (required), optional second line =
/// the daemon's recorded executable path. Pure helper, split out for testing.
pub(crate) fn parse_pid_file(contents: &str) -> Option<(u32, Option<PathBuf>)> {
    let mut lines = contents.lines();
    let pid = parse_pid(lines.next()?)?;
    let exe = lines
        .next()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(PathBuf::from);
    Some((pid, exe))
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

/// Resolve the canonicalized executable path of the live process `pid`.
///
/// Returns `None` when it can't be determined — the process is gone, we lack
/// permission, or the platform is unsupported. The caller treats `None` as
/// "cannot confirm identity" and refuses to signal (fail-secure).
#[cfg(target_os = "linux")]
fn exe_path_of_pid(pid: u32) -> Option<PathBuf> {
    let raw = std::fs::read_link(format!("/proc/{pid}/exe")).ok()?;
    std::fs::canonicalize(raw).ok()
}

// Single vetted FFI exception in an otherwise `#![deny(unsafe_code)]` crate:
// macOS has no `/proc`, so resolving another process's executable (needed to
// confirm a recorded PID is still the daemon before signalling) requires the
// `proc_pidpath` syscall. The call is bounded and its safety is argued inline.
#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
fn exe_path_of_pid(pid: u32) -> Option<PathBuf> {
    // `PROC_PIDPATHINFO_MAXSIZE` = 4 * MAXPATHLEN (4096) = 16384. A fixed
    // stack buffer of that exact size avoids a heap allocation per call.
    let mut buf = [0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    let raw = i32::try_from(pid).ok()?;
    let buf_len = u32::try_from(buf.len()).ok()?;
    // SAFETY: `proc_pidpath` writes at most `buf_len` bytes into `buf`,
    // returning the count written (> 0) or <= 0 on error. We pass the true
    // buffer length and only read the returned count.
    let n = unsafe { libc::proc_pidpath(raw, buf.as_mut_ptr().cast::<libc::c_void>(), buf_len) };
    if n <= 0 {
        return None;
    }
    let len = usize::try_from(n).ok()?;
    let path = std::str::from_utf8(buf.get(..len)?).ok()?;
    std::fs::canonicalize(path).ok()
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn exe_path_of_pid(_pid: u32) -> Option<PathBuf> {
    None
}

/// Whether a live process's executable matches the daemon's recorded one.
///
/// Fail-secure: `true` ONLY when both the recorded path (from the PID file) and
/// the live path (from the OS) are present AND equal. A missing either side is
/// "cannot confirm" → `false` → do not signal. Both paths are canonicalized at
/// their source (write time / read time), so a plain equality compare is exact.
fn exe_matches(recorded: Option<&Path>, live: Option<&Path>) -> bool {
    matches!((recorded, live), (Some(r), Some(l)) if r == l)
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
    /// A live process holds the recorded PID, but we could NOT confirm it is the
    /// Astrid daemon (no recorded exe, unreadable live exe, or a mismatch —
    /// likely PID reuse). We refuse to signal it; the caller should warn and
    /// leave the process alone. Carries the PID for the operator message.
    Unverified(u32),
}

/// Terminate an orphaned daemon identified by the PID in `pid_path`.
///
/// 1. Read the recorded PID; if absent/garbage/dead → [`KillOutcome::NotRunning`].
/// 2. Confirm the live process is the daemon (its executable matches the one
///    recorded in the PID file); if not → [`KillOutcome::Unverified`] (no signal).
/// 3. Send `SIGTERM` and poll up to [`GRACE`] for the process to exit.
/// 4. If still alive, escalate to `SIGKILL` and poll again up to [`GRACE`].
///
/// This is the orphan path for `astrid stop`: the daemon is unreachable over
/// the socket, so a clean shutdown request is impossible. Liveness is checked
/// via the recorded PID, never via the lock directly (the CLI does not open the
/// state db), so the function is self-contained and unit-testable against any
/// PID.
pub(crate) async fn terminate_orphan(pid_path: &Path) -> KillOutcome {
    let Some((pid, recorded_exe)) = read_pid_file(pid_path) else {
        return KillOutcome::NotRunning;
    };
    if !is_process_alive(pid) {
        return KillOutcome::NotRunning;
    }

    // Identity gate (fail-secure): a live PID is not enough — it may be a
    // recycled PID now owned by an unrelated process. Only signal when the live
    // process's executable provably matches the daemon's recorded one. Anything
    // unconfirmable → leave it alone.
    let live_exe = exe_path_of_pid(pid);
    if !exe_matches(recorded_exe.as_deref(), live_exe.as_deref()) {
        return KillOutcome::Unverified(pid);
    }

    // Politely ask it to exit; it may be wedged but still able to handle the
    // signal handler and release the lock.
    #[cfg(unix)]
    let _ = signal(pid, nix::sys::signal::Signal::SIGTERM);
    if wait_for_exit(pid, GRACE).await {
        return KillOutcome::TermExited;
    }

    // Re-verify identity before escalating (fail-secure, grace-window race): the
    // daemon may have exited cleanly during the grace window and the OS may have
    // recycled its PID for an unrelated process. In that case `wait_for_exit`
    // returns false (the recycled PID is alive), but escalating to SIGKILL here
    // would kill an innocent process. Recompute the live exe and refuse to
    // signal unless it still provably matches the recorded daemon exe.
    let live_exe = exe_path_of_pid(pid);
    if !exe_matches(recorded_exe.as_deref(), live_exe.as_deref()) {
        return KillOutcome::Unverified(pid);
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
    fn read_pid_file_round_trips_pid_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("system.pid");
        std::fs::write(&path, "424242").unwrap();
        assert_eq!(read_pid_file(&path), Some((424242, None)));
    }

    #[test]
    fn parse_pid_file_two_line_keeps_exe() {
        let (pid, exe) = parse_pid_file("424242\n/opt/astrid/astrid-daemon\n").unwrap();
        assert_eq!(pid, 424242);
        assert_eq!(exe, Some(PathBuf::from("/opt/astrid/astrid-daemon")));
    }

    #[test]
    fn parse_pid_file_one_line_has_no_exe() {
        assert_eq!(parse_pid_file("424242\n"), Some((424242, None)));
        assert_eq!(parse_pid_file("424242\n   \n"), Some((424242, None)));
    }

    #[test]
    fn parse_pid_file_rejects_garbage_first_line() {
        assert_eq!(parse_pid_file("nope\n/path"), None);
        assert_eq!(parse_pid_file(""), None);
    }

    #[test]
    fn exe_matches_only_when_both_present_and_equal() {
        let a = PathBuf::from("/opt/astrid/astrid-daemon");
        let b = PathBuf::from("/usr/bin/something-else");
        assert!(exe_matches(Some(&a), Some(&a)));
        assert!(!exe_matches(Some(&a), Some(&b)));
        assert!(!exe_matches(None, Some(&a))); // no recorded exe → unconfirmable
        assert!(!exe_matches(Some(&a), None)); // live exe unreadable → unconfirmable
        assert!(!exe_matches(None, None));
    }

    /// REGRESSION (PID reuse): a pidfile whose PID is a real LIVE process (the
    /// test runner itself) but whose recorded exe does NOT match must return
    /// `Unverified` and NEVER signal. If the identity guard regressed, this test
    /// would SIGTERM/SIGKILL the test process — its survival IS the assertion.
    #[tokio::test]
    async fn terminate_orphan_refuses_mismatched_exe_for_live_pid() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("system.pid");
        let me = std::process::id();
        std::fs::write(
            &path,
            format!("{me}\n/nonexistent/definitely-not-astrid-daemon"),
        )
        .unwrap();
        assert_eq!(
            terminate_orphan(&path).await,
            KillOutcome::Unverified(me),
            "a live PID with a mismatched exe must not be signalled"
        );
        // Still here → we did not signal ourselves.
        assert!(is_process_alive(me));
    }

    /// A legacy single-line pidfile (PID only, no recorded exe) pointing at a
    /// live process is also unconfirmable → `Unverified`, not killed.
    #[tokio::test]
    async fn terminate_orphan_refuses_live_pid_without_recorded_exe() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("system.pid");
        let me = std::process::id();
        std::fs::write(&path, format!("{me}")).unwrap();
        assert_eq!(terminate_orphan(&path).await, KillOutcome::Unverified(me));
        assert!(is_process_alive(me));
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

    /// The SIGKILL escalation is gated by the SAME identity check as the initial
    /// SIGTERM ([`exe_matches`]): a live PID whose exe no longer matches the
    /// recorded daemon must yield `Unverified` rather than be killed. This
    /// asserts the gate predicate directly.
    ///
    /// A fully deterministic test of the live grace-window race — daemon exits
    /// AND the OS recycles its exact PID to an unrelated process between SIGTERM
    /// and SIGKILL — is impractical: it would require driving real PID reuse on a
    /// known PID within a ~3s window, which is racy and OS-scheduler-dependent.
    /// The `terminate_orphan_refuses_*` tests above already prove the pre-SIGTERM
    /// gate against a live mismatched PID (the test runner itself); the
    /// escalation re-verification reuses that identical predicate, so the gate's
    /// correctness is what we assert here.
    #[test]
    fn escalation_identity_gate_refuses_on_mismatch() {
        let recorded = PathBuf::from("/opt/astrid/astrid-daemon");
        // Recycled PID now runs an unrelated binary → must not be killed.
        let recycled = PathBuf::from("/usr/bin/unrelated-process");
        assert!(
            !exe_matches(Some(&recorded), Some(&recycled)),
            "escalation must refuse to SIGKILL when the live exe no longer matches"
        );
        // Recorded exe still resolves to the same binary → escalation proceeds.
        assert!(exe_matches(Some(&recorded), Some(&recorded)));
    }
}
