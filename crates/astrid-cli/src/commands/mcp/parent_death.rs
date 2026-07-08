//! Parent-death detection for `astrid mcp serve`.
//!
//! `astrid mcp serve` runs as a child of an MCP client (Claude Desktop, an IDE,
//! another agent runtime) and normally exits when that client closes stdin
//! (EOF). But a client that DIES without closing stdin leaves the shim blocked
//! on `waiting()` forever — an orphan holding its daemon uplinks open (observed
//! in the field: a 4-day orphan, each pinning >=2 uplinks). This module
//! resolves a future when the launching parent process dies, so the shim can
//! drop its transport and free those uplinks.
//!
//! Detection is a portable, low-frequency poll of `getppid()`: when the parent
//! dies the process is reparented — to `init`/pid 1 on Linux, `launchd` on
//! macOS, or a subreaper — so the parent pid CHANGES from the value captured at
//! startup. Watching for that change subsumes the `getppid() == 1` case, also
//! handles subreapers (systemd user services), needs no `unsafe`/platform-
//! specific syscalls, and works identically on macOS and Linux.
//!
//! Stdout discipline: this module never writes to stdout (the MCP transport
//! owns it) — it only reads `getppid()` and sleeps.

use std::time::Duration;

/// Poll cadence for the parent-liveness check.
///
/// Deliberately low frequency: parent death is rare and not latency-sensitive
/// (freeing an orphan a second or two later than theoretically possible is
/// fine), so the poll stays cheap.
const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Resolve when the launching parent process dies (this process is reparented).
///
/// Captures the parent pid at call time, then polls until it changes.
pub(super) async fn wait_for_parent_death() {
    let initial = current_ppid();
    watch_ppid_change(initial, current_ppid, POLL_INTERVAL).await;
}

/// Current parent pid as a raw integer.
fn current_ppid() -> i32 {
    nix::unistd::getppid().as_raw()
}

/// Resolve once `read_ppid()` differs from `initial` — i.e. the parent died and
/// this process was reparented. Resolves IMMEDIATELY if `initial` is already the
/// orphan sentinel `1` (init/launchd): the parent died before we captured its
/// pid, so this process is already orphaned and a reparented process's ppid
/// stays `1` — polling for a change would loop forever.
///
/// Generic over the ppid source so the poll logic is unit-testable without a
/// real fork.
async fn watch_ppid_change<F>(initial: i32, read_ppid: F, poll: Duration)
where
    F: Fn() -> i32,
{
    // Already reparented at startup (parent died before we captured its pid):
    // pid 1 is the orphan sentinel and never changes, so resolve now instead of
    // polling forever. This is the `getppid() == 1` case the module doc names.
    if initial == 1 {
        return;
    }
    loop {
        tokio::time::sleep(poll).await;
        if read_ppid() != initial {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::watch_ppid_change;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicI32, Ordering};
    use std::time::Duration;

    #[tokio::test]
    async fn resolves_when_parent_pid_changes() {
        let ppid = Arc::new(AtomicI32::new(1000));
        let reader = {
            let p = Arc::clone(&ppid);
            move || p.load(Ordering::SeqCst)
        };
        // Simulate the parent dying (reparented) shortly after we start polling.
        let flipper = Arc::clone(&ppid);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            flipper.store(1, Ordering::SeqCst);
        });

        tokio::time::timeout(
            Duration::from_secs(5),
            watch_ppid_change(1000, reader, Duration::from_millis(5)),
        )
        .await
        .expect("must resolve promptly once the parent pid changes");
    }

    #[tokio::test]
    async fn does_not_resolve_while_parent_alive() {
        // A stable parent pid must NOT resolve — the shim keeps serving.
        let res = tokio::time::timeout(
            Duration::from_millis(80),
            watch_ppid_change(1000, || 1000_i32, Duration::from_millis(5)),
        )
        .await;
        assert!(res.is_err(), "must not resolve while the parent is alive");
    }

    #[tokio::test]
    async fn resolves_immediately_when_started_already_reparented() {
        // Parent died before we captured its pid → initial ppid is the orphan
        // sentinel 1, which never changes. Must resolve at once (not loop
        // forever), even with a poll interval far longer than the timeout.
        tokio::time::timeout(
            Duration::from_millis(50),
            watch_ppid_change(1, || 1_i32, Duration::from_hours(1)),
        )
        .await
        .expect("must resolve immediately when started already reparented (ppid == 1)");
    }
}
