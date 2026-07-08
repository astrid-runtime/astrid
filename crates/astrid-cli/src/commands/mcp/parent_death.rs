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
//! macOS, or a subreaper (systemd user services) — so the parent pid CHANGES
//! from the value captured at startup. It needs no `unsafe`/platform-specific
//! syscalls and works identically on macOS and Linux.
//!
//! A pid-1 initial parent is deliberately NOT treated as death. It is ambiguous:
//! the shim may have been launched directly under init (a container whose client
//! IS pid 1, or a systemd/launchd service), where it must KEEP serving — or the
//! real parent may have died before we captured its pid. Reparenting can't
//! distinguish these (init never reparents), and exiting would kill a
//! legitimately init-launched server, so ppid detection is disabled in that
//! case and the shim relies on its stdin-EOF path instead (a dead real parent
//! also closes the stdin pipe).
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
/// this process was reparented.
///
/// If `initial` is `1` (a pid-1 parent — launched directly under init, or
/// already reparented) detection is DISABLED: this future never resolves, so
/// the shim falls back to its stdin-EOF signal rather than exiting instantly and
/// killing a legitimately init-launched server (see the module header).
///
/// Generic over the ppid source so the poll logic is unit-testable without a
/// real fork.
async fn watch_ppid_change<F>(initial: i32, read_ppid: F, poll: Duration)
where
    F: Fn() -> i32,
{
    // A pid-1 initial parent is not watchable via reparenting (init never
    // reparents) and is ambiguous between a legitimate init-launched parent and
    // an already-orphaned shim — so provide NO signal and defer to stdin EOF.
    if initial == 1 {
        std::future::pending::<()>().await;
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
    async fn ppid_one_disables_detection_and_defers_to_stdin() {
        // A pid-1 initial parent (launched under init — container/systemd — or
        // already reparented) is ambiguous and not watchable, so detection must
        // provide NO signal: the future must NOT resolve, letting the shim rely
        // on stdin EOF rather than exiting instantly and killing a legitimately
        // init-launched server.
        let res = tokio::time::timeout(
            Duration::from_millis(80),
            watch_ppid_change(1, || 1_i32, Duration::from_millis(5)),
        )
        .await;
        assert!(
            res.is_err(),
            "ppid == 1 must NOT resolve — defer to stdin EOF, never exit instantly"
        );
    }
}
