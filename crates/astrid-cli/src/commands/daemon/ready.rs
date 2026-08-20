//! Daemon ready-wait budget and the no-kill cutover policy.
//!
//! `astrid start` used to hardcode a 60s wait and SIGKILL the child when the
//! sentinel was late. Layout-1 first cutover can import audit for longer than
//! that, so the wait is `timeouts.daemon_ready_secs` and a still-running child
//! is disowned rather than killed.

use std::path::Path;
use std::process::{Child, ExitStatus};
use std::time::Duration;

pub(super) const DAEMON_READY_POLL_MILLIS: u64 = 50;
pub(super) const DAEMON_READY_POLL: Duration = Duration::from_millis(DAEMON_READY_POLL_MILLIS);

pub(super) const fn readiness_attempts(timeout_secs: u64, poll_millis: u64) -> u64 {
    match timeout_secs.checked_mul(1_000) {
        Some(timeout_millis) => timeout_millis.div_ceil(poll_millis),
        // Operator-settable u64; do not panic after spawn. Overflow means
        // "wait while the child lives".
        None => u64::MAX,
    }
}

pub(super) fn daemon_ready_timeout_secs(workspace_root: Option<&Path>) -> u64 {
    let default = astrid_config::TimeoutsSection::default().daemon_ready_secs;
    let workspace_root = workspace_root
        .map(Path::to_path_buf)
        .or_else(|| std::env::current_dir().ok());
    astrid_config::Config::load_with_layout(
        workspace_root.as_deref(),
        crate::workspace_layout::current(),
    )
    .ok()
    .map_or(default, |resolved| {
        resolved.config.timeouts.daemon_ready_secs
    })
}

/// Result of polling the ready sentinel without signalling the child.
#[derive(Debug)]
pub(super) enum ReadyWaitOutcome {
    Ready,
    ChildExited(ExitStatus),
    StillRunning,
}

pub(super) async fn wait_for_ready(
    ready_path: &Path,
    child: &mut Child,
    timeout_secs: u64,
) -> ReadyWaitOutcome {
    let attempts = readiness_attempts(timeout_secs, DAEMON_READY_POLL_MILLIS);
    for _ in 0..attempts {
        tokio::time::sleep(DAEMON_READY_POLL).await;
        if ready_path.exists() {
            return ReadyWaitOutcome::Ready;
        }
        if let Ok(Some(status)) = child.try_wait() {
            return ReadyWaitOutcome::ChildExited(status);
        }
    }
    match child.try_wait() {
        Ok(Some(status)) => ReadyWaitOutcome::ChildExited(status),
        _ => ReadyWaitOutcome::StillRunning,
    }
}

/// Drop a spawned daemon without SIGKILL when it is still running.
pub(crate) fn disown_if_still_running(mut child: Child) {
    match child.try_wait() {
        Ok(Some(_)) => {
            let _ = child.wait();
        },
        _ => drop(child),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_ready_wait_is_ten_minutes() {
        assert_eq!(
            astrid_config::TimeoutsSection::default().daemon_ready_secs,
            600
        );
        assert_eq!(
            readiness_attempts(600, DAEMON_READY_POLL_MILLIS)
                .checked_mul(DAEMON_READY_POLL_MILLIS)
                .expect("readiness window fits"),
            600_000
        );
    }

    #[test]
    fn legacy_sixty_second_window_still_computes() {
        assert_eq!(
            readiness_attempts(60, DAEMON_READY_POLL_MILLIS)
                .checked_mul(DAEMON_READY_POLL_MILLIS)
                .expect("legacy window fits"),
            60_000
        );
    }

    #[test]
    fn max_daemon_ready_secs_does_not_overflow_attempt_count() {
        assert_eq!(
            readiness_attempts(u64::MAX, DAEMON_READY_POLL_MILLIS),
            u64::MAX
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn persistent_start_does_not_kill_a_still_running_cutover() {
        let temp = tempfile::tempdir().expect("temp dir");
        let ready_path = temp.path().join("system.ready");
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn sleep");
        let outcome = wait_for_ready(&ready_path, &mut child, 1).await;
        assert!(
            matches!(outcome, ReadyWaitOutcome::StillRunning),
            "expected still-running cutover, got {outcome:?}"
        );
        assert!(
            child.try_wait().expect("try_wait").is_none(),
            "persistent start must not SIGKILL a live first cutover"
        );
        let _ = child.kill();
        let _ = child.wait();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unready_wait_reports_an_exited_child() {
        let temp = tempfile::tempdir().expect("temp dir");
        let ready_path = temp.path().join("system.ready");
        let mut child = std::process::Command::new("true")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn true");
        let outcome = wait_for_ready(&ready_path, &mut child, 1).await;
        assert!(
            matches!(outcome, ReadyWaitOutcome::ChildExited(_)),
            "expected exited child, got {outcome:?}"
        );
    }
}
