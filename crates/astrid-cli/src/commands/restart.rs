//! `astrid restart` — graceful daemon restart.
//!
//! Sends `Shutdown` to the running daemon (same path as `astrid stop`),
//! confirms the old process has exited, then spawns a new persistent daemon
//! (same path as `astrid start`).

use anyhow::Result;
use std::process::ExitCode;

use crate::commands::{daemon, daemon_control};
use crate::socket_client;
use crate::theme::Theme;

/// Entry point for `astrid restart`.
pub(crate) async fn run() -> Result<ExitCode> {
    anyhow::ensure!(
        daemon::handle_stop().await? == daemon::StopConfirmation::ConfirmedGone,
        "cannot restart until the previous daemon is confirmed stopped"
    );

    // Transport disappearance does NOT prove the daemon process exited and
    // released the singleton/state-db lock. A wedged daemon may still be alive
    // after its endpoint is gone. Spawning now would
    // race the new daemon against a held lock and fail with "Database … is
    // already locked". Verify the recorded PID is actually gone (terminating it
    // if it survived `handle_stop`'s own kill path) before spawning.
    let pid_path = socket_client::try_pid_path()?;
    if let Some((pid, _exe)) = daemon_control::read_pid_file(&pid_path)
        && daemon_control::is_process_alive(pid)
    {
        eprintln!(
            "{}",
            Theme::warning(&format!(
                "A process holding the recorded daemon PID {pid} is still alive after stop — \
                 verifying before restart."
            ))
        );
        match daemon_control::terminate_orphan(&pid_path).await {
            daemon_control::KillOutcome::StillAlive => {
                anyhow::bail!(
                    "The previous Astrid daemon (PID {pid}) did not exit even after forced termination; \
                     refusing to start a second daemon while the lock may still be held."
                );
            },
            daemon_control::KillOutcome::Unverified(p) => {
                // Fail-secure: a live PID we can't confirm is the daemon (likely
                // PID reuse) is NOT killed. Don't blindly spawn either — if it
                // *were* the daemon, the lock is still held and the spawn would
                // fail on it anyway. Make the operator resolve it explicitly.
                anyhow::bail!(
                    "Cannot confirm PID {p} is the Astrid daemon (possible PID reuse); \
                     refusing to auto-restart. Inspect PID {p} — if it is not Astrid, \
                     remove {} and retry.",
                    pid_path.display()
                );
            },
            _ => {
                let _ = std::fs::remove_file(&pid_path);
            },
        }
    }

    daemon::spawn_persistent_daemon().await?;
    Ok(ExitCode::SUCCESS)
}
