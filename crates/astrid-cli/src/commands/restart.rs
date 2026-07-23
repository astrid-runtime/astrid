//! `astrid restart` — graceful daemon restart.
//!
//! Sends `Shutdown` to the running daemon (same path as `astrid stop`),
//! waits for the socket to close, then spawns a new persistent daemon
//! (same path as `astrid start`). Operators expect the equivalent of
//! `kill -HUP` for picking up new capsule installs.

use std::process::ExitCode;
use std::time::{Duration, Instant};

use anyhow::Result;
use tokio::time::sleep;

use crate::commands::{daemon, daemon_control};
use crate::socket_client;
use crate::theme::Theme;

/// Entry point for `astrid restart`.
pub(crate) async fn run() -> Result<ExitCode> {
    daemon::handle_stop().await?;

    // Wait until the socket file is gone — `handle_stop` returns as
    // soon as the daemon acknowledges the request, but the actual
    // cleanup races with that ack. We poll for the socket so the
    // following `start` doesn't see a stale path.
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(5))
        .unwrap_or_else(Instant::now);
    let socket = socket_client::proxy_socket_path();
    while astrid_core::local_transport::endpoint_is_present(&socket)? && Instant::now() < deadline {
        sleep(Duration::from_millis(100)).await;
    }
    // Best-effort cleanup if the daemon was wedged on shutdown.
    if astrid_core::local_transport::endpoint_is_present(&socket)? {
        let _ = astrid_core::local_transport::remove_endpoint(&socket);
        let _ = std::fs::remove_file(socket_client::readiness_path());
        eprintln!(
            "{}",
            Theme::warning(
                "Daemon did not exit cleanly within 5s — cleaning up stale socket and restarting."
            )
        );
    }

    // The socket file being gone does NOT prove the daemon process exited and
    // released the singleton/state-db lock — a wedged daemon `handle_stop`
    // could not reach over the socket may still be alive. Spawning now would
    // race the new daemon against a held lock and fail with "Database … is
    // already locked". Verify the recorded PID is actually gone (signalling it
    // if it survived `handle_stop`'s own kill path) before spawning.
    let pid_path = socket_client::pid_path();
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
                    "The previous Astrid daemon (PID {pid}) did not exit even after SIGKILL; \
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
