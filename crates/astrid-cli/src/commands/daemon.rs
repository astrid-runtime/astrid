//! Daemon lifecycle commands: start, stop, status, and spawn helpers.

use anyhow::{Context, Result};

use crate::bootstrap::find_companion_binary;
use crate::commands::daemon_control;
use crate::{socket_client, theme};

/// Build a hint string pointing the user to the daemon log directory.
fn log_hint() -> String {
    astrid_core::dirs::AstridHome::resolve()
        .map(|h| format!(" Check logs: {}", h.log_dir().display()))
        .unwrap_or_default()
}

/// Open the daemon boot log (`log/daemon-boot.log`) for append, creating the
/// log directory if needed, so the spawned daemon's stderr is captured.
///
/// A lock-acquisition failure (or any panic) before the kernel's own tracing
/// subscriber initializes prints to stderr and is otherwise lost when stderr
/// is `Stdio::null()`. Capturing it here is the only record of why a daemon
/// died on boot. Returns `None` on any IO error, in which case the caller
/// falls back to `Stdio::null()` rather than failing the spawn.
fn boot_log_stderr() -> Option<std::process::Stdio> {
    let home = astrid_core::dirs::AstridHome::resolve().ok()?;
    let log_dir = home.log_dir();
    std::fs::create_dir_all(&log_dir).ok()?;
    let path = log_dir.join("daemon-boot.log");
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).append(true);
    // Boot stderr can carry sensitive paths/state (home layout, lock paths,
    // panic backtraces) — create it owner-only so other users can't read it.
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let file = opts.open(path).ok()?;
    Some(std::process::Stdio::from(file))
}

/// Spawn the daemon process and wait for it to signal readiness.
///
/// Returns the child process handle on success. The caller must `drop()` it
/// after a successful handshake (to disown), or `kill()` + `wait()` on failure.
///
/// # Errors
/// Returns an error if the daemon binary is not found, fails to spawn, or
/// doesn't become ready within 10 seconds.
pub(crate) async fn spawn_daemon(ready_path: &std::path::Path) -> Result<std::process::Child> {
    println!("{}", theme::Theme::info("Booting Astrid daemon..."));
    let ws = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    let daemon_bin = find_companion_binary("astrid-daemon")?;

    let mut cmd = std::process::Command::new(daemon_bin);
    cmd.arg("--ephemeral");

    if let Some(ws_path) = ws.to_str() {
        cmd.arg("--workspace").arg(ws_path);
    }

    // Capture the daemon's stderr to an append log so a boot failure (lock
    // contention, panic before tracing init) leaves a record instead of
    // vanishing into /dev/null. Stdout stays null — the daemon logs through
    // tracing, not stdout. Fall back to null if the log file can't be opened.
    let stderr = boot_log_stderr().unwrap_or_else(std::process::Stdio::null);
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(stderr);

    // Remove stale readiness file before spawning so we don't
    // mistake a leftover from a crashed daemon for the new one.
    let _ = std::fs::remove_file(ready_path);

    let mut child = cmd
        .spawn()
        .context("Failed to spawn background Kernel daemon")?;

    // Poll for the readiness sentinel instead of the socket file.
    // The readiness file is written only after load_all_capsules()
    // completes (including await_capsule_readiness()), so the accept
    // loop is guaranteed to be running by the time we connect.
    let mut ready = false;
    for _ in 0..200 {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        if ready_path.exists() {
            ready = true;
            break;
        }
        // If the daemon has already exited, stop polling immediately
        // instead of waiting the full 10 seconds.
        if let Ok(Some(status)) = child.try_wait() {
            anyhow::bail!("Daemon exited prematurely ({status}).{}", log_hint());
        }
    }
    if !ready {
        // Kill the child to prevent an orphan daemon that lingers
        // until its idle timeout expires.
        let _ = child.kill();
        let _ = child.wait();
        anyhow::bail!(
            "Daemon failed to become ready within 10 seconds.{}",
            log_hint()
        );
    }
    Ok(child)
}

/// Ensure the daemon is running, spawning it if needed.
///
/// Checks the socket path, cleans up stale sockets, and spawns a fresh
/// daemon when no live daemon is reachable.
pub(crate) async fn ensure_daemon(label: &str) -> Result<()> {
    let socket_path = socket_client::proxy_socket_path();
    let ready_path = socket_client::readiness_path();

    let needs_boot = if socket_path.exists() {
        if tokio::net::UnixStream::connect(&socket_path).await.is_ok() {
            eprintln!("[{label}] Connected to existing daemon");
            false
        } else {
            let _ = std::fs::remove_file(&socket_path);
            let _ = std::fs::remove_file(&ready_path);
            true
        }
    } else {
        true
    };
    if needs_boot {
        spawn_daemon(&ready_path).await?;
    }
    Ok(())
}

/// Spawn a persistent (non-ephemeral) daemon and wait for readiness.
pub(crate) async fn spawn_persistent_daemon() -> Result<()> {
    let ready_path = socket_client::readiness_path();
    println!(
        "{}",
        theme::Theme::info("Starting Astrid daemon (persistent mode)...")
    );
    let ws = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    let daemon_bin = find_companion_binary("astrid-daemon")?;

    let mut cmd = std::process::Command::new(daemon_bin);
    // No --ephemeral flag = persistent mode

    if let Some(ws_path) = ws.to_str() {
        cmd.arg("--workspace").arg(ws_path);
    }

    // Capture the daemon's stderr to an append log so a boot failure (lock
    // contention, panic before tracing init) leaves a record instead of
    // vanishing into /dev/null. Stdout stays null — the daemon logs through
    // tracing, not stdout. Fall back to null if the log file can't be opened.
    let stderr = boot_log_stderr().unwrap_or_else(std::process::Stdio::null);
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(stderr);

    let _ = std::fs::remove_file(&ready_path);

    let mut child = cmd.spawn().context("Failed to spawn Astrid daemon")?;

    let mut ready = false;
    for _ in 0..200 {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        if ready_path.exists() {
            ready = true;
            break;
        }
        if let Ok(Some(status)) = child.try_wait() {
            anyhow::bail!("Daemon exited prematurely ({status}).{}", log_hint());
        }
    }
    if !ready {
        let _ = child.kill();
        let _ = child.wait();
        anyhow::bail!(
            "Daemon failed to become ready within 10 seconds.{}",
            log_hint()
        );
    }

    // Disown the child — it runs independently.
    drop(child);

    println!(
        "{}",
        theme::Theme::success("Astrid daemon started (persistent mode).")
    );
    Ok(())
}

/// Handle `astrid start`.
pub(crate) async fn handle_start() -> Result<()> {
    let socket_path = socket_client::proxy_socket_path();

    // Check if daemon is already running
    if socket_path.exists() {
        if let Ok(_stream) = tokio::net::UnixStream::connect(&socket_path).await {
            println!(
                "{}",
                theme::Theme::warning("Astrid daemon is already running.")
            );
            return Ok(());
        }
        // Stale socket — clean up
        let _ = std::fs::remove_file(&socket_path);
        let _ = std::fs::remove_file(socket_client::readiness_path());
    }

    spawn_persistent_daemon().await
}

/// Handle `astrid status`.
pub(crate) async fn handle_status() -> Result<()> {
    let socket_path = socket_client::proxy_socket_path();
    if !socket_path.exists() {
        println!("{}", theme::Theme::info("No Astrid daemon is running."));
        return Ok(());
    }

    let session_id = astrid_core::SessionId::from_uuid(uuid::Uuid::new_v4());
    match socket_client::SocketClient::connect(session_id, crate::principal::current()).await {
        Ok(mut client) => {
            let req = astrid_core::kernel_api::KernelRequest::GetStatus;
            if let Ok(val) = serde_json::to_value(req) {
                let msg = astrid_types::ipc::IpcMessage::new(
                    "astrid.v1.request.status",
                    astrid_types::ipc::IpcPayload::RawJson(val),
                    uuid::Uuid::nil(),
                );
                client.send_message(msg).await?;

                let raw = client
                    .read_until_topic(
                        "astrid.v1.response.status",
                        std::time::Duration::from_secs(10),
                    )
                    .await?;
                if let Some(astrid_core::kernel_api::KernelResponse::Status(status)) =
                    crate::socket_client::SocketClient::extract_kernel_response(&raw)
                {
                    let uptime_display = format_uptime(status.uptime_secs);
                    println!(
                        "{}",
                        theme::Theme::success(&format!(
                            "Astrid daemon (PID {}, uptime {})",
                            status.pid, uptime_display
                        ))
                    );
                    println!("  Version:    {}", status.version);
                    println!("  Clients:    {}", status.connected_clients);
                    println!("  Capsules:   {} loaded", status.loaded_capsules.len());
                    for capsule in &status.loaded_capsules {
                        println!("    - {capsule}");
                    }
                } else {
                    println!("{}", theme::Theme::error("Unexpected response from daemon"));
                }
            }
        },
        Err(_) => {
            println!(
                "{}",
                theme::Theme::error(
                    "Daemon socket exists but connection failed. \
                     It may be starting up or in a bad state."
                )
            );
        },
    }
    Ok(())
}

/// Handle `astrid stop`.
pub(crate) async fn handle_stop() -> Result<()> {
    let socket_path = socket_client::proxy_socket_path();
    if !socket_path.exists() {
        println!("{}", theme::Theme::info("No Astrid daemon is running."));
        return Ok(());
    }

    let session_id = astrid_core::SessionId::from_uuid(uuid::Uuid::new_v4());
    if let Ok(mut client) =
        socket_client::SocketClient::connect(session_id, crate::principal::current()).await
    {
        let req = astrid_core::kernel_api::KernelRequest::Shutdown {
            reason: Some("astrid stop".to_string()),
        };
        if let Ok(val) = serde_json::to_value(req) {
            let msg = astrid_types::ipc::IpcMessage::new(
                "astrid.v1.request.shutdown",
                astrid_types::ipc::IpcPayload::RawJson(val),
                uuid::Uuid::nil(),
            );
            client.send_message(msg).await?;
            println!("{}", theme::Theme::success("Astrid daemon stopped."));
        }
        // The daemon removes its own PID file on graceful shutdown; clean up
        // best-effort here too in case the shutdown raced or the file was
        // left behind by an earlier wedged run.
        let _ = std::fs::remove_file(socket_client::pid_path());
    } else {
        // Socket exists but the handshake failed — the daemon is hung or
        // half-dead. Deleting the socket alone is NOT enough: the orphaned
        // process keeps holding the singleton/state-db lock, so the next
        // `astrid start` would die with "Database … is already locked". Read
        // the PID it recorded at boot and signal it (SIGTERM, then SIGKILL)
        // before cleaning up, so the lock is actually released.
        let pid_path = socket_client::pid_path();
        match daemon_control::terminate_orphan(&pid_path).await {
            daemon_control::KillOutcome::NotRunning => {
                println!("{}", theme::Theme::info("Cleaned up stale daemon socket."));
            },
            daemon_control::KillOutcome::TermExited | daemon_control::KillOutcome::KilledExited => {
                println!(
                    "{}",
                    theme::Theme::success("Stopped an unresponsive Astrid daemon.")
                );
            },
            daemon_control::KillOutcome::StillAlive => {
                eprintln!(
                    "{}",
                    theme::Theme::error(
                        "An unresponsive Astrid daemon did not exit even after SIGKILL; \
                         the state-db lock may still be held."
                    )
                );
            },
            daemon_control::KillOutcome::Unverified(pid) => {
                eprintln!(
                    "{}",
                    theme::Theme::warning(&format!(
                        "A process (PID {pid}) holds the recorded daemon PID but I can't \
                         confirm it's the Astrid daemon (possible PID reuse) — not killing it. \
                         If the daemon is genuinely stuck, inspect PID {pid} and stop it manually."
                    ))
                );
            },
        }
        let _ = std::fs::remove_file(&socket_path);
        let _ = std::fs::remove_file(socket_client::readiness_path());
        let _ = std::fs::remove_file(&pid_path);
    }
    Ok(())
}

/// Format seconds into a human-readable uptime string.
pub(crate) fn format_uptime(secs: u64) -> String {
    let hours = secs / 3600;
    let minutes = (secs % 3600) / 60;
    let seconds = secs % 60;
    if hours > 0 {
        format!("{hours}h{minutes:02}m{seconds:02}s")
    } else if minutes > 0 {
        format!("{minutes}m{seconds:02}s")
    } else {
        format!("{seconds}s")
    }
}
