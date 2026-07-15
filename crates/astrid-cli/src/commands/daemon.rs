//! Daemon lifecycle commands: start, stop, status, and spawn helpers.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use astrid_core::kernel_api::{DaemonStatus, KernelRequest, KernelResponse};

use crate::bootstrap::find_companion_binary;
use crate::commands::daemon_control;
use crate::{socket_client, theme};

const DAEMON_READY_TIMEOUT_SECS: u64 = 60;
const DAEMON_READY_POLL_MILLIS: u64 = 50;
const DAEMON_READY_POLL: Duration = Duration::from_millis(DAEMON_READY_POLL_MILLIS);
const DAEMON_READY_ATTEMPTS: u64 =
    readiness_attempts(DAEMON_READY_TIMEOUT_SECS, DAEMON_READY_POLL_MILLIS);

const fn readiness_attempts(timeout_secs: u64, poll_millis: u64) -> u64 {
    let Some(timeout_millis) = timeout_secs.checked_mul(1_000) else {
        panic!("daemon readiness timeout overflow")
    };
    timeout_millis.div_ceil(poll_millis)
}

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
/// doesn't become ready within the bounded startup window.
pub(crate) async fn spawn_daemon(
    ready_path: &std::path::Path,
    workspace_root: Option<&Path>,
) -> Result<std::process::Child> {
    spawn_daemon_inner(ready_path, true, workspace_root).await
}

async fn spawn_daemon_inner(
    ready_path: &std::path::Path,
    announce: bool,
    workspace_root: Option<&Path>,
) -> Result<std::process::Child> {
    if announce {
        println!("{}", theme::Theme::info("Booting Astrid daemon..."));
    }
    let ws = workspace_root.map_or_else(
        || std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from(".")),
        Path::to_path_buf,
    );
    let daemon_bin = find_companion_binary("astrid-daemon")?;
    let mut cmd = ephemeral_daemon_command(&daemon_bin, &ws);

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
    for _ in 0..DAEMON_READY_ATTEMPTS {
        tokio::time::sleep(DAEMON_READY_POLL).await;
        if ready_path.exists() {
            ready = true;
            break;
        }
        // If the daemon has already exited, stop polling immediately
        // instead of waiting the full readiness timeout.
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
            "Daemon failed to become ready within {} seconds.{}",
            DAEMON_READY_TIMEOUT_SECS,
            log_hint()
        );
    }
    Ok(child)
}

fn ephemeral_daemon_command(daemon_bin: &Path, workspace_root: &Path) -> std::process::Command {
    let mut cmd = std::process::Command::new(daemon_bin);
    cmd.arg("--ephemeral")
        .arg("--workspace")
        .arg(workspace_root)
        .env(
            "ASTRID_WORKSPACE_STATE_DIR",
            crate::workspace_layout::current().state_dir_name(),
        );
    cmd
}

/// Ensure the daemon is running, spawning it if needed.
///
/// Checks the socket path, cleans up stale sockets, and spawns a fresh
/// daemon when no live daemon is reachable.
pub(crate) async fn ensure_daemon(label: &str) -> Result<()> {
    ensure_daemon_inner(label, true).await
}

/// Ensure the daemon is running without writing to stdout.
///
/// Used by `astrid mcp serve`, whose stdout is the MCP JSON-RPC transport.
pub(crate) async fn ensure_daemon_quiet(label: &str) -> Result<()> {
    ensure_daemon_inner(label, false).await
}

async fn ensure_daemon_inner(label: &str, announce: bool) -> Result<()> {
    let socket_path = socket_client::proxy_socket_path();
    let ready_path = socket_client::readiness_path();

    let needs_boot = if socket_path.exists() {
        if tokio::net::UnixStream::connect(&socket_path).await.is_ok() {
            ensure_daemon_workspace_matches(None).await?;
            if announce {
                eprintln!("[{label}] Connected to existing daemon");
            }
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
        spawn_daemon_inner(&ready_path, announce, None).await?;
        ensure_daemon_workspace_matches(None).await?;
    }
    Ok(())
}

pub(crate) async fn ensure_daemon_workspace_matches(workspace_root: Option<&Path>) -> Result<()> {
    let expected = expected_workspace_fingerprint(workspace_root)?;
    let ready_path = socket_client::readiness_path();

    for _ in 0..DAEMON_READY_ATTEMPTS {
        match std::fs::read_to_string(&ready_path) {
            Ok(metadata) => return validate_daemon_workspace_metadata(&metadata, &expected),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                tokio::time::sleep(DAEMON_READY_POLL).await;
            },
            Err(error) => {
                return Err(error).context("failed to read daemon workspace metadata");
            },
        }
    }

    anyhow::bail!(
        "daemon workspace metadata was not available within {DAEMON_READY_TIMEOUT_SECS} seconds; run `astrid restart`"
    )
}

fn expected_workspace_fingerprint(workspace_root: Option<&Path>) -> Result<String> {
    let root = workspace_root.map_or_else(
        || std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
        Path::to_path_buf,
    );
    astrid_core::dirs::checked_workspace_selection_fingerprint(
        &root,
        crate::workspace_layout::current(),
    )
    .context("selected workspace state path is unsafe")
}

fn validate_daemon_workspace_metadata(metadata: &str, expected: &str) -> Result<()> {
    let Some(actual) = metadata.trim().strip_prefix("v1:") else {
        anyhow::bail!(
            "running daemon does not expose workspace selection metadata; run `astrid restart`"
        );
    };
    if actual != expected {
        anyhow::bail!(
            "running daemon belongs to another project or workspace layout; run `astrid restart` from this project"
        );
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
    cmd.env(
        "ASTRID_WORKSPACE_STATE_DIR",
        crate::workspace_layout::current().state_dir_name(),
    );

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
    for _ in 0..DAEMON_READY_ATTEMPTS {
        tokio::time::sleep(DAEMON_READY_POLL).await;
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
            "Daemon failed to become ready within {} seconds.{}",
            DAEMON_READY_TIMEOUT_SECS,
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

/// What `astrid start` should do, decided from two cheap probes: whether the
/// daemon answered on its socket, and whether a recorded daemon PID is still
/// alive. Kept pure so the branching is unit-testable without a live daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StartAction {
    /// A daemon answered on the socket — it is already running, leave it (and
    /// its live run files) untouched.
    AlreadyRunning,
    /// The socket is unreachable but a recorded daemon PID is still alive — the
    /// daemon is present but not yet (or no longer) serving: mid-boot, mid-
    /// shutdown, wedged, or a PID that has been recycled by an unrelated
    /// process. `start` must NOT clobber it — killing a booting daemon or an
    /// innocent recycled PID is a serious fail-open — so it reports and defers
    /// to `astrid restart` (which owns the identity-gated force-recycle). No
    /// sentinels are touched.
    RunningButUnreachable,
    /// No daemon answered and no recorded process is alive — a clean slate or a
    /// crashed daemon's stale run files. Clear any stale sentinels and spawn.
    HealAndSpawn,
}

/// Decide the start action from the two liveness probes. Pure over its inputs so
/// the "already running vs defer-to-restart vs self-heal" split is testable
/// without spawning a daemon.
///
/// The ordering is what keeps `start` from ever killing or clobbering a live
/// daemon: a reachable daemon is `AlreadyRunning`; a live-but-unreachable one
/// (which includes a daemon still binding its socket during boot) is
/// `RunningButUnreachable` and left strictly alone; only a *dead* recorded PID
/// reaches `HealAndSpawn`, where clearing the stale sentinels is safe because
/// nothing live owns them.
fn decide_start_action(socket_reachable: bool, recorded_pid_alive: bool) -> StartAction {
    if socket_reachable {
        StartAction::AlreadyRunning
    } else if recorded_pid_alive {
        StartAction::RunningButUnreachable
    } else {
        StartAction::HealAndSpawn
    }
}

/// Whether a start action proceeds to clear stale sentinels and spawn a fresh
/// daemon. Only [`StartAction::HealAndSpawn`] does — a dead recorded PID means
/// no live daemon owns the run files, so clearing them is safe. A reachable
/// daemon ([`StartAction::AlreadyRunning`]) and a live-but-unreachable one
/// ([`StartAction::RunningButUnreachable`]) both leave every sentinel intact.
/// Pure predicate so the "dead recorded PID → sentinels cleared; any live daemon
/// → left intact" invariant is testable.
fn start_clears_sentinels(action: StartAction) -> bool {
    matches!(action, StartAction::HealAndSpawn)
}

/// Handle `astrid start`.
///
/// Fast path: a daemon answering on the socket is already running — do nothing.
///
/// Otherwise the socket is absent or unreachable. Two cases, split on whether a
/// recorded daemon PID is still alive:
///
/// - **Alive** (booting, mid-shutdown, wedged, or a recycled PID): the daemon is
///   present but not serving. `start` refuses to touch it — killing a daemon
///   that is merely still binding its socket, or an innocent process that
///   recycled the PID, is a fail-open — and points the operator at
///   `astrid restart`, which owns the identity-gated force-recycle. No sentinels
///   are removed.
/// - **Dead/absent**: a crashed daemon left stale run files
///   (`run/system.{sock,pid,ready}`) behind. Clear ALL of them and spawn onto a
///   clean run-dir, so a crashed daemon transparently recovers on the next
///   `astrid start`, not only on `restart`. Clearing is safe precisely because
///   no live process owns those files.
///
/// This never removes a live daemon's socket or signals a live process — the
/// only mutation happens when the recorded daemon is provably gone.
pub(crate) async fn handle_start() -> Result<()> {
    let socket_path = socket_client::proxy_socket_path();
    let ready_path = socket_client::readiness_path();
    let pid_path = socket_client::pid_path();

    let socket_probe = if socket_path.exists() {
        tokio::net::UnixStream::connect(&socket_path).await.ok()
    } else {
        None
    };
    let socket_reachable = socket_probe.is_some();
    let recorded_pid_alive = daemon_control::read_pid_file(&pid_path)
        .is_some_and(|(pid, _)| daemon_control::is_process_alive(pid));

    match decide_start_action(socket_reachable, recorded_pid_alive) {
        StartAction::AlreadyRunning => {
            ensure_daemon_workspace_matches(None).await?;
            drop(socket_probe);
            println!(
                "{}",
                theme::Theme::warning("Astrid daemon is already running.")
            );
            Ok(())
        },
        StartAction::RunningButUnreachable => {
            // A recorded daemon PID is alive but the socket isn't answering. The
            // daemon may still be binding its socket (boot), shutting down, or
            // wedged — or the PID may have been recycled by an unrelated process.
            // `start` does not force-recycle: it must not kill a booting daemon
            // or an innocent recycled PID, so it defers to `astrid restart`,
            // which does the identity-gated SIGTERM→SIGKILL. Leave every sentinel
            // in place.
            println!(
                "{}",
                theme::Theme::warning(
                    "An Astrid daemon appears to be running but its socket is not reachable yet \
                     (it may be starting up). If it stays unreachable, run `astrid restart`.",
                )
            );
            Ok(())
        },
        StartAction::HealAndSpawn => {
            // Dead/absent recorded PID: a crashed daemon's stale run files. No
            // live process owns them, so clear ALL stale sentinels (socket,
            // readiness, PID) and spawn onto a clean run-dir.
            let _ = std::fs::remove_file(&socket_path);
            let _ = std::fs::remove_file(&ready_path);
            let _ = std::fs::remove_file(&pid_path);
            spawn_persistent_daemon().await
        },
    }
}

/// Handle `astrid status`.
pub(crate) async fn handle_status() -> Result<()> {
    let socket_path = socket_client::proxy_socket_path();
    if !socket_path.exists() {
        println!("{}", theme::Theme::info("No Astrid daemon is running."));
        return Ok(());
    }

    let mut client = socket_client::connect_kernel_for_workspace(None)
        .await
        .context("Daemon socket exists but connection failed")?;
    let status = status_response(
        client
            .request(KernelRequest::GetStatus)
            .await
            .context("Failed to query daemon status")?,
    )?;
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
    Ok(())
}

fn status_response(response: KernelResponse) -> Result<DaemonStatus> {
    match response {
        KernelResponse::Status(status) => Ok(status),
        KernelResponse::Error(message) => {
            anyhow::bail!("daemon rejected status request: {message}")
        },
        other => anyhow::bail!("daemon returned an unexpected status response: {other:?}"),
    }
}

/// Handle `astrid stop`.
///
/// A shutdown request over the socket only earns an ACK ("shutting down"), not a
/// guarantee the process exited and released the singleton/state-db lock. So we
/// capture the recorded PID BEFORE asking, then confirm the process actually
/// exits — escalating with a signal if it wedges mid-shutdown — before reporting
/// success. Runtime files (socket, readiness, PID) are removed only once the
/// daemon is confirmed gone; if a kill can't confirm exit, they are LEFT so
/// `astrid start`/`restart` still see the recorded PID and give an actionable
/// message instead of failing on the held lock with a raw DB error.
pub(crate) async fn handle_stop() -> Result<()> {
    let socket_path = socket_client::proxy_socket_path();
    let pid_path = socket_client::pid_path();

    // Capture the daemon's identity up front: it deletes its own PID file only
    // on a CLEAN exit, so reading it before shutdown is the only reliable way to
    // keep a handle for confirming exit / signalling a wedged shutdown.
    let recorded = daemon_control::read_pid_file(&pid_path);
    let socket_present = socket_path.exists();

    // Genuinely nothing running: no socket AND no live recorded process.
    let recorded_alive = recorded
        .as_ref()
        .is_some_and(|(pid, _)| daemon_control::is_process_alive(*pid));
    if !socket_present && !recorded_alive {
        println!("{}", theme::Theme::info("No Astrid daemon is running."));
        let _ = std::fs::remove_file(&pid_path); // tidy a stale dead-PID file
        return Ok(());
    }

    // Graceful path: the socket is present and serviceable.
    // Deliberately bypass the selected-workspace check: stopping a daemon is
    // the recovery path when that daemon belongs to another project/layout.
    if socket_present && let Ok(client) = socket_client::connect_kernel_for_recovery().await {
        let mut client = client.with_timeout(Duration::from_secs(10));
        match client
            .request(KernelRequest::Shutdown {
                reason: Some("astrid stop".to_string()),
            })
            .await?
        {
            KernelResponse::Success(_) => {
                // ACK only — confirm the process actually exits before
                // declaring success, and escalate if it wedged.
                confirm_graceful_stop(recorded, &pid_path, &socket_path).await;
            },
            KernelResponse::Error(reason) => anyhow::bail!("daemon rejected shutdown: {reason}"),
            other => anyhow::bail!("unexpected response from daemon shutdown: {other:?}"),
        }
        return Ok(());
    }

    // Orphan path: the socket is present but unreachable (hung/half-dead
    // daemon), OR the socket is already gone but a live recorded daemon is still
    // holding the lock. A clean shutdown request is impossible either way, so
    // signal the recorded PID (identity-gated) and clean up. Using the PID we
    // captured up front — not a re-read — closes the window where the daemon
    // deletes its own PID file mid-wedge.
    let outcome = match &recorded {
        Some((pid, exe)) => daemon_control::terminate_known(*pid, exe.as_deref()).await,
        None => daemon_control::KillOutcome::NotRunning,
    };
    report_orphan_stop(outcome, socket_present, &pid_path, &socket_path);
    Ok(())
}

/// After a graceful shutdown ACK, confirm the daemon process actually exited —
/// an ACK is "shutting down", not "exited and released the lock". Wait for the
/// recorded PID to die; if it wedges past the grace window it is still holding
/// the lock, so escalate through the same identity-gated signal path as an
/// unreachable orphan. Runtime files are cleaned only once the process is gone.
async fn confirm_graceful_stop(
    recorded: Option<(u32, Option<PathBuf>)>,
    pid_path: &Path,
    socket_path: &Path,
) {
    let Some((pid, exe)) = recorded else {
        // Legacy pidless daemon (or an unresolved PID): we can't confirm exit,
        // so trust the ACK. The daemon cleans up its own socket on a clean exit;
        // remove the PID file best-effort in case one was left behind.
        println!("{}", theme::Theme::success("Astrid daemon stopped."));
        let _ = std::fs::remove_file(pid_path);
        return;
    };

    if daemon_control::wait_for_exit(pid, daemon_control::GRACE).await {
        // Confirmed gone — clear ALL runtime files. A clean daemon removes its
        // own socket/readiness, but one that wedged briefly before finally
        // exiting may not have, so remove them here too rather than leave a
        // stale socket for the next `status`/`start` to trip on.
        println!("{}", theme::Theme::success("Astrid daemon stopped."));
        remove_runtime_files(pid_path, socket_path);
        return;
    }

    // Acknowledged but still alive past the grace window → wedged mid-shutdown,
    // still holding the lock. Escalate with a signal (identity-gated).
    eprintln!(
        "{}",
        theme::Theme::warning(
            "Daemon acknowledged shutdown but is still running; escalating with a signal so the \
             state-db lock is released."
        )
    );
    let outcome = daemon_control::terminate_known(pid, exe.as_deref()).await;
    report_orphan_stop(outcome, true, pid_path, socket_path);
}

/// Report a signal-based stop outcome and clean up runtime files ONLY when the
/// daemon is confirmed gone. When a kill can't confirm exit (`StillAlive` /
/// `Unverified`), the socket/PID files are LEFT in place so `astrid start` /
/// `astrid restart` still see the recorded PID and can print an actionable
/// message rather than failing on the held lock with a raw DB error.
fn report_orphan_stop(
    outcome: daemon_control::KillOutcome,
    socket_present: bool,
    pid_path: &Path,
    socket_path: &Path,
) {
    match &outcome {
        daemon_control::KillOutcome::NotRunning => {
            if socket_present {
                println!("{}", theme::Theme::info("Cleaned up stale daemon socket."));
            } else {
                println!("{}", theme::Theme::info("No Astrid daemon is running."));
            }
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
                    "An unresponsive Astrid daemon did not exit even after SIGKILL; the \
                     state-db lock may still be held. Inspect the process before retrying."
                )
            );
        },
        daemon_control::KillOutcome::Unverified(pid) => {
            eprintln!(
                "{}",
                theme::Theme::warning(&format!(
                    "A process (PID {pid}) holds the recorded daemon PID but I can't confirm \
                     it's the Astrid daemon (possible PID reuse) — not killing it. If the daemon \
                     is genuinely stuck, inspect PID {pid} and stop it manually."
                ))
            );
        },
    }
    if stop_confirmed_gone(outcome) {
        remove_runtime_files(pid_path, socket_path);
    }
}

/// Remove the daemon's runtime files (socket, readiness, PID), best-effort.
/// Called only once the daemon is confirmed gone — a dead daemon owns none of
/// them, so clearing them leaves a clean slate for the next `start`.
fn remove_runtime_files(pid_path: &Path, socket_path: &Path) {
    let _ = std::fs::remove_file(socket_path);
    let _ = std::fs::remove_file(socket_client::readiness_path());
    let _ = std::fs::remove_file(pid_path);
}

/// Whether a stop outcome CONFIRMS the daemon is gone — the only condition under
/// which runtime files (socket, readiness, PID) may be removed.
///
/// This is the crux of the wedge fix (#1120): `StillAlive`/`Unverified` mean a
/// process may still hold the state-db lock, so the files are kept, leaving the
/// recorded PID for `astrid start`/`restart` to find and act on rather than
/// racing a fresh daemon onto a held lock (which surfaces as a raw "Database …
/// is already locked" error). Pure over its input so the invariant is testable
/// without a live daemon. Takes the `Copy` outcome by value (trivially small).
fn stop_confirmed_gone(outcome: daemon_control::KillOutcome) -> bool {
    matches!(
        outcome,
        daemon_control::KillOutcome::NotRunning
            | daemon_control::KillOutcome::TermExited
            | daemon_control::KillOutcome::KilledExited
    )
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daemon_ready_attempts_match_timeout_window() {
        assert_eq!(
            DAEMON_READY_ATTEMPTS,
            readiness_attempts(DAEMON_READY_TIMEOUT_SECS, DAEMON_READY_POLL_MILLIS)
        );
        assert_eq!(
            DAEMON_READY_ATTEMPTS
                .checked_mul(DAEMON_READY_POLL_MILLIS)
                .expect("readiness window fits"),
            60_000
        );
    }

    #[test]
    fn daemon_workspace_metadata_rejects_unknown_or_different_selection() {
        let expected = "a".repeat(64);
        assert!(validate_daemon_workspace_metadata("", &expected).is_err());
        assert!(
            validate_daemon_workspace_metadata(&format!("v1:{}", "b".repeat(64)), &expected)
                .is_err()
        );
        validate_daemon_workspace_metadata(&format!("v1:{expected}\n"), &expected).unwrap();
    }

    #[test]
    fn explicit_workspace_selection_wins_over_current_directory() {
        let current = std::env::current_dir().expect("current directory");
        let explicit = tempfile::tempdir().expect("explicit workspace");
        assert_ne!(explicit.path(), current);

        assert_eq!(
            expected_workspace_fingerprint(Some(explicit.path())).unwrap(),
            astrid_core::dirs::checked_workspace_selection_fingerprint(
                explicit.path(),
                crate::workspace_layout::current(),
            )
            .unwrap()
        );
        assert_eq!(
            expected_workspace_fingerprint(None).unwrap(),
            astrid_core::dirs::checked_workspace_selection_fingerprint(
                &current,
                crate::workspace_layout::current(),
            )
            .unwrap()
        );
    }

    #[test]
    fn ephemeral_boot_passes_the_selected_workspace_to_the_daemon() {
        use std::ffi::OsStr;

        let command = ephemeral_daemon_command(
            Path::new("/installed/astrid-daemon"),
            Path::new("/selected/project"),
        );
        let args = command.get_args().collect::<Vec<_>>();

        assert_eq!(
            args,
            vec![
                OsStr::new("--ephemeral"),
                OsStr::new("--workspace"),
                OsStr::new("/selected/project"),
            ]
        );
        assert_eq!(
            command
                .get_envs()
                .find(|(name, _)| *name == OsStr::new("ASTRID_WORKSPACE_STATE_DIR"))
                .and_then(|(_, value)| value),
            Some(OsStr::new(
                crate::workspace_layout::current().state_dir_name()
            ))
        );
    }

    /// REGRESSION (#1120): `astrid stop` must remove the socket/PID files ONLY
    /// when the daemon is confirmed gone. Before the fix, stop reported success
    /// and deleted the PID file on the shutdown ACK alone; a daemon that then
    /// wedged mid-shutdown leaked the lock with no PID handle left, and the next
    /// `start` died on it. `StillAlive`/`Unverified` must NOT trigger cleanup.
    #[test]
    fn stop_cleans_up_only_when_confirmed_gone() {
        use daemon_control::KillOutcome;
        assert!(stop_confirmed_gone(KillOutcome::NotRunning));
        assert!(stop_confirmed_gone(KillOutcome::TermExited));
        assert!(stop_confirmed_gone(KillOutcome::KilledExited));
        // A process that may still hold the lock → keep the files so restart/
        // start can find the recorded PID and act on it.
        assert!(!stop_confirmed_gone(KillOutcome::StillAlive));
        assert!(!stop_confirmed_gone(KillOutcome::Unverified(4242)));
    }

    /// A reachable daemon is already running — regardless of whether a recorded
    /// PID looks alive, `start` must take the fast path and leave the live run
    /// files untouched (never clear sentinels).
    #[test]
    fn start_reachable_daemon_is_already_running() {
        assert_eq!(
            decide_start_action(true, false),
            StartAction::AlreadyRunning
        );
        assert_eq!(decide_start_action(true, true), StartAction::AlreadyRunning);
        assert!(!start_clears_sentinels(StartAction::AlreadyRunning));
    }

    /// REGRESSION (daemon-detach self-heal): a crashed daemon leaves stale run
    /// files with a DEAD recorded PID. On the next `astrid start` the socket is
    /// unreachable and the PID is dead → clear ALL stale sentinels and spawn,
    /// so the stale run-dir recovers transparently (not only on `restart`).
    #[test]
    fn start_unreachable_with_dead_pid_heals_and_spawns() {
        let action = decide_start_action(false, false);
        assert_eq!(action, StartAction::HealAndSpawn);
        assert!(start_clears_sentinels(action));
    }

    /// SAFETY INVARIANT: a recorded daemon PID that is still alive but whose
    /// socket is unreachable (a daemon mid-boot still binding its socket, mid-
    /// shutdown, wedged, or a recycled PID) must NEVER be killed or have its
    /// sentinels cleared by `start` — that would clobber a booting daemon or an
    /// innocent process. `start` defers to `restart`, leaving every sentinel
    /// intact.
    #[test]
    fn start_unreachable_with_live_pid_defers_and_leaves_sentinels() {
        let action = decide_start_action(false, true);
        assert_eq!(action, StartAction::RunningButUnreachable);
        assert!(!start_clears_sentinels(action));
    }

    #[test]
    fn status_error_is_not_reported_as_a_successful_status() {
        let error = status_response(KernelResponse::Error("denied".into()))
            .expect_err("kernel status errors must fail the command");
        assert!(
            error
                .to_string()
                .contains("daemon rejected status request: denied")
        );
    }
}
