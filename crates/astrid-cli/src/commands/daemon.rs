//! Daemon lifecycle commands: start, stop, status, and spawn helpers.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, Result};
use astrid_core::kernel_api::{DaemonStatus, KernelRequest, KernelResponse};
use clap::Args;

use crate::bootstrap::find_companion_binary;
use crate::commands::{daemon_control, daemon_process};
use crate::{socket_client, theme};

const DAEMON_READY_TIMEOUT_SECS: u64 = 60;
const DAEMON_READY_POLL_MILLIS: u64 = 50;
const DAEMON_READY_POLL: Duration = Duration::from_millis(DAEMON_READY_POLL_MILLIS);
const DAEMON_PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const DAEMON_READY_ATTEMPTS: u64 =
    readiness_attempts(DAEMON_READY_TIMEOUT_SECS, DAEMON_READY_POLL_MILLIS);

/// Options for `astrid start`.
#[derive(Args, Debug, Clone, Copy)]
pub(crate) struct StartArgs {
    /// Keep the daemon attached to this command and propagate its exit.
    #[arg(long)]
    pub(crate) foreground: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StopConfirmation {
    ConfirmedGone,
    Unconfirmed,
}

#[derive(Debug, PartialEq, Eq)]
enum ShutdownRequestOutcome {
    Acknowledged,
    Escalate(String),
    Rejected(String),
}

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
    astrid_core::platform_fs::ensure_private_directory(&log_dir).ok()?;
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
    let file = opts.open(&path).ok()?;
    astrid_core::platform_fs::restrict_private_file(&path).ok()?;
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
    daemon_process::configure_background(&mut cmd);

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

    // Do not create a throwaway authenticated management connection here.
    // Ephemeral lifetime belongs to the real interactive client that the
    // caller connects immediately after this returns; probing and dropping a
    // temporary client could make the daemon observe "last client gone" before
    // its owner arrives.
    if let Err(error) = wait_for_readiness_signal(&mut child, ready_path).await {
        // Kill the child to prevent an orphan daemon that lingers
        // after an unsuccessful startup.
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
    }
    Ok(child)
}

async fn wait_for_readiness_signal(
    child: &mut std::process::Child,
    ready_path: &Path,
) -> Result<()> {
    let deadline = tokio::time::Instant::now()
        .checked_add(Duration::from_secs(DAEMON_READY_TIMEOUT_SECS))
        .context("daemon readiness deadline overflow")?;
    while tokio::time::Instant::now() < deadline {
        if ready_path.exists() {
            return Ok(());
        }
        if let Ok(Some(status)) = child.try_wait() {
            anyhow::bail!("Daemon exited prematurely ({status}).{}", log_hint());
        }
        tokio::time::sleep(DAEMON_READY_POLL).await;
    }
    anyhow::bail!(
        "Daemon failed to become ready within {} seconds.{}",
        DAEMON_READY_TIMEOUT_SECS,
        log_hint()
    )
}

async fn wait_for_authenticated_readiness(
    child: &mut std::process::Child,
    ready_path: &Path,
    workspace_root: Option<&Path>,
) -> Result<()> {
    let deadline = tokio::time::Instant::now()
        .checked_add(Duration::from_secs(DAEMON_READY_TIMEOUT_SECS))
        .context("daemon readiness deadline overflow")?;
    let mut last_handshake_error = None;

    while tokio::time::Instant::now() < deadline {
        if let Ok(Some(status)) = child.try_wait() {
            anyhow::bail!("Daemon exited prematurely ({status}).{}", log_hint());
        }

        // The file carries the selected-workspace fingerprint; it is not a
        // transport-liveness claim. Readiness is accepted only after the
        // authenticated management roundtrip below succeeds.
        if ready_path.exists() {
            match tokio::time::timeout(Duration::from_secs(2), authenticated_status(workspace_root))
                .await
            {
                Ok(Ok(_)) => return Ok(()),
                Ok(Err(error)) => last_handshake_error = Some(error.to_string()),
                Err(_) => {
                    last_handshake_error =
                        Some("authenticated daemon handshake timed out".to_string());
                },
            }
        }
        tokio::time::sleep(DAEMON_READY_POLL).await;
    }

    let detail = last_handshake_error
        .map(|error| format!(" Last authenticated handshake error: {error}."))
        .unwrap_or_default();
    anyhow::bail!(
        "Daemon failed to become authenticated and ready within {} seconds.{}{}",
        DAEMON_READY_TIMEOUT_SECS,
        detail,
        log_hint()
    )
}

async fn authenticated_status(workspace_root: Option<&Path>) -> Result<DaemonStatus> {
    let mut client = socket_client::connect_kernel_for_workspace(workspace_root)
        .await
        .context("failed to authenticate to daemon")?;
    status_response(
        client
            .request(KernelRequest::GetStatus)
            .await
            .context("authenticated daemon status request failed")?,
    )
}

#[derive(Debug)]
enum DaemonProbe {
    Absent,
    Stale,
    Authenticated(DaemonStatus),
}

async fn probe_authenticated_daemon(workspace_root: Option<&Path>) -> Result<DaemonProbe> {
    let socket_path = socket_client::try_proxy_socket_path()?;
    match astrid_core::local_transport::connect_outcome(&socket_path)
        .await
        .context("failed to probe daemon transport")?
    {
        astrid_core::local_transport::ConnectOutcome::Absent => Ok(DaemonProbe::Absent),
        astrid_core::local_transport::ConnectOutcome::Stale => Ok(DaemonProbe::Stale),
        astrid_core::local_transport::ConnectOutcome::Connected(stream) => {
            drop(stream);
            tokio::time::timeout(DAEMON_PROBE_TIMEOUT, authenticated_status(workspace_root))
                .await
                .map_err(|_| anyhow::anyhow!("authenticated daemon probe timed out after 5s"))?
                .map(DaemonProbe::Authenticated)
        },
    }
}

pub(crate) async fn authenticated_daemon_is_running() -> Result<bool> {
    Ok(matches!(
        probe_authenticated_daemon(None).await?,
        DaemonProbe::Authenticated(_)
    ))
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
    let socket_path = socket_client::try_proxy_socket_path()?;
    let ready_path = socket_client::try_readiness_path()?;

    let needs_boot = match astrid_core::local_transport::connect_outcome(&socket_path).await {
        Ok(astrid_core::local_transport::ConnectOutcome::Connected(stream)) => {
            drop(stream);
            ensure_daemon_workspace_matches(None).await?;
            if announce {
                eprintln!("[{label}] Connected to existing daemon");
            }
            false
        },
        Ok(astrid_core::local_transport::ConnectOutcome::Absent) => true,
        Ok(astrid_core::local_transport::ConnectOutcome::Stale) => {
            astrid_core::local_transport::remove_stale_endpoint(&socket_path)
                .context("failed to clean up stale daemon endpoint")?;
            let _ = std::fs::remove_file(&ready_path);
            true
        },
        Err(error) => return Err(error).context("failed to probe daemon endpoint"),
    };
    if needs_boot {
        spawn_daemon_inner(&ready_path, announce, None).await?;
        ensure_daemon_workspace_matches(None).await?;
    }
    Ok(())
}

pub(crate) async fn ensure_daemon_workspace_matches(workspace_root: Option<&Path>) -> Result<()> {
    let expected = expected_workspace_fingerprint(workspace_root)?;
    let ready_path = socket_client::try_readiness_path()?;

    for _ in 0..DAEMON_READY_ATTEMPTS {
        match std::fs::read_to_string(&ready_path) {
            Ok(metadata) => {
                #[cfg(windows)]
                astrid_core::platform_fs::validate_private_file(&ready_path)
                    .context("daemon readiness metadata is not private")?;
                return validate_daemon_workspace_metadata(&metadata, &expected);
            },
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
    let current_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    expected_workspace_fingerprint_from(workspace_root, &current_dir)
}

fn expected_workspace_fingerprint_from(
    workspace_root: Option<&Path>,
    current_dir: &Path,
) -> Result<String> {
    let root = workspace_root.unwrap_or(current_dir);
    astrid_core::dirs::checked_workspace_selection_fingerprint(
        root,
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
    let ready_path = socket_client::try_readiness_path()?;
    println!(
        "{}",
        theme::Theme::info("Starting Astrid daemon (persistent mode)...")
    );
    let ws = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    let daemon_bin = find_companion_binary("astrid-daemon")?;

    let mut cmd = persistent_daemon_command(&daemon_bin, &ws);
    daemon_process::configure_background(&mut cmd);

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

    if let Err(error) = wait_for_authenticated_readiness(&mut child, &ready_path, Some(&ws)).await {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
    }

    // Disown the child — it runs independently.
    drop(child);

    println!(
        "{}",
        theme::Theme::success("Astrid daemon started (persistent mode).")
    );
    Ok(())
}

fn persistent_daemon_command(daemon_bin: &Path, workspace: &Path) -> std::process::Command {
    let mut command = std::process::Command::new(daemon_bin);
    command.arg("--workspace").arg(workspace).env(
        "ASTRID_WORKSPACE_STATE_DIR",
        crate::workspace_layout::current().state_dir_name(),
    );
    command
}

async fn run_foreground_daemon() -> Result<ExitCode> {
    let ready_path = socket_client::try_readiness_path()?;
    let workspace = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let daemon_bin = find_companion_binary("astrid-daemon")?;
    let mut command = foreground_daemon_command(&daemon_bin, &workspace);

    let _ = std::fs::remove_file(&ready_path);
    let mut child = command
        .spawn()
        .context("Failed to spawn foreground Astrid daemon")?;
    if let Err(error) =
        wait_for_authenticated_readiness(&mut child, &ready_path, Some(&workspace)).await
    {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
    }

    println!(
        "{}",
        theme::Theme::success("Astrid daemon started in foreground mode.")
    );
    let status = tokio::task::spawn_blocking(move || child.wait())
        .await
        .context("foreground daemon wait task failed")?
        .context("failed to wait for foreground daemon")?;
    Ok(exit_code_from_status(status))
}

fn exit_code_from_status(status: std::process::ExitStatus) -> ExitCode {
    let code = status.code().unwrap_or(1).clamp(0, i32::from(u8::MAX));
    ExitCode::from(u8::try_from(code).unwrap_or(1))
}

fn foreground_daemon_command(daemon_bin: &Path, workspace: &Path) -> std::process::Command {
    let mut command = std::process::Command::new(daemon_bin);
    command
        .arg("--workspace")
        .arg(workspace)
        .env(
            "ASTRID_WORKSPACE_STATE_DIR",
            crate::workspace_layout::current().state_dir_name(),
        )
        .env("ASTRID_DAEMON_FOREGROUND", "1")
        .env("ASTRID_DAEMON_LOG_TARGET", "stderr");
    command
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
pub(crate) async fn handle_start(foreground: bool) -> Result<ExitCode> {
    let socket_path = socket_client::try_proxy_socket_path()?;
    let ready_path = socket_client::try_readiness_path()?;
    let pid_path = socket_client::try_pid_path()?;

    let socket_reachable = matches!(
        probe_authenticated_daemon(None).await?,
        DaemonProbe::Authenticated(_)
    );
    let recorded_pid_alive = daemon_control::read_pid_file(&pid_path)
        .is_some_and(|(pid, _)| daemon_control::is_process_alive(pid));

    match decide_start_action(socket_reachable, recorded_pid_alive) {
        StartAction::AlreadyRunning => {
            println!(
                "{}",
                theme::Theme::warning("Astrid daemon is already running.")
            );
            Ok(ExitCode::SUCCESS)
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
            Ok(ExitCode::SUCCESS)
        },
        StartAction::HealAndSpawn => {
            // Dead/absent recorded PID: a crashed daemon's stale run files. No
            // live process owns them, so clear ALL stale sentinels (socket,
            // readiness, PID) and spawn onto a clean run-dir.
            let _ = astrid_core::local_transport::remove_endpoint(&socket_path);
            let _ = std::fs::remove_file(&ready_path);
            let _ = std::fs::remove_file(&pid_path);
            if foreground {
                run_foreground_daemon().await
            } else {
                spawn_persistent_daemon().await?;
                Ok(ExitCode::SUCCESS)
            }
        },
    }
}

/// Handle `astrid status`.
pub(crate) async fn handle_status() -> Result<()> {
    let DaemonProbe::Authenticated(status) = probe_authenticated_daemon(None).await? else {
        println!("{}", theme::Theme::info("No Astrid daemon is running."));
        return Ok(());
    };
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
/// exits — escalating with platform-native forced termination if it wedges
/// mid-shutdown — before reporting success. Runtime files (transport,
/// readiness, PID) are removed only once the
/// daemon is confirmed gone; if a kill can't confirm exit, they are LEFT so
/// `astrid start`/`restart` still see the recorded PID and give an actionable
/// message instead of failing on the held lock with a raw DB error.
pub(crate) async fn handle_stop() -> Result<StopConfirmation> {
    let socket_path = socket_client::try_proxy_socket_path()?;
    let pid_path = socket_client::try_pid_path()?;

    // Capture the daemon's identity up front: it deletes its own PID file only
    // on a CLEAN exit, so reading it before shutdown is the only reliable way to
    // keep a handle for confirming exit / terminating a wedged shutdown.
    let recorded = daemon_control::read_pid_file(&pid_path);
    let endpoint_reachable = daemon_endpoint_reachable(&socket_path).await;

    // Genuinely nothing running: no socket AND no live recorded process.
    let recorded_alive = recorded
        .as_ref()
        .is_some_and(|(pid, _)| daemon_control::is_process_alive(*pid));
    if !endpoint_reachable && !recorded_alive {
        println!("{}", theme::Theme::info("No Astrid daemon is running."));
        let _ = std::fs::remove_file(&pid_path); // tidy a stale dead-PID file
        return Ok(StopConfirmation::ConfirmedGone);
    }

    // Graceful path: the socket is present and serviceable.
    // Deliberately bypass the selected-workspace check: stopping a daemon is
    // the recovery path when that daemon belongs to another project/layout.
    if endpoint_reachable
        && let Ok(Ok(client)) = tokio::time::timeout(
            Duration::from_secs(5),
            socket_client::connect_kernel_for_recovery(),
        )
        .await
    {
        let mut client = client.with_timeout(Duration::from_secs(10));
        match shutdown_request_outcome(
            client
                .request(KernelRequest::Shutdown {
                    reason: Some("astrid stop".to_string()),
                })
                .await,
        ) {
            ShutdownRequestOutcome::Acknowledged => {
                // ACK only — confirm the process actually exits before
                // declaring success, and escalate if it wedged.
                return Ok(confirm_graceful_stop(recorded, &pid_path, &socket_path).await);
            },
            ShutdownRequestOutcome::Escalate(reason) => {
                eprintln!(
                    "{}",
                    theme::Theme::warning(&format!(
                        "Authenticated daemon shutdown failed ({reason}); escalating through the \
                        recorded process identity."
                    ))
                );
            },
            ShutdownRequestOutcome::Rejected(reason) => anyhow::bail!("{reason}"),
        }
    }

    // Orphan path: the socket is present but unreachable (hung/half-dead
    // daemon), OR the socket is already gone but a live recorded daemon is still
    // holding the lock. A clean shutdown request is impossible either way, so
    // terminate the recorded PID (identity-gated) and clean up. Using the PID we
    // captured up front — not a re-read — closes the window where the daemon
    // deletes its own PID file mid-wedge.
    let outcome = match &recorded {
        Some((pid, exe)) => daemon_control::terminate_known(*pid, exe.as_deref()).await,
        None => daemon_control::KillOutcome::NotRunning,
    };
    // A shutdown may have reached the daemon even when its response was lost.
    // If no process remains to terminate, refresh the transport observation:
    // an absent endpoint confirms shutdown, while a connected/indeterminate
    // endpoint may belong to another live daemon and must remain fail-closed.
    let endpoint_reachable = if matches!(outcome, daemon_control::KillOutcome::NotRunning) {
        daemon_endpoint_reachable(&socket_path).await
    } else {
        endpoint_reachable
    };
    Ok(report_orphan_stop(
        outcome,
        endpoint_reachable,
        &pid_path,
        &socket_path,
    ))
}

async fn daemon_endpoint_reachable(socket_path: &Path) -> bool {
    match astrid_core::local_transport::connect_outcome(socket_path).await {
        Ok(astrid_core::local_transport::ConnectOutcome::Connected(stream)) => {
            drop(stream);
            true
        },
        Ok(
            astrid_core::local_transport::ConnectOutcome::Absent
            | astrid_core::local_transport::ConnectOutcome::Stale,
        ) => false,
        Err(_) => true,
    }
}

fn shutdown_request_outcome<E>(
    response: std::result::Result<KernelResponse, E>,
) -> ShutdownRequestOutcome
where
    E: std::fmt::Display,
{
    match response {
        Ok(KernelResponse::Success(_)) => ShutdownRequestOutcome::Acknowledged,
        Ok(KernelResponse::Error(reason)) => {
            ShutdownRequestOutcome::Rejected(format!("daemon rejected shutdown: {reason}"))
        },
        Ok(other) => ShutdownRequestOutcome::Rejected(format!(
            "daemon returned an unexpected shutdown response: {other:?}"
        )),
        Err(error) => ShutdownRequestOutcome::Escalate(format!("shutdown request failed: {error}")),
    }
}

/// After a graceful shutdown ACK, confirm the daemon process actually exited —
/// an ACK is "shutting down", not "exited and released the lock". Wait for the
/// recorded PID to die; if it wedges past the grace window it is still holding
/// the lock, so escalate through the same identity-gated termination path as
/// an unreachable orphan. Runtime files are cleaned only once the process is
/// gone.
async fn confirm_graceful_stop(
    recorded: Option<(u32, Option<PathBuf>)>,
    pid_path: &Path,
    socket_path: &Path,
) -> StopConfirmation {
    let Some((pid, exe)) = recorded else {
        // Legacy pidless daemon (or an unresolved PID): we can't confirm exit,
        // so trust the ACK. The daemon cleans up its own socket on a clean exit;
        // remove the PID file best-effort in case one was left behind.
        println!("{}", theme::Theme::success("Astrid daemon stopped."));
        let _ = std::fs::remove_file(pid_path);
        return StopConfirmation::Unconfirmed;
    };

    if daemon_control::wait_for_exit(pid, daemon_control::GRACE).await {
        // Confirmed gone — clear ALL runtime files. A clean daemon removes its
        // own socket/readiness, but one that wedged briefly before finally
        // exiting may not have, so remove them here too rather than leave a
        // stale socket for the next `status`/`start` to trip on.
        println!("{}", theme::Theme::success("Astrid daemon stopped."));
        remove_runtime_files(pid_path, socket_path);
        return StopConfirmation::ConfirmedGone;
    }

    // Acknowledged but still alive past the grace window → wedged mid-shutdown,
    // still holding the lock. Escalate with forced termination
    // (identity-gated).
    eprintln!(
        "{}",
        theme::Theme::warning(
            "Daemon acknowledged shutdown but is still running; escalating with forced \
             termination so the state-db lock is released."
        )
    );
    let outcome = daemon_control::terminate_known(pid, exe.as_deref()).await;
    report_orphan_stop(outcome, true, pid_path, socket_path)
}

/// Report a forced-stop outcome and clean up runtime files ONLY when the
/// daemon is confirmed gone. When a kill can't confirm exit (`StillAlive` /
/// `Unverified`), the socket/PID files are LEFT in place so `astrid start` /
/// `astrid restart` still see the recorded PID and can print an actionable
/// message rather than failing on the held lock with a raw DB error.
fn report_orphan_stop(
    outcome: daemon_control::KillOutcome,
    endpoint_reachable: bool,
    pid_path: &Path,
    socket_path: &Path,
) -> StopConfirmation {
    match &outcome {
        daemon_control::KillOutcome::NotRunning => {
            if endpoint_reachable {
                eprintln!(
                    "{}",
                    theme::Theme::warning(
                        "The daemon transport is reachable, but authenticated shutdown failed and \
                         no daemon process could be verified. Leaving runtime state intact."
                    )
                );
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
                    "An unresponsive Astrid daemon did not exit even after forced termination; the \
                     state-db lock may still be held. Inspect the process before retrying."
                )
            );
        },
        daemon_control::KillOutcome::Unverified(pid) => {
            eprintln!(
                "{}",
                theme::Theme::warning(&format!(
                    "A process may hold the recorded daemon PID {pid}, but I can't confirm either \
                     its absence or that it's the Astrid daemon — not killing it. If the daemon is \
                     genuinely stuck, inspect PID {pid} and stop it manually."
                ))
            );
        },
    }
    let confirmation = stop_confirmation(outcome, endpoint_reachable);
    if confirmation == StopConfirmation::ConfirmedGone {
        remove_runtime_files(pid_path, socket_path);
    }
    confirmation
}

/// Remove the daemon's runtime files (socket, readiness, PID), best-effort.
/// Called only once the daemon is confirmed gone — a dead daemon owns none of
/// them, so clearing them leaves a clean slate for the next `start`.
fn remove_runtime_files(pid_path: &Path, socket_path: &Path) {
    let _ = astrid_core::local_transport::remove_endpoint(socket_path);
    if let Ok(readiness_path) = socket_client::try_readiness_path() {
        let _ = std::fs::remove_file(readiness_path);
    }
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
const fn stop_confirmed_gone(outcome: daemon_control::KillOutcome) -> bool {
    matches!(
        outcome,
        daemon_control::KillOutcome::NotRunning
            | daemon_control::KillOutcome::TermExited
            | daemon_control::KillOutcome::KilledExited
    )
}

/// Combine process evidence with transport evidence.
///
/// `NotRunning` proves absence only when the transport is also unreachable. A
/// reachable endpoint whose authenticated recovery handshake failed could
/// still belong to the daemon, and without a verified PID there is no safe
/// destructive fallback. Keep that state unconfirmed so restart and update
/// cannot replace a potentially live owner.
const fn stop_confirmation(
    outcome: daemon_control::KillOutcome,
    endpoint_reachable: bool,
) -> StopConfirmation {
    if endpoint_reachable && matches!(outcome, daemon_control::KillOutcome::NotRunning) {
        StopConfirmation::Unconfirmed
    } else if stop_confirmed_gone(outcome) {
        StopConfirmation::ConfirmedGone
    } else {
        StopConfirmation::Unconfirmed
    }
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
#[path = "daemon_tests.rs"]
mod tests;
