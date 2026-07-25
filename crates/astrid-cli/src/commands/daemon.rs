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

#[path = "daemon_runtime.rs"]
mod runtime;
#[cfg(test)]
use runtime::{ShutdownRequestOutcome, shutdown_request_outcome, stop_confirmation};
pub(crate) use runtime::{StopConfirmation, handle_stop};
use runtime::{is_handshake_rejection, remove_runtime_files_if_unowned};

const DAEMON_READY_TIMEOUT_SECS: u64 = 60;
const DAEMON_READY_POLL_MILLIS: u64 = 50;
const DAEMON_READY_POLL: Duration = Duration::from_millis(DAEMON_READY_POLL_MILLIS);
const DAEMON_PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const EXISTING_DAEMON_READY_TIMEOUT: Duration = Duration::from_secs(5);
const CHILD_CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
const DAEMON_READY_ATTEMPTS: u64 =
    readiness_attempts(DAEMON_READY_TIMEOUT_SECS, DAEMON_READY_POLL_MILLIS);

/// Options for `astrid start`.
#[derive(Args, Debug, Clone, Copy)]
pub(crate) struct StartArgs {
    /// Keep the daemon attached to this command and propagate its exit.
    #[arg(long)]
    pub(crate) foreground: bool,
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
    // Boot stderr can carry sensitive paths/state. The platform boundary
    // creates or validates the exact file handle and guarantees true append
    // semantics even when concurrent startup attempts open separate handles.
    let file = astrid_core::platform_fs::open_private_append_file(&path).ok()?;
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

    prepare_runtime_for_spawn().context("failed to claim the daemon runtime namespace")?;

    let mut child = cmd
        .spawn()
        .context("Failed to spawn background Kernel daemon")?;

    // Do not create a throwaway authenticated management connection here.
    // Ephemeral lifetime belongs to the real interactive client that the
    // caller connects immediately after this returns; probing and dropping a
    // temporary client could make the daemon observe "last client gone" before
    // its owner arrives.
    if let Err(error) = wait_for_readiness_signal(&mut child, ready_path).await {
        return Err(startup_error_after_cleanup(error, &mut child).await);
    }
    Ok(child)
}

pub(crate) async fn terminate_child_bounded(
    child: &mut std::process::Child,
) -> std::io::Result<()> {
    if child.try_wait()?.is_some() {
        return Ok(());
    }
    child.kill()?;
    let deadline = tokio::time::Instant::now()
        .checked_add(CHILD_CLEANUP_TIMEOUT)
        .ok_or_else(|| std::io::Error::other("child cleanup deadline overflow"))?;
    loop {
        if child.try_wait()?.is_some() {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "timed out reaping the terminated daemon child",
            ));
        }
        tokio::time::sleep(DAEMON_READY_POLL).await;
    }
}

/// Release the parent-side process handle only after proving the daemon is
/// still running. Background daemons outlive the short-lived CLI by design;
/// an already-exited child is a startup failure, while a live detached child
/// becomes the operating system's responsibility when this CLI exits.
pub(crate) fn detach_running_child(mut child: std::process::Child) -> Result<()> {
    anyhow::ensure!(
        child.try_wait()?.is_none(),
        "daemon exited before its parent could release the process handle"
    );
    drop(child);
    Ok(())
}

async fn startup_error_after_cleanup(
    error: anyhow::Error,
    child: &mut std::process::Child,
) -> anyhow::Error {
    match terminate_child_bounded(child).await {
        Ok(()) => error,
        Err(cleanup_error) => error.context(format!(
            "daemon startup failed and bounded child cleanup also failed: {cleanup_error}"
        )),
    }
}

fn prepare_runtime_for_spawn() -> Result<()> {
    let pid_path = socket_client::try_pid_path()?;
    let socket_path = socket_client::try_proxy_socket_path()?;
    anyhow::ensure!(
        remove_runtime_files_if_unowned(&pid_path, &socket_path)?,
        "another daemon generation owns the runtime namespace"
    );
    Ok(())
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

async fn wait_for_existing_daemon_readiness() -> Result<bool> {
    let deadline = tokio::time::Instant::now()
        .checked_add(EXISTING_DAEMON_READY_TIMEOUT)
        .context("existing daemon readiness deadline overflow")?;
    loop {
        match probe_authenticated_daemon(None).await {
            Ok(DaemonProbe::Authenticated(_)) => return Ok(true),
            Ok(DaemonProbe::Absent | DaemonProbe::Stale) => {},
            Err(error) if is_handshake_rejection(&error) => return Err(error),
            // A daemon that is still composing its uplink can transiently fail
            // the authenticated probe. Keep the wait bounded, then report
            // failure to automation instead of claiming start succeeded.
            Err(_) => {},
        }
        if tokio::time::Instant::now() >= deadline {
            return Ok(false);
        }
        tokio::time::sleep(DAEMON_READY_POLL).await;
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
        // Do not unlink here: another generation could acquire the singleton
        // and publish between this probe and an unguarded cleanup. The spawn
        // path takes the namespace lock and removes stale artifacts while it
        // still owns that lock.
        Ok(astrid_core::local_transport::ConnectOutcome::Stale) => true,
        Err(error) => return Err(error).context("failed to probe daemon endpoint"),
    };
    if needs_boot {
        let child = spawn_daemon_inner(&ready_path, announce, None).await?;
        detach_running_child(child)?;
        ensure_daemon_workspace_matches(None).await?;
    }
    Ok(())
}

pub(crate) async fn ensure_daemon_workspace_matches(workspace_root: Option<&Path>) -> Result<()> {
    let expected = expected_workspace_fingerprint(workspace_root)?;
    let ready_path = socket_client::try_readiness_path()?;

    for _ in 0..DAEMON_READY_ATTEMPTS {
        match astrid_core::platform_fs::read_private_file_to_string(&ready_path) {
            Ok(metadata) => return validate_daemon_workspace_metadata(&metadata, &expected),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::WouldBlock
                ) =>
            {
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

    prepare_runtime_for_spawn().context("failed to claim the daemon runtime namespace")?;

    let mut child = cmd.spawn().context("Failed to spawn Astrid daemon")?;

    if let Err(error) = wait_for_authenticated_readiness(&mut child, &ready_path, Some(&ws)).await {
        return Err(startup_error_after_cleanup(error, &mut child).await);
    }

    // Disown the child — it runs independently.
    detach_running_child(child)?;

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

    prepare_runtime_for_spawn().context("failed to claim the daemon runtime namespace")?;
    let mut child = command
        .spawn()
        .context("Failed to spawn foreground Astrid daemon")?;
    if let Err(error) =
        wait_for_authenticated_readiness(&mut child, &ready_path, Some(&workspace)).await
    {
        return Err(startup_error_after_cleanup(error, &mut child).await);
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

async fn finish_already_running_start(
    workspace_check: impl std::future::Future<Output = Result<()>>,
) -> Result<ExitCode> {
    // The authenticated probe above checks the workspace while connecting, but
    // the daemon can restart and republish the global endpoint before `start`
    // reports success. Re-read the readiness metadata at the success boundary
    // so a daemon now serving another project/layout is never accepted.
    workspace_check
        .await
        .context("running daemon workspace readiness validation failed")?;
    println!(
        "{}",
        theme::Theme::warning("Astrid daemon is already running.")
    );
    Ok(ExitCode::SUCCESS)
}

/// Handle `astrid start`.
///
/// Fast path: a daemon answering on the socket is already running only after
/// its readiness metadata is revalidated against the selected workspace.
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
    let recorded = daemon_control::read_pid_file(&pid_path)?;
    let recorded_pid_alive = recorded
        .as_ref()
        .is_some_and(|identity| daemon_control::is_process_alive(identity.pid));

    match decide_start_action(socket_reachable, recorded_pid_alive) {
        StartAction::AlreadyRunning => {
            finish_already_running_start(ensure_daemon_workspace_matches(None)).await
        },
        StartAction::RunningButUnreachable => {
            if wait_for_existing_daemon_readiness().await? {
                return finish_already_running_start(ensure_daemon_workspace_matches(None)).await;
            }
            // A recorded daemon PID is alive but the socket isn't answering. The
            // daemon may still be binding its socket (boot), shutting down, or
            // wedged — or the PID may have been recycled by an unrelated process.
            // `start` does not force-recycle: it must not kill a booting daemon
            // or an innocent recycled PID, so it defers to `astrid restart`,
            // which does the identity-gated SIGTERM→SIGKILL. Leave every sentinel
            // in place.
            let pid = recorded.as_ref().map(|identity| identity.pid);
            eprintln!(
                "{}",
                theme::Theme::error(&format!(
                    "Astrid daemon PID {} is still alive but did not become authenticated and \
                     reachable within {} seconds. No process or runtime files were touched; run \
                     `astrid restart` if the daemon is stuck.",
                    pid.map_or_else(|| "unknown".to_string(), |pid| pid.to_string()),
                    EXISTING_DAEMON_READY_TIMEOUT.as_secs()
                ))
            );
            Ok(ExitCode::from(1))
        },
        StartAction::HealAndSpawn => {
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
