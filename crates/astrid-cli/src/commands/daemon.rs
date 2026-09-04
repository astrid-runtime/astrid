//! Daemon lifecycle commands: start, stop, status, and spawn helpers.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use astrid_core::kernel_api::{DaemonStatus, KernelRequest, KernelResponse};

use crate::bootstrap::find_companion_binary;
use crate::commands::daemon_control;
use crate::formatter::OutputFormat;
use crate::{socket_client, theme};

mod projection;
mod ready;
mod workspace_fingerprint;
use projection::pack_stopped_projection;
pub(crate) use ready::disown_if_still_running;
use ready::{
    DAEMON_READY_POLL, ReadyWaitOutcome, configured_spawn_timeout_secs, default_daemon_ready_secs,
    readiness_attempts, wait_for_ready,
};
use workspace_fingerprint::{expected_workspace_fingerprints, validate_daemon_workspace_metadata};

const STATUS_CONNECT_TIMEOUT: Duration = Duration::from_secs(1);

/// Build a hint string pointing the user to the daemon log directory.
fn log_hint() -> String {
    astrid_core::dirs::AstridHome::resolve()
        .map(|h| format!(" Check logs: {}", h.log_dir().display()))
        .unwrap_or_default()
}

/// Open the daemon boot log (`log/daemon-boot.log`) for append in an already
/// initialized Astrid home, so the spawned daemon's stderr is captured.
///
/// A lock-acquisition failure (or any panic) before the kernel's own tracing
/// subscriber initializes prints to stderr and is otherwise lost when stderr
/// is detached. A fresh home must remain untouched until the kernel captures
/// its layout origin and durably admits it, so callers inherit stderr when no
/// layout sentinel exists instead of creating `log/` prematurely.
fn boot_log_stderr_for_home(home: &astrid_core::dirs::AstridHome) -> Option<std::process::Stdio> {
    if !matches!(home.layout_version(), Ok(Some(_))) {
        return None;
    }
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

fn boot_log_stderr() -> std::process::Stdio {
    astrid_core::dirs::AstridHome::resolve()
        .ok()
        .and_then(|home| boot_log_stderr_for_home(&home))
        .unwrap_or_else(std::process::Stdio::inherit)
}

/// Spawn the daemon process and wait for it to signal readiness.
///
/// Returns the child process handle on success. The caller must `drop()` it
/// after a successful handshake (to disown). If the daemon is still starting
/// after the wait budget, this disowns the live child instead of SIGKILL.
///
/// # Errors
/// Returns an error if the daemon binary is not found, fails to spawn, exits
/// before ready, or is still starting after `timeouts.daemon_ready_secs`.
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
    // tracing, not stdout. A fresh home inherits stderr so opening the boot log
    // cannot preempt the kernel's durable fresh-layout admission.
    let stderr = boot_log_stderr();
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
    let timeout_secs = configured_spawn_timeout_secs(workspace_root);
    match wait_for_ready(ready_path, &mut child, timeout_secs).await {
        ReadyWaitOutcome::Ready => Ok(child),
        ReadyWaitOutcome::ChildExited(status) => {
            anyhow::bail!("Daemon exited prematurely ({status}).{}", log_hint());
        },
        ReadyWaitOutcome::StillRunning => {
            // Do not SIGKILL a live first cutover (layout-1 audit import
            // can outlive the wait). Disown and tell the operator.
            disown_if_still_running(child);
            anyhow::bail!(
                "Daemon is still starting after {timeout_secs} seconds; it was left running. Check logs or run `astrid status` / retry later.{}",
                log_hint()
            );
        },
    }
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
    ensure_daemon_inner(label, true, DaemonSpawnMode::Ephemeral, None).await
}

/// Ensure the daemon is running without writing to stdout.
///
/// Used by `astrid mcp serve`, whose stdout is the MCP JSON-RPC transport.
pub(crate) async fn ensure_daemon_quiet(label: &str, workspace_root: Option<&Path>) -> Result<()> {
    ensure_daemon_inner(label, false, DaemonSpawnMode::Ephemeral, workspace_root).await
}

/// Ensure a persistent daemon is running for a multi-request workflow.
///
/// Unlike [`ensure_daemon`], a daemon started here remains alive between the
/// workflow's independent admin connections.
pub(crate) async fn ensure_persistent_daemon(label: &str) -> Result<()> {
    ensure_daemon_inner(label, true, DaemonSpawnMode::Persistent, None).await
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DaemonSpawnMode {
    Ephemeral,
    Persistent,
}

async fn ensure_daemon_inner(
    label: &str,
    announce: bool,
    spawn_mode: DaemonSpawnMode,
    workspace_root: Option<&Path>,
) -> Result<()> {
    let start_fence = acquire_daemon_start_fence().await?;
    let result = ensure_daemon_inner_locked(label, announce, spawn_mode, workspace_root).await;
    drop(start_fence);
    result
}

async fn ensure_daemon_inner_locked(
    label: &str,
    announce: bool,
    spawn_mode: DaemonSpawnMode,
    workspace_root: Option<&Path>,
) -> Result<()> {
    let socket_path = socket_client::proxy_socket_path();
    let ready_path = socket_client::readiness_path();
    let outcome = astrid_core::local_transport::connect_outcome(&socket_path)
        .await
        .context("failed to probe daemon endpoint")?;
    let action = decide_ensure_action(&outcome, recorded_daemon_pid_is_alive());
    let needs_boot = match action {
        EnsureAction::UseExisting => {
            if let astrid_core::local_transport::ConnectOutcome::Connected(stream) = outcome {
                drop(stream);
            }
            ensure_daemon_workspace_matches(workspace_root).await?;
            if announce {
                eprintln!("[{label}] Connected to existing daemon");
            }
            false
        },
        EnsureAction::RefuseSecondBoot => {
            anyhow::bail!(unreachable_uplink_message());
        },
        EnsureAction::CleanStaleAndSpawn => {
            astrid_core::local_transport::remove_stale_endpoint(&socket_path)
                .context("failed to clean up stale daemon endpoint")?;
            let _ = std::fs::remove_file(&ready_path);
            true
        },
        EnsureAction::Spawn => true,
    };
    if needs_boot {
        match spawn_mode {
            DaemonSpawnMode::Ephemeral => {
                spawn_daemon_inner(&ready_path, announce, None).await?;
            },
            DaemonSpawnMode::Persistent => spawn_persistent_daemon().await?,
        }
        ensure_daemon_workspace_matches(workspace_root).await?;
    }
    Ok(())
}

pub(crate) async fn ensure_daemon_workspace_matches(workspace_root: Option<&Path>) -> Result<()> {
    let expected = expected_workspace_fingerprints(workspace_root)?;
    let ready_path = socket_client::readiness_path();

    // Default wait only: do not load operator config here. Every admin
    // command including `agent list --format json` hits this path after
    // logging is live; Config::load_with_layout would trace to stderr and
    // poison merged stdout JSON in the crash-recovery smoke.
    let timeout_secs = default_daemon_ready_secs();
    let attempts = readiness_attempts(timeout_secs, ready::DAEMON_READY_POLL_MILLIS);
    for _ in 0..attempts {
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
        "daemon workspace metadata was not available within {timeout_secs} seconds; run `astrid restart`"
    )
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
    // tracing, not stdout. A fresh home inherits stderr so opening the boot log
    // cannot preempt the kernel's durable fresh-layout admission.
    let stderr = boot_log_stderr();
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(stderr);

    let _ = std::fs::remove_file(&ready_path);

    let mut child = cmd.spawn().context("Failed to spawn Astrid daemon")?;

    let timeout_secs = configured_spawn_timeout_secs(Some(&ws));
    match wait_for_ready(&ready_path, &mut child, timeout_secs).await {
        ReadyWaitOutcome::Ready => {
            // Disown the child — it runs independently.
            drop(child);
            println!(
                "{}",
                theme::Theme::success("Astrid daemon started (persistent mode).")
            );
            Ok(())
        },
        ReadyWaitOutcome::ChildExited(status) => {
            anyhow::bail!("Daemon exited prematurely ({status}).{}", log_hint());
        },
        ReadyWaitOutcome::StillRunning => {
            // First cutover can outlive the wait. Never SIGKILL a live migrator.
            disown_if_still_running(child);
            println!(
                "{}",
                theme::Theme::warning(&format!(
                    "Astrid daemon is still starting after {timeout_secs} seconds (first cutover can outlive this wait). It was left running. Check logs or run `astrid status` later."
                ))
            );
            Ok(())
        },
    }
}

pub(crate) fn recorded_daemon_pid_is_alive() -> bool {
    daemon_control::read_pid_file(&socket_client::pid_path())
        .is_some_and(|(pid, _)| daemon_control::is_process_alive(pid))
}

pub(crate) fn unreachable_uplink_message() -> &'static str {
    "an Astrid daemon is recorded as running (PID file) but its uplink is unreachable;      run `astrid restart` instead of starting a second kernel onto the singleton lock"
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EnsureAction {
    UseExisting,
    RefuseSecondBoot,
    CleanStaleAndSpawn,
    Spawn,
}

pub(crate) fn decide_ensure_action(
    outcome: &astrid_core::local_transport::ConnectOutcome,
    recorded_pid_alive: bool,
) -> EnsureAction {
    match outcome {
        astrid_core::local_transport::ConnectOutcome::Connected(_) => EnsureAction::UseExisting,
        astrid_core::local_transport::ConnectOutcome::Absent
        | astrid_core::local_transport::ConnectOutcome::Stale
            if recorded_pid_alive =>
        {
            EnsureAction::RefuseSecondBoot
        },
        astrid_core::local_transport::ConnectOutcome::Stale => EnsureAction::CleanStaleAndSpawn,
        astrid_core::local_transport::ConnectOutcome::Absent => EnsureAction::Spawn,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StatusAction {
    NotRunning,
    RunningButUnreachable,
    QueryLiveSocket,
}

fn decide_status_action(endpoint_present: bool, recorded_pid_alive: bool) -> StatusAction {
    if endpoint_present {
        StatusAction::QueryLiveSocket
    } else if recorded_pid_alive {
        StatusAction::RunningButUnreachable
    } else {
        StatusAction::NotRunning
    }
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

/// Serialize stale healing and boot decisions so two starts cannot both decide
/// that the same pathname is dead and race their children onto the singleton.
pub(crate) async fn acquire_daemon_start_fence() -> Result<Arc<std::fs::File>> {
    let home = astrid_core::dirs::AstridHome::resolve().context("failed to resolve Astrid home")?;
    let path = daemon_start_fence_path(&home);
    let file = tokio::task::spawn_blocking(move || -> std::io::Result<std::fs::File> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
            }
        }
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(&path)?;
        file.lock()?;
        Ok(file)
    })
    .await
    .context("daemon start fence task failed")?
    .map_err(|error| anyhow::anyhow!("failed to acquire daemon start fence: {error}"))?;
    Ok(Arc::new(file))
}

/// Admit a disposable runtime override before lifecycle code can resolve or
/// mutate any path under it.
pub(crate) fn validate_runtime_admission() -> Result<()> {
    let home = astrid_core::dirs::AstridHome::resolve()
        .context("failed to resolve Astrid home for runtime admission")?;
    home.validate_run_dir()
        .context("failed to validate ASTRID_RUN_DIR")
}

/// Keep the start fence outside the home until the kernel admits its layout.
fn daemon_start_fence_path(home: &astrid_core::dirs::AstridHome) -> std::path::PathBuf {
    let digest = blake3::hash(home.root().to_string_lossy().as_bytes());
    std::env::temp_dir()
        .join("astrid-start-fences")
        .join(format!("{digest}.lock"))
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
    validate_runtime_admission()?;
    let start_fence = acquire_daemon_start_fence().await?;
    let result = handle_start_locked().await;
    drop(start_fence);
    result
}

async fn handle_start_locked() -> Result<()> {
    let socket_path = socket_client::proxy_socket_path();
    let ready_path = socket_client::readiness_path();
    let pid_path = socket_client::pid_path();

    let socket_probe = match astrid_core::local_transport::connect_outcome(&socket_path).await {
        Ok(astrid_core::local_transport::ConnectOutcome::Connected(stream)) => Some(stream),
        Ok(
            astrid_core::local_transport::ConnectOutcome::Absent
            | astrid_core::local_transport::ConnectOutcome::Stale,
        )
        | Err(_) => None,
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
            let _ = astrid_core::local_transport::remove_endpoint(&socket_path);
            let _ = std::fs::remove_file(&ready_path);
            let _ = std::fs::remove_file(&pid_path);
            spawn_persistent_daemon().await
        },
    }
}

/// Handle `astrid status`.
pub(crate) async fn handle_status(output_format: OutputFormat) -> Result<()> {
    validate_runtime_admission()?;
    let socket_path = socket_client::proxy_socket_path();
    let endpoint_present = astrid_core::local_transport::endpoint_is_present(&socket_path)
        .context("failed to inspect daemon endpoint")
        .unwrap_or(false);
    let recorded_alive = recorded_daemon_pid_is_alive();
    match decide_status_action(endpoint_present, recorded_alive) {
        StatusAction::NotRunning => {
            print_status(output_format, None)?;
            return Ok(());
        },
        StatusAction::RunningButUnreachable => {
            anyhow::bail!(
                "an Astrid daemon appears to be running but its uplink is unreachable                  (missing or unlinked system.sock while the PID/lock is live).                  run `astrid restart`"
            );
        },
        StatusAction::QueryLiveSocket => {},
    }

    let connect = tokio::time::timeout(
        STATUS_CONNECT_TIMEOUT,
        socket_client::connect_kernel_for_workspace(None),
    )
    .await;
    let Ok(Ok(mut client)) = connect else {
        if recorded_alive {
            anyhow::bail!(
                "an Astrid daemon appears to be running but its uplink is unreachable; run `astrid restart`"
            );
        }
        print_status(output_format, None)?;
        return Ok(());
    };
    let status = status_response(
        client
            .request(KernelRequest::GetStatus)
            .await
            .context("Failed to query daemon status")?,
    )?;
    print_status(output_format, Some(&status))?;
    Ok(())
}

fn print_status(output_format: OutputFormat, status: Option<&DaemonStatus>) -> Result<()> {
    if output_format == OutputFormat::Json {
        let document = status_document(status);
        println!("{}", serde_json::to_string(&document)?);
        return Ok(());
    }
    let Some(status) = status else {
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

fn status_document(status: Option<&DaemonStatus>) -> serde_json::Value {
    status.map_or_else(
        || serde_json::json!({ "state": "stopped" }),
        |status| serde_json::json!({ "state": "running", "daemon": status }),
    )
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
    validate_runtime_admission()?;
    // A pre-lease gateway may legitimately hold the start fence while it boots
    // its daemon. Stop the gateway first so stop can reap it; then the fence
    // linearizes the daemon phase against any other start/restart.
    let gateway = crate::commands::mcp::stop_gateway().await;
    let start_fence = acquire_daemon_start_fence().await?;
    let daemon = stop_daemon().await;
    let projection = if daemon.is_ok() {
        pack_stopped_projection().await
    } else {
        Ok(())
    };
    drop(start_fence);
    let disposition = combine_stop_results(gateway, daemon)?;
    projection?;
    print_stop_disposition(disposition);
    Ok(())
}

pub(crate) async fn handle_gateway_stop() -> Result<()> {
    crate::commands::mcp::stop_gateway().await
}

/// Stop only the daemon while the caller already owns the start fence.
pub(crate) async fn handle_daemon_stop_locked() -> Result<()> {
    let result = stop_daemon().await;
    let projection = if result.is_ok() {
        pack_stopped_projection().await
    } else {
        Ok(())
    };
    projection?;
    print_stop_disposition(result?);
    Ok(())
}

fn print_stop_disposition(disposition: DaemonStopDisposition) {
    let message = match disposition {
        DaemonStopDisposition::AlreadyStopped => "Astrid runtime is stopped.",
        DaemonStopDisposition::Graceful => "Astrid runtime stopped.",
        DaemonStopDisposition::Forced => "Stopped the unresponsive Astrid runtime.",
    };
    println!("{}", theme::Theme::success(message));
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DaemonStopDisposition {
    AlreadyStopped,
    Graceful,
    Forced,
}

fn combine_stop_results(
    gateway: Result<()>,
    daemon: Result<DaemonStopDisposition>,
) -> Result<DaemonStopDisposition> {
    match (gateway, daemon) {
        (Ok(()), Ok(disposition)) => Ok(disposition),
        (Err(primary), Ok(_)) | (Ok(()), Err(primary)) => Err(primary),
        (Err(primary), Err(secondary)) => {
            anyhow::bail!("{primary:#}; additional shutdown failure: {secondary:#}")
        },
    }
}

async fn stop_daemon() -> Result<DaemonStopDisposition> {
    let socket_path = socket_client::proxy_socket_path();
    let pid_path = socket_client::pid_path();

    // Capture the daemon's identity up front: it deletes its own PID file only
    // on a CLEAN exit, so reading it before shutdown is the only reliable way to
    // keep a handle for confirming exit / signalling a wedged shutdown.
    let recorded = daemon_control::read_daemon_identity(&pid_path);
    let socket_present = astrid_core::local_transport::endpoint_is_present(&socket_path)
        .context("failed to inspect daemon endpoint")?;

    // Genuinely nothing running: no socket AND no live recorded process.
    let recorded_alive = recorded
        .as_ref()
        .is_some_and(|identity| daemon_control::is_process_alive(identity.pid));
    if !socket_present && !recorded_alive {
        cleanup_daemon_runtime(&socket_path, &pid_path).await?;
        return Ok(DaemonStopDisposition::AlreadyStopped);
    }

    // Graceful path: the socket is present and serviceable.
    // Deliberately bypass the selected-workspace check: stopping a daemon is
    // the recovery path when that daemon belongs to another project/layout.
    if socket_present && let Ok(client) = socket_client::connect_kernel_for_recovery().await {
        let mut client = client.with_timeout(Duration::from_secs(10));
        let response = client
            .request(KernelRequest::Shutdown {
                reason: Some("astrid stop".to_string()),
            })
            .await
            .context("shutdown stage daemon.shutdown_ack")?;
        let disposition = match response {
            KernelResponse::Success(_) => {
                // ACK only — confirm the process actually exits before
                // declaring success, and escalate if it wedged.
                confirm_graceful_stop(recorded, &socket_path, &pid_path).await?
            },
            KernelResponse::Error(reason) => {
                anyhow::bail!("shutdown stage daemon.shutdown_ack: rejected: {reason}")
            },
            other => {
                anyhow::bail!("shutdown stage daemon.shutdown_ack: unexpected response: {other:?}")
            },
        };
        cleanup_daemon_runtime(&socket_path, &pid_path).await?;
        return Ok(disposition);
    }

    // Orphan path: the socket is present but unreachable (hung/half-dead
    // daemon), OR the socket is already gone but a live recorded daemon is still
    // holding the lock. A clean shutdown request is impossible either way, so
    // signal the recorded PID (identity-gated) and clean up. Using the PID we
    // captured up front — not a re-read — closes the window where the daemon
    // deletes its own PID file mid-wedge.
    let outcome = match recorded.as_ref() {
        Some(identity) => daemon_control::terminate_identity(identity, &pid_path).await,
        None => daemon_control::KillOutcome::NotRunning,
    };
    let disposition = confirm_kill_outcome(outcome)?;
    cleanup_daemon_runtime(&socket_path, &pid_path).await?;
    Ok(disposition)
}

/// After a graceful shutdown ACK, confirm the daemon process actually exited —
/// an ACK is "shutting down", not "exited and released the lock". Wait for the
/// recorded PID to die; if it wedges past the grace window it is still holding
/// the lock, so escalate through the same identity-gated signal path as an
/// unreachable orphan. Runtime files are cleaned only once the process is gone.
async fn confirm_graceful_stop(
    recorded: Option<daemon_control::DaemonIdentity>,
    socket_path: &Path,
    pid_path: &Path,
) -> Result<DaemonStopDisposition> {
    let Some(identity) = recorded else {
        anyhow::bail!(
            "shutdown stage daemon.process_reap: shutdown was acknowledged but no recorded PID exists, so process exit cannot be verified (listener: {})",
            socket_path.display()
        );
    };

    if daemon_control::wait_for_exit(identity.pid, daemon_control::GRACE).await {
        return Ok(DaemonStopDisposition::Graceful);
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
    let outcome = daemon_control::terminate_identity(&identity, pid_path).await;
    confirm_kill_outcome(outcome)
}

fn confirm_kill_outcome(outcome: daemon_control::KillOutcome) -> Result<DaemonStopDisposition> {
    match outcome {
        daemon_control::KillOutcome::NotRunning => Ok(DaemonStopDisposition::AlreadyStopped),
        daemon_control::KillOutcome::TermExited | daemon_control::KillOutcome::KilledExited => {
            Ok(DaemonStopDisposition::Forced)
        },
        daemon_control::KillOutcome::StillAlive => {
            anyhow::bail!(
                "shutdown stage daemon.process_reap: daemon did not exit after forced termination; the singleton lock may still be held"
            );
        },
        daemon_control::KillOutcome::Unverified(pid) => {
            anyhow::bail!(
                "shutdown stage daemon.process_identity: PID {pid} is live but cannot be verified as Astrid; no markers were removed"
            );
        },
    }
}

/// Fence marker cleanup with the same singleton lock the daemon owns. Holding
/// it through removal prevents a replacement daemon from publishing fresh
/// markers between liveness proof and cleanup.
async fn cleanup_daemon_runtime(socket_path: &Path, pid_path: &Path) -> Result<()> {
    let home = astrid_core::dirs::AstridHome::resolve()
        .context("shutdown stage daemon.home_resolution")?;
    cleanup_daemon_runtime_for_home(&home, socket_path, pid_path).await
}

async fn cleanup_daemon_runtime_for_home(
    home: &astrid_core::dirs::AstridHome,
    socket_path: &Path,
    pid_path: &Path,
) -> Result<()> {
    // An idempotent stop on a never-initialized home must not create the Astrid
    // layout merely to prove that its absent runtime is absent.
    let durable_media_present = home
        .storage_volume_path()
        .try_exists()
        .context("shutdown stage durable_media_probe")?;
    let runtime_present = home
        .run_dir()
        .try_exists()
        .context("shutdown stage daemon.runtime_probe")?;
    if !durable_media_present && !runtime_present {
        return Ok(());
    }
    if !runtime_present {
        return Ok(());
    }
    let lock_path = home.run_dir().join("system.lock");
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let lock = options.open(&lock_path).with_context(|| {
        format!(
            "shutdown stage daemon.singleton_lock: open {}",
            lock_path.display()
        )
    })?;
    lock.try_lock().map_err(|error| match error {
        std::fs::TryLockError::WouldBlock => anyhow::anyhow!(
            "shutdown stage daemon.singleton_lock: lock remains held at {}",
            lock_path.display()
        ),
        std::fs::TryLockError::Error(error) => anyhow::anyhow!(
            "shutdown stage daemon.singleton_lock: failed to acquire {}: {error}",
            lock_path.display()
        ),
    })?;

    match astrid_core::local_transport::connect_outcome(socket_path)
        .await
        .context("shutdown stage daemon.listener_probe")?
    {
        astrid_core::local_transport::ConnectOutcome::Connected(_) => {
            anyhow::bail!(
                "shutdown stage daemon.listener_absence: endpoint remains live at {}",
                socket_path.display()
            );
        },
        astrid_core::local_transport::ConnectOutcome::Stale => {
            astrid_core::local_transport::remove_stale_endpoint(socket_path).with_context(
                || {
                    format!(
                        "shutdown stage daemon.listener_cleanup: {}",
                        socket_path.display()
                    )
                },
            )?;
        },
        astrid_core::local_transport::ConnectOutcome::Absent => {},
    }
    astrid_core::local_transport::remove_endpoint(socket_path).with_context(|| {
        format!(
            "shutdown stage daemon.listener_cleanup: {}",
            socket_path.display()
        )
    })?;
    for path in [home.ready_path(), pid_path.to_path_buf(), home.token_path()] {
        match std::fs::remove_file(&path) {
            Ok(()) => {},
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("shutdown stage daemon.marker_cleanup: {}", path.display())
                });
            },
        }
    }
    drop(lock);
    astrid_core::dirs::retire_legacy_source_tree(&home.run_dir()).with_context(|| {
        format!(
            "shutdown stage daemon.runtime_cleanup: {}",
            home.run_dir().display()
        )
    })
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
#[cfg(test)]
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
#[path = "daemon/tests.rs"]
mod tests;
