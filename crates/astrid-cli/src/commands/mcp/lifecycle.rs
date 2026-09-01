//! Shared MCP gateway endpoint, readiness, and orphan cleanup helpers.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use astrid_core::PrincipalId;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

/// The gateway endpoint is deliberately separate from the daemon's
/// `run/system.sock`; a client can reconnect MCP sessions without touching the
/// daemon listener or its singleton lifecycle.
pub(crate) const GATEWAY_SOCKET_NAME: &str = "mcp-gateway.sock";
/// Readiness metadata is written only after the gateway has authenticated its
/// broker uplink and bound the listener.
pub(crate) const GATEWAY_READY_NAME: &str = "mcp-gateway.ready";
const GATEWAY_LIFECYCLE_LOCK_NAME: &str = "mcp-gateway.lifecycle.lock";
const GATEWAY_SUPERVISOR_LOCK_NAME: &str = "mcp-gateway.start.lock";
const GATEWAY_STARTUP_LEASE_NAME: &str = "mcp-gateway.starting";
/// Version of the owner-authenticated gateway control exchange.
pub(crate) const GATEWAY_CONTROL_VERSION: u8 = 1;
/// `ready` is a bounded hook probe, never a doctor or full capsule scan.
pub(crate) const READY_TIMEOUT: Duration = Duration::from_secs(15);
const READY_POLL: Duration = Duration::from_millis(100);
/// A control frame is a tiny owner-local message. This is a protocol/DoS
/// ceiling, not an operator tuning knob.
pub(crate) const MAX_CONTROL_BYTES: usize = 16 * 1024;

/// Versioned preface sent by every short-lived `mcp attach` process before it
/// starts speaking MCP. The gateway uses this host-owned context to preserve
/// the project's `cwd://` root; it is not inferred from the gateway process
/// cwd (which is the runtime home).
pub(crate) const ATTACH_REGISTRATION_VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct AttachRegistration {
    pub version: u8,
    pub principal: String,
    pub host: String,
    pub workspace_abs: String,
    pub host_session_id: String,
    pub hook_token: String,
}

/// Ready metadata written atomically by the gateway.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct GatewayReady {
    pub version: u8,
    pub principal: String,
    pub pid: u32,
    pub hook_token: String,
}

/// Identity for a gateway that has acquired its lifecycle lock but is not yet
/// ready. The boot token binds cleanup to one attempted generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct GatewayStartupLease {
    pub version: u8,
    pub principal: String,
    pub boot_token: String,
    pub supervisor_pid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway_pid: Option<u32>,
}

/// An advisory lock held by one gateway for its entire lifetime.
#[derive(Debug)]
pub(crate) struct GatewayLifecycleLock(std::fs::File);

/// Serializes `mcp ready` spawn attempts without being owned by the gateway.
#[derive(Debug)]
pub(crate) struct GatewaySupervisorLock(std::fs::File);

impl GatewayLifecycleLock {
    pub(crate) const fn file(&self) -> &std::fs::File {
        &self.0
    }
}

impl GatewaySupervisorLock {
    pub(crate) const fn file(&self) -> &std::fs::File {
        &self.0
    }
}

fn open_lock_file(path: &Path) -> Result<std::fs::File> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("MCP gateway lock path has no parent"))?;
    ensure_private_dir(parent)?;
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options
        .open(path)
        .with_context(|| format!("failed to open {}", path.display()))
}

fn try_lock_file(file: std::fs::File, path: &Path) -> Result<Option<std::fs::File>> {
    match file.try_lock() {
        Ok(()) => Ok(Some(file)),
        Err(std::fs::TryLockError::WouldBlock) => Ok(None),
        Err(std::fs::TryLockError::Error(error)) => {
            Err(error).with_context(|| format!("failed to lock {}", path.display()))
        },
    }
}

pub(crate) fn gateway_lifecycle_path() -> Result<PathBuf> {
    Ok(astrid_core::dirs::AstridHome::resolve()?
        .run_dir()
        .join(GATEWAY_LIFECYCLE_LOCK_NAME))
}

pub(crate) fn gateway_supervisor_path() -> Result<PathBuf> {
    Ok(astrid_core::dirs::AstridHome::resolve()?
        .run_dir()
        .join(GATEWAY_SUPERVISOR_LOCK_NAME))
}

pub(crate) fn gateway_startup_lease_path() -> Result<PathBuf> {
    Ok(astrid_core::dirs::AstridHome::resolve()?
        .run_dir()
        .join(GATEWAY_STARTUP_LEASE_NAME))
}

pub(crate) fn try_acquire_gateway_lifecycle() -> Result<Option<GatewayLifecycleLock>> {
    let path = gateway_lifecycle_path()?;
    let file = open_lock_file(&path)?;
    Ok(try_lock_file(file, &path)?.map(GatewayLifecycleLock))
}

pub(crate) fn try_acquire_gateway_supervisor() -> Result<Option<GatewaySupervisorLock>> {
    let path = gateway_supervisor_path()?;
    let file = open_lock_file(&path)?;
    Ok(try_lock_file(file, &path)?.map(GatewaySupervisorLock))
}

pub(crate) fn read_gateway_startup_lease() -> Result<Option<GatewayStartupLease>> {
    let path = gateway_startup_lease_path()?;
    match std::fs::read(&path) {
        Ok(bytes) => {
            let lease: GatewayStartupLease = serde_json::from_slice(&bytes).with_context(|| {
                format!("invalid MCP gateway startup lease at {}", path.display())
            })?;
            if lease.version != 1
                || lease.principal.is_empty()
                || lease.boot_token.len() != 32
                || lease.supervisor_pid == 0
                || lease.gateway_pid.is_some_and(|pid| pid == 0)
            {
                anyhow::bail!("invalid MCP gateway startup lease at {}", path.display());
            }
            Ok(Some(lease))
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("failed to read {}", path.display())),
    }
}

pub(crate) fn write_gateway_startup_lease(lease: &GatewayStartupLease) -> Result<()> {
    let path = gateway_startup_lease_path()?;
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("MCP gateway startup lease path has no parent"))?;
    ensure_private_dir(parent)?;
    let temp = path.with_extension(format!("starting.tmp.{}", std::process::id()));
    let bytes = serde_json::to_vec(lease).context("failed to encode MCP gateway startup lease")?;
    std::fs::write(&temp, bytes).with_context(|| format!("failed to write {}", temp.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::rename(&temp, &path).with_context(|| format!("failed to publish {}", path.display()))
}

pub(crate) fn remove_gateway_startup_lease(boot_token: Option<&str>) -> Result<()> {
    let path = gateway_startup_lease_path()?;
    let lease = read_gateway_startup_lease()?;
    if let Some(lease) = lease
        && let Some(expected) = boot_token
        && lease.boot_token != expected
    {
        anyhow::bail!("MCP gateway startup generation changed before cleanup");
    }
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("failed to remove {}", path.display())),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum GatewayControlOperation {
    Health,
    Stop,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct GatewayControlRequest {
    pub version: u8,
    pub operation: GatewayControlOperation,
    pub pid: u32,
    pub hook_token: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct GatewayControlAck {
    pub version: u8,
    pub operation: GatewayControlOperation,
    pub pid: u32,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl GatewayControlAck {
    pub(crate) const fn success(operation: GatewayControlOperation, pid: u32) -> Self {
        Self {
            version: GATEWAY_CONTROL_VERSION,
            operation,
            pid,
            ok: true,
            error: None,
        }
    }

    pub(crate) fn failure(
        operation: GatewayControlOperation,
        pid: u32,
        error: impl Into<String>,
    ) -> Self {
        Self {
            version: GATEWAY_CONTROL_VERSION,
            operation,
            pid,
            ok: false,
            error: Some(error.into()),
        }
    }
}

/// Resolve a principal once at the command boundary.
pub(crate) fn resolve_principal(requested: Option<&str>) -> Result<PrincipalId> {
    match requested {
        Some(value) => {
            PrincipalId::new(value).with_context(|| format!("invalid MCP principal: {value}"))
        },
        None => Ok(crate::principal::current()),
    }
}

/// Resolve the per-user gateway socket path under the private Astrid home.
pub(crate) fn gateway_socket_path() -> Result<PathBuf> {
    Ok(astrid_core::dirs::AstridHome::resolve()?
        .run_dir()
        .join(GATEWAY_SOCKET_NAME))
}

/// Resolve the gateway readiness metadata path under the private Astrid home.
pub(crate) fn gateway_ready_path() -> Result<PathBuf> {
    Ok(astrid_core::dirs::AstridHome::resolve()?
        .run_dir()
        .join(GATEWAY_READY_NAME))
}

/// Read and validate the gateway's atomically-written readiness record.
pub(crate) fn read_gateway_ready() -> Result<Option<GatewayReady>> {
    let path = gateway_ready_path()?;
    read_gateway_ready_at(&path)
}

fn read_gateway_ready_at(path: &Path) -> Result<Option<GatewayReady>> {
    let body = match std::fs::read_to_string(path) {
        Ok(body) => body,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to read {}", path.display()));
        },
    };
    let record: GatewayReady = serde_json::from_str(&body).with_context(|| {
        format!(
            "invalid MCP gateway readiness metadata at {}",
            path.display()
        )
    })?;
    if record.version != 1
        || record.pid == 0
        || record.principal.is_empty()
        || record.hook_token.is_empty()
    {
        anyhow::bail!(
            "invalid MCP gateway readiness metadata at {}",
            path.display()
        );
    }
    Ok(Some(record))
}

/// Write readiness metadata without exposing a partial record to attachers.
pub(crate) fn write_gateway_ready(record: &GatewayReady) -> Result<()> {
    let path = gateway_ready_path()?;
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("MCP gateway readiness path has no parent"))?;
    ensure_private_dir(parent)?;
    let temp = path.with_extension(format!("ready.tmp.{}", std::process::id()));
    let bytes = serde_json::to_vec(record).context("failed to encode MCP gateway readiness")?;
    std::fs::write(&temp, bytes).with_context(|| format!("failed to write {}", temp.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::rename(&temp, &path)
        .with_context(|| format!("failed to publish {}", path.display()))?;
    Ok(())
}

/// Remove this gateway's readiness marker without deleting a successor's.
pub(crate) fn remove_gateway_ready(record: &GatewayReady) -> Result<()> {
    let path = gateway_ready_path()?;
    remove_gateway_ready_at(&path, record)
}

fn remove_gateway_ready_at(path: &Path, record: &GatewayReady) -> Result<()> {
    match read_gateway_ready_at(path)? {
        Some(current) if current == *record => std::fs::remove_file(path)
            .with_context(|| format!("failed to remove {}", path.display())),
        Some(_) => anyhow::bail!(
            "MCP gateway readiness changed before cleanup at {}",
            path.display()
        ),
        None => Ok(()),
    }
}

/// Create a private runtime directory, preserving the Astrid home boundary.
pub(crate) fn ensure_private_dir(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path).with_context(|| {
        format!(
            "failed to create private runtime directory {}",
            path.display()
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Bind-time cleanup and endpoint ownership check for a gateway listener.
pub(crate) async fn prepare_gateway_socket(_lifecycle: &GatewayLifecycleLock) -> Result<PathBuf> {
    let path = gateway_socket_path()?;
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("MCP gateway socket path has no parent"))?;
    ensure_private_dir(parent)?;

    if path.exists() {
        if UnixStream::connect(&path).await.is_ok() {
            anyhow::bail!("MCP gateway is already running at {}", path.display());
        }
        // The lifecycle lock excludes every gateway generation. If the
        // pathname survived a crash, this holder is now the only process that
        // may remove and replace it.
        std::fs::remove_file(&path).with_context(|| {
            format!(
                "failed to remove stale MCP gateway socket {}",
                path.display()
            )
        })?;
    }
    Ok(path)
}

/// Wait for a ready gateway, starting one child at most once when absent.
pub(crate) async fn wait_for_gateway(principal: &PrincipalId, format: &str) -> Result<ExitCode> {
    let format = ReadyFormat::parse(format)?;
    let socket = gateway_socket_path()?;
    let deadline = Instant::now()
        .checked_add(READY_TIMEOUT)
        .unwrap_or_else(Instant::now);
    let mut spawned = false;
    loop {
        if let Some(record) = read_gateway_ready()? {
            // A gateway is bound to the principal that minted its ready
            // record. Each attach must present that same process principal
            // and the gateway's token before an uplink is selected.
            if record.principal != principal.to_string() {
                anyhow::bail!(
                    "MCP gateway is already bound to principal '{}', not '{}'",
                    record.principal,
                    principal
                );
            }
            match astrid_core::local_transport::connect_outcome(&socket)
                .await
                .context("failed to inspect MCP gateway endpoint")?
            {
                astrid_core::local_transport::ConnectOutcome::Connected(stream) => {
                    request_gateway_control(stream, &record, GatewayControlOperation::Health)
                        .await
                        .context("MCP gateway cannot prove a recoverable daemon uplink")?;
                    emit_ready(format, &record)?;
                    return Ok(ExitCode::SUCCESS);
                },
                astrid_core::local_transport::ConnectOutcome::Absent
                | astrid_core::local_transport::ConnectOutcome::Stale
                    if crate::commands::daemon_control::is_process_alive(record.pid) =>
                {
                    anyhow::bail!(
                        "MCP gateway PID {} is alive but its listener is unavailable",
                        record.pid
                    );
                },
                astrid_core::local_transport::ConnectOutcome::Absent
                | astrid_core::local_transport::ConnectOutcome::Stale => {
                    remove_dead_gateway_markers(&record).await?;
                },
            }
        }
        if !spawned {
            let supervisor = try_acquire_gateway_supervisor()?;
            let Some(supervisor) = supervisor else {
                if Instant::now() >= deadline {
                    anyhow::bail!(
                        "MCP gateway startup supervisor remained active within {} seconds",
                        READY_TIMEOUT.as_secs()
                    );
                }
                tokio::time::sleep(READY_POLL).await;
                continue;
            };
            if read_gateway_ready()?.is_some() {
                continue;
            }
            if let Some(lease) = read_gateway_startup_lease()?
                && crate::commands::daemon_control::is_process_alive(lease.supervisor_pid)
            {
                drop(supervisor);
                if Instant::now() >= deadline {
                    anyhow::bail!(
                        "MCP gateway PID {} is still starting within {} seconds",
                        lease.supervisor_pid,
                        READY_TIMEOUT.as_secs()
                    );
                }
                tokio::time::sleep(READY_POLL).await;
                continue;
            }
            let lifecycle = try_acquire_gateway_lifecycle()?;
            if lifecycle.is_some() {
                drop(supervisor);
                if Instant::now() >= deadline {
                    anyhow::bail!(
                        "MCP gateway is starting but has not published readiness within {} seconds",
                        READY_TIMEOUT.as_secs()
                    );
                }
                tokio::time::sleep(READY_POLL).await;
                continue;
            }
            clean_unowned_gateway_startup()
                .await
                .context("shutdown stage gateway.startup_cleanup")?;
            spawn_gateway(principal)?;
            spawned = true;
        }
        if Instant::now() >= deadline {
            anyhow::bail!(
                "MCP gateway did not become ready within {} seconds",
                READY_TIMEOUT.as_secs()
            );
        }
        tokio::time::sleep(READY_POLL).await;
    }
}

/// Stop the persistent gateway through its owner-authenticated control path.
///
/// Success means the gateway returned its final teardown ACK, its recorded
/// process exited, the listener is absent, and the exact readiness record is
/// gone. Inconsistent or unowned state is left intact and reported.
pub(crate) async fn stop_gateway() -> Result<()> {
    let socket = gateway_socket_path()?;
    let Some(record) = read_gateway_ready()? else {
        let deadline = Instant::now()
            .checked_add(READY_TIMEOUT)
            .unwrap_or_else(Instant::now);
        while try_acquire_gateway_lifecycle()?.is_none()
            || read_gateway_startup_lease()?.is_some_and(|lease| {
                crate::commands::daemon_control::is_process_alive(lease.supervisor_pid)
            })
        {
            if let Some(record) = read_gateway_ready()? {
                return stop_ready_gateway(record, socket).await;
            }
            if Instant::now() >= deadline {
                anyhow::bail!(
                    "shutdown stage gateway.startup_stop: a starting gateway did not become stoppable within {} seconds",
                    READY_TIMEOUT.as_secs()
                );
            }
            tokio::time::sleep(READY_POLL).await;
        }
        let lifecycle = try_acquire_gateway_lifecycle()?.ok_or_else(|| {
            anyhow::anyhow!("shutdown stage gateway.startup_stop: lifecycle changed")
        })?;
        clean_unowned_gateway_startup()
            .await
            .context("shutdown stage gateway.stale_listener_cleanup")?;
        drop(lifecycle);
        return Ok(());
    };
    stop_ready_gateway(record, socket).await
}

async fn stop_ready_gateway(record: GatewayReady, socket: PathBuf) -> Result<()> {
    let stream = match astrid_core::local_transport::connect_outcome(&socket)
        .await
        .context("shutdown stage gateway.listener_probe")?
    {
        astrid_core::local_transport::ConnectOutcome::Connected(stream) => stream,
        astrid_core::local_transport::ConnectOutcome::Absent
        | astrid_core::local_transport::ConnectOutcome::Stale
            if crate::commands::daemon_control::is_process_alive(record.pid) =>
        {
            anyhow::bail!(
                "shutdown stage gateway.listener_absence: PID {} is alive without its authenticated listener",
                record.pid
            );
        },
        astrid_core::local_transport::ConnectOutcome::Absent
        | astrid_core::local_transport::ConnectOutcome::Stale => {
            remove_dead_gateway_markers(&record).await?;
            return Ok(());
        },
    };

    request_gateway_control(stream, &record, GatewayControlOperation::Stop)
        .await
        .context("shutdown stage gateway.final_ack")?;
    if !crate::commands::daemon_control::wait_for_exit(
        record.pid,
        crate::commands::daemon_control::GRACE,
    )
    .await
    {
        anyhow::bail!(
            "shutdown stage gateway.process_reap: authenticated gateway PID {} did not exit",
            record.pid
        );
    }
    remove_dead_gateway_markers(&record).await
}

async fn clean_unowned_gateway_startup() -> Result<()> {
    let lifecycle = try_acquire_gateway_lifecycle()?
        .ok_or_else(|| anyhow::anyhow!("MCP gateway lifecycle remains held"))?;
    let socket = gateway_socket_path()?;
    match astrid_core::local_transport::connect_outcome(&socket)
        .await
        .context("shutdown stage gateway.listener_probe")?
    {
        astrid_core::local_transport::ConnectOutcome::Absent => {},
        astrid_core::local_transport::ConnectOutcome::Stale => {
            astrid_core::local_transport::remove_stale_endpoint(&socket)
                .context("shutdown stage gateway.stale_listener_cleanup")?;
        },
        astrid_core::local_transport::ConnectOutcome::Connected(_) => anyhow::bail!(
            "shutdown stage gateway.authentication: live gateway has no readiness authority"
        ),
    }
    remove_gateway_startup_lease(None).context("shutdown stage gateway.startup_cleanup")?;
    drop(lifecycle);
    Ok(())
}

async fn request_gateway_control(
    stream: UnixStream,
    record: &GatewayReady,
    operation: GatewayControlOperation,
) -> Result<GatewayControlAck> {
    let request = GatewayControlRequest {
        version: GATEWAY_CONTROL_VERSION,
        operation,
        pid: record.pid,
        hook_token: record.hook_token.clone(),
    };
    let (read_half, mut write_half) = stream.into_split();
    let bytes = serde_json::to_vec(&request).context("failed to encode MCP gateway control")?;
    write_half
        .write_all(&bytes)
        .await
        .context("failed to write MCP gateway control")?;
    write_half
        .write_all(b"\n")
        .await
        .context("failed to terminate MCP gateway control")?;
    write_half
        .flush()
        .await
        .context("failed to flush MCP gateway control")?;

    let mut reader = BufReader::new(read_half);
    let response = tokio::time::timeout(READY_TIMEOUT, read_bounded_line(&mut reader))
        .await
        .context("timed out waiting for MCP gateway control acknowledgement")??;
    let ack: GatewayControlAck =
        serde_json::from_slice(&response).context("invalid MCP gateway control acknowledgement")?;
    if ack.version != GATEWAY_CONTROL_VERSION || ack.operation != operation || ack.pid != record.pid
    {
        anyhow::bail!("MCP gateway returned an unbound control acknowledgement");
    }
    if !ack.ok {
        anyhow::bail!(
            "MCP gateway rejected {operation:?}: {}",
            ack.error.as_deref().unwrap_or("unknown gateway failure")
        );
    }
    Ok(ack)
}

pub(crate) async fn read_bounded_line<R>(reader: &mut R) -> Result<Vec<u8>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut line = Vec::new();
    for _ in 0..=MAX_CONTROL_BYTES {
        let byte = reader
            .read_u8()
            .await
            .context("failed to read control frame")?;
        if byte == b'\n' {
            return Ok(line);
        }
        line.push(byte);
    }
    anyhow::bail!("MCP gateway control frame is missing or too large")
}

async fn remove_dead_gateway_markers(record: &GatewayReady) -> Result<()> {
    if crate::commands::daemon_control::is_process_alive(record.pid) {
        anyhow::bail!(
            "shutdown stage gateway.process_reap: PID {} is still alive",
            record.pid
        );
    }
    let lifecycle = try_acquire_gateway_lifecycle()?;
    let Some(lifecycle) = lifecycle else {
        anyhow::bail!(
            "shutdown stage gateway.lifecycle_fence: a successor gateway lifecycle remains active"
        );
    };
    let socket = gateway_socket_path()?;
    match astrid_core::local_transport::connect_outcome(&socket)
        .await
        .context("shutdown stage gateway.listener_probe")?
    {
        astrid_core::local_transport::ConnectOutcome::Connected(_) => {
            anyhow::bail!(
                "shutdown stage gateway.listener_absence: a gateway is still accepting connections"
            );
        },
        astrid_core::local_transport::ConnectOutcome::Absent => {},
        astrid_core::local_transport::ConnectOutcome::Stale => {
            astrid_core::local_transport::remove_stale_endpoint(&socket)
                .context("shutdown stage gateway.listener_cleanup")?;
        },
    }
    remove_gateway_ready(record).context("shutdown stage gateway.ready_cleanup")?;
    remove_gateway_startup_lease(None).context("shutdown stage gateway.startup_cleanup")?;
    drop(lifecycle);
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadyFormat {
    Hook,
    Pretty,
    Json,
}

impl ReadyFormat {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "hook" => Ok(Self::Hook),
            "pretty" => Ok(Self::Pretty),
            "json" => Ok(Self::Json),
            other => anyhow::bail!(
                "unsupported MCP readiness format '{other}'; use hook, pretty, or json"
            ),
        }
    }
}

fn emit_ready(format: ReadyFormat, record: &GatewayReady) -> Result<()> {
    match format {
        ReadyFormat::Hook => println!("ready"),
        ReadyFormat::Pretty => println!("MCP gateway ready (principal {})", record.principal),
        ReadyFormat::Json => println!("{}", serde_json::to_string(record)?),
    }
    Ok(())
}

fn spawn_gateway(principal: &PrincipalId) -> Result<()> {
    let executable =
        std::env::current_exe().context("failed to resolve the Astrid CLI executable")?;
    Command::new(executable)
        .arg("--principal")
        .arg(principal.to_string())
        .arg("mcp")
        .arg("gateway")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("failed to start MCP gateway")?;
    Ok(())
}

/// Entry point for `mcp ready`.
pub(crate) async fn ready(principal: Option<&str>, format: &str) -> Result<ExitCode> {
    let principal = resolve_principal(principal)?;
    wait_for_gateway(&principal, format).await
}

/// A process row from the host's portable `ps` listing.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ProcessRow {
    pid: u32,
    ppid: u32,
    command: String,
}

fn parse_process_row(line: &str) -> Option<ProcessRow> {
    let mut fields = line.split_whitespace();
    let process_id = fields.next()?.parse().ok()?;
    let parent_id = fields.next()?.parse().ok()?;
    let command = fields.collect::<Vec<_>>().join(" ");
    (!command.is_empty()).then_some(ProcessRow {
        pid: process_id,
        ppid: parent_id,
        command,
    })
}

fn command_file_name(token: &str) -> &str {
    Path::new(token)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(token)
}

fn is_env_assignment(token: &str) -> bool {
    let Some((name, _value)) = token.split_once('=') else {
        return false;
    };
    let mut characters = name.bytes();
    let Some(first) = characters.next() else {
        return false;
    };
    (first == b'_' || first.is_ascii_alphabetic())
        && characters.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
}

fn is_python_frame(command: &str) -> bool {
    command.contains("aos-mcp-frame")
        || command.contains("Python.framework")
        || command.split_whitespace().any(|token| {
            matches!(
                command_file_name(token),
                "python3" | "Python" | "aos-mcp-frame"
            )
        })
}

fn is_long_mcp_serve(command: &str) -> bool {
    let tokens = command.split_whitespace().collect::<Vec<_>>();
    let has_mcp_serve = tokens.windows(2).any(|pair| pair == ["mcp", "serve"]);
    let has_timeout = tokens.iter().enumerate().any(|(index, token)| {
        (*token == "--request-timeout"
            && index.checked_add(1).and_then(|next| tokens.get(next)) == Some(&"1d5m"))
            || *token == "--request-timeout=1d5m"
    });
    has_mcp_serve && has_timeout
}

fn is_mcp_attach(command: &str) -> bool {
    if is_python_frame(command) {
        return false;
    }
    let tokens = command.split_whitespace().collect::<Vec<_>>();
    let Some(attach_index) = tokens.windows(2).position(|pair| pair == ["mcp", "attach"]) else {
        return false;
    };
    // Only argv[0] (or an explicit `env VAR=value ...` wrapper) can establish
    // Astrid identity. A basename later in the command is commonly a script,
    // workspace, or argument and must not make an unrelated process reapable.
    let prefix = &tokens[..attach_index];
    let Some(executable) = prefix.first() else {
        return false;
    };
    if matches!(command_file_name(executable), "astrid" | "aos") {
        return true;
    }
    if command_file_name(executable) != "env" {
        return false;
    }
    let mut index = 1;
    while prefix
        .get(index)
        .is_some_and(|token| is_env_assignment(token))
    {
        index = index.saturating_add(1);
    }
    prefix
        .get(index)
        .is_some_and(|token| matches!(command_file_name(token), "astrid" | "aos"))
}

fn is_reapable_mcp(command: &str) -> bool {
    is_long_mcp_serve(command) || is_mcp_attach(command)
}

/// Remove orphaned long-timeout `mcp serve` and `mcp attach` processes.
///
/// Never signals Python `aos-mcp-frame` processes. Those abort on 3.14 if a
/// SIGKILL races `Buffered_close`; attach children are the reap target.
pub(crate) fn gc() -> Result<ExitCode> {
    let output = Command::new("ps")
        .args(["-axo", "pid=,ppid=,command="])
        .output()
        .context("failed to inspect MCP processes with ps")?;
    if !output.status.success() {
        anyhow::bail!("ps failed while inspecting MCP processes");
    }
    let listing = String::from_utf8_lossy(&output.stdout);
    let mut reaped = 0_u32;
    for row in listing.lines().filter_map(parse_process_row) {
        if row.pid == std::process::id() || !is_reapable_mcp(&row.command) {
            continue;
        }
        let parent_dead =
            row.ppid == 1 || !crate::commands::daemon_control::is_process_alive(row.ppid);
        if !parent_dead {
            continue;
        }
        // Re-read the command immediately before signalling to avoid killing a
        // recycled PID that no longer belongs to a reapable MCP shim.
        if !process_command(row.pid).is_some_and(|command| is_reapable_mcp(&command)) {
            continue;
        }
        #[cfg(unix)]
        nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(i32::try_from(row.pid).unwrap_or_default()),
            nix::sys::signal::Signal::SIGTERM,
        )
        .with_context(|| format!("failed to stop orphan MCP process {}", row.pid))?;
        reaped = reaped.saturating_add(1);
    }
    println!("reaped {reaped} orphan MCP process(es)");
    Ok(ExitCode::SUCCESS)
}

fn process_command(pid: u32) -> Option<String> {
    let output = Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "command="])
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncWriteExt, BufReader};
    use tokio::net::UnixStream;

    use super::*;

    #[test]
    fn gateway_lifecycle_admits_only_one_generation() {
        let first = try_acquire_gateway_lifecycle()
            .expect("lifecycle probe")
            .expect("first generation owns the lifecycle");
        assert!(
            try_acquire_gateway_lifecycle()
                .expect("lifecycle probe")
                .is_none(),
            "a successor must not bind while a generation lifecycle is held"
        );
        drop(first);
        assert!(
            try_acquire_gateway_lifecycle()
                .expect("lifecycle probe")
                .is_some(),
            "releasing the lifecycle must permit the next generation"
        );
    }

    #[test]
    fn process_parser_preserves_command_after_pid_fields() {
        let row = parse_process_row(" 123  1 /usr/local/bin/aos mcp serve --request-timeout 1d5m")
            .expect("process row");
        assert_eq!(row.pid, 123);
        assert_eq!(row.ppid, 1);
        assert!(is_long_mcp_serve(&row.command));
    }

    #[test]
    fn gc_match_is_exact_about_timeout_and_verb() {
        assert!(is_long_mcp_serve("aos mcp serve --request-timeout 1d5m"));
        assert!(is_long_mcp_serve("aos mcp serve --request-timeout=1d5m"));
        assert!(!is_long_mcp_serve("aos mcp serve --request-timeout 30s"));
        assert!(!is_long_mcp_serve("aos mcp gateway --request-timeout 1d5m"));
    }

    #[test]
    fn gc_reaps_orphaned_attach_but_never_python_frames() {
        assert!(is_mcp_attach(
            "/Users/me/.aos/runtime/bin/astrid --principal codex-code mcp attach --workspace /tmp/proj"
        ));
        assert!(is_mcp_attach("aos --principal codex-code mcp attach"));
        assert!(!is_mcp_attach(
            "/opt/homebrew/Cellar/python@3.14/3.14.6/Frameworks/Python.framework/Versions/3.14/Resources/Python.app/Contents/MacOS/Python -u /cache/unicity-aos/bin/aos-mcp-frame /runtime/bin/astrid --principal codex-code mcp attach --workspace /plugin"
        ));
        assert!(is_python_frame(
            "Python -u /cache/bin/aos-mcp-frame astrid --principal codex-code mcp attach"
        ));
        assert!(!is_mcp_attach(
            "node worker.js mcp attach --workspace /tmp/astrid"
        ));
        assert!(!is_mcp_attach("node /tmp/astrid worker.js mcp attach"));
        assert!(is_mcp_attach(
            "env ASTRID_SESSION_ID=thread-1 /opt/aos mcp attach --workspace /tmp/proj"
        ));
        assert!(!is_mcp_attach("astrid --principal codex-code mcp gateway"));
        assert!(!is_mcp_attach("aos mcp serve --request-timeout 1d5m"));
    }

    #[test]
    fn ready_record_is_stable_json_contract() {
        let record = GatewayReady {
            version: 1,
            principal: "codex-code".into(),
            pid: 42,
            hook_token: "test-hook-token".into(),
        };
        let body = serde_json::to_string(&record).expect("record json");
        assert_eq!(serde_json::from_str::<GatewayReady>(&body).unwrap(), record);
        assert_eq!(ReadyFormat::parse("hook").unwrap(), ReadyFormat::Hook);
    }

    #[test]
    fn ready_cleanup_cannot_remove_a_successor_record() {
        let temp = tempfile::tempdir().expect("temp dir");
        let path = temp.path().join(GATEWAY_READY_NAME);
        let old = GatewayReady {
            version: 1,
            principal: "codex-code".into(),
            pid: 41,
            hook_token: "old-token".into(),
        };
        let successor = GatewayReady {
            version: 1,
            principal: "codex-code".into(),
            pid: 42,
            hook_token: "successor-token".into(),
        };
        std::fs::write(&path, serde_json::to_vec(&successor).unwrap()).unwrap();

        let error = remove_gateway_ready_at(&path, &old)
            .expect_err("old cleanup must not remove a successor marker");
        assert!(error.to_string().contains("readiness changed"));
        assert_eq!(
            read_gateway_ready_at(&path).unwrap(),
            Some(successor.clone())
        );

        remove_gateway_ready_at(&path, &successor).expect("successor removes its own marker");
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn control_ack_is_bound_to_operation_pid_and_success() {
        for ack in [
            GatewayControlAck::success(GatewayControlOperation::Stop, 42),
            GatewayControlAck::success(GatewayControlOperation::Health, 43),
            GatewayControlAck::failure(GatewayControlOperation::Health, 42, "uplink unavailable"),
        ] {
            let (client, server) = UnixStream::pair().expect("stream pair");
            let serving = tokio::spawn(async move {
                let (read_half, mut write_half) = server.into_split();
                let mut reader = BufReader::new(read_half);
                let request = read_bounded_line(&mut reader).await.expect("request");
                serde_json::from_slice::<GatewayControlRequest>(&request).expect("valid request");
                write_half
                    .write_all(&serde_json::to_vec(&ack).unwrap())
                    .await
                    .unwrap();
                write_half.write_all(b"\n").await.unwrap();
            });
            let record = GatewayReady {
                version: 1,
                principal: "codex-code".into(),
                pid: 42,
                hook_token: "gateway-token".into(),
            };
            request_gateway_control(client, &record, GatewayControlOperation::Health)
                .await
                .expect_err("an unbound or unsuccessful ACK must fail");
            serving.await.expect("fake server");
        }
    }
}
