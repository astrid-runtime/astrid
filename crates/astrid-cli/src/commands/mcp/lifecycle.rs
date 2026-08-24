//! Shared MCP gateway endpoint, readiness, and orphan cleanup helpers.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use astrid_core::PrincipalId;
use serde::{Deserialize, Serialize};
use tokio::net::UnixStream;

/// The gateway endpoint is deliberately separate from the daemon's
/// `run/system.sock`; a client can reconnect MCP sessions without touching the
/// daemon listener or its singleton lifecycle.
pub(crate) const GATEWAY_SOCKET_NAME: &str = "mcp-gateway.sock";
/// Readiness metadata is written only after the gateway has authenticated its
/// broker uplink and bound the listener.
pub(crate) const GATEWAY_READY_NAME: &str = "mcp-gateway.ready";
/// `ready` is a bounded hook probe, never a doctor or full capsule scan.
pub(crate) const READY_TIMEOUT: Duration = Duration::from_secs(15);
const READY_POLL: Duration = Duration::from_millis(100);

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
fn gateway_ready_path() -> Result<PathBuf> {
    Ok(astrid_core::dirs::AstridHome::resolve()?
        .run_dir()
        .join(GATEWAY_READY_NAME))
}

/// Read and validate the gateway's atomically-written readiness record.
pub(crate) fn read_gateway_ready() -> Result<Option<GatewayReady>> {
    let path = gateway_ready_path()?;
    let body = match std::fs::read_to_string(&path) {
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

/// Remove this gateway's readiness marker during a clean shutdown.
pub(crate) fn remove_gateway_ready() {
    if let Ok(path) = gateway_ready_path() {
        let _ = std::fs::remove_file(path);
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
pub(crate) async fn prepare_gateway_socket() -> Result<PathBuf> {
    let path = gateway_socket_path()?;
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("MCP gateway socket path has no parent"))?;
    ensure_private_dir(parent)?;

    if path.exists() {
        if UnixStream::connect(&path).await.is_ok() {
            anyhow::bail!("MCP gateway is already running at {}", path.display());
        }
        // A failed connect means the pathname is stale or the old gateway is
        // still between bind and accept. Removing it is safe because the
        // listener itself is the ownership primitive; a concurrent bind below
        // still wins with `AddrInUse` and is reported rather than clobbered.
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
            if UnixStream::connect(&socket).await.is_ok() {
                emit_ready(format, &record)?;
                return Ok(ExitCode::SUCCESS);
            }
        }
        if !spawned {
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

/// Remove orphaned long-timeout `mcp serve` processes.
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
        if row.pid == std::process::id() || !is_long_mcp_serve(&row.command) {
            continue;
        }
        let parent_dead =
            row.ppid == 1 || !crate::commands::daemon_control::is_process_alive(row.ppid);
        if !parent_dead {
            continue;
        }
        // Re-read the command immediately before signalling to avoid killing a
        // recycled PID that no longer belongs to the long-timeout MCP shim.
        if !process_command(row.pid).is_some_and(|command| is_long_mcp_serve(&command)) {
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
    use super::{GatewayReady, ReadyFormat, is_long_mcp_serve, parse_process_row};

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
}
