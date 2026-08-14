//! Process construction helpers for MCP stdio servers.

#[cfg(windows)]
use process_wrap::tokio::JobObject;
#[cfg(unix)]
use process_wrap::tokio::ProcessGroup;
use process_wrap::tokio::{CommandWrap, KillOnDrop};
use rmcp::ClientLifecycleMode;
use rmcp::model::ProtocolVersion;
use tracing::{info, warn};

use crate::config::ServerConfig;

/// Prefer modern server discovery while retaining explicit legacy fallback.
pub(super) fn mcp_client_lifecycle() -> ClientLifecycleMode {
    ClientLifecycleMode::Auto {
        preferred_versions: vec![ProtocolVersion::V_2026_07_28, ProtocolVersion::V_2025_11_25],
        legacy_version: Some(ProtocolVersion::V_2025_11_25),
    }
}

/// Wrap an MCP subprocess in the platform's process-tree ownership primitive.
///
/// rmcp kills its transport child when the transport is dropped. These wrappers
/// extend that kill to the entire Unix process group or Windows Job Object, so
/// helper processes cannot outlive a retired MCP server. `KillOnDrop` also makes
/// the ownership explicit at process-wrap's layer if startup fails before rmcp
/// finishes constructing the service.
pub(super) fn wrap_process_tree(command: tokio::process::Command) -> CommandWrap {
    let mut command = CommandWrap::from(command);
    command.wrap(KillOnDrop);
    #[cfg(unix)]
    command.wrap(ProcessGroup::leader());
    #[cfg(windows)]
    command.wrap(JobObject);
    command
}

/// Today's date as `YYYY-MM-DD` for daily log file naming.
#[allow(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
pub(super) fn today_date_string() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let days = i64::from((secs / 86400) as u32);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = i64::from(yoe) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

/// Build a `tokio::process::Command` for a trusted (unsandboxed) server.
pub(super) fn build_unsandboxed_command(
    name: &str,
    command: &str,
    config: &ServerConfig,
) -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new(command);
    cmd.args(&config.args);

    for (key, value) in &config.env {
        if astrid_core::env_policy::is_blocked_spawn_env(key) {
            warn!(
                server = %name,
                key = %key,
                "Ignoring blocked env var from server config"
            );
            continue;
        }
        cmd.env(key, value);
    }

    // Prevent leaking runtime-internal vars to child processes.
    cmd.env_remove("ASTRID_SOCKET_PATH");
    cmd.env_remove("ASTRID_SESSION_TOKEN");
    cmd.env_remove("ASTRID_HOME");

    if let Some(cwd) = &config.cwd {
        cmd.current_dir(cwd);
    }

    info!(server = name, "Spawning trusted (unsandboxed) MCP server");
    cmd
}
