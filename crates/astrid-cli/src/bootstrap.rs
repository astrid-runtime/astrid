//! Bootstrap helpers — directory setup, logging, companion-binary
//! discovery, and the interactive-session boot path.
//!
//! Extracted from [`crate::main`] so the dispatcher stays focused on
//! routing subcommands rather than infrastructure.

use std::process::ExitCode;

use anyhow::{Context, Result};
use astrid_core::dirs::AstridHome;

use crate::cli::Cli;
use crate::commands;
use crate::formatter::OutputFormat;
use crate::socket_client;
use crate::theme;

/// Ensure `~/.astrid/` exists without selecting product composition.
#[allow(clippy::unused_async)]
pub(crate) async fn ensure_global_config() {
    if let Ok(home) = AstridHome::resolve() {
        let _ = home.ensure();
    }
}

/// Configure tracing/logging for this CLI invocation.
pub(crate) fn init_logging(cli: &Cli) {
    let workspace_root = std::env::current_dir().ok();
    let unified_cfg = astrid_config::Config::load_with_layout(
        workspace_root.as_deref(),
        crate::workspace_layout::current(),
    )
    .ok()
    .map(|r| r.config);

    let needs_file_log = matches!(cli.command, Some(crate::cli::Commands::Chat { .. }) | None);

    let log_config = if let Some(cfg) = &unified_cfg {
        let mut lc = astrid_telemetry::log_config_from(cfg);
        if cli.verbose {
            "debug".clone_into(&mut lc.level);
        }
        if needs_file_log && let Ok(home) = astrid_core::dirs::AstridHome::resolve() {
            lc.target = astrid_telemetry::LogTarget::File(home.log_dir());
        }
        lc
    } else {
        let level = if cli.verbose { "debug" } else { "info" };
        let mut lc = astrid_telemetry::LogConfig::new(level)
            .with_format(astrid_telemetry::LogFormat::Compact);
        if needs_file_log && let Ok(home) = astrid_core::dirs::AstridHome::resolve() {
            lc.target = astrid_telemetry::LogTarget::File(home.log_dir());
        }
        lc
    };

    // `mcp serve` owns stdout for the MCP JSON-RPC stream. A stray log
    // frame on stdout corrupts the protocol irrecoverably, so force
    // diagnostics off stdout regardless of operator config — to the log
    // file when a home is resolvable, else stderr.
    let mut log_config = log_config;
    if matches!(
        cli.command,
        Some(crate::cli::Commands::Mcp {
            command: crate::cli::McpCommands::Serve
        })
    ) && matches!(log_config.target, astrid_telemetry::LogTarget::Stdout)
    {
        log_config.target = match astrid_core::dirs::AstridHome::resolve() {
            Ok(home) => astrid_telemetry::LogTarget::File(home.log_dir()),
            Err(_) => astrid_telemetry::LogTarget::Stderr,
        };
    }

    if let Err(e) = astrid_telemetry::setup_logging(&log_config) {
        eprintln!("Failed to initialize logging: {e}");
    }
}

/// Locate a companion binary (e.g. `astrid-daemon`, `astrid-build`).
///
/// Search order:
/// 1. Same directory as the current executable (co-installed)
/// 2. `PATH` lookup
pub(crate) fn find_companion_binary(name: &str) -> Result<std::path::PathBuf> {
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    if let Ok(path) = which::which(name) {
        return Ok(path);
    }
    anyhow::bail!(
        "{name} not found. Ensure it is installed alongside the astrid CLI \
         or available in PATH."
    )
}

/// Run the legacy `astrid build` companion binary, used both by the
/// hidden top-level `Build` alias and the new `astrid capsule build`.
pub(crate) fn run_build_companion(
    path: Option<&str>,
    output: Option<&str>,
    project_type: Option<&str>,
    from_mcp_json: Option<&str>,
) -> Result<ExitCode> {
    let build_bin = find_companion_binary("astrid-build")?;
    let mut cmd = std::process::Command::new(build_bin);
    if let Some(p) = path {
        cmd.arg(p);
    }
    if let Some(o) = output {
        cmd.arg("--output").arg(o);
    }
    if let Some(t) = project_type {
        cmd.arg("--type").arg(t);
    }
    if let Some(m) = from_mcp_json {
        cmd.arg("--from-mcp-json").arg(m);
    }
    let status = cmd.status().context("Failed to run astrid-build")?;
    if status.success() {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(
            u8::try_from(status.code().unwrap_or(1).clamp(0, 255)).unwrap_or(1),
        ))
    }
}

/// Resolve the session, check for an existing socket, and boot the
/// kernel locally if necessary. Drives the interactive-session path.
///
/// # Errors
/// Returns an error if the kernel fails to boot or the socket fails to connect.
pub(crate) async fn run_or_connect(
    session: Option<String>,
    workspace: Option<std::path::PathBuf>,
    format: OutputFormat,
) -> Result<()> {
    use astrid_core::SessionId;
    use uuid::Uuid;

    let session_id = if let Some(sid) = session {
        SessionId::from_uuid(
            Uuid::parse_str(&sid).map_err(|e| anyhow::anyhow!("Invalid UUID format: {e}"))?,
        )
    } else {
        SessionId::from_uuid(Uuid::new_v4())
    };

    let socket_path = socket_client::proxy_socket_path();
    let ready_path = socket_client::readiness_path();

    let mut needs_boot = !socket_path.exists();

    if socket_path.exists() {
        match tokio::net::UnixStream::connect(&socket_path).await {
            Ok(_) => {
                println!(
                    "{}",
                    theme::Theme::info("Connecting to existing Astrid daemon...")
                );
            },
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                println!(
                    "{}",
                    theme::Theme::warning(
                        "Found dead socket. Cleaning up and restarting daemon..."
                    )
                );
                let _ = std::fs::remove_file(&socket_path);
                let _ = std::fs::remove_file(&ready_path);
                needs_boot = true;
            },
            Err(e) => {
                anyhow::bail!("Failed to check socket: {e}");
            },
        }
    }

    let mut daemon_child: Option<std::process::Child> = None;

    if needs_boot {
        match commands::daemon::spawn_daemon(&ready_path).await {
            Ok(child) => daemon_child = Some(child),
            Err(e) => return Err(e),
        }
    }

    let mut client = match socket_client::connect_for_workspace(
        session_id.clone(),
        crate::principal::current(),
        workspace.as_deref(),
    )
    .await
    {
        Ok(c) => {
            drop(daemon_child);
            c
        },
        Err(e) => {
            if let Some(mut child) = daemon_child {
                let _ = child.kill();
                let _ = child.wait();
            }
            let log_hint = astrid_core::dirs::AstridHome::resolve().map_or_else(
                |_| "Failed to connect to daemon".to_string(),
                |h| {
                    format!(
                        "Failed to connect to daemon. Check logs: {}",
                        h.log_dir().display()
                    )
                },
            );
            return Err(e.context(log_hint));
        },
    };

    let workspace_root = std::env::current_dir().ok();
    let model_name = astrid_config::Config::load_with_layout(
        workspace_root.as_deref(),
        crate::workspace_layout::current(),
    )
    .ok()
    .map_or_else(|| "unknown".to_string(), |r| r.config.model.model);

    crate::commands::chat::run_chat(&mut client, &session_id, &model_name, format).await
}
