//! `astrid who` — list connected clients with per-agent attribution.
//!
//! The daemon's `KernelRequest::GetStatus` exposes both a total
//! `connected_clients` count and a `connections_by_principal`
//! breakdown sourced from `Kernel::active_connections` (incremented
//! on socket handshake, decremented on disconnect, keyed by the
//! claimed principal). One row is emitted per `(principal,
//! connection)` pair so the operator sees a real per-agent picture
//! instead of a fabricated `default`-only roster.
//!
//! Platform attribution (CLI vs Discord vs Telegram) still needs the
//! `admin.agent.link` IPC tracked in #657. Until that lands, the
//! `PLATFORM` column reads `cli` for every row — the only uplink
//! shipping today — and the info-line footer points at the tracking
//! issue so operators know it's a placeholder.

use std::process::ExitCode;

use anyhow::Result;
use astrid_core::kernel_api::{KernelRequest, KernelResponse};
use clap::Args;
use colored::Colorize;
use serde::Serialize;

use crate::commands::daemon;
use crate::theme::Theme;
use crate::value_formatter::{ValueFormat, emit_structured};

#[derive(Args, Debug, Clone)]
pub(crate) struct WhoArgs {
    /// Output format.
    #[arg(long, default_value = "pretty")]
    pub format: String,
}

/// JSON/YAML/TOML emission shape.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct Connection {
    /// Agent principal.
    pub agent: String,
    /// Platform descriptor — `cli`, `discord`, `telegram` once the
    /// link IPC ships; `unknown` until then.
    pub platform: String,
}

/// Entry point for `astrid who`.
pub(crate) async fn run(args: WhoArgs) -> Result<ExitCode> {
    let format = ValueFormat::parse(&args.format);
    let socket_path = crate::socket_client::proxy_socket_path();
    if !astrid_core::local_transport::endpoint_is_present(&socket_path)? {
        if format.is_pretty() {
            println!("{}", Theme::info("No Astrid daemon is running."));
        } else {
            emit_structured(&Vec::<Connection>::new(), format)?;
        }
        return Ok(ExitCode::SUCCESS);
    }
    let mut client = match crate::socket_client::connect_kernel_for_workspace(None).await {
        Ok(client) => client,
        Err(error) => {
            eprintln!(
                "{}",
                Theme::error(&format!("Failed to connect to daemon: {error:#}"))
            );
            return Ok(ExitCode::from(1));
        },
    };
    let status = match client.request(KernelRequest::GetStatus).await {
        Ok(KernelResponse::Status(status)) => status,
        Ok(KernelResponse::Error(message)) => {
            eprintln!(
                "{}",
                Theme::error(&format!("Daemon rejected status request: {message}"))
            );
            return Ok(ExitCode::from(1));
        },
        Ok(_) => {
            eprintln!("{}", Theme::error("Unexpected response from daemon"));
            return Ok(ExitCode::from(1));
        },
        Err(error) => {
            eprintln!(
                "{}",
                Theme::error(&format!("Failed to query daemon: {error}"))
            );
            return Ok(ExitCode::from(1));
        },
    };

    let connections: Vec<Connection> = match status {
        s if !s.connections_by_principal.is_empty() => s
            .connections_by_principal
            .iter()
            .flat_map(|pc| {
                (0..pc.count).map(move |_| Connection {
                    agent: pc.principal.clone(),
                    platform: "cli".into(),
                })
            })
            .collect(),
        // Daemon doesn't expose per-principal yet (older build) — fall
        // back to the bare count attributed to `default`. Matches the
        // pre-#22 behaviour so a CLI/daemon version skew degrades
        // gracefully instead of returning an empty roster.
        s => {
            let principal = astrid_core::PrincipalId::default();
            (0..s.connected_clients)
                .map(|_| Connection {
                    agent: principal.to_string(),
                    platform: "cli".into(),
                })
                .collect()
        },
    };

    if !format.is_pretty() {
        emit_structured(&connections, format)?;
        return Ok(ExitCode::SUCCESS);
    }
    if connections.is_empty() {
        println!("{}", Theme::info("No clients connected."));
        return Ok(ExitCode::SUCCESS);
    }
    println!(
        "{:<24}  {:<12}  {}",
        "AGENT".bold(),
        "PLATFORM".bold(),
        "STATE".bold()
    );
    for c in &connections {
        println!("{:<24}  {:<12}  {}", c.agent, c.platform, "active".green());
    }
    println!(
        "\n{}",
        Theme::info(
            "Per-client identity attribution (idle time, platform user) needs `admin.agent.link` IPC — tracking #657."
        )
    );
    // Use daemon helper to avoid unused warning until we add idle-time
    // attribution.
    let _ = daemon::format_uptime;
    Ok(ExitCode::SUCCESS)
}
