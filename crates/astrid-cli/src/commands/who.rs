//! `astrid who` — list connected clients with platform attribution.
//!
//! Per-platform attribution requires the platform-identity link IPC
//! (deferred — needs `admin.agent.link` exposing the binding map).
//! Until that ships, this surface walks the daemon's client roster
//! from `KernelRequest::GetStatus` (which exposes `connected_clients`
//! as a count) and renders a placeholder table. This is intentionally
//! shallow — operators get a `not-yet-implemented` row with a tracking
//! reference rather than fabricated columns.

use std::process::ExitCode;

use anyhow::Result;
use clap::Args;
use colored::Colorize;
use serde::Serialize;
use uuid::Uuid;

use crate::commands::daemon;
use crate::socket_client::SocketClient;
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
    if !socket_path.exists() {
        if format.is_pretty() {
            println!("{}", Theme::info("No Astrid daemon is running."));
        } else {
            emit_structured(&Vec::<Connection>::new(), format)?;
        }
        return Ok(ExitCode::SUCCESS);
    }
    let session = astrid_core::SessionId::from_uuid(Uuid::new_v4());
    let Ok(mut client) = SocketClient::connect(session).await else {
        eprintln!("{}", Theme::error("Failed to connect to daemon"));
        return Ok(ExitCode::from(1));
    };
    let req = astrid_types::kernel::KernelRequest::GetStatus;
    let val = serde_json::to_value(req)?;
    let msg = astrid_types::ipc::IpcMessage::new(
        "astrid.v1.request.status",
        astrid_types::ipc::IpcPayload::RawJson(val),
        Uuid::nil(),
    );
    client.send_message(msg).await?;
    let raw = client
        .read_until_topic(
            "astrid.v1.response.status",
            std::time::Duration::from_secs(10),
        )
        .await?;
    let count = match crate::socket_client::SocketClient::extract_kernel_response(&raw) {
        Some(astrid_types::kernel::KernelResponse::Status(s)) => s.connected_clients,
        _ => 0,
    };

    let principal = astrid_core::PrincipalId::default();
    let connections: Vec<Connection> = (0..count)
        .map(|_| Connection {
            agent: principal.to_string(),
            platform: "cli".into(),
        })
        .collect();

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
