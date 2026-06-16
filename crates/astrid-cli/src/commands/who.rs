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
    let Ok(mut client) = SocketClient::connect(session, crate::principal::current()).await else {
        eprintln!("{}", Theme::error("Failed to connect to daemon"));
        return Ok(ExitCode::from(1));
    };
    let req = astrid_core::kernel_api::KernelRequest::GetStatus;
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
    // Reuse the shared envelope extractor so this command tracks any
    // future change to the IPC response wrapper without re-implementing
    // the `{type, value}` unwrap inline (matches `ps` / `daemon` usage).
    let status = match crate::socket_client::SocketClient::extract_kernel_response(&raw) {
        Some(astrid_core::kernel_api::KernelResponse::Status(s)) => Some(s),
        _ => None,
    };

    let connections: Vec<Connection> = match status {
        Some(s) if !s.connections_by_principal.is_empty() => s
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
        Some(s) => {
            let principal = astrid_core::PrincipalId::default();
            (0..s.connected_clients)
                .map(|_| Connection {
                    agent: principal.to_string(),
                    platform: "cli".into(),
                })
                .collect()
        },
        None => Vec::new(),
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
