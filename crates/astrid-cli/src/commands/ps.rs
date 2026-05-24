//! `astrid ps` — list loaded capsules and their lifecycle state.
//!
//! Reads `KernelRequest::GetCapsuleMetadata` for the loaded list. Per-
//! capsule resource accounting (memory, IPC/sec, active calls, uptime)
//! requires telemetry that isn't fully wired (#639) — columns we can't
//! fill yet are marked `—`. We do not fabricate values.

use std::process::ExitCode;

use anyhow::Result;
use clap::Args;
use colored::Colorize;
use serde::Serialize;
use uuid::Uuid;

use astrid_ipc_client::socket_client::SocketClient;
use crate::theme::Theme;
use crate::value_formatter::{ValueFormat, emit_structured};

#[derive(Args, Debug, Clone)]
pub(crate) struct PsArgs {
    /// Output format.
    #[arg(long, default_value = "pretty")]
    pub format: String,
}

/// JSON/YAML/TOML record for one capsule row.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct CapsuleRow {
    /// Capsule name.
    pub capsule: String,
    /// Lifecycle state: `ready`, `loading`, `error`. Today only
    /// `ready` is exposed by `GetCapsuleMetadata` so other states are
    /// inferred as `unknown`.
    pub state: String,
}

/// Entry point for `astrid ps`.
pub(crate) async fn run(args: PsArgs) -> Result<ExitCode> {
    let format = ValueFormat::parse(&args.format);
    let socket_path = astrid_ipc_client::socket_client::proxy_socket_path();
    if !socket_path.exists() {
        if format.is_pretty() {
            println!("{}", Theme::info("No Astrid daemon is running."));
        } else {
            emit_structured(&Vec::<CapsuleRow>::new(), format)?;
        }
        return Ok(ExitCode::SUCCESS);
    }
    let session = astrid_core::SessionId::from_uuid(Uuid::new_v4());
    let Ok(mut client) = SocketClient::connect(session).await else {
        eprintln!("{}", Theme::error("Failed to connect to daemon"));
        return Ok(ExitCode::from(1));
    };
    let req = astrid_types::kernel::KernelRequest::GetCapsuleMetadata;
    let val = serde_json::to_value(req)?;
    let msg = astrid_types::ipc::IpcMessage::new(
        "astrid.v1.request.metadata",
        astrid_types::ipc::IpcPayload::RawJson(val),
        Uuid::nil(),
    );
    client.send_message(msg).await?;
    let raw = client
        .read_until_topic(
            "astrid.v1.response.metadata",
            std::time::Duration::from_secs(10),
        )
        .await?;
    let entries = match astrid_ipc_client::socket_client::SocketClient::extract_kernel_response(&raw) {
        Some(astrid_types::kernel::KernelResponse::CapsuleMetadata(list)) => list,
        _ => Vec::new(),
    };
    let mut rows: Vec<CapsuleRow> = entries
        .into_iter()
        .map(|e| CapsuleRow {
            capsule: e.name,
            state: "ready".into(),
        })
        .collect();
    rows.sort_by(|a, b| a.capsule.cmp(&b.capsule));
    if !format.is_pretty() {
        emit_structured(&rows, format)?;
        return Ok(ExitCode::SUCCESS);
    }
    if rows.is_empty() {
        println!("{}", Theme::info("(no capsules loaded)"));
        return Ok(ExitCode::SUCCESS);
    }
    println!(
        "{:<28}  {:<8}  {:<10}  {:<8}  {}",
        "CAPSULE".bold(),
        "STATE".bold(),
        "MEM".bold(),
        "CALLS".bold(),
        "UPTIME".bold()
    );
    for r in &rows {
        println!(
            "{:<28}  {:<8}  {:<10}  {:<8}  {}",
            r.capsule,
            r.state.green(),
            "—".dimmed(),
            "—".dimmed(),
            "—".dimmed()
        );
    }
    println!(
        "\n{}",
        Theme::info(
            "Memory / call / uptime columns require per-capsule telemetry (#639) — empty until that lands."
        )
    );
    Ok(ExitCode::SUCCESS)
}
