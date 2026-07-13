//! `astrid ps` — list loaded capsules and their lifecycle state.
//!
//! Reads `KernelRequest::GetCapsuleMetadata` for the loaded list. Per-
//! capsule resource accounting (memory, IPC/sec, active calls, uptime)
//! requires telemetry that isn't fully wired (#639) — columns we can't
//! fill yet are marked `—`. We do not fabricate values.

use std::process::ExitCode;

use anyhow::Result;
use astrid_core::kernel_api::{KernelRequest, KernelResponse};
use astrid_uplink::KernelClient;
use clap::Args;
use colored::Colorize;
use serde::Serialize;

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
    let socket_path = crate::socket_client::proxy_socket_path();
    if !socket_path.exists() {
        if format.is_pretty() {
            println!("{}", Theme::info("No Astrid daemon is running."));
        } else {
            emit_structured(&Vec::<CapsuleRow>::new(), format)?;
        }
        return Ok(ExitCode::SUCCESS);
    }
    let Ok(mut client) = KernelClient::connect(crate::principal::current()).await else {
        eprintln!("{}", Theme::error("Failed to connect to daemon"));
        return Ok(ExitCode::from(1));
    };
    let entries = match client.request(KernelRequest::GetCapsuleMetadata).await {
        Ok(KernelResponse::CapsuleMetadata(list)) => list,
        Ok(KernelResponse::Error(message)) => {
            eprintln!(
                "{}",
                Theme::error(&format!(
                    "Daemon rejected capsule metadata request: {message}"
                ))
            );
            return Ok(ExitCode::from(1));
        },
        Ok(_) => {
            eprintln!(
                "{}",
                Theme::error("Unexpected response from daemon while listing capsules")
            );
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
