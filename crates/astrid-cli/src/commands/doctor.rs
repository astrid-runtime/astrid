//! `astrid doctor` — system health check.
//!
//! Inspired by the `flyctl doctor` and `gh doctor` patterns: check
//! every prerequisite and report a single PASS/FAIL line per check.
//! Doctor never auto-fixes — it diagnoses.

use std::process::ExitCode;
use std::time::Duration;

use anyhow::Result;
use astrid_core::dirs::AstridHome;
use clap::Args;
use colored::Colorize;
use uuid::Uuid;

use crate::socket_client::SocketClient;
use crate::theme::Theme;

#[derive(Args, Debug, Clone)]
pub(crate) struct DoctorArgs {
    /// Skip the daemon-roundtrip check (useful when running before
    /// `astrid start`).
    #[arg(long = "no-daemon")]
    pub no_daemon: bool,
}

/// Entry point for `astrid doctor`.
pub(crate) async fn run(args: DoctorArgs) -> Result<ExitCode> {
    println!("{}", "Astrid health check".bold());
    let mut all_passed = true;

    let home_check = match AstridHome::resolve() {
        Ok(home) => {
            check_pass(
                "ASTRID_HOME",
                &format!("resolved to {}", home.root().display()),
            );
            Some(home)
        },
        Err(e) => {
            all_passed = false;
            check_fail("ASTRID_HOME", &format!("{e}"));
            None
        },
    };

    if let Some(home) = home_check.as_ref() {
        let runtime_key = home.runtime_key_path();
        if runtime_key.exists() {
            check_pass(
                "Runtime signing key",
                &format!("present at {}", runtime_key.display()),
            );
        } else {
            check_warn(
                "Runtime signing key",
                &format!(
                    "missing at {}; will be generated on first daemon boot",
                    runtime_key.display()
                ),
            );
        }
        let socket = home.socket_path();
        if socket.exists() {
            check_pass("Daemon socket", &format!("present at {}", socket.display()));
        } else {
            check_warn(
                "Daemon socket",
                &format!("missing at {} — run `astrid start`", socket.display()),
            );
        }
    }

    if !args.no_daemon
        && let Some(home) = home_check.as_ref()
        && home.socket_path().exists()
    {
        match daemon_roundtrip().await {
            Ok(()) => check_pass("Daemon roundtrip", "GetStatus succeeded"),
            Err(e) => {
                all_passed = false;
                check_fail("Daemon roundtrip", &e.to_string());
            },
        }
    }

    println!();
    if all_passed {
        println!("{}", Theme::success("All checks passed."));
        Ok(ExitCode::SUCCESS)
    } else {
        println!("{}", Theme::error("One or more checks failed."));
        Ok(ExitCode::from(1))
    }
}

fn check_pass(name: &str, detail: &str) {
    println!("  [{}]  {} — {}", "OK".green().bold(), name.bold(), detail);
}

fn check_warn(name: &str, detail: &str) {
    println!(
        "  [{}]  {} — {}",
        "WARN".yellow().bold(),
        name.bold(),
        detail
    );
}

fn check_fail(name: &str, detail: &str) {
    println!("  [{}]  {} — {}", "FAIL".red().bold(), name.bold(), detail);
}

async fn daemon_roundtrip() -> Result<()> {
    let session = astrid_core::SessionId::from_uuid(Uuid::new_v4());
    let mut client = tokio::time::timeout(Duration::from_secs(5), SocketClient::connect(session))
        .await
        .map_err(|_| anyhow::anyhow!("connection timed out after 5s"))??;
    let req = astrid_types::kernel::KernelRequest::GetStatus;
    let val = serde_json::to_value(req)?;
    let msg = astrid_types::ipc::IpcMessage::new(
        "astrid.v1.request.status",
        astrid_types::ipc::IpcPayload::RawJson(val),
        Uuid::nil(),
    );
    client.send_message(msg).await?;
    let _raw = client
        .read_until_topic("astrid.v1.response.status", Duration::from_secs(5))
        .await?;
    Ok(())
}
