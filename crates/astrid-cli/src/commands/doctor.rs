//! `astrid doctor` — system health check.
//!
//! Inspired by the `flyctl doctor` and `gh doctor` patterns: check
//! every prerequisite and report a single PASS/FAIL line per check.
//! Doctor never auto-fixes — it diagnoses.

use std::process::ExitCode;
use std::time::Duration;

use anyhow::Result;
use astrid_core::dirs::AstridHome;
use astrid_core::kernel_api::{KernelRequest, KernelResponse};
use astrid_uplink::KernelClient;
use clap::Args;
use colored::Colorize;

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

        // Agent-loop readiness: can the loaded capsule set actually serve a
        // chat turn? A daemon can be healthy yet have no prompt subscriber /
        // response publisher, in which case prompts silently never reply.
        match agent_readiness().await {
            Ok(report) => {
                if report.ready {
                    check_pass(
                        "Agent loop readiness",
                        &format!("ready ({} capsule(s) loaded)", report.loaded_capsules.len()),
                    );
                } else {
                    all_passed = false;
                    check_fail("Agent loop readiness", &readiness_detail(&report));
                }
            },
            // Probe failure is not a hard failure — the daemon may simply be
            // an older build that doesn't answer this request. Warn, don't fail.
            Err(e) => check_warn("Agent loop readiness", &format!("could not probe: {e}")),
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
    let mut client = tokio::time::timeout(
        Duration::from_secs(5),
        KernelClient::connect(crate::principal::current()),
    )
    .await
    .map_err(|_| anyhow::anyhow!("connection timed out after 5s"))??;
    let _ = tokio::time::timeout(
        Duration::from_secs(5),
        client.request(KernelRequest::GetStatus),
    )
    .await
    .map_err(|_| anyhow::anyhow!("daemon response timed out after 5s"))??;
    Ok(())
}

/// Query the daemon for agent-loop readiness over the same socket the
/// other daemon-dependent checks use. Rides the existing
/// `astrid.v1.request.` ingress allowlist prefix — no capsule change needed.
async fn agent_readiness() -> Result<astrid_core::kernel_api::AgentLoopReadiness> {
    let mut client = tokio::time::timeout(
        Duration::from_secs(5),
        KernelClient::connect(crate::principal::current()),
    )
    .await
    .map_err(|_| anyhow::anyhow!("connection timed out after 5s"))??;
    match tokio::time::timeout(
        Duration::from_secs(5),
        client.request(KernelRequest::GetAgentReadiness),
    )
    .await
    .map_err(|_| anyhow::anyhow!("daemon response timed out after 5s"))??
    {
        KernelResponse::AgentReadiness(readiness) => Ok(readiness),
        KernelResponse::Error(msg) => {
            Err(anyhow::anyhow!("daemon rejected readiness query: {msg}"))
        },
        _ => Err(anyhow::anyhow!(
            "daemon did not return an agent-readiness response"
        )),
    }
}

/// Render the FAIL detail line for a not-ready report: each missing piece,
/// space-separated, with unsatisfied interfaces as `ns:iface (req)`.
fn readiness_detail(report: &astrid_core::kernel_api::AgentLoopReadiness) -> String {
    let mut parts: Vec<String> = Vec::new();
    if report.prompt_subscribers.is_empty() {
        parts.push(format!(
            "no capsule subscribes {}",
            astrid_capsule::readiness::AGENT_PROMPT_TOPIC
        ));
    }
    if report.response_publishers.is_empty() {
        parts.push(format!(
            "no capsule publishes {}",
            astrid_capsule::readiness::AGENT_RESPONSE_TOPIC
        ));
    }
    if !report.unsatisfied_required_imports.is_empty() {
        let ifaces: Vec<String> = report
            .unsatisfied_required_imports
            .iter()
            .map(|m| format!("{}:{} ({})", m.namespace, m.interface, m.requirement))
            .collect();
        parts.push(format!("unsatisfied interfaces: {}", ifaces.join(", ")));
    }
    if parts.is_empty() {
        "not ready".to_string()
    } else {
        parts.join("; ")
    }
}
