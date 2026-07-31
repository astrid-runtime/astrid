//! `astrid doctor` — system health check.
//!
//! Inspired by the `flyctl doctor` and `gh doctor` patterns: check
//! every prerequisite and report a single PASS/FAIL line per check.
//! Doctor never auto-fixes — it diagnoses.

use std::process::ExitCode;
use std::time::Duration;

use anyhow::Result;
use astrid_core::dirs::AstridHome;
use astrid_core::kernel_api::{
    KernelRequest, KernelResponse, ProjectionNameDiagnostic, ProjectionNamePolicyPreset,
};
use clap::{Args, ValueEnum};
use colored::Colorize;

use crate::theme::Theme;

#[derive(Args, Debug, Clone)]
pub(crate) struct DoctorArgs {
    /// Skip the daemon-roundtrip check (useful when running before
    /// `astrid start`).
    #[arg(long = "no-daemon")]
    pub no_daemon: bool,
    /// Inspect this principal's content names under a target-volume behavior
    /// profile. The diagnostic is read-only and never repairs the catalog.
    #[arg(
        long = "projection-name-policy",
        value_enum,
        conflicts_with = "no_daemon"
    )]
    pub projection_name_policy: Option<ProjectionPolicyArg>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum ProjectionPolicyArg {
    /// Byte-exact POSIX-style volume.
    PosixExactV1,
    /// Canonical-equivalence, case-sensitive volume.
    UnicodeCanonicalV1,
    /// Canonical-equivalence, case-insensitive volume.
    UnicodeCanonicalCaselessV1,
    /// Case-insensitive Windows-compatible volume.
    WindowsCaselessV1,
}

impl From<ProjectionPolicyArg> for ProjectionNamePolicyPreset {
    fn from(policy: ProjectionPolicyArg) -> Self {
        match policy {
            ProjectionPolicyArg::PosixExactV1 => Self::PosixExactV1,
            ProjectionPolicyArg::UnicodeCanonicalV1 => Self::UnicodeCanonicalV1,
            ProjectionPolicyArg::UnicodeCanonicalCaselessV1 => Self::UnicodeCanonicalCaselessV1,
            ProjectionPolicyArg::WindowsCaselessV1 => Self::WindowsCaselessV1,
        }
    }
}

/// Entry point for `astrid doctor`.
pub(crate) async fn run(args: DoctorArgs) -> Result<ExitCode> {
    println!("{}", "Astrid health check".bold());
    let mut all_passed = true;
    let mut daemon_endpoint_present = false;

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
        match astrid_core::local_transport::endpoint_is_present(&socket) {
            Ok(true) => {
                daemon_endpoint_present = true;
                check_pass("Daemon socket", &format!("present at {}", socket.display()));
            },
            Ok(false) => {
                check_warn(
                    "Daemon socket",
                    &format!("missing at {} — run `astrid start`", socket.display()),
                );
            },
            Err(error) => {
                all_passed = false;
                check_fail("Daemon endpoint", &error.to_string());
            },
        }
    }

    if !args.no_daemon && daemon_endpoint_present {
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

        if let Some(policy) = args.projection_name_policy {
            match projection_name_diagnostic(policy.into()).await {
                Ok(report) => render_projection_name_diagnostic(&report),
                Err(error) => {
                    all_passed = false;
                    check_fail("Projection names", &error.to_string());
                },
            }
        }
    } else if args.projection_name_policy.is_some() {
        all_passed = false;
        check_fail(
            "Projection names",
            "daemon endpoint is required for caller-scoped catalog inspection",
        );
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

fn render_projection_name_diagnostic(report: &ProjectionNameDiagnostic) {
    if report.collisions.is_empty() && report.escaped.is_empty() {
        check_pass(
            "Projection names",
            &format!(
                "{} name(s) are naturally representable under {}",
                report.catalog_entries, report.policy
            ),
        );
        return;
    }

    check_warn(
        "Projection names",
        &format!(
            "{} collision group(s), {} escaped segment(s) under {}",
            report.collisions.len(),
            report.escaped.len(),
            report.policy
        ),
    );
    for collision in &report.collisions {
        println!("         collision ({})", collision.kind);
        for (source, projected) in collision.sources.iter().zip(&collision.projected_segments) {
            println!("           {source:?} -> {}", projected.join("/"));
        }
    }
    for escaped in &report.escaped {
        println!(
            "         escaped {:?} segment {} ({}) -> {}",
            escaped.source,
            escaped.segment_index,
            escaped.reason,
            escaped.projected_segments.join("/")
        );
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
        crate::socket_client::connect_kernel_for_workspace(None),
    )
    .await
    .map_err(|_| anyhow::anyhow!("connection timed out after 5s"))??;
    match tokio::time::timeout(
        Duration::from_secs(5),
        client.request(KernelRequest::GetStatus),
    )
    .await
    .map_err(|_| anyhow::anyhow!("daemon response timed out after 5s"))??
    {
        KernelResponse::Status(_) => Ok(()),
        KernelResponse::Error(message) => {
            Err(anyhow::anyhow!("daemon rejected status request: {message}"))
        },
        _ => Err(anyhow::anyhow!(
            "daemon returned an unexpected status response"
        )),
    }
}

/// Query the daemon for agent-loop readiness over the same socket the
/// other daemon-dependent checks use. Rides the existing
/// `astrid.v1.request.` ingress allowlist prefix — no capsule change needed.
async fn agent_readiness() -> Result<astrid_core::kernel_api::AgentLoopReadiness> {
    let mut client = tokio::time::timeout(
        Duration::from_secs(5),
        crate::socket_client::connect_kernel_for_workspace(None),
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

async fn projection_name_diagnostic(
    policy: ProjectionNamePolicyPreset,
) -> Result<ProjectionNameDiagnostic> {
    let mut client = tokio::time::timeout(
        Duration::from_secs(5),
        crate::socket_client::connect_kernel_for_workspace(None),
    )
    .await
    .map_err(|_| anyhow::anyhow!("connection timed out after 5s"))??;
    tokio::time::timeout(
        Duration::from_secs(30),
        client.projection_name_diagnostic(policy),
    )
    .await
    .map_err(|_| anyhow::anyhow!("projection-name response timed out after 30s"))?
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
