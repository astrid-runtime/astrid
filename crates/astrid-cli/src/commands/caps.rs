//! `astrid caps` — capability inspection and management.
//!
//! Maps directly onto Layer 6 admin IPC topics
//! `astrid.v1.admin.caps.grant` / `astrid.v1.admin.caps.revoke` and
//! reads agent grants/revokes from `astrid.v1.admin.agent.list`.
//!
//! `astrid caps show <name>` (or no-arg, defaulting to the active
//! context) renders a table of effective capabilities by source.
//! Group inheritance is not yet exposed by Layer 6 (no group-membership
//! reverse index); the CLI surfaces direct grants and revokes only and
//! marks group caps as "(via group: <name>)" without listing the
//! capabilities the group confers. This is documented as a Phase 4
//! follow-up.

use std::process::ExitCode;

use anyhow::{Context, Result};
use astrid_core::PrincipalId;
use astrid_types::kernel::{AdminRequestKind, AdminResponseBody, AgentSummary};
use clap::{Args, Subcommand};
use colored::Colorize;
use serde::Serialize;

use crate::admin_client::{AdminClient, into_result};
use crate::context;
use crate::theme::Theme;
use crate::value_formatter::{ValueFormat, emit_structured};

#[derive(Subcommand, Debug, Clone)]
pub(crate) enum CapsCommand {
    /// Show effective capabilities for an agent.
    Show(ShowArgs),
    /// Grant a capability to an agent.
    Grant(GrantArgs),
    /// Revoke a capability from an agent.
    Revoke(RevokeArgs),
    /// Test whether an agent holds a specific capability.
    Check(CheckArgs),
}

#[derive(Args, Debug, Clone)]
pub(crate) struct ShowArgs {
    /// Agent name (defaults to the active context).
    pub name: Option<String>,
    /// Output format.
    #[arg(long, default_value = "pretty")]
    pub format: String,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct GrantArgs {
    /// Agent name.
    pub name: String,
    /// Capability pattern (e.g. `network:egress:api.openai.com`).
    pub capability: String,
    /// Grant to a group instead of an individual (deferred — group
    /// modify IPC is followup work).
    #[arg(short, long, hide = true)]
    pub group: bool,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct RevokeArgs {
    /// Agent name.
    pub name: String,
    /// Capability pattern to revoke.
    pub capability: String,
    /// Revoke from a group (deferred).
    #[arg(short, long, hide = true)]
    pub group: bool,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct CheckArgs {
    /// Agent name.
    pub name: String,
    /// Capability pattern to check.
    pub capability: String,
}

/// Top-level dispatcher for `astrid caps`.
pub(crate) async fn run(cmd: CapsCommand) -> Result<ExitCode> {
    match cmd {
        CapsCommand::Show(args) => run_show(args).await,
        CapsCommand::Grant(args) => run_grant(args).await,
        CapsCommand::Revoke(args) => run_revoke(args).await,
        CapsCommand::Check(args) => run_check(args).await,
    }
}

/// Caps record emitted by `--format json|yaml|toml`.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct CapsRecord {
    /// Principal identifier.
    pub principal: String,
    /// Group memberships (capabilities inherited from these are not
    /// expanded in this view — see module docs).
    pub groups: Vec<String>,
    /// Direct capability grants beyond group inheritance.
    pub grants: Vec<String>,
    /// Capabilities explicitly revoked (highest precedence).
    pub revokes: Vec<String>,
}

impl From<AgentSummary> for CapsRecord {
    fn from(s: AgentSummary) -> Self {
        Self {
            principal: s.principal.to_string(),
            groups: s.groups,
            grants: s.grants,
            revokes: s.revokes,
        }
    }
}

async fn fetch_summary(target: &PrincipalId) -> Result<AgentSummary> {
    let mut client = AdminClient::connect().await?;
    let body = client.request(AdminRequestKind::AgentList).await?;
    let body = into_result(body)?;
    let agents = match body {
        AdminResponseBody::AgentList(list) => list,
        other => anyhow::bail!("unexpected response from kernel: {other:?}"),
    };
    agents
        .into_iter()
        .find(|a| a.principal == *target)
        .with_context(|| format!("agent '{target}' not found"))
}

async fn run_show(args: ShowArgs) -> Result<ExitCode> {
    let target = context::resolve_agent(args.name.as_deref())?;
    let format = ValueFormat::parse(&args.format);
    let summary = fetch_summary(&target).await?;

    if !format.is_pretty() {
        let record: CapsRecord = summary.into();
        emit_structured(&record, format)?;
        return Ok(ExitCode::SUCCESS);
    }

    print_caps_pretty(&summary);
    Ok(ExitCode::SUCCESS)
}

fn print_caps_pretty(agent: &AgentSummary) {
    println!(
        "  {:<60}  {:<24}  STATUS",
        "CAPABILITY".bold(),
        "SOURCE".bold()
    );
    for g in &agent.groups {
        println!(
            "  {:<60}  {:<24}  {}",
            format!("(group: {g})"),
            "group".dimmed(),
            "inherited".green()
        );
    }
    for cap in &agent.grants {
        println!(
            "  {:<60}  {:<24}  {}",
            cap,
            "individual grant".dimmed(),
            "active".green()
        );
    }
    for cap in &agent.revokes {
        println!(
            "  {:<60}  {:<24}  {}",
            cap,
            "individual revoke".dimmed(),
            "revoked".yellow()
        );
    }
    if agent.groups.is_empty() && agent.grants.is_empty() && agent.revokes.is_empty() {
        println!("  {}", Theme::info("(no direct grants or revokes)"));
    }
}

async fn run_grant(args: GrantArgs) -> Result<ExitCode> {
    if args.group {
        eprintln!(
            "astrid: --group on `caps grant` requires an `admin.group.modify --add-caps` IPC topic that has not shipped yet."
        );
        eprintln!(
            "  Use `astrid group modify --add-caps` once available, or grant per-agent for now."
        );
        return Ok(ExitCode::from(2));
    }
    let principal = PrincipalId::new(&args.name).context("invalid agent name")?;
    let mut client = AdminClient::connect().await?;
    let body = client
        .request(AdminRequestKind::CapsGrant {
            principal,
            capabilities: vec![args.capability.clone()],
        })
        .await?;
    let _ = into_result(body)?;
    println!(
        "{}",
        Theme::success(&format!(
            "Granted '{}' to agent '{}'",
            args.capability, args.name
        ))
    );
    Ok(ExitCode::SUCCESS)
}

async fn run_revoke(args: RevokeArgs) -> Result<ExitCode> {
    if args.group {
        eprintln!(
            "astrid: --group on `caps revoke` requires an `admin.group.modify --remove-caps` IPC topic that has not shipped yet."
        );
        return Ok(ExitCode::from(2));
    }
    let principal = PrincipalId::new(&args.name).context("invalid agent name")?;
    let mut client = AdminClient::connect().await?;
    let body = client
        .request(AdminRequestKind::CapsRevoke {
            principal,
            capabilities: vec![args.capability.clone()],
        })
        .await?;
    let _ = into_result(body)?;
    println!(
        "{}",
        Theme::success(&format!(
            "Revoked '{}' from agent '{}'",
            args.capability, args.name
        ))
    );
    Ok(ExitCode::SUCCESS)
}

async fn run_check(args: CheckArgs) -> Result<ExitCode> {
    // The kernel does not expose a `caps:check` IPC topic: capability
    // resolution requires the full GroupConfig + profile, both of
    // which live behind the admin write lock. We approximate by
    // fetching the agent summary and reporting whether the requested
    // capability appears in `grants`, `revokes`, or a group name. This
    // is a CLI convenience — the authoritative check is at the host
    // function boundary, not here.
    let principal = PrincipalId::new(&args.name).context("invalid agent name")?;
    let summary = fetch_summary(&principal).await?;
    if summary.revokes.iter().any(|c| c == &args.capability) {
        println!(
            "{}: {} is revoked from '{}'",
            "denied".red().bold(),
            args.capability,
            args.name
        );
        return Ok(ExitCode::from(1));
    }
    if summary.grants.iter().any(|c| c == &args.capability) {
        println!(
            "{}: '{}' has direct grant for {}",
            "allowed".green().bold(),
            args.name,
            args.capability
        );
        return Ok(ExitCode::SUCCESS);
    }
    if !summary.groups.is_empty() {
        println!(
            "{}: '{}' belongs to groups {} — group capabilities not enumerated by Layer 6",
            "indeterminate".yellow().bold(),
            args.name,
            summary.groups.join(",")
        );
        return Ok(ExitCode::from(2));
    }
    println!(
        "{}: '{}' has no direct grant for {}",
        "denied".red().bold(),
        args.name,
        args.capability
    );
    Ok(ExitCode::from(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_round_trips_to_json() {
        let summary = AgentSummary {
            principal: PrincipalId::new("alice").unwrap(),
            enabled: true,
            groups: vec!["agent".into()],
            grants: vec!["self:capsule:install".into()],
            revokes: vec!["network:egress:evil.com".into()],
        };
        let rec: CapsRecord = summary.into();
        let json = serde_json::to_string(&rec).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["principal"], "alice");
        assert_eq!(parsed["grants"][0], "self:capsule:install");
        assert_eq!(parsed["revokes"][0], "network:egress:evil.com");
    }
}
