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
use astrid_core::kernel_api::{AdminRequestKind, AdminResponseBody, AgentSummary};
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
    /// Capability pattern. Colon-delimited segments of
    /// `[a-zA-Z0-9_-]+` or bare `*` (no dots — capability identifiers
    /// are role labels, not resource URIs). Examples:
    /// `self:capsule:install`, `network:egress:openai`,
    /// `system:shutdown`, `*` (with --unsafe-admin).
    pub capability: String,
    /// Grant to a group instead of an individual (deferred — group
    /// modify IPC is followup work).
    #[arg(short, long, hide = true)]
    pub group: bool,
    /// Required when `capability` is the universal `*` pattern.
    /// Granting `*` to an individual agent confers admin-level
    /// authority; the kernel refuses without this acknowledgement.
    /// Mirrors the same flag on `group create --caps "*"`.
    #[arg(long)]
    pub unsafe_admin: bool,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct RevokeArgs {
    /// Agent name.
    pub name: String,
    /// Capability pattern to revoke. Same grammar as `caps grant` —
    /// colon-delimited `[a-zA-Z0-9_-]+` segments or bare `*`.
    pub capability: String,
    /// Revoke from a group (deferred).
    #[arg(short, long, hide = true)]
    pub group: bool,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct CheckArgs {
    /// Agent name.
    pub name: String,
    /// Capability pattern to check. Same grammar as `caps grant` —
    /// colon-delimited `[a-zA-Z0-9_-]+` segments or bare `*`.
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
    // Pad raw strings *before* applying ANSI escape codes — the
    // `{:<N}` formatter counts every byte (including escape codes)
    // toward width, so colouring a value inside the format spec
    // visually shrinks its column by the ANSI overhead and misaligns
    // every subsequent column.
    println!(
        "  {}  {}  STATUS",
        format!("{:<60}", "CAPABILITY").bold(),
        format!("{:<24}", "SOURCE").bold()
    );
    for g in &agent.groups {
        println!(
            "  {:<60}  {}  {}",
            format!("(group: {g})"),
            format!("{:<24}", "group").dimmed(),
            "inherited".green()
        );
    }
    // Layer 5 precedence is revoke > grant. A grant `cap` is shadowed
    // if ANY revoke pattern matches it under the same segment-glob
    // rules the kernel uses for enforcement
    // (`capability_matches(revoke, cap)`). Exact string equality would
    // miss pattern revokes (e.g. `sys:*` shadowing `sys:status`),
    // misleading an operator into thinking a cap is live when it
    // isn't.
    for cap in &agent.grants {
        let status = if agent
            .revokes
            .iter()
            .any(|r| astrid_core::capability_grammar::capability_matches(r, cap))
        {
            "shadowed by revoke".dimmed().to_string()
        } else {
            "active".green().to_string()
        };
        println!(
            "  {:<60}  {}  {status}",
            cap,
            format!("{:<24}", "individual grant").dimmed(),
        );
    }
    for cap in &agent.revokes {
        println!(
            "  {:<60}  {}  {}",
            cap,
            format!("{:<24}", "individual revoke").dimmed(),
            "revoked".yellow()
        );
    }
    if agent.groups.is_empty() && agent.grants.is_empty() && agent.revokes.is_empty() {
        println!("  {}", Theme::info("(no direct grants or revokes)"));
    }
}

/// Client-side mirror of the kernel's universal-grant rail.
///
/// The bare `"*"` pattern grants admin-equivalent reach to a single
/// agent — a one-step bypass of the group-creation safety rail
/// (`group create --caps "*"` already requires `--unsafe-admin`).
/// Mirroring the check at the CLI saves a round-trip and surfaces the
/// reason inline. Multi-segment wildcards (`network:egress:*`,
/// `self:capsule:*`) are scoped and unaffected.
fn validate_grant_pattern(pattern: &str, unsafe_admin: bool) -> Result<(), &'static str> {
    if pattern == "*" && !unsafe_admin {
        return Err(
            "refusing to grant universal `*` without --unsafe-admin: this confers admin-equivalent reach on a single agent. Re-run with --unsafe-admin if intentional.",
        );
    }
    Ok(())
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
    // Client-side mirror of the kernel's universal-grant rail. The
    // kernel is authoritative — the same check fires there even if a
    // client speaks the wire format directly — but rejecting the
    // request locally saves an IPC round-trip and lets the operator
    // see the explanatory error without scrolling daemon logs.
    if let Err(msg) = validate_grant_pattern(&args.capability, args.unsafe_admin) {
        eprintln!("{}", Theme::error(msg));
        return Ok(ExitCode::from(2));
    }
    let principal = PrincipalId::new(&args.name).context("invalid agent name")?;
    let mut client = AdminClient::connect().await?;
    let body = client
        .request(AdminRequestKind::CapsGrant {
            principal,
            capabilities: vec![args.capability.clone()],
            unsafe_admin: args.unsafe_admin,
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
    // Mirrors the Layer 5 enforcement preamble's resolution order:
    // explicit revokes (highest precedence) → direct grants → group-
    // inherited patterns. Pattern matching uses
    // `astrid_core::capability_grammar::capability_matches` — the
    // same function the kernel runs — so the CLI answer matches what
    // the kernel would decide at request time (modulo races against
    // an admin write between the two admin RPCs we issue below).
    use astrid_core::capability_grammar::capability_matches;

    let principal = PrincipalId::new(&args.name).context("invalid agent name")?;
    let mut client = AdminClient::connect().await?;

    let summary_body = client.request(AdminRequestKind::AgentList).await?;
    let summary_body = into_result(summary_body)?;
    let agents = match summary_body {
        AdminResponseBody::AgentList(list) => list,
        other => anyhow::bail!("unexpected response from kernel: {other:?}"),
    };
    let Some(agent) = agents.iter().find(|a| a.principal == principal) else {
        eprintln!(
            "{}",
            Theme::error(&format!("agent '{principal}' not found"))
        );
        return Ok(ExitCode::from(1));
    };

    // Revoke wins over everything.
    if let Some(pattern) = agent
        .revokes
        .iter()
        .find(|p| capability_matches(p, &args.capability))
    {
        println!(
            "{}: {} {} '{}' (revoke pattern: {pattern})",
            "denied".red().bold(),
            args.capability,
            "is revoked from".dimmed(),
            args.name
        );
        return Ok(ExitCode::from(1));
    }

    // Direct grant beats group inheritance — easier diagnostic.
    if let Some(pattern) = agent
        .grants
        .iter()
        .find(|p| capability_matches(p, &args.capability))
    {
        println!(
            "{}: '{}' {} (grant pattern: {pattern})",
            "allowed".green().bold(),
            args.name,
            "holds a direct grant".dimmed()
        );
        return Ok(ExitCode::SUCCESS);
    }

    // Group inheritance: fetch the full group catalogue and resolve.
    if !agent.groups.is_empty() {
        let groups_body = client.request(AdminRequestKind::GroupList).await?;
        let groups_body = into_result(groups_body)?;
        let groups = match groups_body {
            AdminResponseBody::GroupList(list) => list,
            other => anyhow::bail!("unexpected response from kernel: {other:?}"),
        };

        for group_name in &agent.groups {
            let Some(group) = groups.iter().find(|g| &g.name == group_name) else {
                continue;
            };
            if let Some(pattern) = group
                .capabilities
                .iter()
                .find(|p| capability_matches(p, &args.capability))
            {
                println!(
                    "{}: '{}' {} '{}' (pattern: {pattern})",
                    "allowed".green().bold(),
                    args.name,
                    "inherits from group".dimmed(),
                    group_name
                );
                return Ok(ExitCode::SUCCESS);
            }
        }
    }

    println!(
        "{}: '{}' {} {}",
        "denied".red().bold(),
        args.name,
        "has no grant matching".dimmed(),
        args.capability
    );
    Ok(ExitCode::from(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_grant_pattern_rejects_bare_star_without_unsafe_admin() {
        let err = validate_grant_pattern("*", false).expect_err("bare `*` must be rejected");
        assert!(err.contains("--unsafe-admin"), "msg={err}");
    }

    #[test]
    fn validate_grant_pattern_accepts_bare_star_with_unsafe_admin() {
        validate_grant_pattern("*", true).expect("bare `*` with --unsafe-admin must pass");
    }

    #[test]
    fn validate_grant_pattern_accepts_scoped_wildcards() {
        // Multi-segment wildcards are inherently scoped — the rail only
        // triggers on the universal pattern.
        validate_grant_pattern("network:egress:*", false).expect("scoped wildcard");
        validate_grant_pattern("self:capsule:*", false).expect("scoped wildcard");
        validate_grant_pattern("agent:disable", false).expect("concrete cap");
    }

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
