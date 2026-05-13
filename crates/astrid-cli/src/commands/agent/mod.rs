//! `astrid agent` — agent lifecycle commands.
//!
//! Each verb corresponds to a Layer 6 admin IPC topic
//! (`astrid.v1.admin.agent.*`) plus a CLI-local `switch` / `current`
//! pair that maintains the operator's active context. Delegation
//! flags (`--spawned-by`, `--budget-voucher`, `--grant-access`,
//! `--expires`) and the cross-host A2A subcommands (`discover`, `add`,
//! `card`, `import`, `export`, `delegate`) are parsed but rejected
//! with a tracking-issue reference until #656 / #658 ship.

use std::process::ExitCode;

use anyhow::{Context, Result};
use astrid_core::PrincipalId;
use astrid_types::kernel::{AdminRequestKind, AdminResponseBody, AgentSummary};
use clap::{Args, Subcommand};
use colored::Colorize;
use serde::Serialize;

use crate::admin_client::{AdminClient, into_result};
use crate::commands::stub::{self, ISSUE_DELEGATION, ISSUE_REMOTE_AUTH};
use crate::context;
use crate::theme::Theme;
use crate::value_formatter::{ValueFormat, emit_structured};

#[derive(Subcommand, Debug, Clone)]
#[allow(
    clippy::large_enum_variant,
    reason = "clap subcommand enum, constructed once per process"
)]
pub(crate) enum AgentCommand {
    /// Provision a new agent.
    Create(CreateArgs),
    /// List agents on this host (and registered remotes when ready).
    List(ListArgs),
    /// Show the active agent context.
    Current,
    /// Set the active agent context for subsequent commands.
    Switch(SwitchArgs),
    /// Show details for an agent (defaults to the active context).
    Show(ShowArgs),
    /// Remove an agent identity.
    Delete(DeleteArgs),
    /// Re-enable a previously disabled agent.
    Enable(EnableArgs),
    /// Disable an agent — denies new invocations until re-enabled.
    Disable(DisableArgs),
    /// Modify agent properties (groups, network, processes, rename).
    Modify(ModifyArgs),
    /// Bind a platform identity to an agent.
    Link(LinkArgs),
    /// Unbind a platform identity.
    Unlink(UnlinkArgs),
    /// Discover a remote agent (deferred — see #656/#658).
    Discover(StubArgs),
    /// Register a remote agent for delegation (deferred — see #656/#658).
    Add(StubArgs),
    /// View or serve an A2A Agent Card (deferred — see #656/#658).
    Card(StubArgs),
    /// Export an agent for migration (deferred — see #656/#658).
    Export(StubArgs),
    /// Import an agent on this host (deferred — see #656/#658).
    Import(StubArgs),
    /// Delegate scoped work to another agent (deferred — see #656).
    Delegate(StubArgs),
}

#[derive(Args, Debug, Clone)]
pub(crate) struct CreateArgs {
    /// Agent principal name (a-z, A-Z, 0-9, -, _).
    pub name: String,
    /// Distro to apply on first boot.
    #[arg(short, long, default_value = "astralis")]
    pub distro: String,
    /// Skip distro installation entirely.
    #[arg(long)]
    pub bare: bool,
    /// Group memberships (repeatable). Defaults to `agent`.
    #[arg(long = "group", value_name = "NAME")]
    pub groups: Vec<String>,
    /// Egress allow-list (comma-separated domains). Replaces the default.
    #[arg(long, value_name = "DOMAINS")]
    pub egress: Option<String>,
    /// Process spawn allow-list (comma-separated commands).
    #[arg(long = "process-allow", value_name = "CMDS")]
    pub process_allow: Option<String>,
    /// Bind a platform identity at creation (e.g. `discord:123456789`).
    #[arg(long = "link", value_name = "PLATFORM:ID")]
    pub link: Option<String>,
    /// WASM memory cap.
    #[arg(long, value_name = "SIZE")]
    pub memory: Option<String>,
    /// Per-invocation timeout.
    #[arg(long, value_name = "DURATION")]
    pub timeout: Option<String>,
    /// Home directory storage cap.
    #[arg(long, value_name = "SIZE")]
    pub storage: Option<String>,
    /// Concurrent background process cap.
    #[arg(long, value_name = "N")]
    pub processes: Option<u32>,
    /// Non-interactive mode (accept defaults).
    #[arg(short = 'y', long)]
    pub yes: bool,

    // ── Deferred delegation flags (#656) ─────────────────────────────
    /// Delegation parent agent (deferred — see #656).
    #[arg(long = "spawned-by", value_name = "AGENT", hide = true)]
    pub spawned_by: Option<String>,
    /// Voucher budget from parent (deferred — see #656).
    #[arg(long = "budget-voucher", value_name = "AMOUNT", hide = true)]
    pub budget_voucher: Option<String>,
    /// Voucher resource access pattern (deferred — see #656).
    #[arg(long = "grant-access", value_name = "PATTERN", hide = true)]
    pub grant_access: Option<String>,
    /// Voucher expiry (deferred — see #656).
    #[arg(long = "expires", value_name = "DURATION", hide = true)]
    pub expires: Option<String>,
    /// Persistent budget allocation (deferred — see #653 budget IPC).
    #[arg(long = "budget", value_name = "AMOUNT", hide = true)]
    pub budget: Option<String>,
    /// Budget reset cycle (deferred — see #653 budget IPC).
    #[arg(long = "period", value_name = "monthly|weekly|none", hide = true)]
    pub period: Option<String>,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct ListArgs {
    /// Show registered remote agents (deferred — see #656/#658).
    #[arg(long, hide = true)]
    pub remote: bool,
    /// Filter by group membership.
    #[arg(long = "group", value_name = "NAME")]
    pub group: Option<String>,
    /// Render the delegation hierarchy (deferred — see #656).
    #[arg(long, hide = true)]
    pub tree: bool,
    /// Output format.
    #[arg(long, default_value = "pretty")]
    pub format: String,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct SwitchArgs {
    /// Agent name to switch to.
    pub name: String,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct ShowArgs {
    /// Agent name (defaults to active context).
    pub name: Option<String>,
    /// Output format.
    #[arg(long, default_value = "pretty")]
    pub format: String,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct DeleteArgs {
    /// Agent name.
    pub name: String,
    /// Skip the interactive confirmation.
    #[arg(short = 'y', long)]
    pub yes: bool,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct EnableArgs {
    /// Agent name.
    pub name: String,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct DisableArgs {
    /// Agent name.
    pub name: String,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct ModifyArgs {
    /// Agent name.
    pub name: String,
    /// Add the agent to a group (repeatable).
    #[arg(long = "add-group", value_name = "NAME")]
    pub add_group: Vec<String>,
    /// Remove the agent from a group (repeatable).
    #[arg(long = "remove-group", value_name = "NAME")]
    pub remove_group: Vec<String>,
    /// Rename the principal (deferred — needs kernel-side rename IPC).
    #[arg(long, value_name = "NEW-NAME", hide = true)]
    pub rename: Option<String>,
    /// Replace the egress allow-list (deferred — needs network admin IPC).
    #[arg(long, value_name = "DOMAINS", hide = true)]
    pub egress: Option<String>,
    /// Replace the process allow-list (deferred — needs process admin IPC).
    #[arg(long = "process-allow", value_name = "CMDS", hide = true)]
    pub process_allow: Option<String>,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct LinkArgs {
    /// Agent name.
    pub name: String,
    /// Platform binding in `platform:id` form (e.g. `discord:123`).
    pub binding: String,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct UnlinkArgs {
    /// Agent name.
    pub name: String,
    /// Platform binding to remove.
    pub binding: String,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct StubArgs {
    /// Free-form arguments — accepted so the deferred surface parses
    /// without choking on flags written against the future shape.
    #[arg(allow_hyphen_values = true, trailing_var_arg = true)]
    pub args: Vec<String>,
}

/// Top-level dispatcher for `astrid agent <verb>`.
///
/// Returns an [`ExitCode`] so deferred surfaces can exit with code 2
/// without disturbing the surrounding `Result` flow.
pub(crate) async fn run(cmd: AgentCommand) -> Result<ExitCode> {
    match cmd {
        AgentCommand::Create(args) => run_create(args).await,
        AgentCommand::List(args) => run_list(args).await,
        AgentCommand::Current => run_current(),
        AgentCommand::Switch(args) => run_switch(args).await,
        AgentCommand::Show(args) => run_show(args).await,
        AgentCommand::Delete(args) => run_delete(args).await,
        AgentCommand::Enable(args) => run_enable(args).await,
        AgentCommand::Disable(args) => run_disable(args).await,
        AgentCommand::Modify(args) => run_modify(args).await,
        AgentCommand::Link(args) => Ok(run_link(args)),
        AgentCommand::Unlink(args) => Ok(run_unlink(args)),
        AgentCommand::Discover(_)
        | AgentCommand::Add(_)
        | AgentCommand::Card(_)
        | AgentCommand::Export(_)
        | AgentCommand::Import(_) => Ok(stub::deferred(
            "remote agent / Agent Card management",
            &[ISSUE_DELEGATION, ISSUE_REMOTE_AUTH],
        )),
        AgentCommand::Delegate(_) => Ok(stub::deferred("agent delegation", &[ISSUE_DELEGATION])),
    }
}

/// Sentinel: any of the delegation-related flags was set.
fn create_uses_deferred_flags(args: &CreateArgs) -> bool {
    args.spawned_by.is_some()
        || args.budget_voucher.is_some()
        || args.grant_access.is_some()
        || args.expires.is_some()
        || args.budget.is_some()
        || args.period.is_some()
}

async fn run_create(args: CreateArgs) -> Result<ExitCode> {
    if create_uses_deferred_flags(&args) {
        return Ok(stub::deferred(
            "agent create with delegation/budget flags",
            &[ISSUE_DELEGATION],
        ));
    }
    if args.egress.is_some()
        || args.process_allow.is_some()
        || args.memory.is_some()
        || args.timeout.is_some()
        || args.storage.is_some()
        || args.processes.is_some()
        || args.link.is_some()
        || !args.bare && args.distro != "astralis"
        || args.bare
    {
        // Many of the per-resource flags require kernel-side admin IPC
        // that did NOT ship with Layer 6 (#672 covered agent/group/
        // quota/caps; egress, process-allow, memory/timeout/storage/
        // processes per-create, distro pinning per-create, and identity
        // linking are tracked separately). We accept the flags so the
        // help surface documents them, but reject the create until
        // those handlers exist.
        eprintln!(
            "astrid: per-resource provisioning flags (--egress, --process-allow, --memory, --timeout, --storage, --processes, --distro, --bare, --link) require kernel-side IPC that has not yet shipped."
        );
        eprintln!("  Tracking issue #657 (CLI redesign) coordinates the rollout — for now use:");
        eprintln!("    astrid agent create {}", args.name);
        eprintln!(
            "    astrid quota set --agent {} --memory <SIZE> --timeout <DURATION> ...",
            args.name
        );
        eprintln!(
            "    astrid caps grant {} <capability>  # for egress / process / network",
            args.name
        );
        return Ok(ExitCode::from(2));
    }

    // Validate name client-side so a bad name fails before the IPC.
    let _principal: PrincipalId = PrincipalId::new(&args.name).context("invalid agent name")?;

    let groups: Vec<String> = if args.groups.is_empty() {
        // Empty defaults to the kernel's `agent` group (Layer 6 default).
        // Pass empty so the kernel applies the default rather than the
        // CLI duplicating the policy.
        Vec::new()
    } else {
        args.groups
    };

    let kind = AdminRequestKind::AgentCreate {
        name: args.name.clone(),
        groups,
        grants: Vec::new(),
    };

    let mut client = AdminClient::connect().await?;
    let body = client.request(kind).await?;
    let _ = into_result(body)?;

    println!(
        "{}",
        Theme::success(&format!("Created agent '{}'", args.name))
    );
    Ok(ExitCode::SUCCESS)
}

async fn run_list(args: ListArgs) -> Result<ExitCode> {
    if args.remote {
        return Ok(stub::deferred(
            "agent list --remote",
            &[ISSUE_DELEGATION, ISSUE_REMOTE_AUTH],
        ));
    }
    if args.tree {
        return Ok(stub::deferred(
            "agent list --tree (delegation hierarchy)",
            &[ISSUE_DELEGATION],
        ));
    }
    let format = ValueFormat::parse(&args.format);

    let mut client = AdminClient::connect().await?;
    let body = client.request(AdminRequestKind::AgentList).await?;
    let body = into_result(body)?;

    let mut agents = match body {
        AdminResponseBody::AgentList(list) => list,
        other => anyhow::bail!("unexpected response from kernel: {other:?}"),
    };
    agents.sort_by(|a, b| a.principal.as_str().cmp(b.principal.as_str()));

    if let Some(group) = args.group.as_deref() {
        agents.retain(|a| a.groups.iter().any(|g| g == group));
    }

    if !format.is_pretty() {
        emit_structured(&agents, format)?;
        return Ok(ExitCode::SUCCESS);
    }

    print_agent_table(&agents);
    Ok(ExitCode::SUCCESS)
}

fn print_agent_table(agents: &[AgentSummary]) {
    if agents.is_empty() {
        println!("{}", Theme::info("No agents."));
        return;
    }
    println!(
        "{:<24}  {:<10}  {}",
        "AGENT".bold(),
        "STATE".bold(),
        "GROUPS".bold()
    );
    for agent in agents {
        let state = if agent.enabled {
            "enabled".green()
        } else {
            "disabled".yellow()
        };
        let groups = if agent.groups.is_empty() {
            "—".to_string()
        } else {
            agent.groups.join(",")
        };
        println!(
            "{:<24}  {:<10}  {}",
            agent.principal.as_str(),
            state,
            groups
        );
    }
}

fn run_current() -> Result<ExitCode> {
    let agent = context::active_agent()?;
    println!("{}", agent.as_str());
    Ok(ExitCode::SUCCESS)
}

async fn run_switch(args: SwitchArgs) -> Result<ExitCode> {
    let principal = PrincipalId::new(&args.name).context("invalid agent name")?;
    // Verify the agent exists. An admin client connection is required,
    // but if the daemon is offline we still allow setting context — the
    // operator may be configuring before starting the daemon.
    if let Ok(mut client) = AdminClient::connect().await
        && let Ok(body) = client.request(AdminRequestKind::AgentList).await
        && let AdminResponseBody::AgentList(list) = body
        && !list.iter().any(|a| a.principal == principal)
    {
        eprintln!(
            "{}",
            Theme::warning(&format!(
                "agent '{}' not found on this host (context still set)",
                args.name
            ))
        );
    }
    context::set_active_agent(&principal)?;
    println!(
        "{}",
        Theme::success(&format!("Active agent set to '{principal}'"))
    );
    Ok(ExitCode::SUCCESS)
}

async fn run_show(args: ShowArgs) -> Result<ExitCode> {
    let target = context::resolve_agent(args.name.as_deref())?;
    let format = ValueFormat::parse(&args.format);
    let mut client = AdminClient::connect().await?;
    let body = client.request(AdminRequestKind::AgentList).await?;
    let body = into_result(body)?;
    let agents = match body {
        AdminResponseBody::AgentList(list) => list,
        other => anyhow::bail!("unexpected response from kernel: {other:?}"),
    };
    let Some(agent) = agents.into_iter().find(|a| a.principal == target) else {
        eprintln!("{}", Theme::error(&format!("agent '{target}' not found")));
        return Ok(ExitCode::from(1));
    };
    if !format.is_pretty() {
        emit_structured(&agent, format)?;
        return Ok(ExitCode::SUCCESS);
    }
    print_agent_detail(&agent);
    Ok(ExitCode::SUCCESS)
}

fn print_agent_detail(agent: &AgentSummary) {
    println!("{}", "Agent".bold());
    println!("  Principal: {}", agent.principal.as_str());
    println!(
        "  Enabled:   {}",
        if agent.enabled {
            "yes".green()
        } else {
            "no".yellow()
        }
    );
    println!(
        "  Groups:    {}",
        if agent.groups.is_empty() {
            "(none)".dimmed().to_string()
        } else {
            agent.groups.join(", ")
        }
    );
    if !agent.grants.is_empty() {
        println!("  Grants:");
        for cap in &agent.grants {
            println!("    + {cap}");
        }
    }
    if !agent.revokes.is_empty() {
        println!("  Revokes:");
        for cap in &agent.revokes {
            println!("    - {cap}");
        }
    }
}

async fn run_delete(args: DeleteArgs) -> Result<ExitCode> {
    let principal = PrincipalId::new(&args.name).context("invalid agent name")?;
    if !args.yes {
        eprint!("Delete agent '{principal}' (home directory is NOT removed) [y/N]? ");
        std::io::Write::flush(&mut std::io::stderr()).ok();
        let mut buf = String::new();
        std::io::stdin().read_line(&mut buf).ok();
        if !matches!(buf.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
            eprintln!("aborted.");
            return Ok(ExitCode::from(1));
        }
    }
    let mut client = AdminClient::connect().await?;
    let body = client
        .request(AdminRequestKind::AgentDelete { principal })
        .await?;
    let _ = into_result(body)?;
    println!(
        "{}",
        Theme::success(&format!("Deleted agent '{}'", args.name))
    );
    Ok(ExitCode::SUCCESS)
}

async fn run_enable(args: EnableArgs) -> Result<ExitCode> {
    let principal = PrincipalId::new(&args.name).context("invalid agent name")?;
    let mut client = AdminClient::connect().await?;
    let body = client
        .request(AdminRequestKind::AgentEnable { principal })
        .await?;
    let _ = into_result(body)?;
    println!(
        "{}",
        Theme::success(&format!("Enabled agent '{}'", args.name))
    );
    Ok(ExitCode::SUCCESS)
}

async fn run_disable(args: DisableArgs) -> Result<ExitCode> {
    let principal = PrincipalId::new(&args.name).context("invalid agent name")?;
    let mut client = AdminClient::connect().await?;
    let body = client
        .request(AdminRequestKind::AgentDisable { principal })
        .await?;
    let _ = into_result(body)?;
    println!(
        "{}",
        Theme::success(&format!("Disabled agent '{}'", args.name))
    );
    Ok(ExitCode::SUCCESS)
}

async fn run_modify(args: ModifyArgs) -> Result<ExitCode> {
    if args.rename.is_some() || args.egress.is_some() || args.process_allow.is_some() {
        eprintln!(
            "astrid: --rename, --egress, --process-allow on `agent modify` need kernel-side IPC that has not shipped."
        );
        eprintln!("  Use `astrid caps grant <agent> network:egress:<domain>` for egress changes.");
        eprintln!("  Tracking issue #657 (CLI redesign) coordinates the rollout.");
        return Ok(ExitCode::from(2));
    }
    let principal = PrincipalId::new(&args.name).context("invalid agent name")?;
    if args.add_group.is_empty() && args.remove_group.is_empty() {
        eprintln!("astrid: nothing to do (specify --add-group or --remove-group)");
        return Ok(ExitCode::from(1));
    }
    let mut client = AdminClient::connect().await?;
    let body = client.request(AdminRequestKind::AgentList).await?;
    let body = into_result(body)?;
    let agents = match body {
        AdminResponseBody::AgentList(list) => list,
        other => anyhow::bail!("unexpected response from kernel: {other:?}"),
    };
    let Some(_agent) = agents.iter().find(|a| a.principal == principal) else {
        eprintln!(
            "{}",
            Theme::error(&format!("agent '{principal}' not found"))
        );
        return Ok(ExitCode::from(1));
    };

    // Layer 6 does NOT yet expose a partial-group-update IPC topic for
    // agents. We translate add/remove into capability grants/revokes
    // for the duration of the gap: an agent's "groups" derive from
    // grants when the kernel resolves caps, but until #657's followup
    // wires `admin.agent.modify`, the safest path is to surface this
    // limitation explicitly rather than silently no-op.
    eprintln!(
        "astrid: agent group membership changes need an `admin.agent.modify` IPC topic that has not shipped yet."
    );
    eprintln!(
        "  As a workaround, edit `~/.astrid/etc/profiles/{principal}.toml` directly and reboot the daemon."
    );
    eprintln!("  Tracking issue #657 — CLI redesign followup.");
    Ok(ExitCode::from(2))
}

fn run_link(_args: LinkArgs) -> ExitCode {
    eprintln!(
        "astrid: agent identity linking needs `admin.agent.link` IPC that has not shipped yet."
    );
    eprintln!(
        "  Tracking issue #657 — CLI redesign followup. The identity store API exists; only the admin topic is missing."
    );
    ExitCode::from(2)
}

fn run_unlink(_args: UnlinkArgs) -> ExitCode {
    eprintln!(
        "astrid: agent identity unlinking needs `admin.agent.unlink` IPC that has not shipped yet."
    );
    eprintln!("  Tracking issue #657 — CLI redesign followup.");
    ExitCode::from(2)
}

/// Re-export of [`AgentSummary`] under a friendlier name for the
/// JSON/YAML/TOML emitters used by `--format`.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct AgentRecord {
    /// Principal identifier.
    pub principal: String,
    /// Whether the agent is currently enabled.
    pub enabled: bool,
    /// Group memberships.
    pub groups: Vec<String>,
}

impl From<AgentSummary> for AgentRecord {
    fn from(s: AgentSummary) -> Self {
        Self {
            principal: s.principal.to_string(),
            enabled: s.enabled,
            groups: s.groups,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_with_spawned_by_is_deferred() {
        let args = CreateArgs {
            name: "x".into(),
            distro: "astralis".into(),
            bare: false,
            groups: vec![],
            egress: None,
            process_allow: None,
            link: None,
            memory: None,
            timeout: None,
            storage: None,
            processes: None,
            yes: true,
            spawned_by: Some("parent".into()),
            budget_voucher: None,
            grant_access: None,
            expires: None,
            budget: None,
            period: None,
        };
        assert!(create_uses_deferred_flags(&args));
    }

    #[test]
    fn vanilla_create_is_not_deferred() {
        let args = CreateArgs {
            name: "x".into(),
            distro: "astralis".into(),
            bare: false,
            groups: vec![],
            egress: None,
            process_allow: None,
            link: None,
            memory: None,
            timeout: None,
            storage: None,
            processes: None,
            yes: true,
            spawned_by: None,
            budget_voucher: None,
            grant_access: None,
            expires: None,
            budget: None,
            period: None,
        };
        assert!(!create_uses_deferred_flags(&args));
    }

    #[test]
    fn agent_record_roundtrips_through_json() {
        let summary = AgentSummary {
            principal: PrincipalId::new("alice").unwrap(),
            enabled: true,
            groups: vec!["agent".into()],
            grants: vec![],
            revokes: vec![],
        };
        let rec: AgentRecord = summary.into();
        let json = serde_json::to_string(&rec).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["principal"], "alice");
        assert_eq!(parsed["enabled"], true);
    }
}
