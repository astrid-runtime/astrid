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
use astrid_core::kernel_api::{AdminRequestKind, AdminResponseBody, AgentSummary};
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
    #[arg(short, long)]
    pub distro: Option<String>,
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
    /// Copy env, KV, and secrets from this principal (default: inherit
    /// nothing). The named principal's `.config/env/`, per-capsule KV
    /// namespaces, and per-capsule secret files are copied into the new
    /// agent. Omit to provision a clean, least-privilege agent.
    #[arg(long = "inherit-from", value_name = "PRINCIPAL")]
    pub inherit_from: Option<String>,
    /// Clone an existing principal: a full replica of its capability profile
    /// (groups, grants, revokes, egress, process allow-list, quotas) AND its
    /// state (env/KV/secrets, exactly as `--inherit-from`). An exact copy —
    /// customize afterward with `caps grant` / `quota set` / `agent modify`.
    /// Mutually exclusive with the profile/quota-shaping flags. Cloning a
    /// source that confers admin (`*`) requires `--unsafe-admin`.
    #[arg(
        long = "clone",
        value_name = "PRINCIPAL",
        conflicts_with_all = [
            "groups", "egress", "process_allow", "inherit_from",
            "memory", "timeout", "storage", "processes"
        ]
    )]
    pub clone_from: Option<String>,
    /// Acknowledge cloning an admin-conferring source (one that resolves to
    /// the universal `*`). Required by `--clone <admin-source>`; mirrors the
    /// `--unsafe-admin` flag on `caps grant` / `group create`.
    #[arg(long = "unsafe-admin", requires = "clone_from")]
    pub unsafe_admin: bool,

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
    /// Grant the agent access to a capsule's tools (repeatable).
    #[arg(long = "add-capsule", value_name = "ID")]
    pub add_capsule: Vec<String>,
    /// Revoke the agent's access to a capsule's tools (repeatable).
    #[arg(long = "remove-capsule", value_name = "ID")]
    pub remove_capsule: Vec<String>,
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

async fn run_create(mut args: CreateArgs) -> Result<ExitCode> {
    if create_uses_deferred_flags(&args) {
        return Ok(stub::deferred(
            "agent create with delegation/budget flags",
            &[ISSUE_DELEGATION],
        ));
    }
    if let Some(exit) = check_unshipped_provisioning_flags(&args) {
        return Ok(exit);
    }

    // Parse and validate everything client-side BEFORE any IPC. A
    // malformed quota spec or capability label should fail the whole
    // command, not leave a half-provisioned agent on disk that the
    // operator has to clean up.
    let principal = PrincipalId::new(&args.name).context("invalid agent name")?;
    let quota_updates = parse_quota_flags(&args)?;
    let caps_to_grant = build_caps_to_grant(&args)?;
    // Validate the inheritance source client-side so a typo fails the
    // whole command before any IPC, matching how `name` is handled.
    let inherit_from = args
        .inherit_from
        .as_deref()
        .map(PrincipalId::new)
        .transpose()
        .context("invalid --inherit-from principal")?;
    let clone_from = args
        .clone_from
        .as_deref()
        .map(PrincipalId::new)
        .transpose()
        .context("invalid --clone principal")?;

    // Empty defaults to the kernel's `agent` group (Layer 6 default).
    // Pass empty so the kernel applies the default rather than the CLI
    // duplicating the policy.
    let groups = std::mem::take(&mut args.groups);

    let mut client = crate::admin_client::connect_as_active_agent().await?;
    // Hand `caps_to_grant` directly to `AgentCreate.grants` so the
    // capability grants land in the same admin call as the profile
    // write — atomic from the operator's perspective. The kernel
    // handler validates the full set against the capability grammar
    // before writing the profile, so a malformed pattern can't leave
    // a half-provisioned agent on disk.
    let body = client
        .request(AdminRequestKind::AgentCreate {
            name: args.name.clone(),
            groups,
            grants: caps_to_grant,
            inherit_from,
            clone_from,
            allow_admin_clone: args.unsafe_admin,
        })
        .await?;
    let _ = into_result(body)?;
    println!(
        "{}",
        Theme::success(&format!("Created agent '{}'", args.name))
    );

    if !quota_updates.is_empty() {
        apply_initial_quotas(&mut client, &principal, &quota_updates)
            .await
            .with_context(|| {
                format!(
                    "agent '{}' created, but failed to apply quotas — re-run `astrid quota set -a {} ...` to retry",
                    args.name, args.name
                )
            })?;
    }

    Ok(ExitCode::SUCCESS)
}

/// Reject `--bare`, `--distro`, and `--link` up front —
/// each still needs kernel-side IPC that has not shipped. Returns the
/// exit code for the failure, or `None` if all three are absent.
fn check_unshipped_provisioning_flags(args: &CreateArgs) -> Option<ExitCode> {
    if args.bare {
        eprintln!(
            "astrid: --bare needs a distro management IPC that has not shipped. Track in #657."
        );
        return Some(ExitCode::from(2));
    }
    if args.distro.is_some() {
        eprintln!(
            "astrid: per-agent --distro pinning needs distro management IPC that has not \
             shipped. Track in #657."
        );
        return Some(ExitCode::from(2));
    }
    if args.link.is_some() {
        eprintln!(
            "astrid: --link needs an admin.agent.link IPC that has not shipped. Track in #657."
        );
        return Some(ExitCode::from(2));
    }
    None
}

/// Parse the four quota-flag specs into a delta list. Returns an
/// `Err` for malformed byte / duration strings; that fails the entire
/// `agent create` before any IPC commits to disk.
fn parse_quota_flags(args: &CreateArgs) -> Result<Vec<QuotaField>> {
    let mut updates: Vec<QuotaField> = Vec::new();
    if let Some(s) = args.memory.as_deref() {
        let bytes = crate::commands::quota::parse_bytes(s).context("invalid --memory")?;
        updates.push(QuotaField::Memory(bytes));
    }
    if let Some(s) = args.timeout.as_deref() {
        let secs = crate::commands::quota::parse_duration(s)
            .context("invalid --timeout")?
            .as_secs()
            .max(1);
        updates.push(QuotaField::Timeout(secs));
    }
    if let Some(s) = args.storage.as_deref() {
        let bytes = crate::commands::quota::parse_bytes(s).context("invalid --storage")?;
        updates.push(QuotaField::Storage(bytes));
    }
    if let Some(n) = args.processes {
        updates.push(QuotaField::Processes(n));
    }
    Ok(updates)
}

/// Translate `--egress` / `--process-allow` allow-lists into Layer 6
/// capability patterns and validate each against the capability
/// grammar (no dots in segments, etc.). Catching invalid labels here
/// — before any IPC — prevents the kernel from accepting the agent
/// profile and then rejecting the follow-up grant, which would leave a
/// half-provisioned agent on disk.
fn build_caps_to_grant(args: &CreateArgs) -> Result<Vec<String>> {
    let mut caps: Vec<String> = Vec::new();
    if let Some(domains) = args.egress.as_deref() {
        for entry in domains.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            let cap = format!("network:egress:{entry}");
            astrid_core::capability_grammar::validate_capability(&cap)
                .map_err(|e| anyhow::anyhow!("invalid --egress entry {entry:?}: {e}"))?;
            caps.push(cap);
        }
    }
    if let Some(cmds) = args.process_allow.as_deref() {
        for entry in cmds.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            let cap = format!("process:spawn:{entry}");
            astrid_core::capability_grammar::validate_capability(&cap)
                .map_err(|e| anyhow::anyhow!("invalid --process-allow entry {entry:?}: {e}"))?;
            caps.push(cap);
        }
    }
    Ok(caps)
}

/// Apply the parsed quota deltas: `QuotaGet` to pull the new agent's
/// defaults, replay each requested field, single `QuotaSet`. A failure
/// here leaves the agent in place with default quotas — operator can
/// re-run `astrid quota set -a <name> ...` to retry.
async fn apply_initial_quotas(
    client: &mut AdminClient,
    principal: &PrincipalId,
    updates: &[QuotaField],
) -> Result<()> {
    let body = client
        .request(AdminRequestKind::QuotaGet {
            principal: principal.clone(),
        })
        .await?;
    let body = into_result(body)?;
    let mut quotas = match body {
        AdminResponseBody::Quotas(q) => q,
        other => anyhow::bail!("unexpected response from kernel: {other:?}"),
    };
    for field in updates {
        match field {
            QuotaField::Memory(b) => quotas.max_memory_bytes = *b,
            QuotaField::Timeout(s) => quotas.max_timeout_secs = *s,
            QuotaField::Storage(b) => quotas.max_storage_bytes = *b,
            QuotaField::Processes(n) => quotas.max_background_processes = *n,
        }
    }
    let body = client
        .request(AdminRequestKind::QuotaSet {
            principal: principal.clone(),
            quotas,
        })
        .await?;
    let _ = into_result(body)?;
    println!(
        "  {}",
        Theme::info(&format!(
            "Quotas set ({} field{})",
            updates.len(),
            if updates.len() == 1 { "" } else { "s" }
        ))
    );
    Ok(())
}

/// Discriminator for which quota field a CLI flag is updating, kept
/// out of `Quotas` so we can replay the deltas after fetching the
/// principal's current values from the kernel.
enum QuotaField {
    Memory(u64),
    Timeout(u64),
    Storage(u64),
    Processes(u32),
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

    let mut client = crate::admin_client::connect_as_active_agent().await?;
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
    if let Ok(mut client) = crate::admin_client::connect_as_active_agent().await
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
    let mut client = crate::admin_client::connect_as_active_agent().await?;
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
    let mut client = crate::admin_client::connect_as_active_agent().await?;
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
    let mut client = crate::admin_client::connect_as_active_agent().await?;
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
    let mut client = crate::admin_client::connect_as_active_agent().await?;
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
    if args.add_group.is_empty()
        && args.remove_group.is_empty()
        && args.add_capsule.is_empty()
        && args.remove_capsule.is_empty()
    {
        eprintln!(
            "astrid: nothing to do (specify --add-group, --remove-group, --add-capsule, or --remove-capsule)"
        );
        return Ok(ExitCode::from(1));
    }
    let mut client = crate::admin_client::connect_as_active_agent().await?;
    let outcome = apply_agent_modify(
        &mut client,
        &principal,
        &args.add_group,
        &args.remove_group,
        &args.add_capsule,
        &args.remove_capsule,
    )
    .await?;
    if outcome.changed {
        println!(
            "{}",
            Theme::success(&format!(
                "Updated agent '{principal}' groups: [{}] capsules: [{}]",
                outcome.groups.join(", "),
                outcome.capsules.join(", ")
            ))
        );
    } else {
        println!(
            "{}",
            Theme::info(&format!(
                "agent '{principal}' already has the requested groups and capsules (no change)"
            ))
        );
    }
    Ok(ExitCode::SUCCESS)
}

/// Parsed result of an `admin.agent.modify` round-trip: the principal's
/// resulting group and capsule sets, plus whether the kernel actually
/// changed the profile (`false` on an idempotent no-op re-apply).
pub(crate) struct AgentModifyOutcome {
    /// The principal's group memberships after the delta.
    pub(crate) groups: Vec<String>,
    /// The principal's capsule-access grant set after the delta.
    pub(crate) capsules: Vec<String>,
    /// Whether the profile changed (set-wise). `false` means every
    /// requested add/remove was already reflected — an idempotent re-run.
    pub(crate) changed: bool,
}

/// Issue an `admin.agent.modify` request and parse the kernel's reply.
///
/// The single seam through which group and capsule-access grants reach
/// the kernel. Shared by the `agent modify` verb and `init
/// --grant-capsules` so both provision through the *exact same*
/// idempotent kernel path (`apply_set_delta`) — never a divergent copy of
/// the grant logic. The kernel applies removes-then-adds atomically for
/// the whole request and reports `changed = false` when the resulting set
/// is unchanged, which is what makes a re-apply safe.
///
/// # Errors
/// Propagates transport errors and any `AdminResponseBody::Error` the
/// kernel returns (e.g. the caller lacks `agent:modify`, or the target
/// principal has no profile).
pub(crate) async fn apply_agent_modify(
    client: &mut AdminClient,
    principal: &PrincipalId,
    add_groups: &[String],
    remove_groups: &[String],
    add_capsules: &[String],
    remove_capsules: &[String],
) -> Result<AgentModifyOutcome> {
    let body = client
        .request(AdminRequestKind::AgentModify {
            principal: principal.clone(),
            add_groups: add_groups.to_vec(),
            remove_groups: remove_groups.to_vec(),
            add_capsules: add_capsules.to_vec(),
            remove_capsules: remove_capsules.to_vec(),
        })
        .await?;
    let value = match into_result(body)? {
        AdminResponseBody::Success(v) => v,
        other => anyhow::bail!("unexpected response from kernel: {other:?}"),
    };

    let string_array = |key: &str| -> Vec<String> {
        value
            .get(key)
            .and_then(|g| g.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    };
    Ok(AgentModifyOutcome {
        groups: string_array("groups"),
        capsules: string_array("capsules"),
        changed: value
            .get("changed")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
    })
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
            distro: None,
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
            inherit_from: None,
            clone_from: None,
            unsafe_admin: false,
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
            distro: None,
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
            inherit_from: None,
            clone_from: None,
            unsafe_admin: false,
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
