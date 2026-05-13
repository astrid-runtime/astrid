//! `astrid group` — capability group CRUD.
//!
//! Maps to Layer 6 admin IPC topics `astrid.v1.admin.group.*`.

use std::process::ExitCode;

use anyhow::Result;
use astrid_types::kernel::{AdminRequestKind, AdminResponseBody, GroupSummary};
use clap::{Args, Subcommand};
use colored::Colorize;
use serde::Serialize;

use crate::admin_client::{AdminClient, into_result};
use crate::theme::Theme;
use crate::value_formatter::{ValueFormat, emit_structured};

#[derive(Subcommand, Debug, Clone)]
pub(crate) enum GroupCommand {
    /// Create a new custom group.
    Create(CreateArgs),
    /// Show capabilities for a group.
    Show(ShowArgs),
    /// List every group (built-in + custom).
    List(ListArgs),
    /// Delete a custom group.
    Delete(DeleteArgs),
    /// Modify group capabilities or rename.
    Modify(ModifyArgs),
}

#[derive(Args, Debug, Clone)]
pub(crate) struct CreateArgs {
    /// Group name.
    pub name: String,
    /// Capability list, comma-separated.
    #[arg(long = "caps", value_name = "CAP1,CAP2", value_delimiter = ',')]
    pub caps: Vec<String>,
    /// Optional description.
    #[arg(long)]
    pub description: Option<String>,
    /// Permit the universal `*` capability — required when `--caps`
    /// contains `*` and equivalent to creating an admin group.
    #[arg(long = "unsafe-admin")]
    pub unsafe_admin: bool,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct ShowArgs {
    /// Group name.
    pub name: String,
    /// Output format.
    #[arg(long, default_value = "pretty")]
    pub format: String,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct ListArgs {
    /// Output format.
    #[arg(long, default_value = "pretty")]
    pub format: String,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct DeleteArgs {
    /// Group name.
    pub name: String,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct ModifyArgs {
    /// Group name.
    pub name: String,
    /// Capabilities to add (comma-separated).
    #[arg(long = "add-caps", value_name = "CAPS", value_delimiter = ',')]
    pub add_caps: Vec<String>,
    /// Capabilities to remove (comma-separated).
    #[arg(long = "remove-caps", value_name = "CAPS", value_delimiter = ',')]
    pub remove_caps: Vec<String>,
    /// Replace the description (use empty to clear).
    #[arg(long)]
    pub description: Option<String>,
    /// Rename the group (deferred — Layer 6 group.modify takes name+
    /// capabilities, not a rename).
    #[arg(long, hide = true)]
    pub rename: Option<String>,
}

/// Top-level dispatcher for `astrid group`.
pub(crate) async fn run(cmd: GroupCommand) -> Result<ExitCode> {
    match cmd {
        GroupCommand::Create(args) => run_create(args).await,
        GroupCommand::Show(args) => run_show(args).await,
        GroupCommand::List(args) => run_list(args).await,
        GroupCommand::Delete(args) => run_delete(args).await,
        GroupCommand::Modify(args) => run_modify(args).await,
    }
}

async fn fetch_groups() -> Result<Vec<GroupSummary>> {
    let mut client = AdminClient::connect().await?;
    let body = client.request(AdminRequestKind::GroupList).await?;
    let body = into_result(body)?;
    match body {
        AdminResponseBody::GroupList(list) => Ok(list),
        other => anyhow::bail!("unexpected response from kernel: {other:?}"),
    }
}

async fn run_create(args: CreateArgs) -> Result<ExitCode> {
    if args.caps.is_empty() {
        eprintln!("astrid: --caps is required (use comma-separated values)");
        return Ok(ExitCode::from(1));
    }
    let mut client = AdminClient::connect().await?;
    let body = client
        .request(AdminRequestKind::GroupCreate {
            name: args.name.clone(),
            capabilities: args.caps,
            description: args.description,
            unsafe_admin: args.unsafe_admin,
        })
        .await?;
    let _ = into_result(body)?;
    println!(
        "{}",
        Theme::success(&format!("Created group '{}'", args.name))
    );
    Ok(ExitCode::SUCCESS)
}

async fn run_show(args: ShowArgs) -> Result<ExitCode> {
    let format = ValueFormat::parse(&args.format);
    let groups = fetch_groups().await?;
    let Some(group) = groups.into_iter().find(|g| g.name == args.name) else {
        eprintln!(
            "{}",
            Theme::error(&format!("group '{}' not found", args.name))
        );
        return Ok(ExitCode::from(1));
    };
    if !format.is_pretty() {
        emit_structured(&GroupRecord::from(group), format)?;
        return Ok(ExitCode::SUCCESS);
    }
    print_group_detail(&group);
    Ok(ExitCode::SUCCESS)
}

async fn run_list(args: ListArgs) -> Result<ExitCode> {
    let format = ValueFormat::parse(&args.format);
    let mut groups = fetch_groups().await?;
    groups.sort_by(|a, b| a.name.cmp(&b.name));
    if !format.is_pretty() {
        let records: Vec<GroupRecord> = groups.into_iter().map(GroupRecord::from).collect();
        emit_structured(&records, format)?;
        return Ok(ExitCode::SUCCESS);
    }
    print_group_table(&groups);
    Ok(ExitCode::SUCCESS)
}

async fn run_delete(args: DeleteArgs) -> Result<ExitCode> {
    let mut client = AdminClient::connect().await?;
    let body = client
        .request(AdminRequestKind::GroupDelete {
            name: args.name.clone(),
        })
        .await?;
    let _ = into_result(body)?;
    println!(
        "{}",
        Theme::success(&format!("Deleted group '{}'", args.name))
    );
    Ok(ExitCode::SUCCESS)
}

async fn run_modify(args: ModifyArgs) -> Result<ExitCode> {
    if args.rename.is_some() {
        eprintln!("astrid: --rename on `group modify` is deferred (Layer 6 has no rename).");
        return Ok(ExitCode::from(2));
    }
    if args.add_caps.is_empty() && args.remove_caps.is_empty() && args.description.is_none() {
        eprintln!("astrid: nothing to do (specify --add-caps, --remove-caps, or --description)");
        return Ok(ExitCode::from(1));
    }

    // Layer 6 group.modify replaces the capability list wholesale —
    // get-modify-set round-trip preserves caps not explicitly removed.
    let mut client = AdminClient::connect().await?;
    let body = client.request(AdminRequestKind::GroupList).await?;
    let body = into_result(body)?;
    let groups = match body {
        AdminResponseBody::GroupList(list) => list,
        other => anyhow::bail!("unexpected response from kernel: {other:?}"),
    };
    let Some(group) = groups.into_iter().find(|g| g.name == args.name) else {
        eprintln!(
            "{}",
            Theme::error(&format!("group '{}' not found", args.name))
        );
        return Ok(ExitCode::from(1));
    };
    let mut caps = group.capabilities.clone();
    for c in &args.remove_caps {
        caps.retain(|x| x != c);
    }
    for c in &args.add_caps {
        if !caps.contains(c) {
            caps.push(c.clone());
        }
    }
    let description_change = args
        .description
        .map(|d| if d.is_empty() { None } else { Some(d) });
    let body = client
        .request(AdminRequestKind::GroupModify {
            name: args.name.clone(),
            capabilities: Some(caps),
            description: description_change,
            unsafe_admin: None,
        })
        .await?;
    let _ = into_result(body)?;
    println!(
        "{}",
        Theme::success(&format!("Modified group '{}'", args.name))
    );
    Ok(ExitCode::SUCCESS)
}

fn print_group_table(groups: &[GroupSummary]) {
    if groups.is_empty() {
        println!("{}", Theme::info("No groups."));
        return;
    }
    println!(
        "{:<16}  {:<10}  {}",
        "GROUP".bold(),
        "TYPE".bold(),
        "CAPABILITIES".bold()
    );
    for g in groups {
        let kind = if g.builtin {
            "built-in".dimmed()
        } else {
            "custom".green()
        };
        let caps_summary = if g.capabilities.is_empty() {
            "(none)".dimmed().to_string()
        } else if g.capabilities.len() <= 3 {
            g.capabilities.join(",")
        } else {
            format!(
                "{}, ...({} total)",
                g.capabilities[..3].join(","),
                g.capabilities.len()
            )
        };
        println!("{:<16}  {kind:<10}  {caps_summary}", g.name);
    }
}

fn print_group_detail(group: &GroupSummary) {
    println!(
        "{} {} {}",
        "Group".bold(),
        group.name.cyan(),
        if group.builtin {
            "(built-in)".dimmed().to_string()
        } else {
            "(custom)".green().to_string()
        }
    );
    if let Some(desc) = group.description.as_deref() {
        println!("  Description: {desc}");
    }
    if group.unsafe_admin {
        println!("  {}", "Holds the universal `*` capability".yellow().bold());
    }
    println!("  Capabilities:");
    for cap in &group.capabilities {
        println!("    - {cap}");
    }
}

/// JSON/YAML/TOML emission shape for groups.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct GroupRecord {
    /// Group name.
    pub name: String,
    /// Capability patterns the group confers.
    pub capabilities: Vec<String>,
    /// Optional description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Whether the group opted into the universal `*`.
    pub unsafe_admin: bool,
    /// True for built-in groups.
    pub builtin: bool,
}

impl From<GroupSummary> for GroupRecord {
    fn from(s: GroupSummary) -> Self {
        Self {
            name: s.name,
            capabilities: s.capabilities,
            description: s.description,
            unsafe_admin: s.unsafe_admin,
            builtin: s.builtin,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_round_trips_to_json() {
        let summary = GroupSummary {
            name: "ops".into(),
            capabilities: vec!["agent:create".into(), "agent:delete".into()],
            description: Some("Operators".into()),
            unsafe_admin: false,
            builtin: false,
        };
        let rec: GroupRecord = summary.into();
        let json = serde_json::to_string(&rec).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["name"], "ops");
        assert_eq!(parsed["builtin"], false);
        assert_eq!(parsed["capabilities"][1], "agent:delete");
    }
}
