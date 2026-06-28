//! `astrid pair-device` — per-device pairing lifecycle for a single
//! principal.
//!
//! Unlike `astrid invite` (which mints a NEW principal), pair-device adds a
//! new device's ed25519 key to an EXISTING principal's
//! `AuthConfig.public_keys` under a capability [`scope`](DeviceScope). Each
//! verb maps to an `AdminRequestKind::PairDevice*` variant and is dispatched
//! as the operator's active agent:
//!
//! * `issue` — mint a pair-token tied to the caller's own principal. The
//!   `--scope` / `--allow` / `--deny` flags pick the scope the redeemed device
//!   authenticates under; the kernel validates the requested scope is a subset
//!   of the issuer's authority (no escalation) and gates a full-scope mint on
//!   `self:auth:pair:admin`.
//! * `list` — show a principal's paired devices (`key_id` + scope + label).
//! * `revoke` — remove one paired device by its `key_id`.
//!
//! Redemption is performed by the new device through the HTTP gateway
//! (`POST /api/auth/pair-device/redeem`), not this CLI — the redeeming device
//! holds the private key and receives its scoped session bearer there.

use std::process::ExitCode;

use anyhow::{Context, Result};
use astrid_core::kernel_api::{AdminRequestKind, AdminResponseBody, PairScopeArg};
use astrid_core::profile::DeviceScope;
use clap::{Args, Subcommand};
use colored::Colorize;

use crate::admin_client::{connect_as_active_agent, into_result};
use crate::context;
use crate::theme::Theme;

#[derive(Subcommand, Debug, Clone)]
pub(crate) enum PairDeviceCommand {
    /// Issue a pair-token tied to your own principal. Hand the token to the
    /// new device out-of-band; it redeems through the HTTP gateway.
    Issue(IssueArgs),
    /// List paired devices on a principal.
    List(ListArgs),
    /// Revoke a single paired device by its `key_id`.
    Revoke(RevokeArgs),
}

#[derive(Args, Debug, Clone)]
pub(crate) struct IssueArgs {
    /// Named scope preset for the redeemed device: `full` (unattenuated —
    /// requires `self:auth:pair:admin`) or `use-only` (act with self caps,
    /// cannot pair further or delegate). Defaults to `full`. Mutually
    /// exclusive with `--allow` / `--deny`.
    #[arg(long, conflicts_with_all = ["allow", "deny"])]
    pub scope: Option<String>,
    /// Explicit allow capability pattern(s) for a custom scope (repeatable).
    /// Every pattern must be held by you (no escalation). Selects an explicit
    /// scope; mutually exclusive with `--scope`.
    #[arg(long, conflicts_with = "scope")]
    pub allow: Vec<String>,
    /// Explicit deny capability pattern(s) for a custom scope (repeatable,
    /// deny wins). Mutually exclusive with `--scope`.
    #[arg(long, conflicts_with = "scope")]
    pub deny: Vec<String>,
    /// Optional human-friendly label persisted alongside the new device key
    /// (e.g. "alice's phone").
    #[arg(long)]
    pub label: Option<String>,
    /// Token lifetime in seconds. Defaults kernel-side (5 minutes). Capped at
    /// 1 hour kernel-side — pair-tokens are for immediate use.
    #[arg(long)]
    pub expires_secs: Option<u64>,
    /// Emit the token alone on stdout (suitable for piping into a QR
    /// generator). Default emits a one-line human-readable summary.
    #[arg(long)]
    pub raw: bool,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct ListArgs {
    /// Agent whose devices to list. Defaults to the active context.
    /// Listing another agent's devices needs the global `auth:pair`.
    #[arg(long = "agent")]
    pub principal: Option<String>,
    /// Emit the response as JSON. Default emits a table.
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct RevokeArgs {
    /// The `key_id` of the device to revoke (from `pair-device list`).
    pub key_id: String,
    /// Agent whose device to revoke. Defaults to the active context.
    /// Revoking another agent's device needs the global `auth:pair`.
    #[arg(long = "agent")]
    pub principal: Option<String>,
}

pub(crate) async fn run(command: PairDeviceCommand) -> Result<ExitCode> {
    match command {
        PairDeviceCommand::Issue(args) => run_issue(args).await,
        PairDeviceCommand::List(args) => run_list(args).await,
        PairDeviceCommand::Revoke(args) => run_revoke(args).await,
    }
}

/// Map the issue flags to the kernel [`PairScopeArg`]. A non-empty
/// `--allow`/`--deny` selects an explicit scope; otherwise `--scope`
/// (`full`/absent ⇒ `Full`, any other name ⇒ a preset the kernel resolves).
fn scope_arg(args: &IssueArgs) -> PairScopeArg {
    if !args.allow.is_empty() || !args.deny.is_empty() {
        return PairScopeArg::Explicit {
            allow: args.allow.clone(),
            deny: args.deny.clone(),
        };
    }
    match args.scope.as_deref() {
        None | Some("full") => PairScopeArg::Full,
        Some(name) => PairScopeArg::Preset {
            name: name.to_string(),
        },
    }
}

async fn run_issue(args: IssueArgs) -> Result<ExitCode> {
    let scope = scope_arg(&args);
    let scope_summary = describe_scope_arg(&scope);
    let mut client = connect_as_active_agent().await?;
    let resp = client
        .request(AdminRequestKind::PairDeviceIssue {
            expires_secs: args.expires_secs,
            label: args.label,
            scope,
        })
        .await
        .context("auth.pair.issue request failed")?;
    let body = into_result(resp)?;
    match body {
        AdminResponseBody::PairToken(issued) => {
            if args.raw {
                println!("{}", issued.token);
            } else {
                println!(
                    "{} {} (principal: {}, scope: {}, label: {})",
                    Theme::success("issued"),
                    issued.token.bold(),
                    issued.principal,
                    scope_summary,
                    issued.label.as_deref().unwrap_or("-"),
                );
                println!("expires at unix epoch {}", issued.expires_at_epoch);
            }
            Ok(ExitCode::SUCCESS)
        },
        other => anyhow::bail!("unexpected response shape: {other:?}"),
    }
}

async fn run_list(args: ListArgs) -> Result<ExitCode> {
    let principal = context::resolve_agent(args.principal.as_deref())?;
    let mut client = connect_as_active_agent().await?;
    let resp = client
        .request(AdminRequestKind::PairDeviceList { principal })
        .await
        .context("auth.pair.list request failed")?;
    let body = into_result(resp)?;
    match body {
        AdminResponseBody::PairDeviceListed(devices) => {
            if args.json {
                println!("{}", serde_json::to_string_pretty(&devices)?);
            } else if devices.is_empty() {
                println!("{}", Theme::dimmed("no paired devices"));
            } else {
                println!(
                    "{:<16}  {:<20}  {:<12}  LABEL",
                    "KEY_ID", "SCOPE", "CREATED",
                );
                for d in devices {
                    println!(
                        "{:<16}  {:<20}  {:<12}  {}",
                        d.key_id,
                        describe_scope(&d.scope),
                        d.created_at,
                        d.label.as_deref().unwrap_or("-"),
                    );
                }
            }
            Ok(ExitCode::SUCCESS)
        },
        other => anyhow::bail!("unexpected response shape: {other:?}"),
    }
}

async fn run_revoke(args: RevokeArgs) -> Result<ExitCode> {
    let principal = context::resolve_agent(args.principal.as_deref())?;
    let mut client = connect_as_active_agent().await?;
    let resp = client
        .request(AdminRequestKind::PairDeviceRevoke {
            principal,
            key_id: args.key_id,
        })
        .await
        .context("auth.pair.revoke request failed")?;
    let body = into_result(resp)?;
    match body {
        AdminResponseBody::PairDeviceRevoked { key_id } => {
            println!("{} device {}", Theme::success("revoked"), key_id.bold());
            Ok(ExitCode::SUCCESS)
        },
        other => anyhow::bail!("unexpected response shape: {other:?}"),
    }
}

/// One-line summary of a requested scope arg for the issue confirmation.
fn describe_scope_arg(arg: &PairScopeArg) -> String {
    match arg {
        PairScopeArg::Full => "full".to_string(),
        PairScopeArg::Preset { name } => name.clone(),
        PairScopeArg::Explicit { allow, deny } => {
            format!("allow={} deny={}", join_or_dash(allow), join_or_dash(deny))
        },
    }
}

/// One-line summary of a stored device scope for the list table.
fn describe_scope(scope: &DeviceScope) -> String {
    match scope {
        DeviceScope::Full => "full".to_string(),
        DeviceScope::Scoped { allow, deny } => {
            format!("allow={} deny={}", join_or_dash(allow), join_or_dash(deny))
        },
    }
}

fn join_or_dash(patterns: &[String]) -> String {
    if patterns.is_empty() {
        "-".to_string()
    } else {
        patterns.join(",")
    }
}
