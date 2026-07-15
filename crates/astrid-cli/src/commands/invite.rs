//! `astrid invite` — invite-token lifecycle for multi-principal deployments.
//!
//! Each verb maps 1:1 to an `AdminRequestKind::Invite*` variant (issue
//! #756) and is dispatched as the operator's active agent. Operators
//! issuing invites need the `invite:issue` capability (the built-in
//! `admin` group's `*` covers it); redeeming is unauthenticated by
//! design (the token IS the auth).

use std::process::ExitCode;

use anyhow::{Context, Result};
use astrid_core::PrincipalId;
use astrid_core::kernel_api::{AdminRequestKind, AdminResponseBody};
use clap::{Args, Subcommand};
use colored::Colorize;

use crate::admin_client::{connect_as_active_agent, connect_for_workspace_as, into_result};
use crate::theme::Theme;

#[derive(Subcommand, Debug, Clone)]
pub(crate) enum InviteCommand {
    /// Issue a new invite token. Operators with `invite:issue` only.
    Issue(IssueArgs),
    /// Redeem an invite token, minting a new principal bound to the
    /// supplied ed25519 public key. Unauthenticated — the token is the
    /// auth.
    Redeem(RedeemArgs),
    /// List outstanding invite tokens.
    List(ListArgs),
    /// Revoke an outstanding invite token without consuming it.
    Revoke(RevokeArgs),
}

#[derive(Args, Debug, Clone)]
pub(crate) struct IssueArgs {
    /// Group the redeemer will join.
    #[arg(long, default_value = "agent")]
    pub group: String,
    /// Lifetime in seconds. Defaults to 24 hours. Server caps at 30 days.
    #[arg(long, default_value_t = 24 * 60 * 60)]
    pub expires_secs: u64,
    /// Maximum redemptions before the token is invalidated.
    #[arg(long, default_value_t = 1)]
    pub max_uses: u32,
    /// Optional free-form label (e.g. "alice's tablet").
    #[arg(long)]
    pub metadata: Option<String>,
    /// Emit the token alone on stdout (suitable for piping into a QR
    /// generator or copying into a chat). Default emits a one-line
    /// human-readable summary.
    #[arg(long)]
    pub raw: bool,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct RedeemArgs {
    /// The typed `astrid_inv_` token returned by a prior `astrid invite issue`.
    #[arg(allow_hyphen_values = true)]
    pub token: String,
    /// Hex-encoded ed25519 public key. Accepts bare 64 hex chars or
    /// the self-describing `ed25519:<hex>` form. The new principal's
    /// `AuthConfig.public_keys` is seeded with this entry. Mutually
    /// exclusive with `--keypair`.
    #[arg(long, conflicts_with = "keypair")]
    pub public_key: Option<String>,
    /// Name of a local keypair created via `astrid keypair generate`.
    /// The CLI reads the public key from disk and stamps the
    /// `bound_principal` field on the keypair's meta.toml after a
    /// successful redeem. Mutually exclusive with `--public-key`.
    #[arg(long, conflicts_with = "public_key")]
    pub keypair: Option<String>,
    /// Optional human-friendly name for the new principal. Slugified
    /// server-side; collisions fall back to a random suffix.
    #[arg(long)]
    pub display_name: Option<String>,
    /// After a successful redeem, update `~/.astrid/run/cli-context.toml`
    /// so subsequent `astrid` commands run as the new principal
    /// without an explicit `astrid agent switch`.
    #[arg(long)]
    pub switch: bool,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct ListArgs {
    /// Emit the response as JSON. Default emits a table.
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct RevokeArgs {
    /// Either the raw token or its `blake3:<hex>` fingerprint (from `invite list`).
    #[arg(allow_hyphen_values = true)]
    pub token_or_fingerprint: String,
}

pub(crate) async fn run(command: InviteCommand) -> Result<ExitCode> {
    match command {
        InviteCommand::Issue(args) => run_issue(args).await,
        InviteCommand::Redeem(args) => run_redeem(args).await,
        InviteCommand::List(args) => run_list(args).await,
        InviteCommand::Revoke(args) => run_revoke(args).await,
    }
}

async fn run_issue(args: IssueArgs) -> Result<ExitCode> {
    let mut client = connect_as_active_agent().await?;
    let resp = client
        .request(AdminRequestKind::InviteIssue {
            group: args.group,
            expires_secs: Some(args.expires_secs),
            max_uses: args.max_uses,
            metadata: args.metadata,
        })
        .await
        .context("invite.issue request failed")?;
    let body = into_result(resp)?;
    match body {
        AdminResponseBody::Invite(issued) => {
            if args.raw {
                println!("{}", issued.token);
            } else {
                println!(
                    "{} {} (group: {}, uses: {}, metadata: {})",
                    Theme::success("issued"),
                    issued.token.bold(),
                    issued.group,
                    issued.remaining_uses,
                    issued.metadata.as_deref().unwrap_or("-"),
                );
                if let Some(exp) = issued.expires_at_epoch {
                    println!("expires at unix epoch {exp}");
                }
            }
            Ok(ExitCode::SUCCESS)
        },
        other => anyhow::bail!("unexpected response shape: {other:?}"),
    }
}

async fn run_redeem(args: RedeemArgs) -> Result<ExitCode> {
    // Resolve the public key source: either an explicit `--public-key`
    // hex string or a local `--keypair` reference. Exactly one is
    // required (clap enforces mutual exclusion; this enforces presence).
    let (public_key_hex, keypair_name) = match (args.public_key, args.keypair) {
        (Some(hex), None) => (hex, None),
        (None, Some(name)) => {
            let hex = crate::commands::keypair::load_public_key_hex(&name)
                .with_context(|| format!("load public key for --keypair {name:?}"))?;
            (hex, Some(name))
        },
        (None, None) => anyhow::bail!(
            "redeem requires either --public-key <hex> or --keypair <name>. \
             Generate one with `astrid keypair generate`."
        ),
        (Some(_), Some(_)) => unreachable!("clap conflicts_with prevents this"),
    };

    // Redemption is intentionally unauthenticated kernel-side — the
    // token IS the auth. A fresh-machine redeemer typically has no
    // `cli-context.toml` yet, so don't require an active-agent context
    // here; stamp the IPC message as `default` and let the kernel's
    // `InviteRedeem` dispatch path verify the token internally.
    let mut client = connect_for_workspace_as(PrincipalId::default())
        .await
        .context("connect to daemon for invite redeem")?;
    let resp = client
        .request(AdminRequestKind::InviteRedeem {
            token: args.token,
            public_key: public_key_hex,
            display_name: args.display_name,
        })
        .await
        .context("invite.redeem request failed")?;
    let body = into_result(resp)?;
    match body {
        AdminResponseBody::InviteRedeemed(redeemed) => {
            println!(
                "{} principal: {} (group: {}, key fp: {})",
                Theme::success("redeemed"),
                redeemed.principal.to_string().bold(),
                redeemed.group,
                redeemed.public_key_fingerprint,
            );
            // Best-effort: bind the keypair's meta.toml to the new
            // principal so `astrid keypair list` shows the link.
            // Failure here doesn't fail the redeem itself.
            if let Some(name) = &keypair_name
                && let Err(e) = crate::commands::keypair::record_binding(name, &redeemed.principal)
            {
                tracing::warn!(name = %name, error = %e, "could not record keypair binding");
            }
            if args.switch {
                crate::context::set_active_agent(&redeemed.principal)
                    .context("update cli-context.toml after redeem")?;
                println!(
                    "{} active agent set to {}",
                    Theme::success("→"),
                    redeemed.principal.to_string().bold()
                );
            } else {
                println!(
                    "  next step: astrid agent switch {} (or re-run redeem with --switch)",
                    redeemed.principal
                );
            }
            Ok(ExitCode::SUCCESS)
        },
        other => anyhow::bail!("unexpected response shape: {other:?}"),
    }
}

async fn run_list(args: ListArgs) -> Result<ExitCode> {
    let mut client = connect_as_active_agent().await?;
    let resp = client
        .request(AdminRequestKind::InviteList)
        .await
        .context("invite.list request failed")?;
    let body = into_result(resp)?;
    match body {
        AdminResponseBody::InviteList(invites) => {
            if args.json {
                println!("{}", serde_json::to_string_pretty(&invites)?);
            } else if invites.is_empty() {
                println!("{}", Theme::dimmed("no outstanding invites"));
            } else {
                println!(
                    "{:<71} {:<15} {:>5}  {:<10}  LABEL",
                    "FINGERPRINT", "GROUP", "USES", "EXPIRES",
                );
                for inv in invites {
                    println!(
                        "{:<71} {:<15} {:>5}  {:<10}  {}",
                        inv.token_fingerprint,
                        inv.group,
                        inv.remaining_uses,
                        inv.expires_at_epoch
                            .map_or_else(|| "never".to_string(), |e| e.to_string()),
                        inv.metadata.as_deref().unwrap_or("-"),
                    );
                }
            }
            Ok(ExitCode::SUCCESS)
        },
        other => anyhow::bail!("unexpected response shape: {other:?}"),
    }
}

async fn run_revoke(args: RevokeArgs) -> Result<ExitCode> {
    let mut client = connect_as_active_agent().await?;
    let resp = client
        .request(AdminRequestKind::InviteRevoke {
            token: args.token_or_fingerprint,
        })
        .await
        .context("invite.revoke request failed")?;
    let body = into_result(resp)?;
    match body {
        AdminResponseBody::Success(v) => {
            println!("{} {}", Theme::success("revoked"), v);
            Ok(ExitCode::SUCCESS)
        },
        other => anyhow::bail!("unexpected response shape: {other:?}"),
    }
}
