//! Discover existing users without inspecting or rewriting their storage.

use crate::value_formatter::{ValueFormat, emit_structured};
use anyhow::{Context, Result};
use astrid_core::{
    UserIdentity,
    kernel_api::{AdminRequestKind, AdminResponseBody},
};
use clap::Args;
use std::process::ExitCode;

#[derive(Args, Debug, Clone)]
pub(crate) struct UsersArgs {
    /// Output format.
    #[arg(long, default_value = "pretty")]
    format: String,
}

pub(super) async fn run(args: UsersArgs) -> Result<ExitCode> {
    let mut client = crate::admin_client::connect_as_active_agent().await?;
    let response =
        crate::admin_client::into_result(client.request(AdminRequestKind::QuotaUserList).await?)?;
    let AdminResponseBody::Success(value) = response else {
        anyhow::bail!("unexpected response from user discovery: {response:?}");
    };
    let users: Vec<UserIdentity> = serde_json::from_value(value).context("invalid user roster")?;
    let format = ValueFormat::parse(&args.format);
    if !format.is_pretty() {
        emit_structured(&users, format)?;
    } else if users.is_empty() {
        println!("No registered users.");
    } else {
        for user in users {
            println!("{}  identity={}", user.uid, user.genesis.identity_id);
        }
        println!(
            "Use --format json for genesis public keys; choose the accountable user explicitly."
        );
    }
    Ok(ExitCode::SUCCESS)
}
