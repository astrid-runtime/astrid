//! `astrid agent claim` — explicit first assignment of a named unowned principal.

use std::process::ExitCode;

use anyhow::{Context, Result};
use astrid_core::PrincipalId;
use astrid_core::kernel_api::AdminRequestKind;
use clap::Args;

use crate::admin_client::into_result;
use crate::theme::Theme;

#[derive(Args, Debug, Clone)]
pub(crate) struct ClaimArgs {
    /// Admitted principal that currently has no fleet owner.
    pub name: String,
}

pub(crate) async fn run(args: ClaimArgs) -> Result<ExitCode> {
    let principal = PrincipalId::new(&args.name).context("invalid agent name")?;
    let mut client = crate::admin_client::connect_as_active_agent().await?;
    let body = client
        .request(AdminRequestKind::UserPrincipalClaim {
            principal: principal.clone(),
        })
        .await?;
    into_result(body)?;
    println!(
        "{}",
        Theme::success(&format!(
            "Claimed agent '{principal}' into the authenticated user's fleet"
        ))
    );
    Ok(ExitCode::SUCCESS)
}
