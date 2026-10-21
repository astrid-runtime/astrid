//! Operator-only attribution recovery; never creates or replaces a home.

use anyhow::Result;
use astrid_core::kernel_api::AdminRequestKind;
use astrid_core::{PrincipalId, UserUid};
use clap::Args;
use std::process::ExitCode;

#[derive(Args, Debug, Clone)]
pub(crate) struct AssignUserArgs {
    /// Exact existing principal to attribute; no active-context default.
    #[arg(long)]
    agent: PrincipalId,
    /// Immutable user UID that should pay for this principal's execution.
    #[arg(long)]
    user: UserUid,
}

pub(super) async fn run(args: AssignUserArgs) -> Result<ExitCode> {
    let mut client = crate::admin_client::connect_as_active_agent().await?;
    let response = client
        .request(AdminRequestKind::QuotaAssignUser {
            principal: args.agent.clone(),
            user: args.user,
        })
        .await?;
    crate::admin_client::into_result(response)?;
    println!("Assigned resource user {} to '{}'.", args.user, args.agent);
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Command {
        #[command(flatten)]
        args: AssignUserArgs,
    }

    #[test]
    fn recovery_requires_both_explicit_typed_identities() {
        let user = UserUid::from_bytes([7; 32]).to_string();
        let parsed =
            Command::try_parse_from(["assign-user", "--agent", "worker", "--user", &user]).unwrap();
        assert_eq!(parsed.args.agent.as_str(), "worker");
        assert_eq!(parsed.args.user, UserUid::from_bytes([7; 32]));
        assert!(Command::try_parse_from(["assign-user", "--user", &user]).is_err());
        assert!(Command::try_parse_from(["assign-user", "--agent", "worker"]).is_err());
        assert!(
            Command::try_parse_from(["assign-user", "--agent", "worker", "--user", "not-a-user"])
                .is_err()
        );
    }
}
