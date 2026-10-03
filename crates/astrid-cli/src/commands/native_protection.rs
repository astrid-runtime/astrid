//! Authenticated native protection prerequisite queries.

use anyhow::{Result, bail};
use astrid_core::{
    PrincipalId,
    kernel_api::{KernelRequest, KernelResponse},
};
use clap::{Args, Subcommand};
use std::process::ExitCode;

#[derive(Debug, Subcommand)]
pub(crate) enum NativeProtectionCommand {
    /// Read daemon and principal-bound protection prerequisites.
    Capabilities(CapabilitiesArgs),
}

#[derive(Debug, Args)]
pub(crate) struct CapabilitiesArgs {
    /// Principal to inspect; the global principal authenticates the caller.
    #[arg(long = "target-principal")]
    pub principal: Option<String>,
    /// Output format.
    #[arg(long, default_value = "json", value_parser = ["json"])]
    pub format: String,
}

pub(crate) async fn run(command: NativeProtectionCommand) -> Result<ExitCode> {
    let NativeProtectionCommand::Capabilities(args) = command;
    let principal = args
        .principal
        .map(PrincipalId::new)
        .transpose()?
        .unwrap_or_else(crate::principal::current);
    let mut client = crate::socket_client::connect_kernel_for_workspace(None).await?;
    let capabilities = match client.request(capabilities_request(principal)).await? {
        KernelResponse::NativeProtectionCapabilities(capabilities) => capabilities,
        KernelResponse::Error(_) => bail!("daemon rejected native protection capability query"),
        _ => bail!("daemon returned an unexpected native protection response"),
    };
    // The response type contains only identities, digests and feature names.
    println!("{}", serde_json::to_string(&capabilities)?);
    Ok(ExitCode::SUCCESS)
}

fn capabilities_request(principal: PrincipalId) -> KernelRequest {
    KernelRequest::GetNativeProtectionCapabilities {
        target_principal: principal,
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    #[test]
    fn native_capabilities_cli_preserves_actor_and_target() {
        let cli = crate::cli::Cli::try_parse_from([
            "astrid",
            "--principal",
            "operator",
            "native-protection",
            "capabilities",
            "--target-principal",
            "protected",
            "--format",
            "json",
        ])
        .unwrap();
        assert_eq!(cli.principal.as_deref(), Some("operator"));
        let Some(crate::cli::Commands::NativeProtection {
            command: super::NativeProtectionCommand::Capabilities(args),
        }) = cli.command
        else {
            panic!("wrong command")
        };
        assert_eq!(args.principal.as_deref(), Some("protected"));
        assert_eq!(args.format, "json");
        let request =
            super::capabilities_request(astrid_core::PrincipalId::new("protected").unwrap());
        let astrid_core::kernel_api::KernelRequest::GetNativeProtectionCapabilities {
            target_principal,
        } = request
        else {
            panic!("wrong request")
        };
        assert_eq!(target_principal.as_str(), "protected");
    }

    #[test]
    fn native_capabilities_cli_self_query_uses_global_principal() {
        let cli = crate::cli::Cli::try_parse_from([
            "astrid",
            "native-protection",
            "capabilities",
            "--principal",
            "protected",
            "--format",
            "json",
        ])
        .unwrap();
        assert_eq!(cli.principal.as_deref(), Some("protected"));
        let Some(crate::cli::Commands::NativeProtection {
            command: super::NativeProtectionCommand::Capabilities(args),
        }) = cli.command
        else {
            panic!("wrong command")
        };
        assert!(args.principal.is_none());
    }
}
