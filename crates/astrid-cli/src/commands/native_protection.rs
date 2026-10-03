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
    /// Prepare or discard unpublished native pair upgrades.
    Upgrade {
        #[command(subcommand)]
        command: UpgradeCommand,
    },
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
    let args = match command {
        NativeProtectionCommand::Capabilities(args) => args,
        NativeProtectionCommand::Upgrade { command } => return run_upgrade(command).await,
    };
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

#[derive(Debug, Subcommand)]
pub(crate) enum UpgradeCommand {
    /// Begin an unpublished upgrade lease.
    Begin(UpgradeInput),
    /// Transfer one contiguous archive chunk.
    Stage(UpgradeInput),
    /// Query redacted lease status.
    Status(UpgradeInput),
    /// Discard private staging.
    Abort(UpgradeInput),
}

#[derive(Debug, Args)]
pub(crate) struct UpgradeInput {
    /// Owner-only JSON request file (never an inline credential argument).
    #[arg(long)]
    input: std::path::PathBuf,
}

async fn run_upgrade(command: UpgradeCommand) -> Result<ExitCode> {
    let input = match &command {
        UpgradeCommand::Begin(input)
        | UpgradeCommand::Stage(input)
        | UpgradeCommand::Status(input)
        | UpgradeCommand::Abort(input) => input,
    };
    let bytes = private_upgrade_input(&input.input)?;
    let request = match command {
        UpgradeCommand::Begin(_) => {
            serde_json::from_slice(&bytes).map(KernelRequest::BeginNativePairUpgrade)
        },
        UpgradeCommand::Stage(_) => {
            serde_json::from_slice(&bytes).map(KernelRequest::StageNativePairMember)
        },
        UpgradeCommand::Status(_) => {
            serde_json::from_slice(&bytes).map(KernelRequest::GetNativePairUpgrade)
        },
        UpgradeCommand::Abort(_) => {
            serde_json::from_slice(&bytes).map(KernelRequest::AbortNativePairUpgrade)
        },
    }
    .map_err(|_| anyhow::anyhow!("invalid native pair JSON request"))?;
    // Include serde's Vec<u8> decimal expansion and leave transport envelope headroom.
    anyhow::ensure!(
        serde_json::to_vec(&request)?.len() <= 2 * 1024 * 1024 - 64 * 1024,
        "native pair request exceeds wire limit"
    );
    let mut client = crate::socket_client::connect_kernel_for_workspace(None).await?;
    match client.request(request).await? {
        KernelResponse::NativePairLease(lease) => println!("{}", serde_json::to_string(&lease)?),
        KernelResponse::NativePairState(state) => println!("{}", serde_json::to_string(&state)?),
        _ => bail!("daemon rejected native pair operation"),
    }
    Ok(ExitCode::SUCCESS)
}

fn private_upgrade_input(path: &std::path::Path) -> Result<Vec<u8>> {
    #[cfg(unix)]
    {
        use std::io::Read;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        let metadata = file.metadata()?;
        anyhow::ensure!(
            metadata.is_file() && metadata.permissions().mode().trailing_zeros() >= 6,
            "native pair input must be a private regular file"
        );
        let mut bytes = Vec::new();
        file.take(2 * 1024 * 1024).read_to_end(&mut bytes)?;
        anyhow::ensure!(
            bytes.len() < 2 * 1024 * 1024,
            "native pair input exceeds wire limit"
        );
        Ok(bytes)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        bail!("native pair private input requires Unix permissions")
    }
}

#[cfg(all(test, unix))]
mod upgrade_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn native_pair_private_input_rejects_public_and_oversized_files() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("input.json");
        std::fs::write(&path, b"{}").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(private_upgrade_input(&path).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(private_upgrade_input(&path).unwrap(), b"{}");
        let link = directory.path().join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(private_upgrade_input(&link).is_err());
        std::fs::write(&path, vec![0; 2 * 1024 * 1024]).unwrap();
        assert!(private_upgrade_input(&path).is_err());
    }
    #[test]
    fn native_pair_cli_exposes_only_preparation_operations() {
        use clap::Parser;
        for operation in ["begin", "stage", "status", "abort"] {
            assert!(
                crate::cli::Cli::try_parse_from([
                    "astrid",
                    "native-protection",
                    "upgrade",
                    operation,
                    "--input",
                    "private.json"
                ])
                .is_ok()
            );
        }
        assert!(
            crate::cli::Cli::try_parse_from([
                "astrid",
                "native-protection",
                "upgrade",
                "commit",
                "--input",
                "private.json"
            ])
            .is_err()
        );
    }
}
