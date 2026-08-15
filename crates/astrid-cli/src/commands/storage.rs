//! Hosted filesystem mount command and native-provider handoff.

use std::io::{Read as _, Write as _};
use std::path::PathBuf;
use std::process::{Command, ExitCode, Stdio};

use anyhow::{Context, Result, bail};
use astrid_core::storage_provider::{
    STORAGE_PROVIDER_PROTOCOL_V1, StorageMountSelectorV1, StorageProviderAccessV1,
    StorageProviderCapabilityV1, StorageProviderOperationV1, StorageProviderOutcomeV1,
    StorageProviderRequestV1, StorageProviderResponseV1, StorageProviderSuccessV1,
    StorageProviderViewV1,
};
use astrid_core::{FleetUid, PrincipalId};
use clap::{ArgGroup, Args, Subcommand};

const MAX_PROVIDER_RESPONSE_BYTES: u64 = 64 * 1024;

/// Hosted Astrid filesystem operations.
#[derive(Debug, Clone, Subcommand)]
pub(crate) enum StorageCommand {
    /// Mount one admitted Astrid filesystem view.
    Mount(MountArgs),
    /// Wait for acknowledged dirty state to publish.
    Sync(MountPathArgs),
    /// Inspect provider, lease, staging, and publication state.
    Status(MountPathArgs),
    /// Revoke a mount lease and detach its native volume.
    Unmount(MountPathArgs),
}

/// Selection and access mode for one hosted mount.
#[derive(Debug, Clone, Args)]
#[command(
    group(ArgGroup::new("storage-view").required(true).multiple(false).args([
        "as_principal",
        "fleet",
        "admin"
    ])),
    group(ArgGroup::new("storage-access").multiple(false).args([
        "read_only",
        "read_write"
    ]))
)]
pub(crate) struct MountArgs {
    /// Select a principal view. The global --principal remains the acting identity.
    #[arg(long = "as", value_name = "PRINCIPAL")]
    as_principal: Option<PrincipalId>,
    /// Select a fleet-wide view admitted to the acting principal.
    #[arg(long, value_name = "FLEET_UID")]
    fleet: Option<FleetUid>,
    /// Select the acting principal's supported system-administration view.
    #[arg(long)]
    admin: bool,
    /// Mount read-only. This is the default for --admin.
    #[arg(long)]
    read_only: bool,
    /// Explicitly request a writable view. Required for writable --admin mounts.
    #[arg(long)]
    read_write: bool,
    /// Native mount point or Windows drive target. The provider chooses when omitted.
    #[arg(value_name = "MOUNTPOINT")]
    mountpoint: Option<PathBuf>,
}

/// Existing mount selected by its native path or Windows drive target.
#[derive(Debug, Clone, Args)]
pub(crate) struct MountPathArgs {
    /// Native mount point or Windows drive target.
    #[arg(value_name = "MOUNTPOINT")]
    mountpoint: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum MountView {
    Principal(PrincipalId),
    Fleet(FleetUid),
    Admin,
}

impl MountArgs {
    fn view(&self) -> Result<MountView> {
        match (&self.as_principal, self.fleet, self.admin) {
            (Some(principal), None, false) => Ok(MountView::Principal(principal.clone())),
            (None, Some(fleet), false) => Ok(MountView::Fleet(fleet)),
            (None, None, true) => Ok(MountView::Admin),
            _ => bail!("exactly one of --as, --fleet, or --admin is required"),
        }
    }

    fn access(&self, view: &MountView) -> &'static str {
        if self.read_only || (matches!(view, MountView::Admin) && !self.read_write) {
            "read-only"
        } else {
            "read-write"
        }
    }
}

/// Run a storage command through the platform's lifecycle-independent provider.
pub(crate) fn run(command: StorageCommand) -> Result<ExitCode> {
    let provider_name = platform_provider_name();
    let provider = crate::bootstrap::find_coinstalled_companion_binary(provider_name)
        .with_context(|| {
            format!(
                "the {provider_name} native filesystem provider is required on {}; \
             mounting does not provision storage or bypass Astrid authorization",
                std::env::consts::OS
            )
        })?;
    let acting = crate::principal::current();
    let (operation, required_capabilities) = provider_operation(command)?;
    let request = StorageProviderRequestV1::new(acting.clone(), operation);
    let mut child = Command::new(provider)
        .arg("--astrid-provider-stdio-v1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("failed to start {provider_name}"))?;
    let mut stdin = child
        .stdin
        .take()
        .context("native provider stdin is unavailable")?;
    serde_json::to_writer(&mut stdin, &request).context("encode native provider request")?;
    stdin
        .write_all(b"\n")
        .context("terminate native provider request")?;
    drop(stdin);
    let stdout = child
        .stdout
        .take()
        .context("native provider stdout is unavailable")?;
    let mut response_bytes = Vec::new();
    stdout
        .take(MAX_PROVIDER_RESPONSE_BYTES + 1)
        .read_to_end(&mut response_bytes)
        .context("read native provider response")?;
    if response_bytes.len() as u64 > MAX_PROVIDER_RESPONSE_BYTES {
        let _ = child.kill();
        let _ = child.wait();
        bail!("{provider_name} exceeded the bounded protocol response size");
    }
    let status = child.wait().context("wait for native storage provider")?;
    if !status.success() {
        bail!("{provider_name} exited without a successful protocol response: {status}");
    }
    let response: StorageProviderResponseV1 =
        serde_json::from_slice(&response_bytes).context("decode native provider response")?;
    validate_response(provider_name, &request, &response, &required_capabilities)?;
    render_response(response.outcome)
}

fn provider_operation(
    command: StorageCommand,
) -> Result<(StorageProviderOperationV1, Vec<StorageProviderCapabilityV1>)> {
    Ok(match command {
        StorageCommand::Mount(args) => {
            let view = args.view()?;
            let access = if args.access(&view) == "read-only" {
                StorageProviderAccessV1::ReadOnly
            } else {
                StorageProviderAccessV1::ReadWrite
            };
            let view_capability = match &view {
                MountView::Principal(_) => StorageProviderCapabilityV1::PrincipalView,
                MountView::Fleet(_) => StorageProviderCapabilityV1::FleetView,
                MountView::Admin => StorageProviderCapabilityV1::AdminView,
            };
            let access_capability = match access {
                StorageProviderAccessV1::ReadOnly => StorageProviderCapabilityV1::ReadOnly,
                StorageProviderAccessV1::ReadWrite => StorageProviderCapabilityV1::ReadWrite,
            };
            let view = match view {
                MountView::Principal(principal) => StorageProviderViewV1::Principal(principal),
                MountView::Fleet(fleet) => StorageProviderViewV1::Fleet(fleet),
                MountView::Admin => StorageProviderViewV1::Admin,
            };
            (
                StorageProviderOperationV1::Mount {
                    view,
                    access,
                    mountpoint: args.mountpoint,
                },
                vec![view_capability, access_capability],
            )
        },
        StorageCommand::Sync(args) => (
            StorageProviderOperationV1::Sync {
                selector: StorageMountSelectorV1::NativePath(args.mountpoint),
            },
            vec![StorageProviderCapabilityV1::Lifecycle],
        ),
        StorageCommand::Status(args) => (
            StorageProviderOperationV1::Status {
                selector: StorageMountSelectorV1::NativePath(args.mountpoint),
            },
            vec![StorageProviderCapabilityV1::Lifecycle],
        ),
        StorageCommand::Unmount(args) => (
            StorageProviderOperationV1::Unmount {
                selector: StorageMountSelectorV1::NativePath(args.mountpoint),
            },
            vec![StorageProviderCapabilityV1::Lifecycle],
        ),
    })
}

fn validate_response(
    provider_name: &str,
    request: &StorageProviderRequestV1,
    response: &StorageProviderResponseV1,
    required_capabilities: &[StorageProviderCapabilityV1],
) -> Result<()> {
    if response.protocol_version != STORAGE_PROVIDER_PROTOCOL_V1 {
        bail!(
            "{provider_name} protocol mismatch: expected {}, received {}",
            STORAGE_PROVIDER_PROTOCOL_V1,
            response.protocol_version
        );
    }
    if response.request_id != request.request_id {
        bail!("{provider_name} returned a response for a different request");
    }
    if response.provider.name != provider_name
        || response.provider.version.is_empty()
        || response.provider.version.len() > 128
        || response.provider.version.chars().any(char::is_control)
        || response.provider.capabilities.len() > 16
        || !capabilities_are_unique(&response.provider.capabilities)
    {
        bail!("native provider identity does not match the co-installed executable");
    }
    for capability in required_capabilities {
        if !response.provider.capabilities.contains(capability) {
            bail!("{provider_name} does not advertise required capability {capability:?}");
        }
    }
    let operation_matches = matches!(
        (&request.operation, &response.outcome),
        (
            StorageProviderOperationV1::Mount { .. },
            StorageProviderOutcomeV1::Success(StorageProviderSuccessV1::Mounted { .. })
        ) | (
            StorageProviderOperationV1::Sync { .. },
            StorageProviderOutcomeV1::Success(StorageProviderSuccessV1::Synced { .. })
        ) | (
            StorageProviderOperationV1::Status { .. },
            StorageProviderOutcomeV1::Success(StorageProviderSuccessV1::Status { .. })
        ) | (
            StorageProviderOperationV1::Unmount { .. },
            StorageProviderOutcomeV1::Success(StorageProviderSuccessV1::Unmounted { .. })
        ) | (_, StorageProviderOutcomeV1::Failure(_))
    );
    if !operation_matches {
        bail!("{provider_name} returned a result for a different operation");
    }
    Ok(())
}

fn capabilities_are_unique(capabilities: &[StorageProviderCapabilityV1]) -> bool {
    let mut admitted = Vec::with_capacity(capabilities.len());
    for capability in capabilities {
        if admitted.contains(capability) {
            return false;
        }
        admitted.push(*capability);
    }
    true
}

fn render_response(outcome: StorageProviderOutcomeV1) -> Result<ExitCode> {
    match outcome {
        StorageProviderOutcomeV1::Success(StorageProviderSuccessV1::Mounted {
            mount_id,
            mountpoint,
        }) => println!("mounted {mount_id} at {}", mountpoint.display()),
        StorageProviderOutcomeV1::Success(StorageProviderSuccessV1::Synced { mount_id }) => {
            println!("synced {mount_id}");
        },
        StorageProviderOutcomeV1::Success(StorageProviderSuccessV1::Status {
            mount_id,
            mountpoint,
            access,
            dirty,
        }) => println!(
            "mount {mount_id} at {}: {access:?}, dirty={dirty}",
            mountpoint.display()
        ),
        StorageProviderOutcomeV1::Success(StorageProviderSuccessV1::Unmounted { mount_id }) => {
            println!("unmounted {mount_id}");
        },
        StorageProviderOutcomeV1::Failure(failure) => {
            if failure.code.is_empty()
                || failure.code.len() > 64
                || !failure
                    .code
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                || failure.message.is_empty()
                || failure.message.len() > 4096
                || failure.message.chars().any(char::is_control)
            {
                bail!("native provider returned an invalid structured error");
            }
            eprintln!(
                "storage provider error [{}]: {}",
                failure.code, failure.message
            );
            return Ok(ExitCode::FAILURE);
        },
    }
    Ok(ExitCode::SUCCESS)
}

fn platform_provider_name() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        "astrid-storage-provider-fskit"
    }
    #[cfg(target_os = "linux")]
    {
        "astrid-storage-provider-fuse"
    }
    #[cfg(target_os = "windows")]
    {
        "astrid-storage-provider-winfsp"
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;
    use uuid::Uuid;

    use crate::cli::{Cli, Commands};

    use super::{MountView, StorageCommand, validate_response};
    use astrid_core::storage_provider::{
        StorageMountId, StorageProviderCapabilityV1, StorageProviderIdentityV1,
        StorageProviderOperationV1, StorageProviderOutcomeV1, StorageProviderRequestV1,
        StorageProviderResponseV1, StorageProviderSuccessV1,
    };

    fn mount(arguments: &[&str]) -> super::MountArgs {
        let cli = Cli::try_parse_from(arguments).unwrap();
        let Some(Commands::Storage {
            command: StorageCommand::Mount(args),
        }) = cli.command
        else {
            panic!("expected storage mount")
        };
        args
    }

    #[test]
    fn mount_requires_exactly_one_view() {
        assert!(Cli::try_parse_from(["astrid", "storage", "mount"]).is_err());
        assert!(
            Cli::try_parse_from(["astrid", "storage", "mount", "--as", "alice", "--admin"])
                .is_err()
        );
    }

    #[test]
    fn principal_mount_is_writable_by_default() {
        let args = mount(&["astrid", "storage", "mount", "--as", "alice"]);
        let view = args.view().unwrap();
        assert_eq!(view, MountView::Principal("alice".parse().unwrap()));
        assert_eq!(args.access(&view), "read-write");
    }

    #[test]
    fn admin_mount_is_read_only_unless_explicitly_writable() {
        let args = mount(&["astrid", "storage", "mount", "--admin"]);
        assert_eq!(args.access(&args.view().unwrap()), "read-only");
        let args = mount(&["astrid", "storage", "mount", "--admin", "--read-write"]);
        assert_eq!(args.access(&args.view().unwrap()), "read-write");
    }

    fn status_exchange() -> (StorageProviderRequestV1, StorageProviderResponseV1) {
        let request = StorageProviderRequestV1::new(
            "operator".parse().unwrap(),
            StorageProviderOperationV1::Status {
                selector: astrid_core::storage_provider::StorageMountSelectorV1::NativePath(
                    "/mnt/astrid".into(),
                ),
            },
        );
        let response = StorageProviderResponseV1 {
            protocol_version: astrid_core::storage_provider::STORAGE_PROVIDER_PROTOCOL_V1,
            request_id: request.request_id,
            provider: StorageProviderIdentityV1 {
                name: super::platform_provider_name().to_owned(),
                version: "1.0.0".to_owned(),
                capabilities: vec![StorageProviderCapabilityV1::Lifecycle],
            },
            outcome: StorageProviderOutcomeV1::Success(StorageProviderSuccessV1::Status {
                mount_id: StorageMountId::from_uuid(Uuid::from_bytes([9; 16])),
                mountpoint: "/mnt/astrid".into(),
                access: astrid_core::storage_provider::StorageProviderAccessV1::ReadOnly,
                dirty: false,
            }),
        };
        (request, response)
    }

    #[test]
    fn provider_response_binds_protocol_identity_capability_and_request() {
        let (request, response) = status_exchange();
        validate_response(
            super::platform_provider_name(),
            &request,
            &response,
            &[StorageProviderCapabilityV1::Lifecycle],
        )
        .unwrap();

        let mut wrong_protocol = response.clone();
        wrong_protocol.protocol_version += 1;
        assert!(
            validate_response(
                super::platform_provider_name(),
                &request,
                &wrong_protocol,
                &[StorageProviderCapabilityV1::Lifecycle],
            )
            .is_err()
        );

        let mut wrong_operation = response;
        wrong_operation.outcome =
            StorageProviderOutcomeV1::Success(StorageProviderSuccessV1::Unmounted {
                mount_id: StorageMountId::from_uuid(Uuid::from_bytes([9; 16])),
            });
        assert!(
            validate_response(
                super::platform_provider_name(),
                &request,
                &wrong_operation,
                &[StorageProviderCapabilityV1::Lifecycle],
            )
            .is_err()
        );
    }
}
