//! Hosted filesystem mount command and native-provider handoff.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use anyhow::{Context, Result, bail};
use astrid_core::{FleetUid, PrincipalId};
use clap::{ArgGroup, Args, Subcommand};

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
    let provider = crate::bootstrap::find_companion_binary(provider_name).with_context(|| {
        format!(
            "the {provider_name} native filesystem provider is required on {}; \
             mounting does not provision storage or bypass Astrid authorization",
            std::env::consts::OS
        )
    })?;
    let acting = crate::principal::current();
    let mut process = Command::new(provider);
    match command {
        StorageCommand::Mount(args) => {
            let view = args.view()?;
            process
                .arg("mount")
                .arg("--acting-principal")
                .arg(acting.as_str())
                .arg("--access")
                .arg(args.access(&view));
            match view {
                MountView::Principal(principal) => {
                    process.arg("--view").arg("principal");
                    process.arg("--target-principal").arg(principal.as_str());
                },
                MountView::Fleet(fleet) => {
                    process.arg("--view").arg("fleet");
                    process.arg("--target-fleet").arg(fleet.to_string());
                },
                MountView::Admin => {
                    process.arg("--view").arg("admin");
                },
            }
            if let Some(mountpoint) = args.mountpoint {
                process.arg("--mountpoint").arg(mountpoint);
            }
        },
        StorageCommand::Sync(args) => {
            provider_mount_command(&mut process, "sync", &acting, &args.mountpoint);
        },
        StorageCommand::Status(args) => {
            provider_mount_command(&mut process, "status", &acting, &args.mountpoint);
        },
        StorageCommand::Unmount(args) => {
            provider_mount_command(&mut process, "unmount", &acting, &args.mountpoint);
        },
    }
    let status = process
        .status()
        .with_context(|| format!("failed to start {provider_name}"))?;
    Ok(status
        .code()
        .and_then(|code| u8::try_from(code).ok())
        .map_or(ExitCode::FAILURE, ExitCode::from))
}

fn provider_mount_command(
    process: &mut Command,
    operation: &str,
    acting: &PrincipalId,
    mountpoint: &Path,
) {
    process
        .arg(operation)
        .arg("--acting-principal")
        .arg(acting.as_str())
        .arg("--mountpoint")
        .arg(mountpoint);
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

    use crate::cli::{Cli, Commands};

    use super::{MountView, StorageCommand};

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
}
