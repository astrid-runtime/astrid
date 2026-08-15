#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![deny(clippy::unwrap_used)]

//! Lifecycle companion for Astrid's macOS `FSKit` extension.

use std::collections::BTreeMap;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use astrid_core::kernel_api::{AdminRequestKind, AdminResponseBody};
use astrid_core::storage_filesystem::StorageMountLeaseV1;
use astrid_core::storage_provider::{
    STORAGE_PROVIDER_PROTOCOL_V1, StorageMountId, StorageMountSelectorV1,
    StorageProviderCapabilityV1, StorageProviderFailureV1, StorageProviderIdentityV1,
    StorageProviderOperationV1, StorageProviderOutcomeV1, StorageProviderRequestV1,
    StorageProviderResponseV1, StorageProviderSuccessV1,
};
use astrid_uplink::admin_client::AdminClient;
use serde::{Deserialize, Serialize};

const PROVIDER_NAME: &str = "astrid-storage-provider-fskit";
const MAX_REQUEST_BYTES: u64 = 64 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
struct MountRecord {
    mount_id: StorageMountId,
    requested_by: astrid_core::PrincipalId,
    mountpoint: PathBuf,
    access: astrid_core::storage_provider::StorageProviderAccessV1,
    auto_created_mountpoint: bool,
}

#[derive(Default, Deserialize, Serialize)]
struct MountRegistry {
    mounts: BTreeMap<String, MountRecord>,
}

#[tokio::main]
async fn main() {
    let response = run().await;
    match response {
        Ok(response) => {
            if serde_json::to_writer(std::io::stdout().lock(), &response).is_err() {
                std::process::exit(2);
            }
            println!();
        },
        Err(error) => {
            eprintln!("{PROVIDER_NAME}: {error:#}");
            std::process::exit(2);
        },
    }
}

async fn run() -> Result<StorageProviderResponseV1> {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    if arguments.as_slice() != [std::ffi::OsStr::new("--astrid-provider-stdio-v1")] {
        bail!("this executable is an Astrid provider companion, not an interactive command");
    }
    let mut bytes = Vec::new();
    std::io::stdin()
        .lock()
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .context("read provider request")?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        bail!("provider request exceeds limit");
    }
    let request: StorageProviderRequestV1 =
        serde_json::from_slice(&bytes).context("decode provider request")?;
    if request.protocol_version != STORAGE_PROVIDER_PROTOCOL_V1 {
        bail!("unsupported provider protocol {}", request.protocol_version);
    }
    let request_id = request.request_id;
    let outcome = match execute(request).await {
        Ok(success) => StorageProviderOutcomeV1::Success(success),
        Err(error) => StorageProviderOutcomeV1::Failure(StorageProviderFailureV1 {
            code: "provider-operation".to_owned(),
            message: error.to_string().chars().take(4096).collect(),
        }),
    };
    Ok(StorageProviderResponseV1 {
        protocol_version: STORAGE_PROVIDER_PROTOCOL_V1,
        request_id,
        provider: StorageProviderIdentityV1 {
            name: PROVIDER_NAME.to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            capabilities: vec![
                StorageProviderCapabilityV1::PrincipalView,
                StorageProviderCapabilityV1::FleetView,
                StorageProviderCapabilityV1::AdminView,
                StorageProviderCapabilityV1::ReadOnly,
                StorageProviderCapabilityV1::ReadWrite,
                StorageProviderCapabilityV1::Lifecycle,
            ],
        },
        outcome,
    })
}

async fn execute(request: StorageProviderRequestV1) -> Result<StorageProviderSuccessV1> {
    let acting_principal = request.acting_principal_hint;
    let mut client = AdminClient::connect(acting_principal.clone()).await?;
    match request.operation {
        StorageProviderOperationV1::Mount {
            view,
            access,
            mountpoint,
        } => {
            let (mountpoint, auto_created) = prepare_mountpoint(mountpoint, &view)?;
            let body = client
                .request(AdminRequestKind::StorageMountIssue {
                    view,
                    access,
                    provider: PROVIDER_NAME.to_owned(),
                    mountpoint: mountpoint.clone(),
                })
                .await?;
            let lease = lease_from_response(body)?;
            if let Err(error) = native_mount(&lease, &mountpoint).await {
                let _ = client
                    .request(AdminRequestKind::StorageMountRevoke {
                        mount_id: lease.mount_id,
                    })
                    .await;
                if auto_created {
                    let _ = std::fs::remove_dir(&mountpoint);
                }
                return Err(error);
            }
            update_registry(|registry| {
                registry.mounts.insert(
                    path_key(&mountpoint),
                    MountRecord {
                        mount_id: lease.mount_id,
                        requested_by: acting_principal,
                        mountpoint: mountpoint.clone(),
                        access,
                        auto_created_mountpoint: auto_created,
                    },
                );
                Ok(())
            })?;
            Ok(StorageProviderSuccessV1::Mounted {
                mount_id: lease.mount_id,
                mountpoint,
            })
        },
        StorageProviderOperationV1::Sync { selector } => {
            let record = resolve_record(&selector)?;
            into_success(
                client
                    .request(AdminRequestKind::StorageMountSync {
                        mount_id: record.mount_id,
                    })
                    .await?,
            )?;
            Ok(StorageProviderSuccessV1::Synced {
                mount_id: record.mount_id,
            })
        },
        StorageProviderOperationV1::Status { selector } => {
            let record = resolve_record(&selector)?;
            let status = into_success(
                client
                    .request(AdminRequestKind::StorageMountStatus {
                        mount_id: record.mount_id,
                    })
                    .await?,
            )?;
            let dirty = status
                .get("dirty")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            Ok(StorageProviderSuccessV1::Status {
                mount_id: record.mount_id,
                mountpoint: record.mountpoint,
                access: record.access,
                dirty,
            })
        },
        StorageProviderOperationV1::Unmount { selector } => {
            unmount(&mut client, &acting_principal, &selector).await
        },
    }
}

async fn unmount(
    client: &mut AdminClient,
    acting_principal: &astrid_core::PrincipalId,
    selector: &StorageMountSelectorV1,
) -> Result<StorageProviderSuccessV1> {
    let record = resolve_record(selector)?;
    if &record.requested_by != acting_principal {
        bail!("mount was issued to another acting principal");
    }
    // Validate lease ownership before changing native mount state. The
    // registry is lifecycle bookkeeping, not an authorization source.
    let lease_is_live = unmount_status(
        client
            .request(AdminRequestKind::StorageMountStatus {
                mount_id: record.mount_id,
            })
            .await?,
    )?;
    native_unmount(&record.mountpoint).await?;
    if lease_is_live {
        into_success(
            client
                .request(AdminRequestKind::StorageMountRevoke {
                    mount_id: record.mount_id,
                })
                .await?,
        )?;
    }
    update_registry(|registry| {
        registry.mounts.remove(&path_key(&record.mountpoint));
        Ok(())
    })?;
    if record.auto_created_mountpoint {
        let _ = std::fs::remove_dir(&record.mountpoint);
    }
    Ok(StorageProviderSuccessV1::Unmounted {
        mount_id: record.mount_id,
    })
}

fn lease_from_response(body: AdminResponseBody) -> Result<StorageMountLeaseV1> {
    match body {
        AdminResponseBody::StorageMountLease(lease) => Ok(*lease),
        AdminResponseBody::Error(error) => bail!("kernel refused storage mount: {error}"),
        _ => bail!("kernel returned an unexpected storage mount response"),
    }
}

fn into_success(body: AdminResponseBody) -> Result<serde_json::Value> {
    match body {
        AdminResponseBody::Success(value) => Ok(value),
        AdminResponseBody::Error(error) => {
            bail!("kernel refused storage lifecycle request: {error}")
        },
        _ => bail!("kernel returned an unexpected storage lifecycle response"),
    }
}

fn unmount_status(body: AdminResponseBody) -> Result<bool> {
    match body {
        AdminResponseBody::Success(_) => Ok(true),
        AdminResponseBody::Error(error)
            if error.contains("was not found") || error.contains("expired or revoked") =>
        {
            Ok(false)
        },
        AdminResponseBody::Error(error) => {
            bail!("kernel refused storage unmount authorization: {error}")
        },
        _ => bail!("kernel returned an unexpected storage unmount response"),
    }
}

fn prepare_mountpoint(
    requested: Option<PathBuf>,
    view: &astrid_core::storage_provider::StorageProviderViewV1,
) -> Result<(PathBuf, bool)> {
    let mountpoint = requested.unwrap_or_else(|| {
        let leaf = match view {
            astrid_core::storage_provider::StorageProviderViewV1::Principal(principal) => {
                principal.to_string()
            },
            astrid_core::storage_provider::StorageProviderViewV1::Fleet(fleet) => fleet.to_string(),
            astrid_core::storage_provider::StorageProviderViewV1::Admin => "system".to_owned(),
        };
        std::env::var_os("HOME")
            .map_or_else(|| PathBuf::from("/tmp"), PathBuf::from)
            .join("Astrid")
            .join(leaf)
    });
    if !mountpoint.is_absolute() {
        bail!("mountpoint must be absolute");
    }
    let existed = mountpoint.exists();
    std::fs::create_dir_all(&mountpoint)
        .with_context(|| format!("create mountpoint {}", mountpoint.display()))?;
    astrid_core::platform_fs::verify_no_redirects(&mountpoint)
        .with_context(|| format!("reject redirected mountpoint {}", mountpoint.display()))?;
    if !std::fs::symlink_metadata(&mountpoint)?.is_dir() {
        bail!("mountpoint is not a directory: {}", mountpoint.display());
    }
    if std::fs::read_dir(&mountpoint)?.next().is_some() {
        bail!("mountpoint is not empty: {}", mountpoint.display());
    }
    Ok((mountpoint, !existed))
}

async fn native_mount(lease: &StorageMountLeaseV1, mountpoint: &Path) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        let status = tokio::process::Command::new("/sbin/mount")
            .arg("-t")
            .arg("astridfs")
            .arg(&lease.resource_path)
            .arg(mountpoint)
            .status()
            .await
            .context("invoke macOS FSKit mount")?;
        if !status.success() {
            bail!(
                "macOS FSKit mount failed with {status}; install and enable the Astrid file-system extension"
            );
        }
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (lease, mountpoint);
        bail!("the FSKit provider is available only on macOS")
    }
}

async fn native_unmount(mountpoint: &Path) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        let status = tokio::process::Command::new("/sbin/umount")
            .arg(mountpoint)
            .status()
            .await
            .context("invoke macOS unmount")?;
        if !status.success() {
            bail!("macOS unmount failed with {status}");
        }
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = mountpoint;
        bail!("the FSKit provider is available only on macOS")
    }
}

fn resolve_record(selector: &StorageMountSelectorV1) -> Result<MountRecord> {
    let registry = load_registry()?;
    match selector {
        StorageMountSelectorV1::MountId(mount_id) => registry
            .mounts
            .values()
            .find(|record| record.mount_id == *mount_id)
            .cloned()
            .with_context(|| format!("mount {mount_id} is not registered")),
        StorageMountSelectorV1::NativePath(path) => registry
            .mounts
            .get(&path_key(path))
            .cloned()
            .with_context(|| format!("mountpoint is not registered: {}", path.display())),
    }
}

fn registry_path() -> Result<PathBuf> {
    Ok(astrid_core::dirs::AstridHome::resolve()?
        .run_dir()
        .join("providers")
        .join("fskit-mounts.json"))
}

fn load_registry() -> Result<MountRegistry> {
    let path = registry_path()?;
    match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes).context("decode FSKit mount registry"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(MountRegistry::default()),
        Err(error) => Err(error).context("read FSKit mount registry"),
    }
}

fn update_registry(operation: impl FnOnce(&mut MountRegistry) -> Result<()>) -> Result<()> {
    let path = registry_path()?;
    let parent = path.parent().context("FSKit registry path has no parent")?;
    astrid_core::platform_fs::ensure_private_directory(parent)?;
    let mut registry = load_registry()?;
    operation(&mut registry)?;
    let mut bytes = serde_json::to_vec(&registry)?;
    bytes.push(b'\n');
    astrid_core::platform_fs::atomic_write_private_file(&path, &bytes)?;
    Ok(())
}

fn path_key(path: &Path) -> String {
    // Provider requests use JSON, so a native path must already be Unicode.
    // Preserve that exact representation rather than admitting lossy aliases.
    path.to_str()
        .expect("provider protocol admitted a non-Unicode native path")
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepare_mountpoint_creates_an_empty_directory() {
        let root = tempfile::tempdir().expect("temporary directory");
        let mountpoint = root.path().join("mount");
        let view = astrid_core::storage_provider::StorageProviderViewV1::Admin;

        let (prepared, created) =
            prepare_mountpoint(Some(mountpoint.clone()), &view).expect("prepare mountpoint");

        assert_eq!(prepared, mountpoint);
        assert!(created);
        assert!(prepared.is_dir());
    }

    #[test]
    fn unmount_allows_local_cleanup_after_a_stale_kernel_lease() {
        assert!(
            unmount_status(AdminResponseBody::Success(serde_json::json!({})))
                .expect("live lease status")
        );
        assert!(
            !unmount_status(AdminResponseBody::Error(
                "storage mount lease 123 was not found".to_owned()
            ))
            .expect("stale lease status")
        );
        assert!(
            unmount_status(AdminResponseBody::Error(
                "lease belongs to another principal".into()
            ))
            .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn prepare_mountpoint_rejects_a_symlink() {
        let root = tempfile::tempdir().expect("temporary directory");
        let target = root.path().join("target");
        let redirected = root.path().join("redirected");
        std::fs::create_dir(&target).expect("target directory");
        std::os::unix::fs::symlink(&target, &redirected).expect("mountpoint symlink");
        let view = astrid_core::storage_provider::StorageProviderViewV1::Admin;

        assert!(prepare_mountpoint(Some(redirected), &view).is_err());
    }
}
