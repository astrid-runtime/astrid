//! Native Windows lifecycle and `WinFsp` filesystem provider.

#[cfg(any(windows, test))]
mod callback;
#[cfg(windows)]
mod win;

use std::collections::BTreeMap;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use astrid_core::PrincipalId;
use astrid_core::kernel_api::{AdminRequestKind, AdminResponseBody};
use astrid_core::storage_filesystem::StorageMountLeaseV1;
use astrid_core::storage_provider::{
    STORAGE_PROVIDER_PROTOCOL_V1, StorageMountId, StorageMountSelectorV1, StorageProviderAccessV1,
    StorageProviderCapabilityV1, StorageProviderFailureV1, StorageProviderIdentityV1,
    StorageProviderOperationV1, StorageProviderOutcomeV1, StorageProviderRequestV1,
    StorageProviderResponseV1, StorageProviderSuccessV1,
};
use astrid_uplink::admin_client::AdminClient;
use serde::{Deserialize, Serialize};

const PROVIDER_NAME: &str = "astrid-storage-provider-winfsp";
const MAX_REQUEST_BYTES: u64 = 64 * 1024;
const DAEMON_ARGUMENT: &str = "--astrid-provider-winfsp-daemon-v1";

#[derive(Clone, Debug, Deserialize, Serialize)]
struct MountRecord {
    mount_id: StorageMountId,
    requested_by: PrincipalId,
    mountpoint: PathBuf,
    resource_path: PathBuf,
    control_path: PathBuf,
    access: StorageProviderAccessV1,
    auto_created_mountpoint: bool,
}

#[derive(Default, Deserialize, Serialize)]
struct MountRegistry {
    mounts: BTreeMap<String, MountRecord>,
}

#[tokio::main]
async fn main() {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    if arguments.as_slice() == [std::ffi::OsStr::new(DAEMON_ARGUMENT)] {
        #[cfg(windows)]
        {
            if let Err(error) = win::daemon_main() {
                eprintln!("{PROVIDER_NAME}: {error:#}");
                std::process::exit(2);
            }
            return;
        }
    }

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
        bail!("this executable is an Astrid WinFsp provider, not an interactive command");
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
        } => mount(&mut client, acting_principal, view, access, mountpoint).await,
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

async fn mount(
    client: &mut AdminClient,
    acting_principal: PrincipalId,
    view: astrid_core::storage_provider::StorageProviderViewV1,
    access: StorageProviderAccessV1,
    requested: Option<PathBuf>,
) -> Result<StorageProviderSuccessV1> {
    let (mountpoint, auto_created) = prepare_mountpoint(requested, &view)?;
    let registry_key = path_key(&mountpoint)?;
    if load_registry()?.mounts.contains_key(&registry_key) {
        bail!("mountpoint is already registered: {}", mountpoint.display());
    }
    let body = client
        .request(AdminRequestKind::StorageMountIssue {
            view,
            access,
            provider: PROVIDER_NAME.to_owned(),
            mountpoint: mountpoint.clone(),
        })
        .await?;
    let lease = lease_from_response(body)?;
    let control_path = provider_control_path(&lease.mount_id)?;

    if let Err(error) = native_mount(&lease, &mountpoint).await {
        revoke_after_native_failure(client, &lease, auto_created, &mountpoint).await;
        return Err(error);
    }
    let registered = update_registry(|registry| {
        if registry.mounts.contains_key(&registry_key) {
            bail!(
                "mountpoint was concurrently registered: {}",
                mountpoint.display()
            );
        }
        registry.mounts.insert(
            registry_key.clone(),
            MountRecord {
                mount_id: lease.mount_id,
                requested_by: acting_principal,
                mountpoint: mountpoint.clone(),
                resource_path: lease.resource_path.clone(),
                control_path: control_path.clone(),
                access,
                auto_created_mountpoint: auto_created,
            },
        );
        Ok(())
    });
    if let Err(error) = registered {
        if let Err(unmount_error) = native_unmount(&control_path).await {
            eprintln!("{PROVIDER_NAME}: failed to roll back native mount: {unmount_error:#}");
        } else {
            let _ = client
                .request(AdminRequestKind::StorageMountRevoke {
                    mount_id: lease.mount_id,
                })
                .await;
            if auto_created {
                let _ = std::fs::remove_dir(&mountpoint);
            }
        }
        return Err(error);
    }

    Ok(StorageProviderSuccessV1::Mounted {
        mount_id: lease.mount_id,
        mountpoint,
    })
}

async fn revoke_after_native_failure(
    client: &mut AdminClient,
    lease: &StorageMountLeaseV1,
    auto_created: bool,
    mountpoint: &Path,
) {
    let _ = client
        .request(AdminRequestKind::StorageMountRevoke {
            mount_id: lease.mount_id,
        })
        .await;
    if auto_created {
        let _ = std::fs::remove_dir(mountpoint);
    }
}

async fn unmount(
    client: &mut AdminClient,
    acting_principal: &PrincipalId,
    selector: &StorageMountSelectorV1,
) -> Result<StorageProviderSuccessV1> {
    let record = resolve_record(selector)?;
    if &record.requested_by != acting_principal {
        bail!("mount was issued to another acting principal");
    }
    let lease_is_live = unmount_status(
        client
            .request(AdminRequestKind::StorageMountStatus {
                mount_id: record.mount_id,
            })
            .await?,
    )?;
    native_unmount(&record.control_path).await?;
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
        registry.mounts.remove(&path_key(&record.mountpoint)?);
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

#[cfg(windows)]
fn prepare_mountpoint(
    requested: Option<PathBuf>,
    view: &astrid_core::storage_provider::StorageProviderViewV1,
) -> Result<(PathBuf, bool)> {
    let _ = view;
    let mountpoint = requested.map_or_else(first_free_drive, Ok)?;
    if !mountpoint.is_absolute() {
        bail!("mountpoint must be absolute");
    }
    if is_drive_target(&mountpoint) {
        if std::fs::metadata(&mountpoint).is_ok() {
            bail!(
                "Windows drive target is already in use: {}",
                mountpoint.display()
            );
        }
        return Ok((mountpoint, false));
    }

    let existed = mountpoint.exists();
    if !existed {
        std::fs::create_dir_all(&mountpoint)
            .with_context(|| format!("create mountpoint {}", mountpoint.display()))?;
    }
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

#[cfg(not(windows))]
fn prepare_mountpoint(
    _requested: Option<PathBuf>,
    _view: &astrid_core::storage_provider::StorageProviderViewV1,
) -> Result<(PathBuf, bool)> {
    bail!("the WinFsp provider is available only on Windows")
}

#[cfg(windows)]
fn first_free_drive() -> Result<PathBuf> {
    for letter in b'D'..=b'Z' {
        let root = PathBuf::from(format!("{}:\\", letter as char));
        match std::fs::metadata(&root) {
            Ok(_) => {},
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(root);
            },
            Err(error) => {
                return Err(error)
                    .context(format!("inspect Windows drive target {}", root.display()));
            },
        }
    }
    bail!("no free Windows drive target is available; specify a directory mountpoint")
}

#[cfg(windows)]
fn is_drive_target(path: &Path) -> bool {
    let Some(text) = path.to_str() else {
        return false;
    };
    let bytes = text.as_bytes();
    bytes.len() == 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'\\' || bytes[2] == b'/')
}

#[cfg(windows)]
async fn native_mount(lease: &StorageMountLeaseV1, mountpoint: &Path) -> Result<()> {
    win::spawn_daemon(lease, mountpoint).await
}

#[cfg(not(windows))]
fn native_mount(
    _lease: &StorageMountLeaseV1,
    _mountpoint: &Path,
) -> std::future::Ready<Result<()>> {
    std::future::ready(Err(anyhow::anyhow!(
        "the WinFsp provider is available only on Windows"
    )))
}

#[cfg(windows)]
async fn native_unmount(control_path: &Path) -> Result<()> {
    win::stop_daemon(control_path).await
}

#[cfg(not(windows))]
fn native_unmount(_control_path: &Path) -> std::future::Ready<Result<()>> {
    std::future::ready(Err(anyhow::anyhow!(
        "the WinFsp provider is available only on Windows"
    )))
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
            .get(&path_key(path)?)
            .cloned()
            .with_context(|| format!("mountpoint is not registered: {}", path.display())),
    }
}

fn provider_control_path(mount_id: &StorageMountId) -> Result<PathBuf> {
    Ok(astrid_core::dirs::AstridHome::resolve()?
        .run_dir()
        .join("providers")
        .join(format!("{mount_id}.control")))
}

fn registry_path() -> Result<PathBuf> {
    Ok(astrid_core::dirs::AstridHome::resolve()?
        .run_dir()
        .join("providers")
        .join("winfsp-mounts.json"))
}

fn load_registry() -> Result<MountRegistry> {
    let path = registry_path()?;
    match std::fs::read(&path) {
        Ok(bytes) => {
            astrid_core::platform_fs::validate_private_file(&path)
                .context("validate WinFsp mount registry")?;
            serde_json::from_slice(&bytes).context("decode WinFsp mount registry")
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(MountRegistry::default()),
        Err(error) => Err(error).context("read WinFsp mount registry"),
    }
}

fn update_registry(operation: impl FnOnce(&mut MountRegistry) -> Result<()>) -> Result<()> {
    let path = registry_path()?;
    let parent = path
        .parent()
        .context("WinFsp registry path has no parent")?;
    astrid_core::platform_fs::ensure_private_directory(parent)?;
    let mut registry = load_registry()?;
    operation(&mut registry)?;
    let mut bytes = serde_json::to_vec(&registry)?;
    bytes.push(b'\n');
    astrid_core::platform_fs::atomic_write_private_file(&path, &bytes)?;
    Ok(())
}

fn path_key(path: &Path) -> Result<String> {
    path.to_str()
        .map(str::to_owned)
        .context("provider protocol admitted a non-Unicode native path")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unmount_status_distinguishes_stale_and_refused_leases() {
        assert!(unmount_status(AdminResponseBody::Success(serde_json::json!({}))).unwrap());
        assert!(
            !unmount_status(AdminResponseBody::Error(
                "storage mount lease 123 was not found".to_owned()
            ))
            .unwrap()
        );
        assert!(
            unmount_status(AdminResponseBody::Error(
                "lease belongs to another principal".into()
            ))
            .is_err()
        );
    }
}
