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
        } => mount(&mut client, &acting_principal, view, access, mountpoint).await,
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
    acting_principal: &astrid_core::PrincipalId,
    view: astrid_core::storage_provider::StorageProviderViewV1,
    access: astrid_core::storage_provider::StorageProviderAccessV1,
    requested_mountpoint: Option<PathBuf>,
) -> Result<StorageProviderSuccessV1> {
    let (mountpoint, auto_created) = prepare_mountpoint(requested_mountpoint, &view)?;
    let body = client
        .request(AdminRequestKind::StorageMountIssue {
            view: view.clone(),
            access,
            provider: PROVIDER_NAME.to_owned(),
            mountpoint: mountpoint.clone(),
        })
        .await?;
    let lease = lease_from_response(body)?;
    if let Err(error) = update_registry(|registry| {
        if registry.mounts.contains_key(&path_key(&mountpoint)) {
            bail!("mountpoint is already registered: {}", mountpoint.display());
        }
        registry.mounts.insert(
            path_key(&mountpoint),
            MountRecord {
                mount_id: lease.mount_id,
                requested_by: acting_principal.clone(),
                mountpoint: mountpoint.clone(),
                access,
                auto_created_mountpoint: auto_created,
            },
        );
        Ok(())
    }) {
        revoke_after_registry_failure(client, lease.mount_id).await;
        return match cleanup_created_mountpoint(&mountpoint, auto_created) {
            Err(cleanup) => Err(error.context(cleanup)),
            Ok(()) => Err(error),
        };
    }
    if let Err(error) = native_mount(&lease, &mountpoint).await {
        let rollback =
            rollback_after_native_failure(client, &lease.mount_id, &mountpoint, auto_created).await;
        return Err(error).context(rollback);
    }
    if let Err(error) = validate_mountpoint(&mountpoint) {
        let rollback =
            rollback_after_native_failure(client, &lease.mount_id, &mountpoint, auto_created).await;
        return Err(error).context(rollback);
    }
    Ok(StorageProviderSuccessV1::Mounted {
        mount_id: lease.mount_id,
        mountpoint,
    })
}

async fn unmount(
    client: &mut AdminClient,
    acting_principal: &astrid_core::PrincipalId,
    selector: &StorageMountSelectorV1,
) -> Result<StorageProviderSuccessV1> {
    let record = resolve_record(selector)?;
    validate_mountpoint(&record.mountpoint)?;
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
    validate_mountpoint(&record.mountpoint)?;
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
    cleanup_created_mountpoint(&record.mountpoint, record.auto_created_mountpoint)?;
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

async fn revoke_after_registry_failure(client: &mut AdminClient, mount_id: StorageMountId) {
    let _ = client
        .request(AdminRequestKind::StorageMountRevoke { mount_id })
        .await;
}

async fn rollback_after_native_failure(
    client: &mut AdminClient,
    mount_id: &StorageMountId,
    mountpoint: &Path,
    auto_created: bool,
) -> anyhow::Error {
    let mut errors = Vec::new();
    let native_unmounted = match native_unmount(mountpoint).await {
        Ok(()) => true,
        Err(error) => {
            errors.push(format!("unmount: {error:#}"));
            false
        },
    };
    if !native_unmounted {
        return anyhow::anyhow!(
            "mount rollback left the lease registered for recovery; {}",
            errors.join("; ")
        );
    }
    if let Err(error) = client
        .request(AdminRequestKind::StorageMountRevoke {
            mount_id: *mount_id,
        })
        .await
    {
        errors.push(format!("revoke: {error:#}"));
    }
    if errors.is_empty()
        && let Err(error) = update_registry(|registry| {
            registry.mounts.remove(&path_key(mountpoint));
            Ok(())
        })
    {
        errors.push(format!("registry: {error:#}"));
    }
    if errors.is_empty()
        && let Err(error) = cleanup_created_mountpoint(mountpoint, auto_created)
    {
        errors.push(format!("cleanup: {error:#}"));
    }
    anyhow::anyhow!("mount rollback incomplete: {}", errors.join("; "))
}

fn cleanup_created_mountpoint(mountpoint: &Path, auto_created: bool) -> Result<()> {
    if !auto_created {
        return Ok(());
    }
    validate_mountpoint(mountpoint)?;
    let mut entries = std::fs::read_dir(mountpoint)
        .with_context(|| format!("read auto-created mountpoint {}", mountpoint.display()))?;
    if entries.next().is_some() {
        bail!(
            "auto-created mountpoint is not empty: {}",
            mountpoint.display()
        );
    }
    std::fs::remove_dir(mountpoint)
        .with_context(|| format!("remove auto-created mountpoint {}", mountpoint.display()))
}

fn prepare_mountpoint(
    requested: Option<PathBuf>,
    view: &astrid_core::storage_provider::StorageProviderViewV1,
) -> Result<(PathBuf, bool)> {
    let mountpoint =
        requested.map_or_else(|| default_mountpoint(std::env::var_os("HOME"), view), Ok)?;
    validate_mountpoint_layout(&mountpoint)?;
    let existed = match std::fs::symlink_metadata(&mountpoint) {
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => {
            return Err(error)
                .with_context(|| format!("inspect mountpoint {}", mountpoint.display()));
        },
    };
    if existed {
        validate_mountpoint(&mountpoint)?;
    } else {
        astrid_core::platform_fs::ensure_private_directory(&mountpoint)
            .with_context(|| format!("create private mountpoint {}", mountpoint.display()))?;
        validate_mountpoint(&mountpoint)?;
    }
    Ok((mountpoint, !existed))
}

fn default_mountpoint(
    home: Option<std::ffi::OsString>,
    view: &astrid_core::storage_provider::StorageProviderViewV1,
) -> Result<PathBuf> {
    let home = home
        .map(PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("HOME is required to choose a private mountpoint"))?;
    if !home.is_absolute() {
        bail!("HOME must be absolute to choose a private mountpoint");
    }
    let leaf = match view {
        astrid_core::storage_provider::StorageProviderViewV1::Principal(principal) => {
            principal.to_string()
        },
        astrid_core::storage_provider::StorageProviderViewV1::Fleet(fleet) => fleet.to_string(),
        astrid_core::storage_provider::StorageProviderViewV1::Admin => "system".to_owned(),
    };
    Ok(home.join("Astrid").join(leaf))
}

fn validate_mountpoint(mountpoint: &Path) -> Result<()> {
    validate_mountpoint_layout(mountpoint)?;
    astrid_core::platform_fs::verify_no_redirects(mountpoint)
        .with_context(|| format!("reject redirected mountpoint {}", mountpoint.display()))?;
    astrid_core::platform_fs::validate_private_directory(mountpoint)
        .with_context(|| format!("reject unsafe mountpoint {}", mountpoint.display()))?;
    if std::fs::read_dir(mountpoint)?.next().is_some() {
        bail!("mountpoint is not empty: {}", mountpoint.display());
    }
    Ok(())
}

fn validate_mountpoint_layout(mountpoint: &Path) -> Result<()> {
    if !mountpoint.is_absolute() {
        bail!("mountpoint must be absolute");
    }
    if mountpoint.components().any(|component| {
        matches!(
            component,
            std::path::Component::ParentDir | std::path::Component::CurDir
        )
    }) {
        bail!("mountpoint contains traversal: {}", mountpoint.display());
    }
    if mountpoint.parent().is_none() {
        bail!("mountpoint must be below a parent directory");
    }
    Ok(())
}

#[cfg(target_os = "macos")]
async fn native_mount(lease: &StorageMountLeaseV1, mountpoint: &Path) -> Result<()> {
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
fn native_mount(lease: &StorageMountLeaseV1, mountpoint: &Path) -> std::future::Ready<Result<()>> {
    let _ = (lease, mountpoint);
    std::future::ready(Err(anyhow::anyhow!(
        "the FSKit provider is available only on macOS"
    )))
}

#[cfg(target_os = "macos")]
async fn native_unmount(mountpoint: &Path) -> Result<()> {
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
fn native_unmount(mountpoint: &Path) -> std::future::Ready<Result<()>> {
    let _ = mountpoint;
    std::future::ready(Err(anyhow::anyhow!(
        "the FSKit provider is available only on macOS"
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
    let parent = path.parent().context("FSKit registry path has no parent")?;
    astrid_core::platform_fs::validate_private_directory(parent)
        .context("validate private FSKit registry directory")?;
    read_registry(&path)
}

fn read_registry(path: &Path) -> Result<MountRegistry> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => {
            astrid_core::platform_fs::validate_private_file(path)
                .context("validate private FSKit mount registry")?;
            let bytes = std::fs::read(path).context("read FSKit mount registry")?;
            serde_json::from_slice(&bytes).context("decode FSKit mount registry")
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(MountRegistry::default()),
        Err(error) => Err(error).context("inspect FSKit mount registry"),
    }
}

fn update_registry(operation: impl FnOnce(&mut MountRegistry) -> Result<()>) -> Result<()> {
    let path = registry_path()?;
    let parent = path.parent().context("FSKit registry path has no parent")?;
    astrid_core::platform_fs::ensure_private_directory(parent)?;
    let _lock = acquire_registry_lock(parent)?;
    let mut registry = read_registry(&path)?;
    operation(&mut registry)?;
    let mut bytes = serde_json::to_vec(&registry)?;
    bytes.push(b'\n');
    astrid_core::platform_fs::atomic_write_private_file(&path, &bytes)?;
    Ok(())
}

fn acquire_registry_lock(parent: &Path) -> Result<std::fs::File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;

        use fs2::FileExt as _;
        use nix::fcntl::OFlag;

        let path = parent.join("fskit-mounts.json.lock");
        if path.exists() {
            astrid_core::platform_fs::validate_private_file(&path)
                .context("validate private FSKit registry lock")?;
        }
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(OFlag::O_NOFOLLOW.bits())
            .open(&path)
            .context("open FSKit registry lock")?;
        astrid_core::platform_fs::validate_private_file(&path)
            .context("validate private FSKit registry lock")?;
        file.lock_exclusive().context("lock FSKit mount registry")?;
        Ok(file)
    }

    #[cfg(not(unix))]
    {
        use fs2::FileExt as _;

        let path = parent.join("fskit-mounts.json.lock");
        if path.exists() {
            astrid_core::platform_fs::validate_private_file(&path)
                .context("validate private FSKit registry lock")?;
        }
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&path)
            .context("open FSKit registry lock")?;
        astrid_core::platform_fs::validate_private_file(&path)
            .context("validate private FSKit registry lock")?;
        file.lock_exclusive().context("lock FSKit mount registry")?;
        Ok(file)
    }
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
    use std::os::unix::fs::PermissionsExt as _;

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
        assert_eq!(
            std::fs::metadata(&prepared)
                .expect("prepared mountpoint metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }

    #[cfg(unix)]
    #[test]
    fn prepare_mountpoint_rejects_an_existing_public_directory() {
        let root = tempfile::tempdir().expect("temporary directory");
        let mountpoint = root.path().join("mount");
        std::fs::create_dir(&mountpoint).expect("public mountpoint");
        std::fs::set_permissions(&mountpoint, std::fs::Permissions::from_mode(0o755))
            .expect("public mountpoint mode");
        let view = astrid_core::storage_provider::StorageProviderViewV1::Admin;

        let error = prepare_mountpoint(Some(mountpoint.clone()), &view)
            .expect_err("public mountpoint must be rejected");

        assert!(error.to_string().contains("unsafe mountpoint"));
        assert_eq!(
            std::fs::metadata(&mountpoint)
                .expect("rejected public mountpoint metadata")
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
    }

    #[test]
    fn default_mountpoint_requires_an_absolute_home() {
        let view = astrid_core::storage_provider::StorageProviderViewV1::Admin;

        assert!(default_mountpoint(None, &view).is_err());
        assert!(default_mountpoint(Some("relative".into()), &view).is_err());
        assert_eq!(
            default_mountpoint(Some("/Users/operator".into()), &view)
                .expect("absolute default mountpoint"),
            PathBuf::from("/Users/operator/Astrid/system")
        );
    }

    #[test]
    fn prepare_mountpoint_rejects_traversal() {
        let view = astrid_core::storage_provider::StorageProviderViewV1::Admin;

        assert!(prepare_mountpoint(Some("/tmp/../escape".into()), &view).is_err());
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

    #[cfg(unix)]
    #[test]
    fn prepare_mountpoint_rejects_a_redirected_parent() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().expect("temporary directory");
        let outside = tempfile::tempdir().expect("outside directory");
        let redirect = root.path().join("redirect");
        symlink(outside.path(), &redirect).expect("redirected parent");
        let view = astrid_core::storage_provider::StorageProviderViewV1::Admin;

        assert!(prepare_mountpoint(Some(redirect.join("mount")), &view).is_err());
        assert!(!outside.path().join("mount").exists());
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    #[ignore = "actual FSKit runtime: requires macOS 26, a signed enabled extension, and a live lease resource"]
    async fn actual_fskit_mount_and_unmount_round_trip() {
        let resource = PathBuf::from(
            std::env::var("ASTRID_FSKIT_ACTUAL_RESOURCE")
                .expect("ASTRID_FSKIT_ACTUAL_RESOURCE must name a live lease resource"),
        );
        let mountpoint = PathBuf::from(
            std::env::var("ASTRID_FSKIT_ACTUAL_MOUNTPOINT")
                .expect("ASTRID_FSKIT_ACTUAL_MOUNTPOINT must name a private empty mountpoint"),
        );
        let token = std::env::var("ASTRID_FSKIT_ACTUAL_TOKEN")
            .expect("ASTRID_FSKIT_ACTUAL_TOKEN must name the live lease bearer token");
        astrid_core::platform_fs::validate_private_directory(&resource)
            .expect("live lease resource must be private");
        astrid_core::platform_fs::validate_private_file(&resource.join("lease.json"))
            .expect("live lease manifest must be private");
        let lease = StorageMountLeaseV1 {
            mount_id: StorageMountId::new(),
            view: astrid_core::storage_provider::StorageProviderViewV1::Admin,
            access: astrid_core::storage_provider::StorageProviderAccessV1::ReadOnly,
            callback_path: resource.join("control.sock"),
            resource_path: resource,
            lease_token: token,
            expires_at_epoch_secs: u64::MAX,
        };

        native_mount(&lease, &mountpoint)
            .await
            .expect("actual FSKit mount");
        let output = std::process::Command::new("/sbin/mount")
            .output()
            .expect("read macOS mount table");
        assert!(output.status.success());
        let table = String::from_utf8_lossy(&output.stdout);
        assert!(
            table.contains(&format!(" on {} ", mountpoint.display())),
            "mount table does not contain {}: {table}",
            mountpoint.display()
        );

        native_unmount(&mountpoint)
            .await
            .expect("actual FSKit unmount");
        let output = std::process::Command::new("/sbin/mount")
            .output()
            .expect("read macOS mount table after unmount");
        assert!(output.status.success());
        let table = String::from_utf8_lossy(&output.stdout);
        assert!(!table.contains(&format!(" on {} ", mountpoint.display())));
    }
}
