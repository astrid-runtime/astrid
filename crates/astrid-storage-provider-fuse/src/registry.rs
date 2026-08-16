//! Per-mount lifecycle registry.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use astrid_core::storage_provider::{StorageMountId, StorageProviderAccessV1};
use nix::fcntl::{Flock, FlockArg};
use serde::{Deserialize, Serialize};

/// Non-secret lifecycle bookkeeping for one detached provider service.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct MountRecord {
    /// Kernel lease identity.
    pub mount_id: StorageMountId,
    /// Acting principal that requested the lease.
    pub requested_by: astrid_core::PrincipalId,
    /// Canonical native mountpoint.
    pub mountpoint: PathBuf,
    /// Access class fixed by the kernel lease.
    pub access: StorageProviderAccessV1,
    /// Whether this provider created and therefore owns the empty leaf directory.
    pub auto_created_mountpoint: bool,
    /// Private detached-service control socket.
    pub control_path: PathBuf,
}

/// Acquire the process-wide lifecycle lock used to serialize mount admission.
pub(crate) fn lock_registry() -> Result<Flock<File>> {
    let directory = registry_directory()?;
    astrid_core::platform_fs::ensure_private_directory(&directory)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(directory.join(".lock"))
        .context("open FUSE provider lifecycle lock")?;
    Flock::lock(file, FlockArg::LockExclusive)
        .map_err(|(_, error)| anyhow::anyhow!("lock FUSE provider lifecycle registry: {error}"))
}

/// Load all records in mount-id order.
pub(crate) fn load_registry() -> Result<BTreeMap<String, MountRecord>> {
    let directory = registry_directory()?;
    let mut records = BTreeMap::new();
    let entries = std::fs::read_dir(&directory);
    let entries = match entries {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(records),
        Err(error) => return Err(error).context("read FUSE provider registry"),
    };
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.extension().is_none_or(|extension| extension != "json") {
            continue;
        }
        let record: MountRecord = serde_json::from_slice(&std::fs::read(&path)?)
            .with_context(|| format!("decode FUSE provider record {}", path.display()))?;
        if path
            .file_stem()
            .is_none_or(|stem| stem.to_string_lossy() != record.mount_id.to_string())
        {
            anyhow::bail!(
                "FUSE provider registry filename does not match its mount identity: {}",
                path.display()
            );
        }
        let key = path_key(&record.mountpoint)?;
        if let Some(existing) = records.insert(key, record.clone()) {
            anyhow::bail!(
                "duplicate FUSE provider mountpoint {} in records {} and {}",
                record.mountpoint.display(),
                existing.mount_id,
                record.mount_id
            );
        }
    }
    Ok(records)
}

/// Atomically persist one private record.
pub(crate) fn write_record(record: &MountRecord) -> Result<()> {
    let directory = registry_directory()?;
    astrid_core::platform_fs::ensure_private_directory(&directory)?;
    let path = record_path(&record.mount_id)?;
    let mut bytes = serde_json::to_vec(record)?;
    bytes.push(b'\n');
    astrid_core::platform_fs::atomic_write_private_file(&path, &bytes)?;
    Ok(())
}

/// Remove one record by mount identity.
pub(crate) fn remove_record(mount_id: &StorageMountId) -> Result<()> {
    let path = record_path(mount_id)?;
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("remove FUSE provider record"),
    }
}

/// Resolve a selector against all records.
pub(crate) fn resolve_record(
    selector: &astrid_core::storage_provider::StorageMountSelectorV1,
) -> Result<MountRecord> {
    let registry = load_registry()?;
    match selector {
        astrid_core::storage_provider::StorageMountSelectorV1::MountId(mount_id) => registry
            .values()
            .find(|record| &record.mount_id == mount_id)
            .cloned()
            .with_context(|| format!("mount {mount_id} is not registered")),
        astrid_core::storage_provider::StorageMountSelectorV1::NativePath(path) => registry
            .get(&path_key(path)?)
            .cloned()
            .with_context(|| format!("mountpoint is not registered: {}", path.display())),
    }
}

/// Expected private control socket for a mount identity.
pub(crate) fn control_path(mount_id: &StorageMountId) -> Result<PathBuf> {
    Ok(astrid_core::dirs::AstridHome::resolve()?
        .run_dir()
        .join("providers")
        .join("fuse")
        .join(format!("{mount_id}.sock")))
}

fn registry_directory() -> Result<PathBuf> {
    Ok(astrid_core::dirs::AstridHome::resolve()?
        .run_dir()
        .join("providers")
        .join("fuse")
        .join("mounts"))
}

fn record_path(mount_id: &StorageMountId) -> Result<PathBuf> {
    Ok(registry_directory()?.join(format!("{mount_id}.json")))
}

fn path_key(path: &Path) -> Result<String> {
    path.to_str()
        .map(str::to_owned)
        .context("provider registry paths must be Unicode text")
}
