//! Resource-path cleanup for native storage-mount leases.

use std::io;
use std::path::Path;

use astrid_core::local_transport;
use astrid_core::storage_provider::StorageMountId;

use super::LEASE_MANIFEST_NAME;

/// Stage that failed while removing a native mount's private resources.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MountCleanupStage {
    Callback,
    Manifest,
    Directory,
}

impl std::fmt::Display for MountCleanupStage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Callback => "callback",
            Self::Manifest => "manifest",
            Self::Directory => "directory",
        })
    }
}

/// Diagnostic cleanup failure for drain and revoke.
#[derive(Debug)]
pub(crate) struct MountCleanupError {
    pub(crate) mount_id: Option<StorageMountId>,
    pub(crate) stage: MountCleanupStage,
    pub(crate) source: io::Error,
}

impl std::fmt::Display for MountCleanupError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.mount_id {
            Some(mount_id) => write!(
                formatter,
                "storage mount {mount_id} cleanup failed at {}: {}",
                self.stage, self.source
            ),
            None => write!(
                formatter,
                "storage mount cleanup failed at {}: {}",
                self.stage, self.source
            ),
        }
    }
}

pub(super) fn cleanup_resource_paths(
    resource_path: &Path,
    callback_path: &Path,
    fault: Option<MountCleanupStage>,
) -> Result<(), (MountCleanupStage, io::Error)> {
    if fault == Some(MountCleanupStage::Callback) {
        return Err((
            MountCleanupStage::Callback,
            io::Error::other("injected callback cleanup failure"),
        ));
    }
    match local_transport::remove_endpoint(callback_path) {
        Ok(()) => {},
        Err(error) if error.kind() == io::ErrorKind::NotFound => {},
        Err(error) => return Err((MountCleanupStage::Callback, error)),
    }
    if fault == Some(MountCleanupStage::Manifest) {
        return Err((
            MountCleanupStage::Manifest,
            io::Error::other("injected manifest cleanup failure"),
        ));
    }
    match std::fs::remove_file(resource_path.join(LEASE_MANIFEST_NAME)) {
        Ok(()) => {},
        Err(error) if error.kind() == io::ErrorKind::NotFound => {},
        Err(error) => return Err((MountCleanupStage::Manifest, error)),
    }
    if fault == Some(MountCleanupStage::Directory) {
        return Err((
            MountCleanupStage::Directory,
            io::Error::other("injected directory cleanup failure"),
        ));
    }
    match std::fs::remove_dir(resource_path) {
        Ok(()) => {},
        Err(error) if error.kind() == io::ErrorKind::NotFound => {},
        Err(error) => return Err((MountCleanupStage::Directory, error)),
    }
    if let Some(root) = resource_path.parent() {
        let _ = std::fs::remove_dir(root);
    }
    Ok(())
}

pub(super) fn cleanup_error(
    mount_id: Option<StorageMountId>,
    stage: MountCleanupStage,
    source: io::Error,
) -> MountCleanupError {
    MountCleanupError {
        mount_id,
        stage,
        source,
    }
}
