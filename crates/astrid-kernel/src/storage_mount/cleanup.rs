//! Resource-path cleanup for native storage-mount leases.

use std::io;
use std::path::Path;

use astrid_core::local_transport;
use astrid_core::storage_provider::StorageMountId;

use super::LEASE_MANIFEST_NAME;

/// The Windows private-file writer leaves its transaction lock as a named
/// artifact after the handle is released. Mount cleanup owns this one file;
/// every other unexpected entry must keep directory removal fail-closed.
#[cfg(windows)]
const PRIVATE_WRITE_TRANSACTION_LOCK_NAME: &str = ".astrid-private-write.lock";

/// Stage that failed while removing a native mount's private resources.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MountCleanupStage {
    Callback,
    Drain,
    Manifest,
    Directory,
}

impl std::fmt::Display for MountCleanupStage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Callback => "callback",
            Self::Drain => "drain",
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
    #[cfg(windows)]
    {
        // Any private-file manifest transaction has returned before this
        // function is called, and mapped cleanup has released its listener.
        // The Windows writer leaves this exact lock artifact behind. Do not
        // scan or recursively remove the directory: unknown entries must
        // remain a directory-stage failure for an explicit retry path.
        // Report lock errors at Manifest because this is manifest transaction
        // metadata, not an unknown directory entry cleanup may ignore.
        match std::fs::remove_file(resource_path.join(PRIVATE_WRITE_TRANSACTION_LOCK_NAME)) {
            Ok(()) => {},
            Err(error) if error.kind() == io::ErrorKind::NotFound => {},
            Err(error) => return Err((MountCleanupStage::Manifest, error)),
        }
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

#[cfg(all(test, windows))]
mod tests {
    use super::{MountCleanupStage, PRIVATE_WRITE_TRANSACTION_LOCK_NAME, cleanup_resource_paths};

    #[test]
    fn cleanup_removes_known_writer_lock_but_preserves_unknown_entries() {
        let temporary = tempfile::tempdir().expect("temporary cleanup root");
        let resource_path = temporary.path().join("mounts").join("resource");
        std::fs::create_dir_all(&resource_path).expect("resource directory");
        let callback_path = resource_path.join("control.endpoint");
        std::fs::write(resource_path.join("lease.json"), b"manifest").expect("lease manifest");
        std::fs::write(
            resource_path.join(PRIVATE_WRITE_TRANSACTION_LOCK_NAME),
            b"transaction lock",
        )
        .expect("writer lock artifact");
        let unrelated = resource_path.join("unexpected-entry");
        std::fs::write(&unrelated, b"must remain").expect("unrelated entry");

        let error = cleanup_resource_paths(&resource_path, &callback_path, None)
            .expect_err("unknown resource entries must keep cleanup fail-closed");
        assert_eq!(error.0, MountCleanupStage::Directory);
        assert!(
            !resource_path
                .join(PRIVATE_WRITE_TRANSACTION_LOCK_NAME)
                .exists(),
            "known writer lock should be removed before directory cleanup"
        );
        assert!(unrelated.exists(), "unknown entries must never be removed");
        assert!(resource_path.exists(), "directory remains for retry");

        std::fs::remove_file(&unrelated).expect("remove test residue");
        cleanup_resource_paths(&resource_path, &callback_path, None)
            .expect("cleanup should succeed once unknown entry is removed");
        assert!(!resource_path.exists());
    }
}

#[cfg(all(test, not(windows)))]
mod tests {
    use super::{MountCleanupStage, cleanup_resource_paths};

    #[test]
    fn cleanup_preserves_unknown_entries_and_retries() {
        let temporary = tempfile::tempdir().expect("temporary cleanup root");
        let resource_path = temporary.path().join("mounts").join("resource");
        std::fs::create_dir_all(&resource_path).expect("resource directory");
        let callback_path = resource_path.join("control.sock");
        std::fs::write(resource_path.join("lease.json"), b"manifest").expect("lease manifest");
        let unrelated = resource_path.join("unexpected-entry");
        std::fs::write(&unrelated, b"must remain").expect("unrelated entry");

        let error = cleanup_resource_paths(&resource_path, &callback_path, None)
            .expect_err("unknown resource entries must keep cleanup fail-closed");
        assert_eq!(error.0, MountCleanupStage::Directory);
        assert!(unrelated.exists(), "unknown entries must never be removed");
        assert!(resource_path.exists(), "directory remains for retry");

        std::fs::remove_file(&unrelated).expect("remove test residue");
        cleanup_resource_paths(&resource_path, &callback_path, None)
            .expect("cleanup should succeed once unknown entry is removed");
        assert!(!resource_path.exists());
    }
}
