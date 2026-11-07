//! Scoped legacy readers must never convert the operator's only source copy.

use std::path::Path;
use std::sync::Arc;

use super::native_io::CapturedDirectory;
use crate::{KvStore, StorageError, StorageResult};

mod intent;
mod owner;
mod retire;
mod store;
use store::SnapshotStore;
#[cfg(windows)]
mod source_lock;

pub use intent::LegacyRetirementIntent;
pub use owner::LegacySource;
pub use retire::{
    LegacyRetirementStage, capture_authorized_legacy_retirement_stage, resume_legacy_retirement,
    resume_staged_legacy_retirement,
};

/// Original-source protection retained during a snapshot operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LegacySourceKind {
    /// No files existed at capture; retirement must use atomic empty removal.
    EmptyDirectory,
    /// A shared original LOCK excludes cooperative legacy writers.
    LockedDatabase,
}

// Even an aborted cleanup future must retain files until closure is proven.
struct SnapshotWorkspace(Option<CapturedDirectory>);

impl SnapshotWorkspace {
    fn create() -> StorageResult<Self> {
        let path =
            std::env::temp_dir().join(format!("astrid-legacy-snapshot-{}", uuid::Uuid::new_v4()));
        // The platform primitive creates exclusively with private access at
        // namespace creation. An existing name is never adopted or removed.
        astrid_core::platform_fs::create_private_directory(&path).map_err(snapshot_error)?;
        astrid_core::platform_fs::create_private_directory(&path.join("database"))
            .map_err(snapshot_error)?;
        Ok(Self(Some(CapturedDirectory::open(&path)?)))
    }

    fn remove(mut self) -> StorageResult<()> {
        if let Some(directory) = self.0.take() {
            let path = directory.path().to_path_buf();
            directory.remove().inspect_err(|error| {
                tracing::warn!(%error, path = %path.display(), "retain unremoved legacy snapshot");
            })?;
        }
        Ok(())
    }
}

impl Drop for SnapshotWorkspace {
    fn drop(&mut self) {
        if let Some(retained) = self.0.as_ref() {
            tracing::warn!(path = %retained.path().display(), "retain unclosed legacy snapshot");
        }
    }
}

struct SnapshotReader {
    store: Option<Arc<SnapshotStore>>,
    workspace: Option<SnapshotWorkspace>,
}

impl SnapshotReader {
    fn spawn_cleanup(
        &mut self,
    ) -> StorageResult<Option<tokio::task::JoinHandle<StorageResult<()>>>> {
        let runtime = tokio::runtime::Handle::try_current().map_err(snapshot_error)?;
        let (Some(store), Some(workspace)) = (self.store.take(), self.workspace.take()) else {
            return Ok(None);
        };
        Ok(Some(runtime.spawn(async move {
            // A caller dropping its wait must not cancel the engine close.
            // Upstream marks a tree closed before all shutdown awaits finish;
            // retrying an interrupted close is not proof that its workers ended.
            if let Err(error) = store.close_reader().await {
                tracing::error!(%error, "cannot close legacy snapshot");
                return Err(error);
            }
            drop(store);
            tokio::task::spawn_blocking(move || workspace.remove())
                .await
                .map_err(snapshot_error)?
                .inspect_err(|error| {
                    tracing::error!(%error, "remove closed legacy snapshot");
                })
        })))
    }

    async fn close(&mut self) -> StorageResult<()> {
        if let Some(cleanup) = self.spawn_cleanup()? {
            cleanup.await.map_err(snapshot_error)??;
        }
        Ok(())
    }
}

impl Drop for SnapshotReader {
    fn drop(&mut self) {
        // Dropping the join handle detaches cleanup; it does not abort it.
        // Without a runtime SnapshotWorkspace retains the private copy.
        if let Err(error) = self.spawn_cleanup() {
            tracing::error!(%error, "cannot schedule legacy snapshot cleanup");
        }
    }
}

/// Run an operation on a private copy of a quiescent legacy database.
///
/// Only the copy is opened, since newer legacy readers may convert its format.
/// Uses the same no-follow file-copy boundary as principal-store migration.
/// The operation receives raw legacy namespaces, not a native owner projection.
/// On return (including an operation's error value), the reader is closed before
/// its uniquely owned workspace is removed. Escaped store handles are closed.
/// Cancellation schedules that cleanup on the current runtime; if the runtime
/// is unavailable or closing fails, the copy is retained and its path logged.
/// A shared lock on the original database excludes cooperative legacy writers
/// throughout copying and reading, without rewriting its lock file. A truly
/// empty source needs no lock; a nonempty source without a regular LOCK fails.
///
/// # Errors
///
/// Returns an error if private copying, opening, closing, or cleanup fails.
/// The original source is never opened by the legacy engine. Retirement is a
/// separate owner method under a persisted intent.
pub async fn with_legacy_kv_snapshot<T>(
    source: &Path,
    operation: impl AsyncFnOnce(Arc<dyn KvStore>, LegacySource) -> T,
) -> StorageResult<T> {
    let source = source.to_path_buf();
    // Copying, fsync, and upstream format conversion perform blocking I/O.
    // Keep them off the async worker while retaining the source lock in the
    // returned owner through the operation and proven reader shutdown.
    let (mut reader, store, owner) =
        tokio::task::spawn_blocking(move || owner::prepare_snapshot(&source))
            .await
            .map_err(snapshot_error)??;
    let result = operation(store, owner).await;
    reader.close().await?;
    Ok(result)
}

pub(super) fn snapshot_error(error: impl std::fmt::Display) -> StorageError {
    StorageError::Connection(format!("legacy snapshot: {error}"))
}

#[cfg(test)]
mod retire_tests;
#[cfg(test)]
mod test_directory;
#[cfg(test)]
mod tests;

#[cfg(all(test, windows))]
mod windows_lock_tests;
