//! Scoped legacy readers must never convert the operator's only source copy.

use std::path::Path;
use std::sync::Arc;

use super::native_io::PrivateDirectory;
use crate::{KvStore, StorageError, StorageResult, SurrealKvStore};

mod store;
use store::SnapshotStore;

// Even an aborted cleanup future must retain files until closure is proven.
struct SnapshotWorkspace(Option<tempfile::TempDir>);

impl SnapshotWorkspace {
    fn remove(mut self) -> StorageResult<()> {
        if let Some(workspace) = self.0.take() {
            workspace.close().map_err(snapshot_error)?;
        }
        Ok(())
    }
}

impl Drop for SnapshotWorkspace {
    fn drop(&mut self) {
        if let Some(workspace) = self.0.take() {
            let retained = workspace.keep();
            tracing::warn!(path = %retained.display(), "retain unclosed legacy snapshot");
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
            workspace.remove().inspect_err(|error| {
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
/// The original source is never opened by the legacy engine or removed here.
pub async fn with_legacy_kv_snapshot<T>(
    source: &Path,
    operation: impl AsyncFnOnce(Arc<dyn KvStore>) -> T,
) -> StorageResult<T> {
    let source = PrivateDirectory::open(source)?;
    let _source_lock = lock_source(&source)?;
    let workspace = tempfile::Builder::new()
        .prefix("astrid-legacy-snapshot-")
        .tempdir()
        .map_err(snapshot_error)?;
    astrid_core::platform_fs::ensure_private_directory(workspace.path()).map_err(snapshot_error)?;
    let path = workspace.path().join("database");
    astrid_core::platform_fs::ensure_private_directory(&path).map_err(snapshot_error)?;
    let destination = PrivateDirectory::open(&path)?;
    super::migrations::copy_legacy_tree(&source, &destination)?;
    drop(destination);
    let store = Arc::new(SnapshotStore::new(SurrealKvStore::open(&path)?));
    let mut reader = SnapshotReader {
        store: Some(Arc::clone(&store)),
        workspace: Some(SnapshotWorkspace(Some(workspace))),
    };
    let result = operation(store).await;
    reader.close().await?;
    Ok(result)
}

fn lock_source(source: &PrivateDirectory) -> StorageResult<Option<std::fs::File>> {
    if source.entries()?.is_empty() {
        return Ok(None);
    }
    // Open read-only and no-follow: an engine opener truncates LOCK before
    // acquiring it. A shared lock also permits the copy's separate read handle
    // on Windows, where exclusive byte-range locks prevent even reads.
    let lock = source.open_file(Path::new("LOCK"))?;
    lock.try_lock_shared().map_err(snapshot_error)?;
    Ok(Some(lock))
}

fn snapshot_error(error: impl std::fmt::Display) -> StorageError {
    StorageError::Connection(format!("legacy snapshot: {error}"))
}

#[cfg(test)]
mod tests;
