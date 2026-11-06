//! Scoped legacy readers must never convert the operator's only source copy.

use std::path::Path;
use std::sync::Arc;

use super::native_io::PrivateDirectory;
use crate::{KvStore, StorageError, StorageResult, SurrealKvStore};

mod store;
use store::SnapshotStore;

/// Original-source protection retained during a snapshot operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LegacySourceKind {
    /// No files existed at capture; retirement must use atomic empty removal.
    EmptyDirectory,
    /// A shared original LOCK excludes cooperative legacy writers.
    LockedDatabase,
}

// Even an aborted cleanup future must retain files until closure is proven.
struct SnapshotWorkspace(Option<std::path::PathBuf>);

impl SnapshotWorkspace {
    fn create() -> StorageResult<Self> {
        let path =
            std::env::temp_dir().join(format!("astrid-legacy-snapshot-{}", uuid::Uuid::new_v4()));
        // The platform primitive creates exclusively with private access at
        // namespace creation. An existing name is never adopted or removed.
        astrid_core::platform_fs::create_private_directory(&path).map_err(snapshot_error)?;
        Ok(Self(Some(path)))
    }

    fn remove(mut self) -> StorageResult<()> {
        if let Some(path) = self.0.as_ref() {
            astrid_core::dirs::retire_legacy_source_tree(path).map_err(snapshot_error)?;
            self.0 = None;
        }
        Ok(())
    }
}

impl Drop for SnapshotWorkspace {
    fn drop(&mut self) {
        if let Some(retained) = self.0.as_ref() {
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
/// The original source is never opened by the legacy engine or removed here.
pub async fn with_legacy_kv_snapshot<T>(
    source: &Path,
    operation: impl AsyncFnOnce(Arc<dyn KvStore>, LegacySourceKind) -> T,
) -> StorageResult<T> {
    let source = source.to_path_buf();
    // Copying, fsync, and upstream format conversion perform blocking I/O.
    // Keep them off the async worker while retaining the source lock in the
    // returned owner through the operation and proven reader shutdown.
    let (mut reader, store, source_lock) =
        tokio::task::spawn_blocking(move || prepare_snapshot(&source))
            .await
            .map_err(snapshot_error)??;
    let kind = if source_lock.is_some() {
        LegacySourceKind::LockedDatabase
    } else {
        LegacySourceKind::EmptyDirectory
    };
    let result = operation(store, kind).await;
    reader.close().await?;
    drop(source_lock);
    Ok(result)
}

fn prepare_snapshot(
    source: &Path,
) -> StorageResult<(SnapshotReader, Arc<SnapshotStore>, Option<std::fs::File>)> {
    let source = PrivateDirectory::open(source)?;
    let source_lock = lock_source(&source)?;
    let workspace = SnapshotWorkspace::create()?;
    let copy = (|| {
        let path = workspace
            .0
            .as_ref()
            .ok_or_else(|| snapshot_error("missing workspace"))?
            .join("database");
        astrid_core::platform_fs::ensure_private_directory(&path).map_err(snapshot_error)?;
        let destination = PrivateDirectory::open(&path)?;
        super::migrations::copy_legacy_tree(&source, &destination)?;
        drop(destination);
        Ok::<_, StorageError>(path)
    })();
    let path = match copy {
        Ok(path) => path,
        Err(error) => {
            // No engine was opened: a failed copy has no worker lifetime to
            // retain. Remove only this exclusively created private workspace.
            workspace.remove()?;
            return Err(error);
        },
    };
    let store = Arc::new(SnapshotStore::new(SurrealKvStore::open(&path)?));
    let reader = SnapshotReader {
        store: Some(Arc::clone(&store)),
        workspace: Some(workspace),
    };
    Ok((reader, store, source_lock))
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
