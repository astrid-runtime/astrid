//! A snapshot owns its engine; escaped handles cannot outlive its scope.

use async_trait::async_trait;
use tokio::sync::{RwLock, RwLockReadGuard};

use crate::{KvStore, StorageError, StorageResult, SurrealKvStore};

struct OpenSnapshot {
    store: SurrealKvStore,
    // Keep the source fence with its engine, including failed/unscheduled
    // cleanup and escaped readers. Successful close drains reads, then drops
    // both resources together; a closed escaped wrapper retains neither.
    _source_lock: Option<std::fs::File>,
}

pub(super) struct SnapshotStore(RwLock<Option<OpenSnapshot>>);

impl SnapshotStore {
    pub(super) fn new(store: SurrealKvStore, source_lock: Option<std::fs::File>) -> Self {
        Self(RwLock::new(Some(OpenSnapshot {
            store,
            _source_lock: source_lock,
        })))
    }

    async fn read(&self) -> StorageResult<RwLockReadGuard<'_, SurrealKvStore>> {
        RwLockReadGuard::try_map(self.0.read().await, |inner| {
            inner.as_ref().map(|snapshot| &snapshot.store)
        })
        .map_err(|_| StorageError::Internal("legacy snapshot is closed".to_owned()))
    }

    pub(super) async fn close_reader(&self) -> StorageResult<()> {
        // Drain concurrent reads before closing. Removing the engine from the
        // shared wrapper also releases its memory and file handles when an
        // operation returns or spawns a task retaining an Arc to this wrapper.
        let mut inner = self.0.write().await;
        if let Some(snapshot) = inner.as_ref() {
            snapshot.store.close().await?;
        }
        *inner = None;
        Ok(())
    }

    fn frozen() -> StorageError {
        StorageError::Internal("legacy snapshot is read-only".to_owned())
    }
}

#[async_trait]
impl KvStore for SnapshotStore {
    async fn get(&self, namespace: &str, key: &str) -> StorageResult<Option<Vec<u8>>> {
        self.read().await?.get(namespace, key).await
    }

    async fn exists(&self, namespace: &str, key: &str) -> StorageResult<bool> {
        self.read().await?.exists(namespace, key).await
    }

    async fn list_keys(&self, namespace: &str) -> StorageResult<Vec<String>> {
        self.read().await?.list_keys(namespace).await
    }

    async fn list_keys_with_prefix(
        &self,
        namespace: &str,
        prefix: &str,
    ) -> StorageResult<Vec<String>> {
        self.read()
            .await?
            .list_keys_with_prefix(namespace, prefix)
            .await
    }

    async fn list_keys_with_prefix_page(
        &self,
        namespace: &str,
        prefix: &str,
        after: Option<&str>,
        limit: usize,
    ) -> StorageResult<Vec<String>> {
        self.read()
            .await?
            .list_keys_with_prefix_page(namespace, prefix, after, limit)
            .await
    }

    async fn set(&self, _namespace: &str, _key: &str, _value: Vec<u8>) -> StorageResult<()> {
        Err(Self::frozen())
    }

    async fn delete(&self, _namespace: &str, _key: &str) -> StorageResult<bool> {
        Err(Self::frozen())
    }

    async fn compare_and_swap(
        &self,
        _namespace: &str,
        _key: &str,
        _expected: Option<&[u8]>,
        _new: Vec<u8>,
    ) -> StorageResult<bool> {
        Err(Self::frozen())
    }

    async fn clear_namespace(&self, _namespace: &str) -> StorageResult<u64> {
        Err(Self::frozen())
    }

    async fn clear_prefix(&self, _namespace: &str, _prefix: &str) -> StorageResult<u64> {
        Err(Self::frozen())
    }

    async fn close(&self) -> StorageResult<()> {
        // Only the scoped owner may close. A consumer must not start an engine
        // shutdown it can cancel before the workspace owner observes completion.
        Err(Self::frozen())
    }
}

#[cfg(test)]
mod tests {
    use super::super::{SnapshotReader, SnapshotWorkspace};
    use super::*;
    use std::sync::Arc;

    fn reader_with_source_fence(
        source: &std::path::Path,
    ) -> (SnapshotReader, Arc<SnapshotStore>, std::path::PathBuf) {
        let workspace = tempfile::tempdir().unwrap();
        let path = workspace.path().to_path_buf();
        let source_lock = std::fs::File::open(source).unwrap();
        source_lock.try_lock_shared().unwrap();
        let store = Arc::new(SnapshotStore::new(
            SurrealKvStore::open(path.join("database")).unwrap(),
            Some(source_lock),
        ));
        let reader = SnapshotReader {
            store: Some(Arc::clone(&store)),
            workspace: Some(SnapshotWorkspace(Some(
                crate::principal_state::native_io::CapturedDirectory::open(&workspace.keep())
                    .unwrap(),
            ))),
        };
        (reader, store, path)
    }

    #[tokio::test]
    async fn cancellation_retains_source_fence_until_active_reads_drain() {
        for cancel_close_wait in [false, true] {
            let source = tempfile::NamedTempFile::new().unwrap();
            let (mut reader, store, path) = reader_with_source_fence(source.path());
            let reading = store.read().await.unwrap();
            if cancel_close_wait {
                let mut closing = Box::pin(reader.close());
                tokio::select! {
                    result = &mut closing => panic!("close must drain active reads: {result:?}"),
                    () = tokio::task::yield_now() => {},
                }
                assert!(path.exists());
                // End the caller's wait while the independently owned cleanup is stuck
                // behind a real read guard. It must finish after that reader leaves.
                drop(closing);
            }
            // Exercise both dropping the scoped owner itself and abandoning its
            // already-started close wait. The read guard blocks the real close.
            drop(reader);
            tokio::task::yield_now().await;
            assert!(
                matches!(
                    source.as_file().try_lock(),
                    Err(std::fs::TryLockError::WouldBlock)
                ),
                "cancellation released the source fence before reader closure"
            );
            drop(reading);
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                while super::super::tests::workspace_name_present(&path) {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            assert!(store.get("test", "key").await.is_err());
            source.as_file().try_lock().unwrap();
            source.as_file().unlock().unwrap();
        }
    }

    #[tokio::test]
    async fn unscheduled_cleanup_keeps_source_fence_with_live_snapshot_reader() {
        let source = tempfile::NamedTempFile::new().unwrap();
        let (reader, store, path) = reader_with_source_fence(source.path());
        let reading = store.read().await.unwrap();
        // This thread has no Tokio runtime: scheduling cleanup must fail. The
        // escaped live engine and its read guard still own the source fence.
        std::thread::spawn(move || drop(reader)).join().unwrap();
        assert!(path.exists());
        assert!(matches!(
            source.as_file().try_lock(),
            Err(std::fs::TryLockError::WouldBlock)
        ));
        drop(reading);
        store.close_reader().await.unwrap();
        assert!(store.get("test", "key").await.is_err());
        source.as_file().try_lock().unwrap();
        source.as_file().unlock().unwrap();
        crate::principal_state::native_io::CapturedDirectory::open(&path)
            .unwrap()
            .remove()
            .unwrap();
        assert!(!path.exists());
    }
}
