//! A snapshot owns its engine; escaped handles cannot outlive its scope.

use async_trait::async_trait;
use tokio::sync::{RwLock, RwLockReadGuard};

use crate::{KvStore, StorageError, StorageResult, SurrealKvStore};

pub(super) struct SnapshotStore(RwLock<Option<SurrealKvStore>>);

impl SnapshotStore {
    pub(super) fn new(store: SurrealKvStore) -> Self {
        Self(RwLock::new(Some(store)))
    }

    async fn read(&self) -> StorageResult<RwLockReadGuard<'_, SurrealKvStore>> {
        RwLockReadGuard::try_map(self.0.read().await, Option::as_ref)
            .map_err(|_| StorageError::Internal("legacy snapshot is closed".to_owned()))
    }

    pub(super) async fn close_reader(&self) -> StorageResult<()> {
        // Drain concurrent reads before closing. Removing the engine from the
        // shared wrapper also releases its memory and file handles when an
        // operation returns or spawns a task retaining an Arc to this wrapper.
        let mut inner = self.0.write().await;
        if let Some(store) = inner.as_ref() {
            store.close().await?;
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

    #[tokio::test]
    async fn cancelled_close_wait_still_drains_reads_before_cleanup() {
        let workspace = tempfile::tempdir().unwrap();
        let path = workspace.path().to_path_buf();
        let store = Arc::new(SnapshotStore::new(
            SurrealKvStore::open(path.join("database")).unwrap(),
        ));
        let mut reader = SnapshotReader {
            store: Some(Arc::clone(&store)),
            workspace: Some(SnapshotWorkspace(Some(
                crate::principal_state::native_io::CapturedDirectory::open(&workspace.keep())
                    .unwrap(),
            ))),
        };
        let reading = store.read().await.unwrap();
        let mut closing = Box::pin(reader.close());
        tokio::select! {
            result = &mut closing => panic!("close must drain active reads: {result:?}"),
            () = tokio::task::yield_now() => {},
        }
        assert!(path.exists());
        // End the caller's wait while the independently owned cleanup is stuck
        // behind a real read guard. It must finish after that reader leaves.
        drop(closing);
        drop(reading);
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while super::super::tests::workspace_name_present(&path) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(store.get("test", "key").await.is_err());
    }
}
