//! Read-only adapter over a layout-1 audit Surreal tree.
//!
//! MOVE may only observe source bytes. The boot singleton is still the
//! process freeze; this adapter refuses writes if a caller aims the source
//! at dest APIs.

use std::sync::Arc;

use async_trait::async_trait;

use astrid_storage::{KvBatchOutcome, KvMutationBatch, KvStore, StorageError, StorageResult};

const FROZEN: &str = "legacy audit source is frozen during MOVE";

pub(super) struct FrozenKvStore {
    inner: Arc<dyn KvStore>,
}

impl FrozenKvStore {
    pub(super) fn new(inner: Arc<dyn KvStore>) -> Self {
        Self { inner }
    }

    fn frozen() -> StorageError {
        StorageError::Internal(FROZEN.to_owned())
    }
}

#[async_trait]
impl KvStore for FrozenKvStore {
    async fn get(&self, namespace: &str, key: &str) -> StorageResult<Option<Vec<u8>>> {
        self.inner.get(namespace, key).await
    }

    async fn set(&self, _namespace: &str, _key: &str, _value: Vec<u8>) -> StorageResult<()> {
        Err(Self::frozen())
    }

    async fn delete(&self, _namespace: &str, _key: &str) -> StorageResult<bool> {
        Err(Self::frozen())
    }

    async fn exists(&self, namespace: &str, key: &str) -> StorageResult<bool> {
        self.inner.exists(namespace, key).await
    }

    async fn list_keys(&self, namespace: &str) -> StorageResult<Vec<String>> {
        self.inner.list_keys(namespace).await
    }

    async fn list_keys_with_prefix(
        &self,
        namespace: &str,
        prefix: &str,
    ) -> StorageResult<Vec<String>> {
        self.inner.list_keys_with_prefix(namespace, prefix).await
    }

    async fn list_keys_with_prefix_page(
        &self,
        namespace: &str,
        prefix: &str,
        after: Option<&str>,
        limit: usize,
    ) -> StorageResult<Vec<String>> {
        self.inner
            .list_keys_with_prefix_page(namespace, prefix, after, limit)
            .await
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

    async fn apply_batch(&self, _batch: &KvMutationBatch) -> StorageResult<KvBatchOutcome> {
        Err(Self::frozen())
    }

    fn supports_atomic_batch(&self) -> bool {
        false
    }

    async fn clear_namespace(&self, _namespace: &str) -> StorageResult<u64> {
        Err(Self::frozen())
    }

    async fn clear_prefix(&self, _namespace: &str, _prefix: &str) -> StorageResult<u64> {
        Err(Self::frozen())
    }

    async fn close(&self) -> StorageResult<()> {
        self.inner.close().await
    }
}
