//! Host-only namespace adapter for the authoritative system audit projection.

use astrid_storage::{
    KvBatchCondition, KvBatchMutation, KvBatchOutcome, KvEntryKey, KvMutationBatch, KvStore,
    ScopedKvStore, StorageResult,
};
use async_trait::async_trait;
use std::sync::Arc;

use crate::error::{AuditError, AuditResult};

/// Project audit namespaces into one kernel-owned system-control scope.
///
/// The runtime principal store is also used by capsule KV, so merely sharing
/// its backend is not sufficient: every audit key must be stamped into the
/// non-guest `system:control:audit` namespace. The adapter keeps the existing
/// logical namespaces as key prefixes, which makes the migration format stable
/// while ensuring principal home mounts cannot observe or mutate audit data.
pub(super) struct AuditSystemNamespace {
    scoped: ScopedKvStore,
}

impl AuditSystemNamespace {
    pub(super) fn new(store: Arc<dyn KvStore>) -> AuditResult<Self> {
        let scoped = ScopedKvStore::new(store, "system:control:audit")
            .map_err(|error| AuditError::StorageError(error.to_string()))?;
        Ok(Self { scoped })
    }

    fn key(namespace: &str, key: &str) -> String {
        format!("{namespace}:{key}")
    }

    fn prefix(namespace: &str, prefix: &str) -> String {
        format!("{namespace}:{prefix}")
    }

    fn strip_namespace(namespace: &str, key: &str) -> Option<String> {
        key.strip_prefix(&format!("{namespace}:"))
            .map(ToOwned::to_owned)
    }
}

#[async_trait]
impl KvStore for AuditSystemNamespace {
    fn supports_atomic_batch(&self) -> bool {
        self.scoped.backend().supports_atomic_batch()
    }

    async fn get(&self, namespace: &str, key: &str) -> StorageResult<Option<Vec<u8>>> {
        self.scoped.get(&Self::key(namespace, key)).await
    }

    async fn set(&self, namespace: &str, key: &str, value: Vec<u8>) -> StorageResult<()> {
        self.scoped.set(&Self::key(namespace, key), value).await
    }

    async fn delete(&self, namespace: &str, key: &str) -> StorageResult<bool> {
        self.scoped.delete(&Self::key(namespace, key)).await
    }

    async fn exists(&self, namespace: &str, key: &str) -> StorageResult<bool> {
        self.scoped.exists(&Self::key(namespace, key)).await
    }

    async fn list_keys(&self, namespace: &str) -> StorageResult<Vec<String>> {
        let prefix = format!("{namespace}:");
        Ok(self
            .scoped
            .list_keys_with_prefix(&prefix)
            .await?
            .into_iter()
            .filter_map(|key| key.strip_prefix(&prefix).map(ToOwned::to_owned))
            .collect())
    }

    async fn list_keys_with_prefix(
        &self,
        namespace: &str,
        prefix: &str,
    ) -> StorageResult<Vec<String>> {
        let full_prefix = Self::prefix(namespace, prefix);
        Ok(self
            .scoped
            .list_keys_with_prefix(&full_prefix)
            .await?
            .into_iter()
            .filter_map(|key| Self::strip_namespace(namespace, &key))
            .filter(|key| key.starts_with(prefix))
            .collect())
    }

    async fn list_keys_with_prefix_page(
        &self,
        namespace: &str,
        prefix: &str,
        after: Option<&str>,
        limit: usize,
    ) -> StorageResult<Vec<String>> {
        let full_prefix = Self::prefix(namespace, prefix);
        let full_after = after.map(|cursor| Self::key(namespace, cursor));
        Ok(self
            .scoped
            .backend()
            .list_keys_with_prefix_page(
                self.scoped.namespace(),
                &full_prefix,
                full_after.as_deref(),
                limit,
            )
            .await?
            .into_iter()
            .filter_map(|key| Self::strip_namespace(namespace, &key))
            .filter(|key| key.starts_with(prefix))
            .collect())
    }

    async fn compare_and_swap(
        &self,
        namespace: &str,
        key: &str,
        expected: Option<&[u8]>,
        new: Vec<u8>,
    ) -> StorageResult<bool> {
        self.scoped
            .compare_and_swap(&Self::key(namespace, key), expected, new)
            .await
    }

    async fn apply_batch(&self, batch: &KvMutationBatch) -> StorageResult<KvBatchOutcome> {
        // A logical audit batch contains the historical namespaces used by
        // the legacy adapter.  Collapse each pair into a key in the one
        // operator-only system-control scope before forwarding it to the
        // backend's atomic transaction primitive.
        let conditions = batch.conditions().iter().map(|condition| match condition {
            KvBatchCondition::ValueEquals { key, expected } => KvBatchCondition::ValueEquals {
                key: self.physical_key(key),
                expected: expected.clone(),
            },
        });
        let mutations = batch.mutations().iter().map(|mutation| match mutation {
            KvBatchMutation::Set { key, value } => KvBatchMutation::Set {
                key: self.physical_key(key),
                value: value.clone(),
            },
            KvBatchMutation::Delete { key } => KvBatchMutation::Delete {
                key: self.physical_key(key),
            },
        });
        let physical = KvMutationBatch::new(conditions, mutations)?;
        self.scoped.backend().apply_batch(&physical).await
    }

    async fn clear_namespace(&self, namespace: &str) -> StorageResult<u64> {
        self.scoped.clear_prefix(&format!("{namespace}:")).await
    }

    async fn clear_prefix(&self, namespace: &str, prefix: &str) -> StorageResult<u64> {
        self.scoped
            .clear_prefix(&Self::prefix(namespace, prefix))
            .await
    }

    async fn close(&self) -> StorageResult<()> {
        // The system projection shares RuntimePrincipalStore ownership. The
        // kernel closes that owner once through its primary KV handle; closing
        // this view must not race a second engine shutdown.
        Ok(())
    }
}

impl AuditSystemNamespace {
    fn physical_key(&self, key: &KvEntryKey) -> KvEntryKey {
        // `ScopedKvStore` has already validated the fixed namespace.  The
        // logical namespace is encoded into the key so the backend receives
        // one owner and cannot commit a cross-owner batch.
        KvEntryKey::new(
            self.scoped.namespace(),
            Self::key(key.namespace(), key.key()),
        )
        .expect("validated audit namespace key")
    }
}
