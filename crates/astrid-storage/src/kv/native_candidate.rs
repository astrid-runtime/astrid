//! Native policy publication fence shared by live guest mutations and commit.

use super::{KvBatchOutcome, KvMutationBatch, KvStore};
use crate::StorageResult;
use async_trait::async_trait;
use std::sync::Arc;

/// Serializes policy mutations (including blobs/keys) and capture/commit.
#[derive(Default)]
pub struct NativePolicyFence {
    mutex: Arc<tokio::sync::Mutex<()>>,
}

impl NativePolicyFence {
    /// Hold through snapshot or policy comparison and pair publication.
    pub async fn lock(&self) -> tokio::sync::OwnedMutexGuard<()> {
        Arc::clone(&self.mutex).lock_owned().await
    }

    fn affects(namespace: &str, key: Option<&str>) -> bool {
        namespace.ends_with(":capsule:codewall-enforcer")
            && key.is_none_or(|key| key.starts_with("policy/"))
            || namespace.ends_with(":control:env:codewall-enforcer")
            || namespace.ends_with(":control:env:codewall-protocol")
    }
}

/// Live adapter; all destructive forms, including batch and clear, join the fence.
pub struct NativePolicyKv {
    inner: Arc<dyn KvStore>,
    fence: Arc<NativePolicyFence>,
    frozen: bool,
}

impl NativePolicyKv {
    /// Wrap the authoritative backend once at runtime-store construction.
    #[must_use]
    pub fn new(inner: Arc<dyn KvStore>, fence: Arc<NativePolicyFence>) -> Self {
        Self {
            inner,
            fence,
            frozen: false,
        }
    }

    /// Protect the immutable policy in a detached candidate's guest KV view.
    #[must_use]
    pub fn detached(inner: Arc<dyn KvStore>) -> Self {
        Self {
            inner,
            fence: Arc::new(NativePolicyFence::default()),
            frozen: true,
        }
    }

    async fn guard(
        &self,
        ns: &str,
        key: Option<&str>,
    ) -> StorageResult<Option<tokio::sync::OwnedMutexGuard<()>>> {
        if NativePolicyFence::affects(ns, key) {
            if self.frozen {
                return Err(crate::StorageError::InvalidKey(
                    "native candidate policy is immutable".into(),
                ));
            }
            Ok(Some(self.fence.lock().await))
        } else {
            Ok(None)
        }
    }
}

#[async_trait]
impl KvStore for NativePolicyKv {
    async fn get(&self, ns: &str, key: &str) -> StorageResult<Option<Vec<u8>>> {
        self.inner.get(ns, key).await
    }
    async fn exists(&self, ns: &str, key: &str) -> StorageResult<bool> {
        self.inner.exists(ns, key).await
    }
    async fn list_keys(&self, ns: &str) -> StorageResult<Vec<String>> {
        self.inner.list_keys(ns).await
    }
    async fn list_keys_with_prefix(&self, ns: &str, prefix: &str) -> StorageResult<Vec<String>> {
        self.inner.list_keys_with_prefix(ns, prefix).await
    }
    async fn list_keys_with_prefix_page(
        &self,
        ns: &str,
        prefix: &str,
        after: Option<&str>,
        limit: usize,
    ) -> StorageResult<Vec<String>> {
        self.inner
            .list_keys_with_prefix_page(ns, prefix, after, limit)
            .await
    }
    async fn set(&self, ns: &str, key: &str, value: Vec<u8>) -> StorageResult<()> {
        let _guard = self.guard(ns, Some(key)).await?;
        self.inner.set(ns, key, value).await
    }
    async fn delete(&self, ns: &str, key: &str) -> StorageResult<bool> {
        let _guard = self.guard(ns, Some(key)).await?;
        self.inner.delete(ns, key).await
    }
    async fn compare_and_swap(
        &self,
        ns: &str,
        key: &str,
        expected: Option<&[u8]>,
        new: Vec<u8>,
    ) -> StorageResult<bool> {
        let _guard = self.guard(ns, Some(key)).await?;
        self.inner.compare_and_swap(ns, key, expected, new).await
    }
    async fn clear_namespace(&self, ns: &str) -> StorageResult<u64> {
        let _guard = self.guard(ns, None).await?;
        self.inner.clear_namespace(ns).await
    }
    async fn clear_prefix(&self, ns: &str, prefix: &str) -> StorageResult<u64> {
        let overlaps_policy = ns.ends_with(":capsule:codewall-enforcer")
            && ("policy/".starts_with(prefix) || prefix.starts_with("policy/"));
        let _guard = if overlaps_policy || NativePolicyFence::affects(ns, Some(prefix)) {
            self.guard(ns, None).await?
        } else {
            None
        };
        self.inner.clear_prefix(ns, prefix).await
    }
    fn supports_atomic_batch(&self) -> bool {
        self.inner.supports_atomic_batch()
    }
    async fn apply_batch(&self, batch: &KvMutationBatch) -> StorageResult<KvBatchOutcome> {
        let needs_fence = batch.mutations().iter().any(|mutation| {
            let key = mutation.key();
            NativePolicyFence::affects(key.namespace(), Some(key.key()))
        });
        if needs_fence && self.frozen {
            return Err(crate::StorageError::InvalidKey(
                "native candidate policy is immutable".into(),
            ));
        }
        let _guard = if needs_fence {
            Some(self.fence.lock().await)
        } else {
            None
        };
        self.inner.apply_batch(batch).await
    }
    async fn close(&self) -> StorageResult<()> {
        self.inner.close().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn native_candidate_policy_snapshot_not_torn() {
        let fence = Arc::new(NativePolicyFence::default());
        let backend = Arc::new(NativePolicyKv::new(
            Arc::new(super::super::MemoryKvStore::new()),
            Arc::clone(&fence),
        ));
        let ns = "alice:capsule:codewall-enforcer";
        backend
            .set(ns, "policy/active", b"old".to_vec())
            .await
            .unwrap();
        let guard = fence.lock().await;
        let writer = Arc::clone(&backend);
        let task =
            tokio::spawn(async move { writer.set(ns, "policy/active", b"new".to_vec()).await });
        tokio::task::yield_now().await;
        assert!(!task.is_finished());
        assert_eq!(
            backend.get(ns, "policy/active").await.unwrap(),
            Some(b"old".to_vec())
        );
        // Unrelated protocol custody remains writable under the policy fence.
        backend
            .set("alice:capsule:codewall-protocol", "outbox/1", vec![1])
            .await
            .unwrap();
        drop(guard);
        task.await.unwrap().unwrap();
        assert_eq!(
            backend.get(ns, "policy/active").await.unwrap(),
            Some(b"new".to_vec())
        );
    }

    #[tokio::test]
    async fn native_candidate_shared_and_principal_text_writes_join_fence() {
        let fence = Arc::new(NativePolicyFence::default());
        let backend = Arc::new(NativePolicyKv::new(
            Arc::new(super::super::MemoryKvStore::new()),
            Arc::clone(&fence),
        ));
        for ns in [
            "system:control:env:codewall-enforcer",
            "principal-uid:control:env:codewall-protocol",
        ] {
            for operation in 0..6 {
                let guard = fence.lock().await;
                let writer = Arc::clone(&backend);
                let task = tokio::spawn(async move {
                    match operation {
                        0 => writer.set(ns, "env/key", vec![1]).await,
                        1 => writer.delete(ns, "env/key").await.map(|_| ()),
                        2 => writer
                            .compare_and_swap(ns, "env/key", None, vec![1])
                            .await
                            .map(|_| ()),
                        3 => writer.clear_namespace(ns).await.map(|_| ()),
                        4 => writer.clear_prefix(ns, "env/").await.map(|_| ()),
                        _ => {
                            let batch = super::super::KvMutationBatch::new(
                                [],
                                [super::super::KvBatchMutation::Delete {
                                    key: super::super::KvEntryKey::new(ns, "env/key").unwrap(),
                                }],
                            )
                            .unwrap();
                            writer.apply_batch(&batch).await.map(|_| ())
                        },
                    }
                });
                tokio::task::yield_now().await;
                assert!(
                    !task.is_finished(),
                    "unfenced environment mutation {operation}"
                );
                drop(guard);
                task.await.unwrap().unwrap();
            }
        }
    }

    #[tokio::test]
    async fn native_candidate_frozen_policy_rejects_all_mutation_forms() {
        let backend = Arc::new(super::super::MemoryKvStore::new());
        let ns = "alice:capsule:codewall-enforcer";
        backend.set(ns, "policy/active", vec![1]).await.unwrap();
        backend.set(ns, "audit/outbox/1", vec![1]).await.unwrap();
        let frozen = NativePolicyKv::detached(backend.clone());
        assert!(frozen.set(ns, "policy/active", vec![2]).await.is_err());
        assert!(frozen.delete(ns, "policy/active").await.is_err());
        assert!(
            frozen
                .compare_and_swap(ns, "policy/active", Some(&[1]), vec![2])
                .await
                .is_err()
        );
        assert!(frozen.clear_namespace(ns).await.is_err());
        assert!(frozen.clear_prefix(ns, "pol").await.is_err());
        let batch = super::super::KvMutationBatch::new(
            [],
            [super::super::KvBatchMutation::Delete {
                key: super::super::KvEntryKey::new(ns, "policy/active").unwrap(),
            }],
        )
        .unwrap();
        assert!(frozen.apply_batch(&batch).await.is_err());
        assert_eq!(frozen.clear_prefix(ns, "audit/").await.unwrap(), 1);
        assert_eq!(
            backend.get(ns, "policy/active").await.unwrap(),
            Some(vec![1])
        );
    }
}
