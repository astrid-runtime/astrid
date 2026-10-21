//! A real lost CAS must re-read authorization time before a second attempt.

use super::tests::{bytes, envelope, fixture};
use crate::{KvStore, MemoryKvStore, StorageResult};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

struct ExpireOnConflict {
    backend: Arc<MemoryKvStore>,
    lose_next: AtomicBool,
    clock: Arc<AtomicU64>,
}
#[async_trait::async_trait]
impl KvStore for ExpireOnConflict {
    async fn get(&self, namespace: &str, key: &str) -> StorageResult<Option<Vec<u8>>> {
        self.backend.get(namespace, key).await
    }
    async fn set(&self, namespace: &str, key: &str, value: Vec<u8>) -> StorageResult<()> {
        self.backend.set(namespace, key, value).await
    }
    async fn delete(&self, namespace: &str, key: &str) -> StorageResult<bool> {
        self.backend.delete(namespace, key).await
    }
    async fn exists(&self, namespace: &str, key: &str) -> StorageResult<bool> {
        self.backend.exists(namespace, key).await
    }
    async fn list_keys(&self, namespace: &str) -> StorageResult<Vec<String>> {
        self.backend.list_keys(namespace).await
    }
    async fn clear_namespace(&self, namespace: &str) -> StorageResult<u64> {
        self.backend.clear_namespace(namespace).await
    }
    async fn compare_and_swap(
        &self,
        namespace: &str,
        key: &str,
        expected: Option<&[u8]>,
        new: Vec<u8>,
    ) -> StorageResult<bool> {
        if self.lose_next.swap(false, Ordering::SeqCst) {
            self.clock.store(1500, Ordering::SeqCst);
            return Ok(false);
        }
        self.backend
            .compare_and_swap(namespace, key, expected, new)
            .await
    }
}

#[tokio::test]
async fn pending_and_commit_recheck_expiry_on_lost_cas() {
    for commit in [false, true] {
        let mut f = fixture();
        let envelope = envelope(&f).await;
        if commit {
            f.store
                .begin_hosted_owner(&envelope, || 1000)
                .await
                .unwrap();
        }
        let before = bytes(&f).await;
        let clock = Arc::new(AtomicU64::new(1000));
        let backend = Arc::new(ExpireOnConflict {
            backend: f.backend.clone(),
            lose_next: AtomicBool::new(true),
            clock: clock.clone(),
        });
        f.store = crate::OwnershipStore::new(backend, f.directory.clone()).unwrap();
        let result = if commit {
            f.store
                .commit_hosted_owner(&envelope, || clock.load(Ordering::SeqCst))
                .await
                .map(|_| ())
        } else {
            f.store
                .begin_hosted_owner(&envelope, || clock.load(Ordering::SeqCst))
                .await
        };
        assert!(result.is_err());
        assert_eq!(bytes(&f).await, before);
    }
}
