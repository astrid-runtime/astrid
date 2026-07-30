use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;

use super::*;
use crate::{KvStore, MemoryKvStore, StorageError, StorageResult};

#[derive(Debug, Default)]
struct FailingSetKv {
    inner: MemoryKvStore,
    reject_sets: AtomicBool,
}

#[async_trait]
impl KvStore for FailingSetKv {
    async fn get(&self, namespace: &str, key: &str) -> StorageResult<Option<Vec<u8>>> {
        self.inner.get(namespace, key).await
    }

    async fn set(&self, namespace: &str, key: &str, value: Vec<u8>) -> StorageResult<()> {
        if self.reject_sets.load(Ordering::SeqCst) {
            return Err(StorageError::Internal("injected set failure".to_owned()));
        }
        self.inner.set(namespace, key, value).await
    }

    async fn delete(&self, namespace: &str, key: &str) -> StorageResult<bool> {
        self.inner.delete(namespace, key).await
    }

    async fn exists(&self, namespace: &str, key: &str) -> StorageResult<bool> {
        self.inner.exists(namespace, key).await
    }

    async fn list_keys(&self, namespace: &str) -> StorageResult<Vec<String>> {
        self.inner.list_keys(namespace).await
    }

    async fn compare_and_swap(
        &self,
        namespace: &str,
        key: &str,
        expected: Option<&[u8]>,
        new: Vec<u8>,
    ) -> StorageResult<bool> {
        self.inner
            .compare_and_swap(namespace, key, expected, new)
            .await
    }

    async fn clear_namespace(&self, namespace: &str) -> StorageResult<u64> {
        self.inner.clear_namespace(namespace).await
    }
}

#[tokio::test]
async fn failed_identity_persistence_restores_the_exact_directory_state() {
    let backend = Arc::new(FailingSetKv::default());
    let bootstrap =
        KvIdentityStore::new(ScopedKvStore::new(backend.clone(), "system:identity").unwrap());
    let original = PrincipalId::new("Alice").unwrap();
    let renamed = PrincipalId::new("Alice-Renamed").unwrap();
    let user = bootstrap
        .create_principal(original.clone(), [0x11; 32])
        .await
        .unwrap();
    let identity = bootstrap
        .get_principal_identity(user.id)
        .await
        .unwrap()
        .unwrap();
    let principals = PrincipalDirectory::default();
    principals.register(original.clone(), identity.uid).unwrap();
    let store = KvIdentityStore::with_principal_directory(
        ScopedKvStore::new(backend.clone(), "system:identity").unwrap(),
        principals.clone(),
    );

    backend.reject_sets.store(true, Ordering::SeqCst);
    assert!(
        store
            .bind_principal_identity(user.id, original.clone(), [0x22; 32])
            .await
            .is_err()
    );
    assert_eq!(principals.uid_for(&original).unwrap(), identity.uid);

    assert!(
        store
            .bind_principal_identity(user.id, renamed.clone(), [0x22; 32])
            .await
            .is_err()
    );
    assert_eq!(principals.uid_for(&original).unwrap(), identity.uid);
    assert!(principals.uid_for(&renamed).is_err());
}
