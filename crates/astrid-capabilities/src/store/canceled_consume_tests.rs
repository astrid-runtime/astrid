//! Drop a single-use caller after the backend has installed its marker.
use super::*;
use astrid_storage::StorageResult;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::Notify;

struct GatedStore {
    inner: MemoryKvStore,
    gate: AtomicBool,
    applied: Notify,
}

#[async_trait::async_trait]
impl KvStore for GatedStore {
    async fn get(&self, ns: &str, key: &str) -> StorageResult<Option<Vec<u8>>> {
        self.inner.get(ns, key).await
    }
    async fn set(&self, ns: &str, key: &str, value: Vec<u8>) -> StorageResult<()> {
        self.inner.set(ns, key, value).await
    }
    async fn delete(&self, ns: &str, key: &str) -> StorageResult<bool> {
        self.inner.delete(ns, key).await
    }
    async fn exists(&self, ns: &str, key: &str) -> StorageResult<bool> {
        self.inner.exists(ns, key).await
    }
    async fn list_keys(&self, ns: &str) -> StorageResult<Vec<String>> {
        self.inner.list_keys(ns).await
    }
    async fn clear_namespace(&self, ns: &str) -> StorageResult<u64> {
        self.inner.clear_namespace(ns).await
    }
    async fn compare_and_swap(
        &self,
        ns: &str,
        key: &str,
        expected: Option<&[u8]>,
        value: Vec<u8>,
    ) -> StorageResult<bool> {
        let won = self
            .inner
            .compare_and_swap(ns, key, expected, value)
            .await?;
        if won && self.gate.swap(false, Ordering::Relaxed) {
            self.applied.notify_one();
            std::future::pending::<()>().await;
        }
        Ok(won)
    }
}

#[tokio::test]
async fn a_canceled_consumer_cannot_win_again_live_or_after_reopen() {
    let backend = Arc::new(GatedStore {
        inner: MemoryKvStore::new(),
        gate: AtomicBool::new(true),
        applied: Notify::new(),
    });
    let store = CapabilityStore::with_kv_store(backend.clone())
        .await
        .unwrap();
    let token = single_use_token();
    let id = token.id.clone();
    store.add(token).await.unwrap();

    let mut attempt = Box::pin(store.use_token(&id));
    tokio::select! {
        result = &mut attempt => panic!("expected cancellation before acknowledgement: {result:?}"),
        () = backend.applied.notified() => {}
    }
    assert_eq!(
        backend
            .inner
            .get(NS_USED, &id.0.to_string())
            .await
            .unwrap()
            .as_deref(),
        Some(PRESENCE_MARKER)
    );
    drop(attempt);
    assert!(!store.is_used(&id).await);

    let reopened = CapabilityStore::with_kv_store(backend).await.unwrap();
    assert!(reopened.is_used(&id).await);
    assert!(matches!(
        reopened.use_token(&id).await,
        Err(CapabilityError::TokenAlreadyUsed { .. })
    ));
    assert!(matches!(
        store.use_token(&id).await,
        Err(CapabilityError::TokenAlreadyUsed { .. })
    ));
    assert!(store.is_used(&id).await);
}
