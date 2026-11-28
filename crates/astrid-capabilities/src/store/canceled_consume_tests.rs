//! Exercise live and reopened admission across interrupted marker writes.
use super::*;
use astrid_storage::StorageResult;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::Notify;

struct GatedStore {
    inner: MemoryKvStore,
    gate: AtomicBool,
    reject_revocation: bool,
    applied: Notify,
}

#[async_trait::async_trait]
impl KvStore for GatedStore {
    async fn get(&self, ns: &str, key: &str) -> StorageResult<Option<Vec<u8>>> {
        self.inner.get(ns, key).await
    }
    async fn set(&self, ns: &str, key: &str, value: Vec<u8>) -> StorageResult<()> {
        if ns == NS_REVOKED && self.reject_revocation {
            return Err(astrid_storage::StorageError::Internal(
                "rejected marker".into(),
            ));
        }
        self.inner.set(ns, key, value).await?;
        if ns == NS_REVOKED && self.gate.swap(false, Ordering::Relaxed) {
            self.applied.notify_one();
            std::future::pending::<()>().await;
        }
        Ok(())
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
        reject_revocation: false,
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

#[tokio::test]
async fn revocation_fences_live_use_and_reopens_only_applied_markers() {
    for reject_revocation in [true, false] {
        let backend = Arc::new(GatedStore {
            inner: MemoryKvStore::new(),
            gate: AtomicBool::new(!reject_revocation),
            reject_revocation,
            applied: Notify::new(),
        });
        let store = CapabilityStore::with_kv_store(backend.clone())
            .await
            .unwrap();
        let token = single_use_token();
        let id = token.id.clone();
        store.add(token).await.unwrap();
        let mut attempt = Box::pin(store.revoke(&id));
        if reject_revocation {
            assert!(matches!(
                attempt.as_mut().await,
                Err(CapabilityError::StorageError(_))
            ));
        } else {
            tokio::select! {
                result = &mut attempt => panic!("expected pending revocation acknowledgement: {result:?}"),
                () = backend.applied.notified() => {}
            }
        }
        drop(attempt);
        assert!(matches!(
            store.use_token(&id).await,
            Err(CapabilityError::TokenRevoked { .. })
        ));
        let marker = backend
            .inner
            .get(NS_REVOKED, &id.0.to_string())
            .await
            .unwrap();
        assert_eq!(
            marker.as_deref(),
            (!reject_revocation).then_some(PRESENCE_MARKER)
        );
        let reopened = CapabilityStore::with_kv_store(backend).await.unwrap();
        if reject_revocation {
            // The backend rejected the write before making any change.
            assert_eq!(reopened.use_token(&id).await.unwrap().id, id);
        } else {
            assert!(matches!(
                reopened.use_token(&id).await,
                Err(CapabilityError::TokenRevoked { .. })
            ));
        }
    }
}
