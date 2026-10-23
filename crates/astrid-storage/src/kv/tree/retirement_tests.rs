//! Retiring-owner authority is explicitly non-increasing, never unlimited.
use super::*;
use crate::KvStore;
use crate::engine::InMemoryEngine;
use crate::principal_state::Blake3ObjectIdentityV1;
use std::sync::atomic::{AtomicBool, Ordering};

#[tokio::test]
async fn retirement_rejects_growth_and_ordinary_writes_still_require_live_policy() {
    let unavailable = Arc::new(AtomicBool::new(false));
    let policy = Arc::clone(&unavailable);
    let quota: Arc<dyn KvQuotaResolver<String>> = Arc::new(move |_: &String| {
        if policy.load(Ordering::Acquire) {
            Err(StorageError::Internal("retired quota profile".into()))
        } else {
            Ok(Some(4096))
        }
    });
    let engine = Arc::new(InMemoryEngine::<String, _>::new(Blake3ObjectIdentityV1));
    let store = TreeKvStore::<String, Blake3ObjectIdentityV1, _, _>::from_engine_with_quota(
        engine,
        |namespace: &str| Ok(namespace.to_owned()),
        quota,
    );
    store.set("agent", "key", b"old".to_vec()).await.unwrap();
    unavailable.store(true, Ordering::Release);
    assert!(store.set("agent", "key", b"new".to_vec()).await.is_err());
    let attempt = store.blocking_store().mutate_with_quota(
        &"agent".to_owned(),
        MutationQuota::NonIncreasing,
        |_, _| {
            Ok((
                (),
                vec![(b"agent\0other".to_vec(), Some(b"growth".to_vec()))],
                true,
            ))
        },
    );
    assert!(
        attempt
            .unwrap_err()
            .to_string()
            .contains("would increase storage usage")
    );
    assert_eq!(
        store.get("agent", "key").await.unwrap(),
        Some(b"old".to_vec())
    );
    assert!(store.get("agent", "other").await.unwrap().is_none());
    assert_eq!(store.clear_owner(&"agent".to_owned()).unwrap(), 1);
    assert_eq!(store.clear_owner(&"agent".to_owned()).unwrap(), 0);
}
