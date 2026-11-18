use std::sync::Arc;

use super::tree_tests::{Resolver, TestIdentity};
use super::{KvStore, MemoryKvStore, PrincipalKvStore, TreeKvStore};
use crate::engine::InMemoryEngine;

const NS: &str = "alice:capsule:identity";
const OTHER_NS: &str = "bob:capsule:identity";

async fn contract(store: Arc<dyn KvStore>) {
    assert!(
        !store
            .compare_and_delete(NS, "key", Vec::new())
            .await
            .unwrap()
    );
    store.set(NS, "key", Vec::new()).await.unwrap();
    store.set(OTHER_NS, "key", Vec::new()).await.unwrap();
    assert!(
        !store
            .compare_and_delete(NS, "key", b"wrong".to_vec())
            .await
            .unwrap()
    );
    assert_eq!(store.get(NS, "key").await.unwrap(), Some(Vec::new()));
    assert!(
        store
            .compare_and_delete(NS, "key", Vec::new())
            .await
            .unwrap()
    );
    assert!(
        !store
            .compare_and_delete(NS, "key", Vec::new())
            .await
            .unwrap()
    );
    assert_eq!(store.get(OTHER_NS, "key").await.unwrap(), Some(Vec::new()));

    for (namespace, key) in [("", "key"), ("bad\0ns", "key"), (NS, ""), (NS, "bad\0key")] {
        assert!(
            store
                .compare_and_delete(namespace, key, Vec::new())
                .await
                .is_err()
        );
    }

    // In either legal ordering the replacement survives: removal happens
    // before the write, or the predicate observes the replacement and fails.
    for iteration in 0..64 {
        let key = format!("race/{iteration}");
        store.set(NS, &key, b"old".to_vec()).await.unwrap();
        let barrier = Arc::new(tokio::sync::Barrier::new(3));
        let delete_store = store.clone();
        let delete_barrier = barrier.clone();
        let delete_key = key.clone();
        let delete = tokio::spawn(async move {
            delete_barrier.wait().await;
            delete_store
                .compare_and_delete(NS, &delete_key, b"old".to_vec())
                .await
        });
        let write_store = store.clone();
        let write_barrier = barrier.clone();
        let write_key = key.clone();
        let write = tokio::spawn(async move {
            write_barrier.wait().await;
            write_store
                .set(NS, &write_key, b"replacement".to_vec())
                .await
        });
        barrier.wait().await;
        let (deleted, written) = (delete.await.unwrap(), write.await.unwrap());
        deleted.unwrap();
        #[cfg(not(feature = "legacy-surrealkv"))]
        written.unwrap();
        #[cfg(feature = "legacy-surrealkv")]
        if let Err(error) = written {
            // Legacy ordinary writes expose a retryable MVCC conflict. The
            // successful conditional delete may win; retry only that explicit
            // dependency error after the race, never an arbitrary I/O failure.
            assert!(matches!(error, crate::StorageError::Internal(ref message)
                if *message == surrealkv::Error::TransactionWriteConflict.to_string()
                    || *message == surrealkv::Error::TransactionRetry.to_string()));
            store.set(NS, &key, b"replacement".to_vec()).await.unwrap();
        }
        assert_eq!(
            store.get(NS, &key).await.unwrap(),
            Some(b"replacement".to_vec())
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn memory_conditional_delete_contract() {
    contract(Arc::new(MemoryKvStore::new())).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tree_conditional_delete_contract() {
    contract(Arc::new(
        TreeKvStore::<String, TestIdentity, Resolver, _>::from_engine(
            Arc::new(InMemoryEngine::new(TestIdentity)),
            Resolver,
        ),
    ))
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn principal_conditional_delete_contract() {
    contract(Arc::new(PrincipalKvStore::new(
        Arc::new(InMemoryEngine::new(TestIdentity)),
        Resolver,
    )))
    .await;
}

#[cfg(feature = "legacy-surrealkv")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn legacy_conditional_delete_contract() {
    let directory = tempfile::tempdir().unwrap();
    let store = Arc::new(super::SurrealKvStore::open(directory.path()).unwrap());
    contract(store.clone()).await;
    store.close().await.unwrap();
}

#[cfg(not(target_family = "wasm"))]
#[tokio::test]
async fn durable_conditional_delete_survives_reopen() {
    use super::tree_tests::Utf8Codec;
    use crate::engine::{DurableEngine, RecoveryLimits};
    let directory = tempfile::tempdir().unwrap();
    {
        let engine = Arc::new(
            DurableEngine::open(
                directory.path(),
                TestIdentity,
                Utf8Codec,
                RecoveryLimits::process_addressable(),
            )
            .unwrap(),
        );
        let store = TreeKvStore::<String, TestIdentity, Resolver, _>::from_engine(engine, Resolver);
        store.set(NS, "removed", b"old".to_vec()).await.unwrap();
        store
            .set(NS, "preserved", b"replacement".to_vec())
            .await
            .unwrap();
        assert!(
            store
                .compare_and_delete(NS, "removed", b"old".to_vec())
                .await
                .unwrap()
        );
        assert!(
            !store
                .compare_and_delete(NS, "preserved", b"old".to_vec())
                .await
                .unwrap()
        );
        store.close().await.unwrap();
    }
    let engine = Arc::new(
        DurableEngine::open(
            directory.path(),
            TestIdentity,
            Utf8Codec,
            RecoveryLimits::process_addressable(),
        )
        .unwrap(),
    );
    let store = TreeKvStore::<String, TestIdentity, Resolver, _>::from_engine(engine, Resolver);
    assert_eq!(store.get(NS, "removed").await.unwrap(), None);
    assert_eq!(
        store.get(NS, "preserved").await.unwrap(),
        Some(b"replacement".to_vec())
    );
    store.close().await.unwrap();
}
