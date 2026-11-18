use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};

use super::tree_tests::{Resolver, TestIdentity};
use super::{KvStore, MemoryKvStore, PrincipalKvStore, TreeKvStore};
use crate::StorageError;
use crate::engine::InMemoryEngine;

const NS: &str = "alice:capsule:identity";

async fn contract(store: Arc<dyn KvStore>) {
    for (namespace, key, value) in [
        (NS, "link/a", b"first".as_slice()),
        (NS, "link/empty", b"".as_slice()),
        (NS, "link/β", b"unicode".as_slice()),
        (NS, "link0/outside", b"outside".as_slice()),
        (
            "alice:capsule:other",
            "link/a",
            b"other namespace".as_slice(),
        ),
        ("bob:capsule:identity", "link/a", b"other owner".as_slice()),
    ] {
        store.set(namespace, key, value.to_vec()).await.unwrap();
    }
    let rows = Arc::new(Mutex::new(BTreeMap::new()));
    let collected = rows.clone();
    store
        .visit_entries_with_prefix(
            NS,
            "link/",
            Box::new(move |namespace, key, value| {
                assert_eq!(namespace, NS);
                assert!(
                    collected
                        .lock()
                        .unwrap()
                        .insert(key.to_owned(), value.to_vec())
                        .is_none()
                );
                Ok(())
            }),
        )
        .await
        .unwrap();
    assert_eq!(
        *rows.lock().unwrap(),
        BTreeMap::from([
            ("link/a".to_owned(), b"first".to_vec()),
            ("link/empty".to_owned(), Vec::new()),
            ("link/β".to_owned(), b"unicode".to_vec()),
        ])
    );

    store
        .visit_entries_with_prefix(
            NS,
            "absent/",
            Box::new(|_, _, _| {
                panic!("absent range called visitor");
            }),
        )
        .await
        .unwrap();
    for (namespace, prefix) in [("", "link/"), ("bad\0ns", "link/"), (NS, "bad\0prefix")] {
        assert!(
            store
                .visit_entries_with_prefix(
                    namespace,
                    prefix,
                    Box::new(|_, _, _| {
                        panic!("invalid range called visitor");
                    })
                )
                .await
                .is_err()
        );
    }
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = calls.clone();
    let error = store
        .visit_entries_with_prefix(
            NS,
            "link/",
            Box::new(move |_, _, _| {
                counted.fetch_add(1, Ordering::Relaxed);
                Err(StorageError::Internal("visitor refused row".to_owned()))
            }),
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("visitor refused row"));
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    let all = Arc::new(AtomicUsize::new(0));
    let counted = all.clone();
    store
        .visit_entries_with_prefix(
            NS,
            "",
            Box::new(move |namespace, _, _| {
                assert_eq!(namespace, NS);
                counted.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }),
        )
        .await
        .unwrap();
    assert_eq!(all.load(Ordering::Relaxed), 4);
}

#[tokio::test]
async fn memory_prefix_visit_contract() {
    contract(Arc::new(MemoryKvStore::new())).await;
}

#[tokio::test]
async fn tree_prefix_visit_contract() {
    contract(Arc::new(
        TreeKvStore::<String, TestIdentity, Resolver, _>::from_engine(
            Arc::new(InMemoryEngine::new(TestIdentity)),
            Resolver,
        ),
    ))
    .await;
}

#[tokio::test]
async fn principal_prefix_visit_contract() {
    contract(Arc::new(PrincipalKvStore::new(
        Arc::new(InMemoryEngine::new(TestIdentity)),
        Resolver,
    )))
    .await;
}

#[cfg(feature = "legacy-surrealkv")]
#[tokio::test]
async fn legacy_prefix_visit_contract() {
    let directory = tempfile::tempdir().unwrap();
    let store = Arc::new(super::SurrealKvStore::open(directory.path()).unwrap());
    contract(store.clone()).await;
    store.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tree_prefix_visit_keeps_one_snapshot_while_a_writer_commits() {
    let store = Arc::new(
        TreeKvStore::<String, TestIdentity, Resolver, _>::from_engine(
            Arc::new(InMemoryEngine::new(TestIdentity)),
            Resolver,
        ),
    );
    store
        .set(NS, "link/a", b"checkpoint".to_vec())
        .await
        .unwrap();
    store
        .set(NS, "link/z", b"before checkpoint".to_vec())
        .await
        .unwrap();
    store.checkpoint_for_test("alice".to_owned()).unwrap();
    store
        .set(NS, "link/z", b"captured overlay".to_vec())
        .await
        .unwrap();
    let (sender, receiver) = mpsc::channel();
    let (resume, continued) = mpsc::channel();
    let rows = Arc::new(Mutex::new(BTreeMap::new()));
    let collected = rows.clone();
    let scanning = store.clone();
    let scan = tokio::spawn(async move {
        scanning
            .visit_entries_with_prefix(
                NS,
                "link/",
                Box::new(move |_, key, value| {
                    collected
                        .lock()
                        .unwrap()
                        .insert(key.to_owned(), value.to_vec());
                    if key == "link/a" {
                        sender.send(()).unwrap();
                        continued
                            .recv_timeout(std::time::Duration::from_secs(10))
                            .unwrap();
                    }
                    Ok(())
                }),
            )
            .await
            .unwrap();
    });
    tokio::task::spawn_blocking(move || {
        receiver
            .recv_timeout(std::time::Duration::from_secs(10))
            .unwrap();
    })
    .await
    .unwrap();
    let changed = store.set(NS, "link/z", b"new root".to_vec()).await;
    resume.send(()).unwrap();
    changed.unwrap();
    scan.await.unwrap();
    assert_eq!(
        *rows.lock().unwrap(),
        BTreeMap::from([
            ("link/a".to_owned(), b"checkpoint".to_vec()),
            ("link/z".to_owned(), b"captured overlay".to_vec()),
        ])
    );
    assert_eq!(
        store.get(NS, "link/z").await.unwrap(),
        Some(b"new root".to_vec())
    );
}
