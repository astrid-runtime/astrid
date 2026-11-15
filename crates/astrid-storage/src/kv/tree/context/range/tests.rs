use std::collections::BTreeMap;
use std::sync::Arc;

use crate::engine::InMemoryEngine;
use crate::kv::tree_tests::{Resolver, TestIdentity};
use crate::{KvStore, TreeKvStore};

#[tokio::test]
async fn prefix_entries_merge_one_checkpoint_with_live_overlay() {
    let engine = Arc::new(InMemoryEngine::new(TestIdentity));
    let store = TreeKvStore::<String, TestIdentity, Resolver, _>::from_engine(engine, Resolver);
    let namespace = "alice:capsule:first";
    let spilled = vec![0x51; 512 * 1024];
    for (key, value) in [
        ("link/a", b"old".to_vec()),
        ("link/deleted", b"old".to_vec()),
        ("link/spilled", spilled.clone()),
        ("link0/outside", b"outside".to_vec()),
    ] {
        store.set(namespace, key, value).await.unwrap();
    }
    store
        .set("alice:capsule:other", "link/a", b"other namespace".to_vec())
        .await
        .unwrap();
    store
        .set("bob:capsule:first", "link/a", b"other owner".to_vec())
        .await
        .unwrap();
    store.checkpoint_for_test("alice".to_owned()).unwrap();

    store
        .set(namespace, "link/a", b"replacement".to_vec())
        .await
        .unwrap();
    store.delete(namespace, "link/deleted").await.unwrap();
    store
        .set(namespace, "link/β", b"unicode".to_vec())
        .await
        .unwrap();
    store
        .set(namespace, "link/empty", Vec::new())
        .await
        .unwrap();
    let entries = store
        .list_entries_with_prefix(namespace, "link/")
        .await
        .unwrap();
    assert!(entries.iter().all(|entry| entry.namespace == namespace));
    let actual = entries
        .into_iter()
        .map(|entry| (entry.key, entry.value))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        actual,
        BTreeMap::from([
            ("link/a".to_owned(), b"replacement".to_vec()),
            ("link/empty".to_owned(), Vec::new()),
            ("link/spilled".to_owned(), spilled),
            ("link/β".to_owned(), b"unicode".to_vec()),
        ])
    );
    assert!(
        store
            .list_entries_with_prefix(namespace, "missing/")
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        store
            .list_entries_with_prefix(namespace, "invalid\0prefix")
            .await
            .is_err()
    );
}
