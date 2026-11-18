//! Exercise the dependency's real transaction oracle, not an adapter mutex.

use super::{KvStore, SurrealKvStore, composite_key, is_transaction_conflict};

#[tokio::test]
async fn stale_removal_cannot_overwrite_an_unconditional_replacement() {
    let directory = tempfile::tempdir().unwrap();
    let store = SurrealKvStore::open(directory.path()).unwrap();
    store.set("ns", "key", b"old".to_vec()).await.unwrap();
    let key = composite_key("ns", "key");
    let mut removal = store.tree.begin().unwrap();
    assert_eq!(removal.get(&key).unwrap(), Some(b"old".to_vec()));
    removal.delete(&key).unwrap();
    store
        .set("ns", "key", b"replacement".to_vec())
        .await
        .unwrap();
    let error = removal.commit().await.unwrap_err();
    assert!(is_transaction_conflict(&error), "{error}");
    assert_eq!(
        store.get("ns", "key").await.unwrap(),
        Some(b"replacement".to_vec())
    );
    store.close().await.unwrap();
}

#[tokio::test]
async fn ordinary_writer_started_before_conditional_delete_cannot_commit_stale_state() {
    let directory = tempfile::tempdir().unwrap();
    let store = SurrealKvStore::open(directory.path()).unwrap();
    store.set("ns", "key", b"old".to_vec()).await.unwrap();
    let key = composite_key("ns", "key");
    let mut writer = store.tree.begin().unwrap();
    writer.set(&key, b"replacement").unwrap();
    assert!(
        store
            .compare_and_delete("ns", "key", b"old".to_vec())
            .await
            .unwrap()
    );
    let error = writer.commit().await.unwrap_err();
    assert!(is_transaction_conflict(&error), "{error}");
    assert_eq!(store.get("ns", "key").await.unwrap(), None);
    store.close().await.unwrap();
}
