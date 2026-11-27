use std::collections::BTreeMap;
use std::sync::Arc;

use crate::engine::InMemoryEngine;
use crate::error::StorageError;
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

#[tokio::test]
async fn prefix_visitor_releases_decoded_checkpoint_pages_and_preserves_ordered_lists() {
    let engine = Arc::new(InMemoryEngine::new(TestIdentity));
    let store = TreeKvStore::<String, TestIdentity, Resolver, _>::from_engine(engine, Resolver);
    let namespace = "alice:capsule:first";
    for index in 0..512_u32 {
        store
            .set(namespace, &format!("link/{index:04}"), vec![0x51; 128])
            .await
            .unwrap();
    }
    store
        .set(namespace, "link0/outside", vec![0x52; 128])
        .await
        .unwrap();
    store.checkpoint_for_test("alice".to_owned()).unwrap();
    store.delete(namespace, "link/0001").await.unwrap();
    store
        .set(namespace, "link/0000", b"replacement".to_vec())
        .await
        .unwrap();
    store.set(namespace, "link/new", Vec::new()).await.unwrap();

    let start = crate::kv::composite_key(namespace, "link/");
    let end = crate::kv::prefix_range_end(namespace, "link/");
    let blocking = store.blocking_store();
    let actual = blocking
        .read("alice".to_owned(), |context, header| {
            let mut rows = BTreeMap::new();
            context.visit_projected_entries_in_range(
                header,
                &start,
                &end,
                namespace.len().strict_add(1),
                |key, value| {
                    assert!(rows.insert(key.to_owned(), value.to_vec()).is_none());
                    Ok(())
                },
            )?;
            assert!(
                context.nodes.is_empty(),
                "read walk retained decoded checkpoint bodies"
            );
            let keys = context.projected_keys_in_range(
                header,
                &start,
                &end,
                namespace.len().strict_add(1),
            )?;
            assert_eq!(keys, rows.keys().cloned().collect::<Vec<_>>());
            assert!(
                context.nodes.is_empty(),
                "key-only scan retained decoded checkpoint bodies"
            );
            let physical = |index| crate::kv::composite_key(namespace, &format!("link/{index:04}"));
            let mut attempted = Vec::new();
            let refused = physical(103);
            let result = context.visit_slots_in_range(header.tree, &physical(98), &physical(107), |_, entry| {
                let stop = entry.key == refused;
                attempted.push(entry.key);
                if stop { Err(StorageError::Serialization("refused slot".into())) } else { Ok(()) }
            });
            assert!(matches!(result, Err(StorageError::Serialization(message)) if message == "refused slot"));
            assert_eq!(attempted, (98..=103).map(physical).collect::<Vec<_>>());
            Ok(rows)
        })
        .unwrap();
    assert_eq!(actual.len(), 512);
    assert_eq!(actual["link/0000"], b"replacement");
    assert!(!actual.contains_key("link/0001"));
    assert!(actual["link/new"].is_empty());
    let entries = store
        .list_entries_with_prefix(namespace, "link/")
        .await
        .unwrap();
    assert_eq!(
        entries
            .iter()
            .map(|entry| entry.key.as_str())
            .collect::<Vec<_>>(),
        actual.keys().map(String::as_str).collect::<Vec<_>>()
    );
    for entry in entries {
        assert_eq!(entry.namespace, namespace);
        assert_eq!(entry.value, actual[&entry.key]);
    }
}

#[tokio::test]
async fn prefix_deletions_release_pages_and_reuse_observed_values() {
    let engine = Arc::new(InMemoryEngine::new(TestIdentity));
    let store = TreeKvStore::<String, TestIdentity, Resolver, _>::from_engine(engine, Resolver);
    let namespace = "alice:capsule:first";
    for index in 0..512 {
        store
            .set(namespace, &format!("link/{index:04}"), vec![0x51; 128])
            .await
            .unwrap();
    }
    store
        .set(namespace, "outside", b"untouched".to_vec())
        .await
        .unwrap();
    store.checkpoint_for_test("alice".to_owned()).unwrap();
    store
        .set(namespace, "link/0001", b"replacement".to_vec())
        .await
        .unwrap();
    store.delete(namespace, "link/0002").await.unwrap();
    store.set(namespace, "link/new", Vec::new()).await.unwrap();
    let start = crate::kv::composite_key(namespace, "link/");
    let end = crate::kv::prefix_range_end(namespace, "link/");
    store
        .blocking_store()
        .read("alice".to_owned(), |context, header| {
            let deletions = context.projected_deletions_in_range(header, &start, &end)?;
            assert_eq!(deletions.len(), 512);
            assert!(
                context.nodes.is_empty(),
                "clear retained decoded checkpoint pages"
            );
            let projection = context.apply_mutations(header, deletions)?;
            assert!(
                context.nodes.is_empty(),
                "clear repeated point lookups after observing the values"
            );
            assert_eq!(projection.totals.entries, 1);
            Ok(())
        })
        .unwrap();
}
