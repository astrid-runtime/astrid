//! Large evolving values must share unchanged immutable content.
use super::*;

#[tokio::test]
async fn local_edit_to_large_value_does_not_retain_another_full_blob() {
    let engine = Arc::new(MeasuringEngine::new());
    let store = TreeKvStore::<String, TestIdentity, Resolver, MeasuringEngine>::from_engine(
        engine.clone(),
        Resolver,
    );
    let mut seed = 0x12ab_56cd_90ef_3412;
    let original: Vec<u8> = (0..8 * 1024 * 1024)
        .map(|_| next(&mut seed).to_le_bytes()[0])
        .collect();
    store
        .set("alice:capsule:ownership", "graph", original.clone())
        .await
        .unwrap();
    let old_root = engine.inner.root(&"alice".to_owned()).unwrap();
    let old_snapshot = engine.inner.snapshot(&"alice".to_owned()).unwrap().unwrap();
    let mut edited = original.clone();
    edited.splice(3_000_000..3_000_000, [0x55; 4096]);
    assert!(
        store
            .compare_and_swap(
                "alice:capsule:ownership",
                "graph",
                Some(&original),
                edited.clone()
            )
            .await
            .unwrap()
    );
    assert_eq!(
        store.get("alice:capsule:ownership", "graph").await.unwrap(),
        Some(edited)
    );
    assert_ne!(engine.inner.root(&"alice".to_owned()), Some(old_root));
    for (id, record) in old_snapshot.records() {
        assert_eq!(
            engine.inner.object(*id).as_ref(),
            Some(record),
            "history object {id:?} changed"
        );
    }
    let appended = engine.last_authoritative_bytes();
    eprintln!(
        "existing_bytes={} inserted_bytes=4096 appended_bytes={appended}",
        original.len()
    );
    assert!(
        appended < original.len() as u64 / 4,
        "local insertion retained {appended} new bytes for an {}-byte existing value",
        original.len()
    );
}

#[tokio::test]
async fn failed_cas_and_quota_cannot_admit_chunked_content() {
    use crate::kv::KvQuotaResolver;
    let engine = Arc::new(InMemoryEngine::new(TestIdentity));
    let quota: Arc<dyn KvQuotaResolver<String>> = Arc::new(|_: &String| Ok(Some(600_000)));
    let store = TreeKvStore::<String, TestIdentity, Resolver, _>::from_engine_with_quota(
        engine.clone(),
        Resolver,
        quota,
    );
    let original = vec![0x42; 512 * 1024];
    store
        .set("alice:capsule:ownership", "graph", original.clone())
        .await
        .unwrap();
    let count = engine.object_count();
    let root = engine.root(&"alice".to_owned());
    assert!(
        !store
            .compare_and_swap(
                "alice:capsule:ownership",
                "graph",
                Some(b"wrong"),
                vec![0x55; 512 * 1024]
            )
            .await
            .unwrap()
    );
    assert!(
        store
            .set("alice:capsule:ownership", "graph", vec![0x55; 700_000])
            .await
            .is_err()
    );
    assert_eq!(engine.object_count(), count);
    assert_eq!(engine.root(&"alice".to_owned()), root);
    assert_eq!(
        store.get("alice:capsule:ownership", "graph").await.unwrap(),
        Some(original)
    );
}

#[cfg(not(target_family = "wasm"))]
#[tokio::test]
async fn chunked_values_survive_durable_reopen_and_checkpoint() {
    let directory = tempfile::tempdir().unwrap();
    let original = vec![0x42; 512 * 1024];
    let mut edited = original.clone();
    edited.splice(250_000..250_000, [0x55; 4096]);
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
        store
            .set("alice:capsule:ownership", "graph", original.clone())
            .await
            .unwrap();
        assert!(
            store
                .compare_and_swap(
                    "alice:capsule:ownership",
                    "graph",
                    Some(&original),
                    edited.clone()
                )
                .await
                .unwrap()
        );
        assert!(store.checkpoint_for_test("alice".to_owned()).unwrap());
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
    assert_eq!(
        store.get("alice:capsule:ownership", "graph").await.unwrap(),
        Some(edited)
    );
    assert_eq!(
        store.get("bob:capsule:ownership", "graph").await.unwrap(),
        None
    );
    store.close().await.unwrap();
}
