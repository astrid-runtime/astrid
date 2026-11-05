//! Causal regressions for sealed checkpoint boundary certificates.
use super::*;
use std::sync::atomic::Ordering;

// `TreeValidation` is crate-private to `kv` and re-exported by `tree`.
use crate::kv::tree::TreeValidation;

#[test]
fn empty_tree_validation_certificate_names_no_root() {
    assert_eq!(TreeValidation::EMPTY.root(), None);
}

#[tokio::test]
async fn certified_point_read_survives_checkpoint_for_chunked_values() {
    let engine = Arc::new(MeasuringEngine::new());
    let store =
        TreeKvStore::<String, TestIdentity, Resolver, _>::from_engine(engine.clone(), Resolver);
    let namespace = "alice:capsule:ownership";
    let original = vec![0x42; 512 * 1024];
    store
        .set(namespace, "large", original.clone())
        .await
        .unwrap();
    store
        .set(namespace, "small", b"keep".to_vec())
        .await
        .unwrap();
    store.checkpoint_for_test("alice".to_owned()).unwrap();
    super::admission_test_support::drain_checkpoint_tasks(&engine).await;

    assert_eq!(
        store.get(namespace, "large").await.unwrap(),
        Some(original.clone())
    );
    assert_eq!(
        store.get(namespace, "small").await.unwrap(),
        Some(b"keep".to_vec())
    );

    // Overlay miss after another mutation still returns checkpointed bytes.
    store
        .set(namespace, "marker", b"delta".to_vec())
        .await
        .unwrap();
    assert_eq!(store.get(namespace, "large").await.unwrap(), Some(original));
    store.close().await.unwrap();
}

#[tokio::test]
async fn retirement_to_empty_checkpoint_cannot_resurrect_prior_chunked_values() {
    let engine = Arc::new(MeasuringEngine::new());
    let store =
        TreeKvStore::<String, TestIdentity, Resolver, _>::from_engine(engine.clone(), Resolver);
    let namespace = "alice:capsule:ownership";
    let original = vec![0x7a; 512 * 1024];
    store.set(namespace, "large", original).await.unwrap();
    store.checkpoint_for_test("alice".to_owned()).unwrap();
    super::admission_test_support::drain_checkpoint_tasks(&engine).await;
    assert!(store.delete(namespace, "large").await.unwrap());
    store.checkpoint_for_test("alice".to_owned()).unwrap();
    super::admission_test_support::drain_checkpoint_tasks(&engine).await;
    assert_eq!(store.get(namespace, "large").await.unwrap(), None);
    assert!(store.list_keys(namespace).await.unwrap().is_empty());
    store.close().await.unwrap();
}

#[tokio::test]
async fn visit_entries_remains_fully_validating_with_a_certificate_present() {
    let engine = Arc::new(MeasuringEngine::new());
    let store =
        TreeKvStore::<String, TestIdentity, Resolver, _>::from_engine(engine.clone(), Resolver);
    let namespace = "alice:capsule:ownership";
    let original = vec![0x11; 512 * 1024];
    store.set(namespace, "large", original).await.unwrap();
    store.checkpoint_for_test("alice".to_owned()).unwrap();
    super::admission_test_support::drain_checkpoint_tasks(&engine).await;

    // clear_owner uses visit_entries, which must keep fully validating value
    // reads even when a certificate exists on the projection.
    let removed = store.clear_owner(&"alice".to_owned()).unwrap();
    assert_eq!(removed, 1);
    assert_eq!(store.get(namespace, "large").await.unwrap(), None);
    store.close().await.unwrap();
}

#[tokio::test]
async fn foreign_principal_projection_cannot_read_another_owners_chunked_value() {
    let engine = Arc::new(MeasuringEngine::new());
    let store =
        TreeKvStore::<String, TestIdentity, Resolver, _>::from_engine(engine.clone(), Resolver);
    let original = vec![0x5a; 512 * 1024];
    store
        .set("alice:capsule:ownership", "large", original.clone())
        .await
        .unwrap();
    store.checkpoint_for_test("alice".to_owned()).unwrap();
    super::admission_test_support::drain_checkpoint_tasks(&engine).await;

    assert_eq!(
        store.get("alice:capsule:ownership", "large").await.unwrap(),
        Some(original)
    );
    assert_eq!(
        store.get("bob:capsule:ownership", "large").await.unwrap(),
        None
    );
    store
        .set("bob:capsule:ownership", "large", vec![0x5b; 512 * 1024])
        .await
        .unwrap();
    store.checkpoint_for_test("bob".to_owned()).unwrap();
    super::admission_test_support::drain_checkpoint_tasks(&engine).await;
    assert_ne!(
        store.get("alice:capsule:ownership", "large").await.unwrap(),
        store.get("bob:capsule:ownership", "large").await.unwrap()
    );
    store.close().await.unwrap();
}

#[tokio::test]
async fn metadata_checkpoint_still_avoids_rebuild_while_certified_reads_remain_correct() {
    let engine = Arc::new(MeasuringEngine::new());
    let store =
        TreeKvStore::<String, TestIdentity, Resolver, _>::from_engine(engine.clone(), Resolver);
    let namespace = "alice:capsule:ownership";
    let original = vec![0x42; 512 * 1024];
    store
        .set(namespace, "large", original.clone())
        .await
        .unwrap();
    store
        .set(namespace, "updated", b"old".to_vec())
        .await
        .unwrap();
    store.checkpoint_for_test("alice".to_owned()).unwrap();
    super::admission_test_support::drain_checkpoint_tasks(&engine).await;
    store
        .set(namespace, "updated", b"latest".to_vec())
        .await
        .unwrap();
    engine.identified_chunk_bytes.store(0, Ordering::Relaxed);
    store.checkpoint_for_test("alice".to_owned()).unwrap();
    super::admission_test_support::drain_checkpoint_tasks(&engine).await;
    assert_eq!(engine.identified_chunk_bytes.load(Ordering::Relaxed), 0);
    assert_eq!(store.get(namespace, "large").await.unwrap(), Some(original));
    assert_eq!(
        store.get(namespace, "updated").await.unwrap(),
        Some(b"latest".to_vec())
    );
    store.close().await.unwrap();
}
