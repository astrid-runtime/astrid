use super::*;
use crate::StorageResult;
use crate::engine::{
    DurableEngine, ObjectCacheCapacity, ObjectCacheConfig, PrincipalCodec, RecoveryLimits,
};
use crate::kv::{KvStore, TreeKvStore};
use crate::principal_state::Blake3ObjectIdentityV1;
use std::num::NonZeroU64;
use std::sync::Arc;

#[derive(Clone, Copy)]
struct Utf8Codec;
impl PrincipalCodec<String> for Utf8Codec {
    fn encode(&self, owner: &String) -> Vec<u8> {
        owner.as_bytes().to_vec()
    }
    fn decode(&self, bytes: &[u8]) -> Option<String> {
        std::str::from_utf8(bytes).ok().map(str::to_owned)
    }
}
type Engine = DurableEngine<String, Blake3ObjectIdentityV1, Utf8Codec>;
type Store = TreeKvStore<String, Blake3ObjectIdentityV1, fn(&str) -> StorageResult<String>, Engine>;
fn fixture(path: &std::path::Path, bytes: u64) -> (Arc<Engine>, Store) {
    fn resolve(namespace: &str) -> StorageResult<String> {
        crate::kv::validate_namespace(namespace)?;
        Ok(namespace.to_owned())
    }
    let config =
        NonZeroU64::new(bytes).map_or_else(ObjectCacheConfig::disabled, ObjectCacheConfig::bounded);
    let engine = Arc::new(
        Engine::open_with_object_cache(
            path,
            Blake3ObjectIdentityV1,
            Utf8Codec,
            RecoveryLimits::process_addressable(),
            config,
        )
        .unwrap(),
    );
    let store = Store::from_engine(Arc::clone(&engine), resolve);
    (engine, store)
}

#[tokio::test]
async fn decoded_overlays_obey_shared_budget_and_reconstruct_after_eviction() {
    let dir = tempfile::tempdir().unwrap();
    let (engine, store) = fixture(dir.path(), 256 * 1024);
    let owner = "owner".to_owned();
    for index in 0..24 {
        store
            .set(&owner, &format!("key-{index}"), vec![index; 4096])
            .await
            .unwrap();
    }
    let header = store.blocking_store().header(owner.clone()).unwrap();
    let head = header.head.unwrap();
    let projection = load(engine.as_ref(), &owner, head).expect("live overlay admitted");
    assert!(
        projection.retained_bytes() >= 24 * 4096,
        "values must be charged"
    );
    assert!(engine.object_cache_stats().resident_projection_bytes >= projection.retained_bytes());
    assert!(engine.object_cache_stats().resident_bytes <= 256 * 1024);
    engine.set_object_cache_capacity(ObjectCacheCapacity::Disabled);
    assert!(load(engine.as_ref(), &owner, head).is_none());
    assert_eq!(engine.object_cache_stats().resident_bytes, 0);
    for index in 0..24 {
        assert_eq!(
            store.get(&owner, &format!("key-{index}")).await.unwrap(),
            Some(vec![index; 4096])
        );
    }
    assert!(
        store
            .blocking_store()
            .checkpoint_once(owner.clone(), true)
            .unwrap()
    );
    assert_eq!(
        store.get(&owner, "key-7").await.unwrap(),
        Some(vec![7; 4096])
    );
    assert_eq!(engine.object_cache_stats().resident_projection_bytes, 0);
    engine.close().unwrap();
    drop(store);
    drop(engine);
    let (reopened, store) = fixture(dir.path(), 0);
    assert_eq!(
        store.get(&owner, "key-7").await.unwrap(),
        Some(vec![7; 4096])
    );
    assert_eq!(store.clear_owner(&owner).unwrap(), 24);
    assert!(store.get(&owner, "key-7").await.unwrap().is_none());
    reopened.close().unwrap();
}

#[tokio::test]
async fn replacement_discards_superseded_heads_and_never_crosses_owners() {
    let dir = tempfile::tempdir().unwrap();
    let (engine, store) = fixture(dir.path(), 512 * 1024);
    let alice = "alice".to_owned();
    let bob = "bob".to_owned();
    store.set(&alice, "key", vec![1; 8192]).await.unwrap();
    let old_head = store
        .blocking_store()
        .header(alice.clone())
        .unwrap()
        .head
        .unwrap();
    assert!(load(engine.as_ref(), &alice, old_head).is_some());
    assert!(load(engine.as_ref(), &bob, old_head).is_none());
    store.set(&alice, "key", vec![2; 8192]).await.unwrap();
    assert!(
        load(engine.as_ref(), &alice, old_head).is_none(),
        "superseded payload is redundant"
    );
    assert_eq!(store.get(&alice, "key").await.unwrap(), Some(vec![2; 8192]));
    assert!(store.get(&bob, "key").await.unwrap().is_none());
    assert_eq!(engine.object_cache_stats().resident_projection_entries, 1);
    engine.close().unwrap();
}

#[tokio::test]
async fn many_owners_with_over_budget_overlays_leave_no_payload_side_map() {
    let dir = tempfile::tempdir().unwrap();
    let (engine, store) = fixture(dir.path(), 4096);
    for index in 0..64 {
        let owner = format!("owner-{index}");
        store.set(&owner, "key", vec![0x71; 8192]).await.unwrap();
        assert_eq!(
            store.get(&owner, "key").await.unwrap(),
            Some(vec![0x71; 8192])
        );
        assert_eq!(engine.object_cache_stats().resident_projection_bytes, 0);
        assert!(engine.object_cache_stats().resident_bytes <= 4096);
        assert_eq!(store.clear_owner(&owner).unwrap(), 1);
    }
    assert!(store.validation.trees.lock().is_empty());
    engine.close().unwrap();
}

#[tokio::test]
async fn disabled_cache_retains_no_overlay_nodes_after_a_header_read() {
    let dir = tempfile::tempdir().unwrap();
    let (engine, store) = fixture(dir.path(), 0);
    let owner = "owner".to_owned();
    store.set(&owner, "key", vec![0x42; 8192]).await.unwrap();
    let header = store.blocking_store().header(owner.clone()).unwrap();
    assert_eq!(
        header.overlay.root_strong_count(),
        1,
        "disabled cache must not retain an off-budget overlay clone"
    );
    drop(header);
    assert_eq!(engine.object_cache_stats().resident_projection_bytes, 0);
    assert_eq!(
        store.get(&owner, "key").await.unwrap(),
        Some(vec![0x42; 8192])
    );
    engine.close().unwrap();
}

#[tokio::test]
async fn mismatched_accelerator_head_falls_back_to_authenticated_deltas() {
    let dir = tempfile::tempdir().unwrap();
    let (engine, store) = fixture(dir.path(), 512 * 1024);
    let owner = "owner".to_owned();
    store.set(&owner, "key", vec![0x31; 8192]).await.unwrap();
    let head = store
        .blocking_store()
        .header(owner.clone())
        .unwrap()
        .head
        .unwrap();
    assert!(engine.retain_kv_projection_cache(
        &owner,
        head,
        DECODED_KV_CACHE_KEY,
        ProjectionCacheEntry::new(Projection::empty())
    ));
    assert!(load(engine.as_ref(), &owner, head).is_none());
    assert_eq!(
        store.get(&owner, "key").await.unwrap(),
        Some(vec![0x31; 8192])
    );
    assert_eq!(
        load(engine.as_ref(), &owner, head).unwrap().head,
        Some(head)
    );
    engine.close().unwrap();
}
