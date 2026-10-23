//! Cache retirement must include work that was already admitted before purge.
use super::*;
use crate::content::PrincipalContentStore;
use crate::engine::InMemoryEngine;
use crate::kv::{KvStore, TreeKvStore};
use crate::principal_state::Blake3ObjectIdentityV1;
use crate::{ContentName, StorageResult};

type Engine = InMemoryEngine<String, Blake3ObjectIdentityV1>;
type Store = TreeKvStore<String, Blake3ObjectIdentityV1, fn(&str) -> StorageResult<String>, Engine>;

fn fixture() -> (Store, PrincipalContentStore<String, Engine>) {
    fn resolve(namespace: &str) -> StorageResult<String> {
        crate::kv::validate_namespace(namespace)?;
        Ok(namespace.to_owned())
    }
    let engine = Arc::new(Engine::new(Blake3ObjectIdentityV1));
    let store = Store::from_engine(Arc::clone(&engine), resolve);
    let content = PrincipalContentStore::from_engine_with_quota_and_validation(
        engine,
        Arc::new(|_: &String| Ok(None)),
        Arc::clone(&store.validated_content),
        Arc::clone(&store.validation),
    );
    (store, content)
}

fn assert_forgotten(store: &Store, owner: &String) {
    assert!(!store.validation.trees.lock().contains_key(owner));
    assert!(!store.validation.projections.lock().contains_key(owner));
    assert!(!store.validated_content.lock().contains_key(owner));
}

#[tokio::test]
async fn owner_churn_leaves_no_projection_cache_or_cleanup_tombstones() {
    let (store, content) = fixture();
    let name = ContentName::new("retained-content").unwrap();
    for index in 0..128 {
        let owner = format!("immutable-owner-{index}");
        store.set(&owner, "key", b"private".to_vec()).await.unwrap();
        content.put(&owner, &name, b"non-KV state").unwrap();
        assert_eq!(store.clear_owner(&owner).unwrap(), 1);
        assert_eq!(store.clear_owner(&owner).unwrap(), 0);
        assert_forgotten(&store, &owner);
        assert!(store.checkpointing.lock().is_empty());
    }
    assert!(store.validation.trees.lock().is_empty());
    assert!(store.validation.projections.lock().is_empty());
    assert!(store.validated_content.lock().is_empty());
}

#[tokio::test]
async fn purged_owner_pending_checkpoint_cannot_leave_repopulated_caches() {
    let (store, content) = fixture();
    let owner = "retiring".to_owned();
    let peer = "peer".to_owned();
    store.set(&owner, "key", b"private".to_vec()).await.unwrap();
    store
        .set(&peer, "key", b"peer state".to_vec())
        .await
        .unwrap();
    let name = ContentName::new("retained-content").unwrap();
    content.put(&owner, &name, b"non-KV state").unwrap();
    let lease = content.open_read(&owner, &name).unwrap().unwrap();
    let blocking = store.blocking_store();
    let registration = CheckpointRegistration::acquire(blocking.clone(), owner.clone()).unwrap();
    assert!(CheckpointRegistration::acquire(blocking.clone(), owner.clone()).is_none());
    blocking
        .checkpoint_once_after(owner.clone(), true, || {
            assert_eq!(store.clear_owner(&owner)?, 1);
            assert_forgotten(&store, &owner);
            Ok(())
        })
        .unwrap();
    // The admitted checkpoint's fresh header/commit may refill accelerators.
    assert!(store.validation.projections.lock().contains_key(&owner));
    assert!(store.validated_content.lock().contains_key(&owner));
    drop(registration);
    assert_forgotten(&store, &owner);
    assert!(store.checkpointing.lock().is_empty());
    assert_eq!(lease.read().unwrap(), b"non-KV state");
    assert!(store.get(&owner, "key").await.unwrap().is_none());
    assert_eq!(
        store.get(&peer, "key").await.unwrap(),
        Some(b"peer state".to_vec())
    );
}

#[tokio::test]
async fn ordinary_checkpoint_keeps_live_accelerators() {
    let (store, _) = fixture();
    let owner = "live".to_owned();
    store.set(&owner, "key", b"value".to_vec()).await.unwrap();
    let blocking = store.blocking_store();
    let registration = CheckpointRegistration::acquire(blocking.clone(), owner.clone()).unwrap();
    assert!(blocking.checkpoint_once(owner.clone(), true).unwrap());
    drop(registration);
    assert!(store.validation.projections.lock().contains_key(&owner));
    assert!(store.checkpointing.lock().is_empty());
}

#[tokio::test]
async fn unwinding_checkpoint_releases_retirement_cleanup_obligation() {
    let (store, _) = fixture();
    let owner = "retiring".to_owned();
    store.set(&owner, "key", b"value".to_vec()).await.unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _registration =
            CheckpointRegistration::acquire(store.blocking_store(), owner.clone()).unwrap();
        store.clear_owner(&owner).unwrap();
        store.blocking_store().header(owner.clone()).unwrap();
        panic!("injected checkpoint unwind");
    }));
    assert!(result.is_err());
    assert_forgotten(&store, &owner);
    assert!(store.checkpointing.lock().is_empty());
}

#[tokio::test]
async fn writer_request_before_atomic_completion_is_not_lost() {
    let (store, _) = fixture();
    let owner = "live".to_owned();
    let mut first = CheckpointRegistration::acquire(store.blocking_store(), owner.clone()).unwrap();
    // A writer requests maintenance after the worker's last root observation.
    assert!(CheckpointRegistration::acquire(store.blocking_store(), owner.clone()).is_none());
    assert!(
        !first.finish_or_retry(),
        "concurrent writer lost its maintenance wakeup"
    );
    assert!(store.checkpointing.lock().contains_key(&owner));
    assert!(first.finish_or_retry());
    assert!(store.checkpointing.lock().is_empty());
    // A request after atomic completion must queue fresh work. Dropping the old
    // completed registration must not remove that new owner's registration.
    let second = CheckpointRegistration::acquire(store.blocking_store(), owner.clone()).unwrap();
    drop(first);
    assert!(store.checkpointing.lock().contains_key(&owner));
    drop(second);
    assert!(store.checkpointing.lock().is_empty());
}
