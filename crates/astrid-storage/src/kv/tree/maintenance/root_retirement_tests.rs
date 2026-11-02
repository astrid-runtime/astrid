//! An already admitted checkpoint must respect whole-root retirement.

use super::*;
use astrid_core::PrincipalUid;

use crate::content::PrincipalContentStore;
use crate::engine::{DurableEngine, RecoveryLimits};
use crate::kv::{KvStore, TreeKvStore};
use crate::principal_state::{Blake3ObjectIdentityV1, StateOwner, StateOwnerCodecV2};
use crate::{ContentName, StorageError, StorageResult};

#[tokio::test]
async fn admitted_checkpoint_cannot_restore_removed_root_or_retired_projections() {
    let directory = tempfile::tempdir().unwrap();
    let open = || {
        DurableEngine::open(
            directory.path(),
            Blake3ObjectIdentityV1,
            StateOwnerCodecV2,
            RecoveryLimits::process_addressable(),
        )
        .unwrap()
    };
    let engine = Arc::new(open());
    let owner = StateOwner::Principal(PrincipalUid::from_bytes([0xC1; 32]));
    let peer = StateOwner::Principal(PrincipalUid::from_bytes([0xC2; 32]));
    let store = TreeKvStore::<_, Blake3ObjectIdentityV1, _, _>::from_engine(
        Arc::clone(&engine),
        move |namespace: &str| {
            crate::kv::validate_namespace(namespace)?;
            Ok(if namespace == "retiring" { owner } else { peer })
        },
    );
    let content = PrincipalContentStore::from_engine_with_quota_and_validation(
        Arc::clone(&engine),
        Arc::new(|_: &StateOwner| Ok(None)),
        Arc::clone(&store.validated_content),
        Arc::clone(&store.validation),
    );
    store
        .set("retiring", "key", b"private".to_vec())
        .await
        .unwrap();
    store
        .set("peer", "key", b"peer bytes".to_vec())
        .await
        .unwrap();
    let name = ContentName::new("immutable-content").unwrap();
    content.put(&owner, &name, b"read lease bytes").unwrap();
    let lease = content.open_read(&owner, &name).unwrap().unwrap();
    let peer_root = engine.root(&peer).unwrap();
    let blocking = store.blocking_store();
    let registration = CheckpointRegistration::acquire(blocking.clone(), owner).unwrap();
    let checkpoint = blocking
        .checkpoint_once_after(owner, true, || -> StorageResult<()> {
            let root = engine.root(&owner).unwrap().unwrap();
            engine
                .remove_root(&owner, root)
                .map_err(|error| StorageError::Internal(error.to_string()))?;
            store.forget_retired_owner(&owner);
            content.forget_owner_projection_state(&owner);
            Ok(())
        })
        .unwrap();
    assert!(
        !checkpoint,
        "an admitted checkpoint restored the retired root"
    );
    drop(registration);
    assert!(engine.root(&owner).unwrap().is_none());
    assert!(!store.validation.trees.lock().contains_key(&owner));
    assert!(!store.validation.projections.lock().contains_key(&owner));
    assert!(!store.validated_content.lock().contains_key(&owner));
    assert!(store.checkpointing.lock().is_empty());
    assert_eq!(engine.root(&peer).unwrap(), peer_root);
    assert_eq!(
        store.get("peer", "key").await.unwrap(),
        Some(b"peer bytes".to_vec())
    );
    assert_eq!(lease.read().unwrap(), b"read lease bytes");
    engine.close().unwrap();
    let reopened = open();
    assert!(reopened.root(&owner).unwrap().is_none());
    assert_eq!(reopened.root(&peer).unwrap(), peer_root);
    reopened.close().unwrap();
}
