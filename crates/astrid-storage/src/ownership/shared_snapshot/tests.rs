use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

use async_trait::async_trait;
use chrono::{TimeZone as _, Utc};
use tokio::sync::Notify;
use uuid::Uuid;

use super::super::*;
use crate::{MemoryKvStore, StorageResult};
use astrid_core::{FleetGenesis, UserGenesis};

#[derive(Debug, Default)]
struct ObservedKv {
    inner: MemoryKvStore,
    reads: AtomicUsize,
    fail: AtomicBool,
    block_next: AtomicBool,
    blocked: Notify,
    release: Notify,
}

#[async_trait]
impl KvStore for ObservedKv {
    async fn get(&self, namespace: &str, key: &str) -> StorageResult<Option<Vec<u8>>> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        if self.fail.load(Ordering::SeqCst) {
            return Err(StorageError::Internal("injected read failure".into()));
        }
        let raw = self.inner.get(namespace, key).await?;
        if self.block_next.swap(false, Ordering::SeqCst) {
            self.blocked.notify_one();
            self.release.notified().await;
        }
        Ok(raw)
    }
    async fn set(&self, n: &str, k: &str, v: Vec<u8>) -> StorageResult<()> {
        self.inner.set(n, k, v).await
    }
    async fn delete(&self, n: &str, k: &str) -> StorageResult<bool> {
        self.inner.delete(n, k).await
    }
    async fn exists(&self, n: &str, k: &str) -> StorageResult<bool> {
        self.inner.exists(n, k).await
    }
    async fn clear_namespace(&self, n: &str) -> StorageResult<u64> {
        self.inner.clear_namespace(n).await
    }
    async fn list_keys(&self, n: &str) -> StorageResult<Vec<String>> {
        self.inner.list_keys(n).await
    }
    async fn compare_and_swap(
        &self,
        n: &str,
        k: &str,
        expected: Option<&[u8]>,
        new: Vec<u8>,
    ) -> StorageResult<bool> {
        self.inner.compare_and_swap(n, k, expected, new).await
    }
}

fn fixture() -> (Arc<ObservedKv>, PrincipalDirectory, OwnershipStore) {
    let backend = Arc::new(ObservedKv::default());
    let directory = PrincipalDirectory::default();
    let store = OwnershipStore::new(backend.clone(), directory.clone()).unwrap();
    (backend, directory, store)
}

async fn populate(
    store: &OwnershipStore,
    directory: &PrincipalDirectory,
) -> (PrincipalId, PrincipalUid) {
    let at = Utc.timestamp_opt(1_700_000_000, 0).single().unwrap();
    let user = UserIdentity::from_genesis(UserGenesis::from_parts(Uuid::from_u128(1), at, [1; 32]))
        .unwrap();
    let fleet =
        FleetIdentity::from_genesis(FleetGenesis::from_parts(Uuid::from_u128(2), at, user.uid))
            .unwrap();
    let uid = PrincipalUid::from_bytes([3; 32]);
    let alias = PrincipalId::new("owner").unwrap();
    directory.register(alias.clone(), uid).unwrap();
    store.create_user(user.clone()).await.unwrap();
    store.create_fleet(fleet.clone()).await.unwrap();
    store
        .assign_principal(PrincipalOwnership {
            principal_uid: uid,
            fleet_uid: fleet.uid,
            assigned_by: user.uid,
        })
        .await
        .unwrap();
    (alias, uid)
}

#[tokio::test]
async fn shared_reads_fetch_every_time_and_share_only_with_clones() {
    let (backend, directory, store) = fixture();
    let first = store.load_shared().await.unwrap();
    let clone = store.clone().load_shared().await.unwrap();
    assert!(Arc::ptr_eq(&first, &clone));
    assert_eq!(backend.reads.load(Ordering::SeqCst), 2);
    let separate = OwnershipStore::new(backend, directory)
        .unwrap()
        .load_shared()
        .await
        .unwrap();
    assert!(!Arc::ptr_eq(&first, &separate));
}

#[tokio::test]
async fn same_bytes_revalidate_live_directory_without_discarding_decoded_graph() {
    let (_, directory, store) = fixture();
    let (alias, uid) = populate(&store, &directory).await;
    let first = store.load_shared().await.unwrap();
    directory.unregister(&alias, uid);
    assert!(store.load_shared().await.is_err());
    directory.register(alias.clone(), uid).unwrap();
    assert!(Arc::ptr_eq(&first, &store.load_shared().await.unwrap()));
    directory.replace_all([]).unwrap();
    assert!(store.load_shared().await.is_err());
    directory.replace_all([(alias, uid)]).unwrap();
    assert!(store.load_shared().await.is_ok());
}

#[tokio::test]
async fn external_changes_replace_one_slot_and_release_previous_graph() {
    let (backend, _, store) = fixture();
    let first = store.load_shared().await.unwrap();
    let old = Arc::downgrade(&first);
    let graph = OwnershipSnapshot {
        local_user_binding_initialized: true,
        ..OwnershipSnapshot::default()
    };
    backend
        .set(
            OWNERSHIP_NAMESPACE,
            GRAPH_KEY,
            serde_json::to_vec(&graph).unwrap(),
        )
        .await
        .unwrap();
    let next = store.load_shared().await.unwrap();
    assert!(!Arc::ptr_eq(&first, &next));
    assert!(!first.local_user_binding_initialized);
    assert!(next.local_user_binding_initialized);
    drop(first);
    assert!(old.upgrade().is_none());
    backend
        .delete(OWNERSHIP_NAMESPACE, GRAPH_KEY)
        .await
        .unwrap();
    assert!(
        !store
            .load_shared()
            .await
            .unwrap()
            .local_user_binding_initialized
    );
}

#[tokio::test]
async fn cached_graph_never_masks_bad_storage_or_document() {
    let (backend, _, store) = fixture();
    let first = store.load_shared().await.unwrap();
    backend.fail.store(true, Ordering::SeqCst);
    assert!(matches!(
        store.load_shared().await,
        Err(OwnershipError::Storage(_))
    ));
    backend.fail.store(false, Ordering::SeqCst);
    for bytes in [Vec::new(), b"{".to_vec(), b"{}".to_vec(), b"null".to_vec()] {
        backend
            .set(OWNERSHIP_NAMESPACE, GRAPH_KEY, bytes)
            .await
            .unwrap();
        assert!(store.load_shared().await.is_err());
    }
    let unsupported = OwnershipSnapshot {
        format_version: 2,
        ..OwnershipSnapshot::default()
    };
    backend
        .set(
            OWNERSHIP_NAMESPACE,
            GRAPH_KEY,
            serde_json::to_vec(&unsupported).unwrap(),
        )
        .await
        .unwrap();
    assert!(store.load_shared().await.is_err());
    backend
        .delete(OWNERSHIP_NAMESPACE, GRAPH_KEY)
        .await
        .unwrap();
    assert!(Arc::ptr_eq(&first, &store.load_shared().await.unwrap()));
}

#[tokio::test]
async fn blocked_storage_read_does_not_block_other_shared_readers() {
    let (backend, _, store) = fixture();
    store.load_shared().await.unwrap();
    backend.block_next.store(true, Ordering::SeqCst);
    let reader = store.clone();
    let first = tokio::spawn(async move { reader.load_shared().await });
    backend.blocked.notified().await;
    let second = tokio::time::timeout(std::time::Duration::from_secs(2), store.load_shared()).await;
    backend.release.notify_one();
    first.await.unwrap().unwrap();
    second
        .expect("second reader must reach storage independently")
        .unwrap();
}

#[tokio::test]
async fn late_old_read_cannot_hide_a_new_storage_generation() {
    let (backend, _, store) = fixture();
    backend.block_next.store(true, Ordering::SeqCst);
    let reader = store.clone();
    let old = tokio::spawn(async move { reader.load_shared().await });
    backend.blocked.notified().await;
    let graph = OwnershipSnapshot {
        local_user_binding_initialized: true,
        ..OwnershipSnapshot::default()
    };
    backend
        .set(
            OWNERSHIP_NAMESPACE,
            GRAPH_KEY,
            serde_json::to_vec(&graph).unwrap(),
        )
        .await
        .unwrap();
    assert!(
        store
            .load_shared()
            .await
            .unwrap()
            .local_user_binding_initialized
    );
    backend.release.notify_one();
    assert!(!old.await.unwrap().unwrap().local_user_binding_initialized);
    assert!(
        store
            .load_shared()
            .await
            .unwrap()
            .local_user_binding_initialized
    );
}

#[tokio::test]
async fn warmed_readers_do_not_supply_mutation_authority_or_mask_retirement() {
    let (backend, directory, store) = fixture();
    let (alias, uid) = populate(&store, &directory).await;
    let first = store.load_shared().await.unwrap();
    let owner = first.principal_owner(uid).unwrap().clone();
    let user = owner.assigned_by;
    let mut invalid = (*first).clone();
    invalid.principal_ownership.clear();
    backend
        .set(
            OWNERSHIP_NAMESPACE,
            GRAPH_KEY,
            serde_json::to_vec(&invalid).unwrap(),
        )
        .await
        .unwrap();
    assert!(store.assign_principal(owner).await.is_err());
    backend
        .set(
            OWNERSHIP_NAMESPACE,
            GRAPH_KEY,
            serde_json::to_vec(first.as_ref()).unwrap(),
        )
        .await
        .unwrap();
    assert!(store.capture_derived_ownership(uid).await.is_ok());
    store.ensure_alias_available(&alias).await.unwrap();
    store
        .bind_user_device(uid, [7; 32], user, user)
        .await
        .unwrap();
    let guard = store
        .guard_principal_deletion_for_device(uid, alias.clone(), uid, &[7; 32])
        .await
        .unwrap();
    drop(guard);
    assert!(matches!(
        store.ensure_alias_available(&alias).await,
        Err(OwnershipError::DeletionAliasReserved { .. })
    ));
    assert!(matches!(
        store.capture_derived_ownership(uid).await,
        Err(OwnershipError::PrincipalDeletionInProgress(_))
    ));
}
