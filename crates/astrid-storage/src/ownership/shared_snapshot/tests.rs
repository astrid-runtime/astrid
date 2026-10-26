use super::*;
use crate::{KvStore, MemoryKvStore, PrincipalDirectory, StorageResult};
use astrid_core::{
    FleetGenesis, FleetIdentity, PrincipalId, PrincipalOwnership, PrincipalUid, UserGenesis,
    UserIdentity,
};
use chrono::{TimeZone, Utc};
use std::sync::atomic::{AtomicUsize, Ordering};

async fn assigned() -> (
    OwnershipStore,
    Arc<MemoryKvStore>,
    PrincipalDirectory,
    PrincipalId,
    PrincipalUid,
) {
    let raw = Arc::new(MemoryKvStore::new());
    let directory = PrincipalDirectory::default();
    let alias = PrincipalId::new("shared-owner").unwrap();
    let uid = PrincipalUid::from_bytes([9; 32]);
    directory.register(alias.clone(), uid).unwrap();
    let store = OwnershipStore::new(raw.clone(), directory.clone()).unwrap();
    let now = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
    let user = UserIdentity::from_genesis(UserGenesis::from_parts(
        uuid::Uuid::from_u128(1),
        now,
        [1; 32],
    ))
    .unwrap();
    let fleet = FleetIdentity::from_genesis(FleetGenesis::from_parts(
        uuid::Uuid::from_u128(2),
        now,
        user.uid,
    ))
    .unwrap();
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
    (store, raw, directory, alias, uid)
}

#[tokio::test]
async fn shared_graph_tracks_external_bytes_and_drops_superseded_snapshots() {
    let (store, raw, directory, _, uid) = assigned().await;
    let first = store.load_shared().await.unwrap();
    assert!(Arc::ptr_eq(
        &first,
        &store.clone().load_shared().await.unwrap()
    ));
    let weak = Arc::downgrade(&first);
    let external = OwnershipStore::new(raw, directory).unwrap();
    let now = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
    let user = UserIdentity::from_genesis(UserGenesis::from_parts(
        uuid::Uuid::from_u128(3),
        now,
        [3; 32],
    ))
    .unwrap();
    external.create_user(user.clone()).await.unwrap();
    let next = store.load_shared().await.unwrap();
    assert!(!Arc::ptr_eq(&first, &next));
    assert!(next.user(user.uid).is_some());
    assert!(next.principal_owner(uid).is_some());
    assert!(
        first.user(user.uid).is_none(),
        "retained snapshots must be immutable"
    );
    drop(first);
    assert!(
        weak.upgrade().is_none(),
        "cache retained a superseded graph"
    );
    assert_eq!(store.load().await.unwrap(), *next);
}

#[tokio::test]
async fn unchanged_graph_is_revalidated_after_directory_removal_and_replacement() {
    let (store, _, directory, alias, uid) = assigned().await;
    let first = store.load_shared().await.unwrap();
    directory.unregister(&alias, uid);
    assert!(
        store.load_shared().await.is_err(),
        "cached graph bypassed directory removal"
    );
    directory.register(alias.clone(), uid).unwrap();
    let restored = store.load_shared().await.unwrap();
    assert_eq!(*first, *restored);
    directory.replace_all([]).unwrap();
    assert!(
        store.load_shared().await.is_err(),
        "cached graph bypassed whole-directory replacement"
    );
    directory.register(alias.clone(), uid).unwrap();
    store.load_shared().await.unwrap();
    directory
        .rename(uid, &alias, PrincipalId::new("renamed-owner").unwrap())
        .unwrap();
    assert!(
        store
            .load_shared()
            .await
            .unwrap()
            .principal_owner(uid)
            .is_some()
    );
}

#[tokio::test]
async fn invalid_or_empty_stored_bytes_never_fall_back_to_cached_authority() {
    let (store, raw, _, _, _) = assigned().await;
    let first = store.load_shared().await.unwrap();
    let valid = raw
        .get(super::super::OWNERSHIP_NAMESPACE, GRAPH_KEY)
        .await
        .unwrap()
        .unwrap();
    for invalid in [b"malformed".to_vec(), Vec::new(), b"{}".to_vec()] {
        raw.set(super::super::OWNERSHIP_NAMESPACE, GRAPH_KEY, invalid)
            .await
            .unwrap();
        assert!(store.load_shared().await.is_err());
    }
    raw.set(super::super::OWNERSHIP_NAMESPACE, GRAPH_KEY, valid)
        .await
        .unwrap();
    assert_eq!(*first, *store.load_shared().await.unwrap());
    raw.delete(super::super::OWNERSHIP_NAMESPACE, GRAPH_KEY)
        .await
        .unwrap();
    assert_eq!(
        *store.load_shared().await.unwrap(),
        OwnershipSnapshot::default()
    );
    raw.set(super::super::OWNERSHIP_NAMESPACE, GRAPH_KEY, Vec::new())
        .await
        .unwrap();
    assert!(
        store.load_shared().await.is_err(),
        "missing and present-empty must differ"
    );
}

#[test]
fn directory_revision_changes_only_for_successful_state_changes() {
    let directory = PrincipalDirectory::default();
    let initial = directory.revision();
    let alias = PrincipalId::new("revision").unwrap();
    let uid = PrincipalUid::from_bytes([4; 32]);
    directory.register(alias.clone(), uid).unwrap();
    let registered = directory.revision();
    assert_ne!(initial, registered);
    directory.register(alias.clone(), uid).unwrap();
    assert_eq!(registered, directory.revision());
    assert!(
        directory
            .register(alias.clone(), PrincipalUid::from_bytes([5; 32]))
            .is_err()
    );
    assert_eq!(registered, directory.revision());
    directory
        .rename(uid, &alias, PrincipalId::new("revision-renamed").unwrap())
        .unwrap();
    let renamed = directory.revision();
    assert_ne!(registered, renamed);
    directory.replace_all([(alias.clone(), uid)]).unwrap();
    let replaced = directory.revision();
    assert_ne!(renamed, replaced);
    directory.unregister(&alias, uid);
    assert_ne!(replaced, directory.revision());
}

#[derive(Default)]
struct ConcurrentReads {
    inner: MemoryKvStore,
    active: AtomicUsize,
    peak: AtomicUsize,
    reads: AtomicUsize,
}

#[async_trait::async_trait]
impl KvStore for ConcurrentReads {
    async fn get(&self, namespace: &str, key: &str) -> StorageResult<Option<Vec<u8>>> {
        let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(active, Ordering::SeqCst);
        self.reads.fetch_add(1, Ordering::SeqCst);
        tokio::task::yield_now().await;
        let value = self.inner.get(namespace, key).await;
        self.active.fetch_sub(1, Ordering::SeqCst);
        value
    }
    async fn set(&self, namespace: &str, key: &str, value: Vec<u8>) -> StorageResult<()> {
        self.inner.set(namespace, key, value).await
    }
    async fn delete(&self, namespace: &str, key: &str) -> StorageResult<bool> {
        self.inner.delete(namespace, key).await
    }
    async fn exists(&self, namespace: &str, key: &str) -> StorageResult<bool> {
        self.inner.exists(namespace, key).await
    }
    async fn list_keys(&self, namespace: &str) -> StorageResult<Vec<String>> {
        self.inner.list_keys(namespace).await
    }
    async fn compare_and_swap(
        &self,
        namespace: &str,
        key: &str,
        expected: Option<&[u8]>,
        new: Vec<u8>,
    ) -> StorageResult<bool> {
        self.inner
            .compare_and_swap(namespace, key, expected, new)
            .await
    }
    async fn clear_namespace(&self, namespace: &str) -> StorageResult<u64> {
        self.inner.clear_namespace(namespace).await
    }
}

#[tokio::test]
async fn concurrent_cold_loads_share_one_decode_and_fetch_current_bytes_each_time() {
    let (_, seeded, directory, _, _) = assigned().await;
    let bytes = seeded
        .get(super::super::OWNERSHIP_NAMESPACE, GRAPH_KEY)
        .await
        .unwrap()
        .unwrap();
    let raw = Arc::new(ConcurrentReads::default());
    raw.inner
        .set(super::super::OWNERSHIP_NAMESPACE, GRAPH_KEY, bytes)
        .await
        .unwrap();
    let store = OwnershipStore::new(raw.clone(), directory).unwrap();
    let mut tasks = Vec::new();
    for _ in 0..64 {
        let cloned = store.clone();
        tasks.push(tokio::spawn(
            async move { cloned.load_shared().await.unwrap() },
        ));
    }
    let first = tasks.remove(0).await.unwrap();
    for task in tasks {
        assert!(Arc::ptr_eq(&first, &task.await.unwrap()));
    }
    assert_eq!(
        raw.peak.load(Ordering::SeqCst),
        1,
        "concurrent callers retained separate raw graph buffers"
    );
    assert_eq!(
        raw.reads.load(Ordering::SeqCst),
        64,
        "cache skipped current authority reads"
    );
}

#[tokio::test]
async fn directory_change_after_cache_selection_cannot_return_old_authority() {
    let (store, _, directory, alias, uid) = assigned().await;
    let cached = store.load_shared().await.unwrap();
    let selected_revision = directory.revision();
    // Force the interleaving between selecting the cached graph and the
    // final return fence. This is the same helper used by every load.
    directory.unregister(&alias, uid);
    assert!(
        store
            .confirm_directory(&cached, selected_revision)
            .await
            .is_err(),
        "directory drift returned authority validated before retirement"
    );
}
