use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use async_trait::async_trait;
use chrono::{TimeZone, Utc};
use ed25519_dalek::{Signer, SigningKey};
use tokio::sync::{Barrier, Notify};
use uuid::Uuid;

use super::*;
use crate::MemoryKvStore;
use astrid_core::{
    FirstOwnerClaim, FleetGenesis, PrincipalGenesis, PrincipalIdentity, UserGenesis,
};

#[derive(Debug)]
struct ReadBarrierKv {
    inner: MemoryKvStore,
    barrier: Barrier,
    reads_armed: AtomicBool,
    ownership_reads: AtomicUsize,
    ordered_cas_armed: AtomicBool,
    ownership_cas: AtomicUsize,
    first_cas_waiting: Notify,
    second_cas_done: Notify,
}

impl ReadBarrierKv {
    fn new() -> Self {
        Self {
            inner: MemoryKvStore::new(),
            barrier: Barrier::new(2),
            reads_armed: AtomicBool::new(false),
            ownership_reads: AtomicUsize::new(0),
            ordered_cas_armed: AtomicBool::new(false),
            ownership_cas: AtomicUsize::new(0),
            first_cas_waiting: Notify::new(),
            second_cas_done: Notify::new(),
        }
    }

    fn arm_reads(&self) {
        self.ownership_reads.store(0, Ordering::SeqCst);
        self.reads_armed.store(true, Ordering::SeqCst);
    }

    fn arm_ordered_cas(&self) {
        self.ownership_cas.store(0, Ordering::SeqCst);
        self.ordered_cas_armed.store(true, Ordering::SeqCst);
    }

    async fn wait_for_first_cas(&self) {
        self.first_cas_waiting.notified().await;
    }
}

#[async_trait]
impl KvStore for ReadBarrierKv {
    async fn get(&self, namespace: &str, key: &str) -> crate::StorageResult<Option<Vec<u8>>> {
        let value = self.inner.get(namespace, key).await?;
        if self.reads_armed.load(Ordering::SeqCst)
            && namespace == OWNERSHIP_NAMESPACE
            && key == GRAPH_KEY
            && self.ownership_reads.fetch_add(1, Ordering::SeqCst) < 2
        {
            self.barrier.wait().await;
        }
        Ok(value)
    }

    async fn set(&self, namespace: &str, key: &str, value: Vec<u8>) -> crate::StorageResult<()> {
        self.inner.set(namespace, key, value).await
    }

    async fn delete(&self, namespace: &str, key: &str) -> crate::StorageResult<bool> {
        self.inner.delete(namespace, key).await
    }

    async fn exists(&self, namespace: &str, key: &str) -> crate::StorageResult<bool> {
        self.inner.exists(namespace, key).await
    }

    async fn list_keys(&self, namespace: &str) -> crate::StorageResult<Vec<String>> {
        self.inner.list_keys(namespace).await
    }

    async fn compare_and_swap(
        &self,
        namespace: &str,
        key: &str,
        expected: Option<&[u8]>,
        new: Vec<u8>,
    ) -> crate::StorageResult<bool> {
        if self.ordered_cas_armed.load(Ordering::SeqCst)
            && namespace == OWNERSHIP_NAMESPACE
            && key == GRAPH_KEY
        {
            match self.ownership_cas.fetch_add(1, Ordering::SeqCst) {
                0 => {
                    self.first_cas_waiting.notify_one();
                    self.second_cas_done.notified().await;
                },
                1 => {
                    let result = self
                        .inner
                        .compare_and_swap(namespace, key, expected, new)
                        .await;
                    self.second_cas_done.notify_one();
                    return result;
                },
                _ => {},
            }
        }
        self.inner
            .compare_and_swap(namespace, key, expected, new)
            .await
    }

    async fn clear_namespace(&self, namespace: &str) -> crate::StorageResult<u64> {
        self.inner.clear_namespace(namespace).await
    }
}

fn at(seconds: i64) -> chrono::DateTime<Utc> {
    Utc.timestamp_opt(seconds, 0).single().unwrap()
}

fn fixture_nonce() -> [u8; 32] {
    let mut nonce = [0_u8; 32];
    getrandom::fill(&mut nonce).expect("fixture nonce");
    nonce
}

fn user(id: u128, key: u8) -> UserIdentity {
    UserIdentity::from_genesis(UserGenesis::from_parts(
        Uuid::from_u128(id),
        at(1_700_000_000),
        [key; 32],
    ))
    .unwrap()
}

fn fleet(id: u128, creator: UserUid) -> FleetIdentity {
    FleetIdentity::from_genesis(FleetGenesis::from_parts(
        Uuid::from_u128(id),
        at(1_700_000_001),
        creator,
    ))
    .unwrap()
}

fn principal(id: u128, key: u8) -> PrincipalUid {
    PrincipalIdentity::from_genesis(PrincipalGenesis::from_parts(
        Uuid::from_u128(id),
        at(1_700_000_002),
        [key; 32],
    ))
    .unwrap()
    .uid
}

async fn enrolled_store() -> (OwnershipStore, PrincipalDirectory) {
    let principals = PrincipalDirectory::default();
    let store = OwnershipStore::new(Arc::new(MemoryKvStore::new()), principals.clone()).unwrap();
    enroll_store(&store, &principals).await;
    (store, principals)
}

async fn enroll_store(store: &OwnershipStore, principals: &PrincipalDirectory) {
    let key = SigningKey::from_bytes(&[91; 32]);
    let bootstrap_user = UserIdentity::from_genesis(UserGenesis::from_parts(
        Uuid::from_u128(0xfeed),
        at(1_700_000_000),
        key.verifying_key().to_bytes(),
    ))
    .unwrap();
    let bootstrap_fleet = fleet(0xbeef, bootstrap_user.uid);
    let bootstrap_principal = principal(0xcafe, 92);
    admit_principal(principals, "bootstrap-principal", bootstrap_principal);
    let nonce = fixture_nonce();
    let unsigned = FirstOwnerClaim::from_parts(
        [41; 32],
        [42; 32],
        [43; 32],
        [44; 32],
        bootstrap_user.uid,
        bootstrap_fleet.uid,
        bootstrap_principal,
        key.verifying_key().to_bytes(),
        nonce,
        1,
        [0; 64],
    )
    .unwrap();
    let claim = FirstOwnerClaim::from_parts(
        *unsigned.machine_context(),
        *unsigned.boot_context(),
        *unsigned.kernel_identity(),
        *unsigned.system_generation(),
        unsigned.user_uid(),
        unsigned.fleet_uid(),
        unsigned.principal_uid(),
        *unsigned.initial_user_public_key(),
        *unsigned.nonce(),
        unsigned.authority_epoch().get(),
        key.sign(&unsigned.canonical_message()).to_bytes(),
    )
    .unwrap();
    assert_eq!(*claim.nonce(), nonce);
    store.begin_first_owner(claim).await.unwrap();
    store
        .commit_first_owner(claim, bootstrap_user, bootstrap_fleet)
        .await
        .unwrap();
}

fn admit_principal(directory: &PrincipalDirectory, alias: &str, uid: PrincipalUid) {
    directory
        .register(astrid_core::PrincipalId::new(alias).unwrap(), uid)
        .unwrap();
}

#[tokio::test]
async fn fleet_creation_atomically_bootstraps_its_owner() {
    let (store, _) = enrolled_store().await;
    let owner = user(1, 1);
    let owned_fleet = fleet(10, owner.uid);
    store.create_user(owner.clone()).await.unwrap();
    store.create_fleet(owned_fleet.clone()).await.unwrap();

    let graph = store.load().await.unwrap();
    let membership = graph
        .fleet(owned_fleet.uid)
        .unwrap()
        .membership(owner.uid)
        .unwrap();
    assert_eq!(membership.role, FleetRole::Owner);
    assert_eq!(membership.granted_by, owner.uid);
}

#[tokio::test]
async fn principal_cannot_be_silently_reassigned() {
    let (store, principals) = enrolled_store().await;
    let owner = user(1, 1);
    let first = fleet(10, owner.uid);
    let second = fleet(11, owner.uid);
    let principal_uid = principal(20, 2);
    admit_principal(&principals, "test-principal", principal_uid);
    store.create_user(owner.clone()).await.unwrap();
    store.create_fleet(first.clone()).await.unwrap();
    store.create_fleet(second.clone()).await.unwrap();
    store
        .assign_principal(PrincipalOwnership {
            principal_uid,
            fleet_uid: first.uid,
            assigned_by: owner.uid,
        })
        .await
        .unwrap();

    let error = store
        .assign_principal(PrincipalOwnership {
            principal_uid,
            fleet_uid: second.uid,
            assigned_by: owner.uid,
        })
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        OwnershipError::PrincipalAlreadyOwned { .. }
    ));
    assert_eq!(
        store
            .load()
            .await
            .unwrap()
            .principal_owner(principal_uid)
            .unwrap()
            .fleet_uid,
        first.uid
    );
}

#[tokio::test]
async fn explicit_transfer_requires_management_of_both_fleets() {
    let (store, principals) = enrolled_store().await;
    let first_owner = user(1, 1);
    let second_owner = user(2, 2);
    let first = fleet(10, first_owner.uid);
    let second = fleet(11, second_owner.uid);
    let principal_uid = principal(20, 3);
    admit_principal(&principals, "test-principal", principal_uid);
    store.create_user(first_owner.clone()).await.unwrap();
    store.create_user(second_owner.clone()).await.unwrap();
    store.create_fleet(first.clone()).await.unwrap();
    store.create_fleet(second.clone()).await.unwrap();
    store
        .assign_principal(PrincipalOwnership {
            principal_uid,
            fleet_uid: first.uid,
            assigned_by: first_owner.uid,
        })
        .await
        .unwrap();

    let denied = store
        .transfer_principal(principal_uid, first.uid, second.uid, first_owner.uid)
        .await
        .unwrap_err();
    assert!(matches!(denied, OwnershipError::NotFleetManager { .. }));

    store
        .set_membership(
            second.uid,
            first_owner.uid,
            FleetRole::Administrator,
            second_owner.uid,
        )
        .await
        .unwrap();
    store
        .transfer_principal(principal_uid, first.uid, second.uid, first_owner.uid)
        .await
        .unwrap();
    assert_eq!(
        store
            .load()
            .await
            .unwrap()
            .principal_owner(principal_uid)
            .unwrap()
            .fleet_uid,
        second.uid
    );
}

#[tokio::test]
async fn last_owner_cannot_be_demoted_or_removed() {
    let (store, _) = enrolled_store().await;
    let owner = user(1, 1);
    let owned_fleet = fleet(10, owner.uid);
    store.create_user(owner.clone()).await.unwrap();
    store.create_fleet(owned_fleet.clone()).await.unwrap();

    assert!(matches!(
        store
            .set_membership(owned_fleet.uid, owner.uid, FleetRole::Member, owner.uid)
            .await,
        Err(OwnershipError::LastOwner(_))
    ));
    assert!(matches!(
        store
            .remove_member(owned_fleet.uid, owner.uid, owner.uid)
            .await,
        Err(OwnershipError::LastOwner(_))
    ));
}

#[tokio::test]
async fn administrator_cannot_escalate_to_owner_or_remove_one() {
    let (store, _) = enrolled_store().await;
    let owner = user(1, 1);
    let administrator = user(2, 2);
    let owned_fleet = fleet(10, owner.uid);
    store.create_user(owner.clone()).await.unwrap();
    store.create_user(administrator.clone()).await.unwrap();
    store.create_fleet(owned_fleet.clone()).await.unwrap();
    store
        .set_membership(
            owned_fleet.uid,
            administrator.uid,
            FleetRole::Administrator,
            owner.uid,
        )
        .await
        .unwrap();

    assert!(matches!(
        store
            .set_membership(
                owned_fleet.uid,
                administrator.uid,
                FleetRole::Owner,
                administrator.uid,
            )
            .await,
        Err(OwnershipError::OwnerAuthorityRequired(_))
    ));
    assert!(matches!(
        store
            .remove_member(owned_fleet.uid, owner.uid, administrator.uid)
            .await,
        Err(OwnershipError::OwnerAuthorityRequired(_))
    ));
}

#[tokio::test]
async fn malformed_persisted_graph_fails_closed() {
    let backend = Arc::new(MemoryKvStore::new());
    let raw: Arc<dyn KvStore> = backend.clone();
    let store = OwnershipStore::new(raw, PrincipalDirectory::default()).unwrap();
    backend
        .set(OWNERSHIP_NAMESPACE, GRAPH_KEY, b"not-json".to_vec())
        .await
        .unwrap();
    assert!(matches!(
        store.load().await,
        Err(OwnershipError::Serialization(_))
    ));
}

#[tokio::test]
async fn concurrent_principal_assignments_do_not_lose_updates() {
    let backend = Arc::new(ReadBarrierKv::new());
    let raw: Arc<dyn KvStore> = backend.clone();
    let principals = PrincipalDirectory::default();
    let store = OwnershipStore::new(raw, principals.clone()).unwrap();
    enroll_store(&store, &principals).await;
    let owner = user(1, 1);
    let owned_fleet = fleet(10, owner.uid);
    let first = principal(20, 2);
    let second = principal(21, 3);
    admit_principal(&principals, "first-principal", first);
    admit_principal(&principals, "second-principal", second);
    store.create_user(owner.clone()).await.unwrap();
    store.create_fleet(owned_fleet.clone()).await.unwrap();

    let first_store = OwnershipStore::new(backend.clone(), principals.clone()).unwrap();
    let second_store = OwnershipStore::new(backend.clone(), principals.clone()).unwrap();
    backend.arm_reads();
    let (first_result, second_result) = tokio::join!(
        first_store.assign_principal(PrincipalOwnership {
            principal_uid: first,
            fleet_uid: owned_fleet.uid,
            assigned_by: owner.uid,
        }),
        second_store.assign_principal(PrincipalOwnership {
            principal_uid: second,
            fleet_uid: owned_fleet.uid,
            assigned_by: owner.uid,
        })
    );
    first_result.unwrap();
    second_result.unwrap();

    let graph = store.load().await.unwrap();
    assert_eq!(
        graph.principal_owner(first).unwrap().fleet_uid,
        owned_fleet.uid
    );
    assert_eq!(
        graph.principal_owner(second).unwrap().fleet_uid,
        owned_fleet.uid
    );
}

#[tokio::test]
async fn unknown_principals_are_rejected_on_assignment_and_reopen() {
    let backend = Arc::new(MemoryKvStore::new());
    let admitted = PrincipalDirectory::default();
    let raw: Arc<dyn KvStore> = backend.clone();
    let store = OwnershipStore::new(raw, admitted.clone()).unwrap();
    enroll_store(&store, &admitted).await;
    let owner = user(1, 1);
    let owned_fleet = fleet(10, owner.uid);
    let principal_uid = principal(20, 2);
    store.create_user(owner.clone()).await.unwrap();
    store.create_fleet(owned_fleet.clone()).await.unwrap();

    assert!(matches!(
        store
            .assign_principal(PrincipalOwnership {
                principal_uid,
                fleet_uid: owned_fleet.uid,
                assigned_by: owner.uid,
            })
            .await,
        Err(OwnershipError::PrincipalNotFound(uid)) if uid == principal_uid
    ));

    admit_principal(&admitted, "admitted-principal", principal_uid);
    store
        .assign_principal(PrincipalOwnership {
            principal_uid,
            fleet_uid: owned_fleet.uid,
            assigned_by: owner.uid,
        })
        .await
        .unwrap();

    let reopened = OwnershipStore::new(backend, PrincipalDirectory::default()).unwrap();
    assert!(matches!(
        reopened.load().await,
        Err(OwnershipError::CorruptGraph(message))
            if message.contains("absent from the admitted principal directory")
    ));
}

#[tokio::test]
async fn deletion_guard_serializes_assignment_with_directory_removal() {
    let backend = Arc::new(MemoryKvStore::new());
    let principals = PrincipalDirectory::default();
    let store = OwnershipStore::new(backend.clone(), principals.clone()).unwrap();
    let independently_opened = OwnershipStore::new(backend.clone(), principals.clone()).unwrap();
    enroll_store(&store, &principals).await;
    let owner = user(1, 1);
    let owned_fleet = fleet(10, owner.uid);
    let principal_uid = principal(20, 2);
    let alias = astrid_core::PrincipalId::new("deleting-principal").unwrap();
    principals.register(alias.clone(), principal_uid).unwrap();
    store.create_user(owner.clone()).await.unwrap();
    store.create_fleet(owned_fleet.clone()).await.unwrap();

    let deletion_guard = store.guard_principal_deletion(principal_uid).await.unwrap();
    let assignment = tokio::spawn(async move {
        independently_opened
            .assign_principal(PrincipalOwnership {
                principal_uid,
                fleet_uid: owned_fleet.uid,
                assigned_by: owner.uid,
            })
            .await
    });

    assert!(matches!(
        assignment.await.unwrap(),
        Err(OwnershipError::PrincipalDeletionInProgress(uid)) if uid == principal_uid
    ));
    principals.unregister(&alias, principal_uid);
    deletion_guard.finish().await.unwrap();
    assert!(
        store
            .load()
            .await
            .unwrap()
            .principal_owner(principal_uid)
            .is_none()
    );
}

#[tokio::test]
async fn deletion_reservation_can_be_finished_by_alias_after_identity_disappears() {
    let backend = Arc::new(MemoryKvStore::new());
    let principals = PrincipalDirectory::default();
    let store = OwnershipStore::new(backend.clone(), principals.clone()).unwrap();
    let independently_opened = OwnershipStore::new(backend, principals.clone()).unwrap();
    enroll_store(&store, &principals).await;
    let principal_uid = principal(20, 2);
    let alias = astrid_core::PrincipalId::new("recoverable-deletion").unwrap();
    principals.register(alias.clone(), principal_uid).unwrap();

    let guard = store
        .guard_principal_deletion_for_alias(principal_uid, alias.clone())
        .await
        .unwrap();
    assert!(matches!(
        independently_opened
            .finish_principal_deletion_by_alias(&alias)
            .await,
        Err(OwnershipError::PrincipalDeletionStillLive(uid)) if uid == principal_uid
    ));
    principals.unregister(&alias, principal_uid);
    drop(guard);

    assert!(
        store
            .finish_principal_deletion_by_alias(&alias)
            .await
            .unwrap()
    );
    assert!(
        !store
            .finish_principal_deletion_by_alias(&alias)
            .await
            .unwrap()
    );
    assert!(matches!(
        store.guard_principal_deletion(principal_uid).await,
        Err(OwnershipError::PrincipalNotFound(uid)) if uid == principal_uid
    ));
}

#[tokio::test]
async fn interrupted_deletion_reserves_alias_until_resumed_guard_finishes() {
    let backend = Arc::new(MemoryKvStore::new());
    let principals = PrincipalDirectory::default();
    let store = OwnershipStore::new(backend, principals.clone()).unwrap();
    enroll_store(&store, &principals).await;
    let principal_uid = principal(20, 2);
    let alias = astrid_core::PrincipalId::new("recoverable-deletion").unwrap();
    principals.register(alias.clone(), principal_uid).unwrap();
    let guard = store
        .guard_principal_deletion_for_alias(principal_uid, alias.clone())
        .await
        .unwrap();
    principals.unregister(&alias, principal_uid);
    drop(guard);

    assert!(matches!(
        store.ensure_alias_available(&alias).await,
        Err(OwnershipError::DeletionAliasReserved { principal, .. })
            if principal == principal_uid
    ));
    let resumed = store
        .resume_principal_deletion_by_alias(&alias)
        .await
        .unwrap()
        .expect("reservation exists");
    assert_eq!(resumed.principal_uid(), principal_uid);
    resumed.finish().await.unwrap();
    store.ensure_alias_available(&alias).await.unwrap();
}

#[tokio::test]
async fn legacy_alias_reservation_blocks_recreation_without_a_live_identity() {
    let backend = Arc::new(MemoryKvStore::new());
    let principals = PrincipalDirectory::default();
    let store = OwnershipStore::new(backend, principals.clone()).unwrap();
    enroll_store(&store, &principals).await;
    let alias = astrid_core::PrincipalId::new("legacy-partial-delete").unwrap();

    let guard = store
        .guard_legacy_alias_deletion(alias.clone())
        .await
        .unwrap();
    let reservation_uid = guard.principal_uid();
    drop(guard);

    assert!(matches!(
        store.ensure_alias_available(&alias).await,
        Err(OwnershipError::DeletionAliasReserved { principal, .. })
            if principal == reservation_uid
    ));
    let resumed = store
        .resume_principal_deletion_by_alias(&alias)
        .await
        .unwrap()
        .expect("legacy reservation exists");
    resumed.finish().await.unwrap();
    store.ensure_alias_available(&alias).await.unwrap();
}

#[tokio::test]
async fn deletion_reservation_rejects_a_second_deletion_for_the_same_alias() {
    let backend = Arc::new(MemoryKvStore::new());
    let principals = PrincipalDirectory::default();
    let store = OwnershipStore::new(backend, principals.clone()).unwrap();
    enroll_store(&store, &principals).await;
    let first = principal(20, 2);
    let second = principal(21, 3);
    let alias = astrid_core::PrincipalId::new("reserved-alias").unwrap();
    principals.register(alias.clone(), first).unwrap();

    let guard = store
        .guard_principal_deletion_for_alias(first, alias.clone())
        .await
        .unwrap();
    principals.unregister(&alias, first);
    drop(guard);
    principals.register(alias.clone(), second).unwrap();

    assert!(matches!(
        store
            .guard_principal_deletion_for_alias(second, alias.clone())
            .await,
        Err(OwnershipError::DeletionAliasReserved { principal, .. }) if principal == first
    ));
}

#[tokio::test]
async fn stale_assignment_retries_and_observes_deletion_reservation() {
    let backend = Arc::new(ReadBarrierKv::new());
    let principals = PrincipalDirectory::default();
    let store = OwnershipStore::new(backend.clone(), principals.clone()).unwrap();
    let independently_opened = OwnershipStore::new(backend.clone(), principals.clone()).unwrap();
    enroll_store(&store, &principals).await;
    let owner = user(1, 1);
    let owned_fleet = fleet(10, owner.uid);
    let principal_uid = principal(20, 2);
    let alias = astrid_core::PrincipalId::new("stale-assignment").unwrap();
    principals.register(alias.clone(), principal_uid).unwrap();
    store.create_user(owner.clone()).await.unwrap();
    store.create_fleet(owned_fleet.clone()).await.unwrap();

    backend.arm_ordered_cas();
    let assignment = tokio::spawn(async move {
        independently_opened
            .assign_principal(PrincipalOwnership {
                principal_uid,
                fleet_uid: owned_fleet.uid,
                assigned_by: owner.uid,
            })
            .await
    });
    backend.wait_for_first_cas().await;

    let deletion_guard = store.guard_principal_deletion(principal_uid).await.unwrap();
    assert!(matches!(
        assignment.await.unwrap(),
        Err(OwnershipError::PrincipalDeletionInProgress(uid)) if uid == principal_uid
    ));
    principals.unregister(&alias, principal_uid);
    deletion_guard.finish().await.unwrap();
    assert!(
        store
            .load()
            .await
            .unwrap()
            .principal_owner(principal_uid)
            .is_none()
    );
}
