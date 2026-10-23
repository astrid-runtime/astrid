//! Crash/retry proof for multi-owner immutable UID retirement.

use std::sync::Arc;

use astrid_core::dirs::AstridHome;
use astrid_core::principal::PrincipalId;
use astrid_core::{FleetUid, PrincipalUid};

use crate::principal_state::{RuntimePrincipalStore, StateOwner, open_runtime_principal_store};
use crate::{
    CapsuleInstallExpectation, CapsulePackage, ContentName, KvQuotaResolver, OwnershipError,
    OwnershipStore, PrincipalDeletionGuard, WorkspaceBranchStore, WorkspaceUid,
};

struct RetirementRetryFixture {
    home: AstridHome,
    _directory: tempfile::TempDir,
    store: RuntimePrincipalStore,
    ownership: OwnershipStore,
    deletion: PrincipalDeletionGuard,
    uid: PrincipalUid,
    peer: PrincipalUid,
    alias: PrincipalId,
    private: ContentName,
    peer_package: CapsulePackage,
    fleets: [StateOwner; 2],
    audit_bytes: Vec<u8>,
}

fn unlimited_quota() -> Arc<dyn KvQuotaResolver<StateOwner>> {
    Arc::new(|_: &StateOwner| Ok(None))
}

async fn open_store(home: &AstridHome) -> RuntimePrincipalStore {
    open_runtime_principal_store(home, unlimited_quota())
        .await
        .unwrap()
}

async fn seed_retry_fixture() -> RetirementRetryFixture {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let store = open_store(&home).await;
    let uid = PrincipalUid::from_bytes([0x91; 32]);
    let peer = PrincipalUid::from_bytes([0x92; 32]);
    let alias = PrincipalId::new("retry-retired").unwrap();
    store
        .principal_directory()
        .register(alias.clone(), uid)
        .unwrap();
    store
        .principal_directory()
        .register(PrincipalId::new("retry-peer").unwrap(), peer)
        .unwrap();

    let ownership = OwnershipStore::new(store.kv(), store.principal_directory()).unwrap();
    let deletion = ownership
        .guard_principal_deletion_for_alias(uid, alias.clone())
        .await
        .unwrap();

    let audit_bytes = b"system audit retained across retry".to_vec();
    store
        .system_control_kv("audit")
        .unwrap()
        .set("principal-chain:retry", audit_bytes.clone())
        .await
        .unwrap();

    let private = ContentName::new("private-content").unwrap();
    store
        .content()
        .put(&StateOwner::Principal(uid), &private, b"retire-me")
        .unwrap();
    store
        .content()
        .put(&StateOwner::Principal(peer), &private, b"peer-keep")
        .unwrap();

    let peer_package = CapsulePackage::new(vec![2, 1], vec![2, 2], vec![2, 3]);
    install_packages(&store, uid, peer, &peer_package);
    let fleets = [
        StateOwner::Fleet(FleetUid::from_bytes([0x21; 32])),
        StateOwner::Fleet(FleetUid::from_bytes([0x22; 32])),
    ];
    seed_fleet_bindings(&store, uid, peer, &fleets);

    RetirementRetryFixture {
        home,
        _directory: directory,
        store,
        ownership,
        deletion,
        uid,
        peer,
        alias,
        private,
        peer_package,
        fleets,
        audit_bytes,
    }
}

fn install_packages(
    store: &RuntimePrincipalStore,
    uid: PrincipalUid,
    peer: PrincipalUid,
    peer_package: &CapsulePackage,
) {
    let registry = store.capsules();
    registry
        .install(
            &StateOwner::Principal(uid),
            "retired-cap",
            &CapsulePackage::new(vec![1, 1], vec![1, 2], vec![1, 3]),
            CapsuleInstallExpectation::Absent,
        )
        .unwrap();
    registry
        .install(
            &StateOwner::Principal(peer),
            "peer-cap",
            peer_package,
            CapsuleInstallExpectation::Absent,
        )
        .unwrap();
}

fn seed_fleet_bindings(
    store: &RuntimePrincipalStore,
    uid: PrincipalUid,
    peer: PrincipalUid,
    fleets: &[StateOwner; 2],
) {
    let branches = WorkspaceBranchStore::new(store.content());
    let prefix = ContentName::new("workspace/default").unwrap();
    for owner in fleets {
        let receipt = WorkspaceUid::random();
        branches
            .begin_for_uid_at(owner, uid, receipt, prefix.clone())
            .unwrap();
        branches.promote(owner, receipt).unwrap();
        branches
            .begin_for_uid_at(owner, uid, WorkspaceUid::random(), prefix.clone())
            .unwrap();
        branches
            .begin_for_uid_at(owner, peer, WorkspaceUid::random(), prefix.clone())
            .unwrap();
    }
}

fn drop_first_fleet_only(
    store: &RuntimePrincipalStore,
    uid: PrincipalUid,
    fleets: &[StateOwner; 2],
) {
    let branches = WorkspaceBranchStore::new(store.content());
    for binding in branches.list_bindings_by_uid(&fleets[0], uid).unwrap() {
        branches.drop(&fleets[0], binding.branch_id()).unwrap();
    }
    assert!(
        branches
            .list_bindings_by_uid(&fleets[0], uid)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        branches
            .list_bindings_by_uid(&fleets[1], uid)
            .unwrap()
            .len(),
        2
    );
    assert!(
        store
            .engine
            .root(&StateOwner::Principal(uid))
            .unwrap()
            .is_some()
    );
}

async fn reopen_under_reservation(
    home: &AstridHome,
    alias: &PrincipalId,
    uid: PrincipalUid,
) -> (
    RuntimePrincipalStore,
    OwnershipStore,
    PrincipalDeletionGuard,
) {
    let store = open_store(home).await;
    let ownership = OwnershipStore::new(store.kv(), store.principal_directory()).unwrap();
    assert!(matches!(
        ownership.ensure_alias_available(alias).await,
        Err(OwnershipError::DeletionAliasReserved { principal, .. }) if principal == uid
    ));
    let resumed = ownership
        .resume_principal_deletion_by_alias(alias)
        .await
        .unwrap()
        .expect("durable deletion reservation survives reopen");
    assert_eq!(resumed.principal_uid(), uid);
    (store, ownership, resumed)
}

fn assert_partial_progress_survived_reopen(
    store: &RuntimePrincipalStore,
    uid: PrincipalUid,
    fleets: &[StateOwner; 2],
) {
    let branches = WorkspaceBranchStore::new(store.content());
    assert!(
        branches
            .list_bindings_by_uid(&fleets[0], uid)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        branches
            .list_bindings_by_uid(&fleets[1], uid)
            .unwrap()
            .len(),
        2
    );
    assert!(
        store
            .engine
            .root(&StateOwner::Principal(uid))
            .unwrap()
            .is_some()
    );
}

fn assert_full_retirement(
    store: &RuntimePrincipalStore,
    uid: PrincipalUid,
    peer: PrincipalUid,
    fleets: &[StateOwner; 2],
    private: &ContentName,
    peer_package: &CapsulePackage,
) {
    let branches = WorkspaceBranchStore::new(store.content());
    for owner in fleets {
        assert!(
            branches
                .list_bindings_by_uid(owner, uid)
                .unwrap()
                .is_empty()
        );
        assert_eq!(branches.list_bindings_by_uid(owner, peer).unwrap().len(), 1);
    }
    assert!(
        store
            .engine
            .root(&StateOwner::Principal(uid))
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .content()
            .read(&StateOwner::Principal(uid), private)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store
            .content()
            .read(&StateOwner::Principal(peer), private)
            .unwrap(),
        Some(b"peer-keep".to_vec())
    );
    assert_eq!(
        store
            .capsules()
            .get(&StateOwner::Principal(uid), "retired-cap")
            .unwrap(),
        None
    );
    assert!(
        store
            .capsules()
            .list(&StateOwner::Principal(uid))
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        store
            .capsules()
            .get(&StateOwner::Principal(peer), "peer-cap")
            .unwrap(),
        Some(peer_package.clone())
    );
}

async fn assert_system_and_reservation(
    store: &RuntimePrincipalStore,
    ownership: &OwnershipStore,
    alias: &PrincipalId,
    uid: PrincipalUid,
    audit_bytes: &[u8],
) {
    assert_eq!(
        store
            .system_control_kv("audit")
            .unwrap()
            .get("principal-chain:retry")
            .await
            .unwrap(),
        Some(audit_bytes.to_vec())
    );
    assert!(matches!(
        ownership.ensure_alias_available(alias).await,
        Err(OwnershipError::DeletionAliasReserved { principal, .. }) if principal == uid
    ));
}

#[tokio::test]
async fn purge_retries_after_partial_fleet_cleanup_under_durable_reservation() {
    let fixture = seed_retry_fixture().await;
    drop_first_fleet_only(&fixture.store, fixture.uid, &fixture.fleets);

    fixture
        .store
        .principal_directory()
        .unregister(&fixture.alias, fixture.uid);
    drop(fixture.deletion);
    fixture.store.engine.close().unwrap();
    drop(fixture.ownership);
    drop(fixture.store);

    let (store, ownership, resumed) =
        reopen_under_reservation(&fixture.home, &fixture.alias, fixture.uid).await;
    assert_partial_progress_survived_reopen(&store, fixture.uid, &fixture.fleets);

    assert!(store.purge_principal_state(fixture.uid).unwrap());
    assert!(!store.purge_principal_state(fixture.uid).unwrap());
    assert_full_retirement(
        &store,
        fixture.uid,
        fixture.peer,
        &fixture.fleets,
        &fixture.private,
        &fixture.peer_package,
    );
    assert_system_and_reservation(
        &store,
        &ownership,
        &fixture.alias,
        fixture.uid,
        &fixture.audit_bytes,
    )
    .await;

    resumed.finish().await.unwrap();
    ownership
        .ensure_alias_available(&fixture.alias)
        .await
        .unwrap();
    store.engine.close().unwrap();
}
