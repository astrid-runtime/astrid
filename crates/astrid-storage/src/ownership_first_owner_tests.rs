use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use chrono::{TimeZone, Utc};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::Value;
use uuid::Uuid;

use super::*;
use crate::{KvStore, MemoryKvStore, StorageError, StorageResult};
use astrid_core::{
    FirstOwnerClaim, FleetGenesis, FleetIdentity, PrincipalGenesis, PrincipalIdentity, UserGenesis,
    UserIdentity,
};

fn at(seconds: i64) -> chrono::DateTime<Utc> {
    Utc.timestamp_opt(seconds, 0).single().unwrap()
}

struct Fixture {
    backend: Arc<MemoryKvStore>,
    store: OwnershipStore,
    principals: PrincipalDirectory,
    claim: FirstOwnerClaim,
    user: UserIdentity,
    fleet: FleetIdentity,
    principal_uid: astrid_core::PrincipalUid,
}

struct FailOnceKv {
    inner: MemoryKvStore,
    fail_next_cas: AtomicBool,
}

impl FailOnceKv {
    fn new() -> Self {
        Self {
            inner: MemoryKvStore::new(),
            fail_next_cas: AtomicBool::new(false),
        }
    }

    fn fail_next_cas(&self) {
        self.fail_next_cas.store(true, Ordering::SeqCst);
    }
}

#[async_trait]
impl KvStore for FailOnceKv {
    async fn get(&self, namespace: &str, key: &str) -> StorageResult<Option<Vec<u8>>> {
        self.inner.get(namespace, key).await
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
        if self.fail_next_cas.swap(false, Ordering::SeqCst) {
            return Err(StorageError::Internal(
                "injected first-owner CAS failure".to_owned(),
            ));
        }
        self.inner
            .compare_and_swap(namespace, key, expected, new)
            .await
    }

    async fn clear_namespace(&self, namespace: &str) -> StorageResult<u64> {
        self.inner.clear_namespace(namespace).await
    }
}

fn fixture() -> Fixture {
    let backend = Arc::new(MemoryKvStore::new());
    let principals = PrincipalDirectory::default();
    let store = OwnershipStore::new(backend.clone(), principals.clone()).unwrap();
    let signing_key = SigningKey::from_bytes(&[7; 32]);
    let user = UserIdentity::from_genesis(UserGenesis::from_parts(
        Uuid::from_u128(1),
        at(1_700_000_000),
        signing_key.verifying_key().to_bytes(),
    ))
    .unwrap();
    let fleet = FleetIdentity::from_genesis(FleetGenesis::from_parts(
        Uuid::from_u128(2),
        at(1_700_001_000),
        user.uid,
    ))
    .unwrap();
    let principal_uid = PrincipalIdentity::from_genesis(PrincipalGenesis::from_parts(
        Uuid::from_u128(3),
        at(1_700_002_000),
        [9; 32],
    ))
    .unwrap()
    .uid;
    let unsigned = FirstOwnerClaim::from_parts(
        [1; 32],
        [2; 32],
        [3; 32],
        [4; 32],
        user.uid,
        fleet.uid,
        principal_uid,
        user.genesis.initial_public_key,
        [5; 32],
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
        signing_key.sign(&unsigned.canonical_message()).to_bytes(),
    )
    .unwrap();
    principals
        .register(
            astrid_core::PrincipalId::new("root").unwrap(),
            principal_uid,
        )
        .unwrap();
    Fixture {
        backend,
        store,
        principals,
        claim,
        user,
        fleet,
        principal_uid,
    }
}

#[tokio::test]
async fn begin_is_pending_only_and_commit_is_one_atomic_transition() {
    let fixture = fixture();
    assert_eq!(
        fixture
            .store
            .begin_first_owner(fixture.claim)
            .await
            .unwrap(),
        FirstOwnerEnrollment::Pending {
            claim: fixture.claim
        }
    );
    let pending = fixture.store.load().await.unwrap();
    assert!(pending.principal_owners().next().is_none());
    assert!(pending.fleets().next().is_none());

    // Reopen a fresh store handle before the commit: a crash after Begin must
    // leave durable Pending with no authority edges, while a later Commit
    // publishes all edges in one graph CAS.
    let reopened =
        OwnershipStore::new(fixture.backend.clone(), fixture.principals.clone()).unwrap();
    assert!(reopened.first_owner_state().await.unwrap().is_pending());
    let enrolled = reopened
        .commit_first_owner(fixture.claim, fixture.user.clone(), fixture.fleet.clone())
        .await
        .unwrap();
    assert!(enrolled.is_enrolled());
    let fresh = OwnershipStore::new(fixture.backend.clone(), fixture.principals.clone()).unwrap();
    let graph = fresh.load().await.unwrap();
    assert_eq!(
        graph
            .principal_owner(fixture.principal_uid)
            .unwrap()
            .fleet_uid,
        fixture.fleet.uid
    );
    assert_eq!(
        graph
            .fleet(fixture.fleet.uid)
            .unwrap()
            .membership(fixture.user.uid)
            .unwrap()
            .role,
        FleetRole::Owner
    );
}

#[tokio::test]
async fn exact_replay_is_idempotent_but_different_replay_is_rejected() {
    let fixture = fixture();
    fixture
        .store
        .begin_first_owner(fixture.claim)
        .await
        .unwrap();
    fixture
        .store
        .commit_first_owner(fixture.claim, fixture.user.clone(), fixture.fleet.clone())
        .await
        .unwrap();
    assert_eq!(
        fixture
            .store
            .begin_first_owner(fixture.claim)
            .await
            .unwrap(),
        FirstOwnerEnrollment::Enrolled {
            claim: fixture.claim
        }
    );

    let signing_key = SigningKey::from_bytes(&[7; 32]);
    let mut changed = fixture.claim;
    let mut nonce = *changed.nonce();
    nonce[0] ^= 1;
    let unsigned = FirstOwnerClaim::from_parts(
        *changed.machine_context(),
        *changed.boot_context(),
        *changed.kernel_identity(),
        *changed.system_generation(),
        changed.user_uid(),
        changed.fleet_uid(),
        changed.principal_uid(),
        *changed.initial_user_public_key(),
        nonce,
        changed.authority_epoch().get(),
        [0; 64],
    )
    .unwrap();
    changed = FirstOwnerClaim::from_parts(
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
        signing_key.sign(&unsigned.canonical_message()).to_bytes(),
    )
    .unwrap();
    assert!(matches!(
        fixture.store.begin_first_owner(changed).await,
        Err(OwnershipError::FirstOwner(FirstOwnerError::AlreadyEnrolled))
    ));
}

#[tokio::test]
async fn injected_commit_cas_failure_leaves_only_pending_state() {
    let source = fixture();
    let backend = Arc::new(FailOnceKv::new());
    let store = OwnershipStore::new(backend.clone(), source.principals.clone()).unwrap();
    store.begin_first_owner(source.claim).await.unwrap();
    backend.fail_next_cas();
    assert!(matches!(
        store
            .commit_first_owner(source.claim, source.user.clone(), source.fleet.clone())
            .await,
        Err(OwnershipError::Storage(StorageError::Internal(message)))
            if message == "injected first-owner CAS failure"
    ));
    let pending = store.load().await.unwrap();
    assert!(pending.first_owner_state().is_pending());
    assert!(pending.fleets().next().is_none());
    assert!(pending.principal_owners().next().is_none());
    assert!(
        store
            .commit_first_owner(source.claim, source.user, source.fleet)
            .await
            .unwrap()
            .is_enrolled()
    );
}

#[tokio::test]
async fn tampered_pending_claim_fails_closed_on_reopen() {
    let fixture = fixture();
    fixture
        .store
        .begin_first_owner(fixture.claim)
        .await
        .unwrap();
    let raw = fixture
        .backend
        .get(super::OWNERSHIP_NAMESPACE, super::GRAPH_KEY)
        .await
        .unwrap()
        .unwrap();
    let mut json: Value = serde_json::from_slice(&raw).unwrap();
    json["enrollment"]["Pending"]["claim"]["signature"] = Value::String("00".repeat(64));
    fixture
        .backend
        .set(
            super::OWNERSHIP_NAMESPACE,
            super::GRAPH_KEY,
            serde_json::to_vec(&json).unwrap(),
        )
        .await
        .unwrap();
    assert!(matches!(
        fixture.store.load().await,
        Err(OwnershipError::FirstOwner(FirstOwnerError::Claim(
            astrid_core::FirstOwnerClaimError::InvalidSignature
        )))
    ));
}

#[tokio::test]
async fn commit_revalidates_deletion_and_directory_identity() {
    let fixture = fixture();
    fixture
        .store
        .begin_first_owner(fixture.claim)
        .await
        .unwrap();
    let guard = fixture
        .store
        .guard_principal_deletion_for_alias(
            fixture.principal_uid,
            astrid_core::PrincipalId::new("root").unwrap(),
        )
        .await
        .unwrap();
    // The guard serializes the deletion reservation write with ownership
    // mutations. Drop it after the reservation is durable so the commit can
    // observe the reservation rather than waiting on the exclusive barrier.
    drop(guard);
    assert!(matches!(
        fixture
            .store
            .commit_first_owner(fixture.claim, fixture.user.clone(), fixture.fleet.clone())
            .await,
        Err(OwnershipError::FirstOwner(
            FirstOwnerError::PrincipalDeletionInProgress
        ))
    ));
    fixture.principals.unregister(
        &astrid_core::PrincipalId::new("root").unwrap(),
        fixture.principal_uid,
    );
    assert!(matches!(
        fixture
            .store
            .ensure_alias_available(&astrid_core::PrincipalId::new("root").unwrap())
            .await,
        Err(OwnershipError::DeletionAliasReserved { .. })
    ));
    let replacement = PrincipalIdentity::from_genesis(PrincipalGenesis::from_parts(
        Uuid::from_u128(4),
        at(1_700_003_000),
        [10; 32],
    ))
    .unwrap();
    fixture
        .principals
        .register(
            astrid_core::PrincipalId::new("root").unwrap(),
            replacement.uid,
        )
        .unwrap();
    assert!(matches!(
        fixture
            .store
            .commit_first_owner(fixture.claim, fixture.user.clone(), fixture.fleet.clone())
            .await,
        Err(OwnershipError::FirstOwner(
            FirstOwnerError::PrincipalNotAdmitted
        ))
    ));
}

#[tokio::test]
async fn concurrent_different_claims_have_one_pending_winner() {
    let fixture = fixture();
    let signing_key = SigningKey::from_bytes(&[7; 32]);
    let mut unsigned = fixture.claim;
    let mut nonce = *unsigned.nonce();
    nonce[0] ^= 1;
    unsigned = FirstOwnerClaim::from_parts(
        *unsigned.machine_context(),
        *unsigned.boot_context(),
        *unsigned.kernel_identity(),
        *unsigned.system_generation(),
        unsigned.user_uid(),
        unsigned.fleet_uid(),
        unsigned.principal_uid(),
        *unsigned.initial_user_public_key(),
        nonce,
        unsigned.authority_epoch().get(),
        [0; 64],
    )
    .unwrap();
    let changed_claim = FirstOwnerClaim::from_parts(
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
        signing_key.sign(&unsigned.canonical_message()).to_bytes(),
    )
    .unwrap();
    let left = OwnershipStore::new(fixture.backend.clone(), fixture.principals.clone()).unwrap();
    let right = OwnershipStore::new(fixture.backend.clone(), fixture.principals.clone()).unwrap();
    let (first, second) = tokio::join!(
        left.begin_first_owner(fixture.claim),
        right.begin_first_owner(changed_claim),
    );
    assert!(first.is_ok() ^ second.is_ok());
    let error = if let Err(error) = first {
        error
    } else {
        second.unwrap_err()
    };
    assert!(matches!(
        error,
        OwnershipError::FirstOwner(FirstOwnerError::Replay)
    ));
}

#[tokio::test]
async fn empty_legacy_graph_migrates_but_legacy_authority_fails_closed() {
    let fixture = fixture();
    fixture
        .backend
        .set(
            super::OWNERSHIP_NAMESPACE,
            super::GRAPH_KEY,
            br#"{"format_version":1,"users":{},"fleets":{},"principal_ownership":{},"principal_deletions":{}}"#.to_vec(),
        )
        .await
        .unwrap();
    assert_eq!(
        fixture.store.first_owner_state().await.unwrap(),
        FirstOwnerEnrollment::Unenrolled
    );

    fixture
        .store
        .create_user(fixture.user.clone())
        .await
        .unwrap();
    fixture
        .store
        .create_fleet(fixture.fleet.clone())
        .await
        .unwrap();
    fixture
        .store
        .assign_principal(astrid_core::PrincipalOwnership {
            principal_uid: fixture.principal_uid,
            fleet_uid: fixture.fleet.uid,
            assigned_by: fixture.user.uid,
        })
        .await
        .unwrap();
    let raw = fixture
        .backend
        .get(super::OWNERSHIP_NAMESPACE, super::GRAPH_KEY)
        .await
        .unwrap()
        .unwrap();
    let mut json: Value = serde_json::from_slice(&raw).unwrap();
    json["format_version"] = Value::from(1);
    json.as_object_mut().unwrap().remove("enrollment");
    fixture
        .backend
        .set(
            super::OWNERSHIP_NAMESPACE,
            super::GRAPH_KEY,
            serde_json::to_vec(&json).unwrap(),
        )
        .await
        .unwrap();
    assert!(matches!(
        fixture.store.load().await,
        Err(OwnershipError::LegacyOwnershipRequiresEnrollment)
    ));
}
