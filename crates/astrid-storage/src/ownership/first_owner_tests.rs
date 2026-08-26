use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Barrier};

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

fn fixture_nonce() -> [u8; 32] {
    let mut nonce: [u8; 32] = std::array::from_fn(|_| 0_u8);
    getrandom::fill(&mut nonce).expect("fixture nonce");
    nonce
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
    let nonce = fixture_nonce();
    let unsigned = FirstOwnerClaim::from_parts(
        [1; 32],
        [2; 32],
        [3; 32],
        [4; 32],
        user.uid,
        fleet.uid,
        principal_uid,
        user.genesis.initial_public_key,
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
        signing_key.sign(&unsigned.canonical_message()).to_bytes(),
    )
    .unwrap();
    assert_eq!(*claim.nonce(), nonce);
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

fn signed_claim_with_expiry(
    fixture: &Fixture,
    authority_generation: u64,
    expires_at: u64,
    authority_epoch: u64,
) -> Result<FirstOwnerClaim, astrid_core::FirstOwnerClaimError> {
    let signing_key = SigningKey::from_bytes(&[7; 32]);
    let unsigned = FirstOwnerClaim::from_parts_with_authority(
        *fixture.claim.machine_context(),
        *fixture.claim.boot_context(),
        *fixture.claim.kernel_identity(),
        *fixture.claim.system_generation(),
        fixture.claim.user_uid(),
        fixture.claim.fleet_uid(),
        fixture.claim.principal_uid(),
        *fixture.claim.initial_user_public_key(),
        *fixture.claim.nonce(),
        authority_generation,
        expires_at,
        authority_epoch,
        [0; 64],
    )?;
    FirstOwnerClaim::from_parts_with_authority(
        *unsigned.machine_context(),
        *unsigned.boot_context(),
        *unsigned.kernel_identity(),
        *unsigned.system_generation(),
        unsigned.user_uid(),
        unsigned.fleet_uid(),
        unsigned.principal_uid(),
        *unsigned.initial_user_public_key(),
        *unsigned.nonce(),
        unsigned.authority_generation().get(),
        unsigned.expires_at(),
        unsigned.authority_epoch().get(),
        signing_key.sign(&unsigned.canonical_message()).to_bytes(),
    )
}

#[test]
fn zero_expiry_is_rejected_at_the_signed_claim_boundary() {
    let fixture = fixture();
    assert_eq!(
        signed_claim_with_expiry(&fixture, 1, 0, 1),
        Err(astrid_core::FirstOwnerClaimError::ZeroExpiry)
    );
}

#[tokio::test]
async fn begin_after_expiry_never_creates_pending_state() {
    let fixture = fixture();
    let claim = signed_claim_with_expiry(&fixture, 1, 10, 1).unwrap();
    assert!(matches!(
        fixture.store.begin_first_owner_at(claim, 10).await,
        Err(OwnershipError::FirstOwner(FirstOwnerError::Expired))
    ));
    assert_eq!(
        fixture.store.first_owner_state().await.unwrap(),
        FirstOwnerEnrollment::Unenrolled
    );
}

#[tokio::test]
async fn commit_after_expiry_leaves_only_pending_state() {
    let fixture = fixture();
    let claim = signed_claim_with_expiry(&fixture, 1, 10, 1).unwrap();
    fixture.store.begin_first_owner_at(claim, 9).await.unwrap();
    assert!(matches!(
        fixture
            .store
            .commit_first_owner_with_clock(
                &claim,
                fixture.user.clone(),
                fixture.fleet.clone(),
                || 10,
            )
            .await,
        Err(OwnershipError::FirstOwner(FirstOwnerError::Expired))
    ));
    let pending = fixture.store.load().await.unwrap();
    assert!(pending.first_owner_state().is_pending());
    assert!(pending.user(fixture.user.uid).is_none());
    assert!(pending.fleet(fixture.fleet.uid).is_none());
    assert!(pending.principal_owner(fixture.principal_uid).is_none());
}

#[tokio::test]
async fn explicit_expiry_advances_counters_and_stales_replay() {
    let fixture = fixture();
    let claim = signed_claim_with_expiry(&fixture, 1, 10, 1).unwrap();
    fixture.store.begin_first_owner_at(claim, 9).await.unwrap();
    assert!(matches!(
        fixture.store.expire_first_owner_at(10).await,
        Ok(FirstOwnerEnrollment::Cancelled { claim: expired }) if expired == claim
    ));
    let cancelled = fixture.store.load().await.unwrap();
    assert_eq!(cancelled.authority_epoch().get(), 2);
    assert_eq!(cancelled.authority_generation().get(), 2);
    assert!(matches!(
        fixture.store.begin_first_owner_at(claim, 10).await,
        Err(OwnershipError::FirstOwner(FirstOwnerError::StaleClaim))
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delayed_commit_crossing_expiry_cannot_publish_owner_edges() {
    let fixture = fixture();
    let claim = signed_claim_with_expiry(&fixture, 1, 10, 1).unwrap();
    fixture.store.begin_first_owner_at(claim, 9).await.unwrap();

    let entered_clock = Arc::new(Barrier::new(2));
    let release_clock = Arc::new(Barrier::new(2));
    let now = Arc::new(AtomicU64::new(9));
    let store = fixture.store.clone();
    let user = fixture.user.clone();
    let fleet = fixture.fleet.clone();
    let clock_entered = Arc::clone(&entered_clock);
    let clock_release = Arc::clone(&release_clock);
    let clock_now = Arc::clone(&now);
    let commit = tokio::spawn(async move {
        store
            .commit_first_owner_with_clock(&claim, user, fleet, move || {
                clock_entered.wait();
                clock_release.wait();
                clock_now.load(Ordering::Acquire)
            })
            .await
    });

    // The injected clock is reached only from inside the mutation closure,
    // after the lock and current Pending graph have been acquired/decoded.
    entered_clock.wait();
    now.store(10, Ordering::Release);
    release_clock.wait();
    assert!(matches!(
        commit.await.unwrap(),
        Err(OwnershipError::FirstOwner(FirstOwnerError::Expired))
    ));

    let pending = fixture.store.load().await.unwrap();
    assert!(pending.first_owner_state().is_pending());
    assert!(pending.user(fixture.user.uid).is_none());
    assert!(pending.fleet(fixture.fleet.uid).is_none());
    assert!(pending.principal_owner(fixture.principal_uid).is_none());
    assert_eq!(pending.authority_epoch().get(), 1);
    assert_eq!(pending.authority_generation().get(), 1);
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
async fn pending_first_owner_rejects_deletion_reservation() {
    let fixture = fixture();
    fixture
        .store
        .begin_first_owner(fixture.claim)
        .await
        .unwrap();
    assert!(matches!(
        fixture
            .store
            .guard_principal_deletion_for_alias(
                fixture.principal_uid,
                astrid_core::PrincipalId::new("root").unwrap(),
            )
            .await,
        Err(OwnershipError::AuthorityNotEnrolled)
    ));
    assert!(
        fixture
            .store
            .commit_first_owner(fixture.claim, fixture.user, fixture.fleet)
            .await
            .unwrap()
            .is_enrolled()
    );
}

#[tokio::test]
async fn pending_first_owner_rejects_authority_mutations_until_commit() {
    let fixture = fixture();
    fixture
        .store
        .begin_first_owner(fixture.claim)
        .await
        .unwrap();
    let second_fleet = FleetIdentity::from_genesis(FleetGenesis::from_parts(
        Uuid::from_u128(4),
        at(1_700_003_000),
        fixture.user.uid,
    ))
    .unwrap();
    assert!(matches!(
        fixture.store.create_fleet(second_fleet).await,
        Err(OwnershipError::AuthorityNotEnrolled)
    ));
    assert!(matches!(
        fixture
            .store
            .transfer_principal(
                fixture.principal_uid,
                fixture.fleet.uid,
                fixture.fleet.uid,
                fixture.user.uid,
            )
            .await,
        Err(OwnershipError::AuthorityNotEnrolled)
    ));
}

#[tokio::test]
async fn enrolled_graph_rejects_missing_user_identity_or_owner_membership() {
    let missing_user = fixture();
    missing_user
        .store
        .begin_first_owner(missing_user.claim)
        .await
        .unwrap();
    missing_user
        .store
        .commit_first_owner(
            missing_user.claim,
            missing_user.user.clone(),
            missing_user.fleet.clone(),
        )
        .await
        .unwrap();
    let raw = missing_user
        .backend
        .get(super::OWNERSHIP_NAMESPACE, super::GRAPH_KEY)
        .await
        .unwrap()
        .unwrap();
    let mut json: Value = serde_json::from_slice(&raw).unwrap();
    json["users"]
        .as_object_mut()
        .unwrap()
        .remove(&missing_user.user.uid.to_string());
    missing_user
        .backend
        .set(
            super::OWNERSHIP_NAMESPACE,
            super::GRAPH_KEY,
            serde_json::to_vec(&json).unwrap(),
        )
        .await
        .unwrap();
    assert!(matches!(
        missing_user.store.load().await,
        Err(OwnershipError::CorruptGraph(_))
    ));

    // Owner membership is checked independently on a fresh valid fixture.
    let second = fixture();
    second.store.begin_first_owner(second.claim).await.unwrap();
    second
        .store
        .commit_first_owner(second.claim, second.user.clone(), second.fleet.clone())
        .await
        .unwrap();
    let raw = second
        .backend
        .get(super::OWNERSHIP_NAMESPACE, super::GRAPH_KEY)
        .await
        .unwrap()
        .unwrap();
    let mut json: Value = serde_json::from_slice(&raw).unwrap();
    json["fleets"][second.fleet.uid.to_string()]["memberships"]
        .as_object_mut()
        .unwrap()
        .remove(&second.user.uid.to_string());
    second
        .backend
        .set(
            super::OWNERSHIP_NAMESPACE,
            super::GRAPH_KEY,
            serde_json::to_vec(&json).unwrap(),
        )
        .await
        .unwrap();
    assert!(matches!(
        second.store.load().await,
        Err(OwnershipError::CorruptGraph(_))
    ));
}

#[tokio::test]
async fn cancelled_claim_is_stale_after_reopen_and_cannot_mint_a_new_owner() {
    let fixture = fixture();
    fixture
        .store
        .begin_first_owner(fixture.claim)
        .await
        .unwrap();
    fixture
        .store
        .cancel_first_owner(fixture.claim)
        .await
        .unwrap();
    let reopened =
        OwnershipStore::new(fixture.backend.clone(), fixture.principals.clone()).unwrap();
    assert!(matches!(
        reopened.begin_first_owner(fixture.claim).await,
        Err(OwnershipError::FirstOwner(FirstOwnerError::StaleClaim))
    ));
    let changed_key = SigningKey::from_bytes(&[8; 32]);
    let current = reopened.load().await.unwrap();
    let unsigned = FirstOwnerClaim::from_parts_with_authority(
        *fixture.claim.machine_context(),
        *fixture.claim.boot_context(),
        *fixture.claim.kernel_identity(),
        *fixture.claim.system_generation(),
        fixture.claim.user_uid(),
        fixture.claim.fleet_uid(),
        fixture.claim.principal_uid(),
        changed_key.verifying_key().to_bytes(),
        *fixture.claim.nonce(),
        current.authority_generation().get(),
        u64::MAX,
        current.authority_epoch().get(),
        [0; 64],
    )
    .unwrap();
    let changed = FirstOwnerClaim::from_parts_with_authority(
        *unsigned.machine_context(),
        *unsigned.boot_context(),
        *unsigned.kernel_identity(),
        *unsigned.system_generation(),
        unsigned.user_uid(),
        unsigned.fleet_uid(),
        unsigned.principal_uid(),
        *unsigned.initial_user_public_key(),
        *unsigned.nonce(),
        current.authority_generation().get(),
        u64::MAX,
        unsigned.authority_epoch().get(),
        changed_key.sign(&unsigned.canonical_message()).to_bytes(),
    )
    .unwrap();
    reopened.begin_first_owner(changed).await.unwrap();
    assert!(matches!(
        reopened
            .commit_first_owner(changed, fixture.user, fixture.fleet)
            .await,
        Err(OwnershipError::FirstOwner(
            FirstOwnerError::IdentityMismatch("user")
        ))
    ));
}

#[tokio::test]
async fn post_enrollment_transfer_preserves_claim_counters_and_rejects_new_owner() {
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
    let second_fleet = FleetIdentity::from_genesis(FleetGenesis::from_parts(
        Uuid::from_u128(5),
        at(1_700_003_001),
        fixture.user.uid,
    ))
    .unwrap();
    fixture
        .store
        .create_fleet(second_fleet.clone())
        .await
        .unwrap();
    fixture
        .store
        .transfer_principal(
            fixture.principal_uid,
            fixture.fleet.uid,
            second_fleet.uid,
            fixture.user.uid,
        )
        .await
        .unwrap();
    let graph = fixture.store.load().await.unwrap();
    assert_eq!(graph.authority_epoch(), fixture.claim.authority_epoch());
    assert_eq!(
        graph.authority_generation(),
        fixture.claim.authority_generation()
    );
    assert_eq!(
        graph.first_owner_state(),
        FirstOwnerEnrollment::Enrolled {
            claim: fixture.claim
        }
    );

    let other_key = SigningKey::from_bytes(&[10; 32]);
    let other_user = UserIdentity::from_genesis(UserGenesis::from_parts(
        Uuid::from_u128(6),
        at(1_700_003_002),
        other_key.verifying_key().to_bytes(),
    ))
    .unwrap();
    let other_fleet = FleetIdentity::from_genesis(FleetGenesis::from_parts(
        Uuid::from_u128(7),
        at(1_700_003_003),
        other_user.uid,
    ))
    .unwrap();
    let nonce = fixture_nonce();
    let unsigned = FirstOwnerClaim::from_parts(
        *fixture.claim.machine_context(),
        *fixture.claim.boot_context(),
        *fixture.claim.kernel_identity(),
        *fixture.claim.system_generation(),
        other_user.uid,
        other_fleet.uid,
        fixture.claim.principal_uid(),
        other_key.verifying_key().to_bytes(),
        nonce,
        fixture.claim.authority_epoch().get(),
        [0; 64],
    )
    .unwrap();
    let other_claim = FirstOwnerClaim::from_parts(
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
        other_key.sign(&unsigned.canonical_message()).to_bytes(),
    )
    .unwrap();
    assert_eq!(*other_claim.nonce(), nonce);
    assert!(matches!(
        fixture.store.begin_first_owner(other_claim).await,
        Err(OwnershipError::FirstOwner(FirstOwnerError::AlreadyEnrolled))
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

    assert!(matches!(
        fixture.store.create_user(fixture.user.clone()).await,
        Err(OwnershipError::AuthorityNotEnrolled)
    ));
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
