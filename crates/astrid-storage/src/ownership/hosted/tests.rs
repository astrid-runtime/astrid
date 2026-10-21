use super::*;
use crate::{KvStore, MemoryKvStore, OwnershipStore, PrincipalDirectory};
use astrid_core::identity::hosted_owner::{HostedOwnerEnvelope, HostedOwnerPolicy};
use astrid_core::{
    FleetGenesis, FleetIdentity, PrincipalId, PrincipalUid, UserGenesis, UserIdentity,
};
use chrono::{TimeZone, Utc};
use ed25519_dalek::{Signer, SigningKey};
use std::{num::NonZeroU64, sync::Arc};

pub(super) struct Fixture {
    pub(super) backend: Arc<MemoryKvStore>,
    pub(super) store: OwnershipStore,
    pub(super) directory: PrincipalDirectory,
    pub(super) owner: SigningKey,
    pub(super) deployment: SigningKey,
    pub(super) user: UserIdentity,
    pub(super) fleet: FleetIdentity,
    pub(super) principal: PrincipalUid,
    pub(super) device: [u8; 32],
}

pub(super) fn fixture() -> Fixture {
    let backend = Arc::new(MemoryKvStore::new());
    let directory = PrincipalDirectory::default();
    let principal = PrincipalUid::from_bytes([3; 32]);
    directory
        .register(PrincipalId::new("default").unwrap(), principal)
        .unwrap();
    let owner = SigningKey::from_bytes(&[7; 32]);
    let deployment = SigningKey::from_bytes(&[8; 32]);
    let user = UserIdentity::from_genesis(UserGenesis::from_parts(
        Uuid::from_u128(1),
        Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
        owner.verifying_key().to_bytes(),
    ))
    .unwrap();
    let fleet = FleetIdentity::from_genesis(FleetGenesis::from_parts(
        Uuid::from_u128(2),
        Utc.timestamp_opt(1_700_000_001, 0).unwrap(),
        user.uid,
    ))
    .unwrap();
    let store = OwnershipStore::new(backend.clone(), directory.clone()).unwrap();
    Fixture {
        backend,
        store,
        directory,
        owner,
        deployment,
        user,
        fleet,
        principal,
        device: SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes(),
    }
}

fn policy(f: &Fixture, generation: u64) -> HostedOwnerPolicy {
    HostedOwnerPolicy {
        target: astrid_core::identity::hosted_owner::HostedOwnerTarget {
            principal: f.principal,
            public_key: f.device,
        },
        deployment_key: f.deployment.verifying_key().to_bytes(),
        generation: NonZeroU64::new(generation).unwrap(),
        expires_at: NonZeroU64::new(2000).unwrap(),
    }
}

pub(super) async fn envelope(f: &Fixture) -> HostedOwnerEnvelope {
    f.store
        .configure_hosted_owner(policy(f, 1), [42; 32], || 1000)
        .await
        .unwrap();
    let mut challenge = f
        .store
        .challenge_hosted_owner(
            f.principal,
            f.device,
            f.user.clone(),
            f.fleet.clone(),
            1500,
            || 1000,
        )
        .await
        .unwrap();
    challenge.claim = challenge.claim.with_signature(
        f.owner
            .sign(&challenge.claim.canonical_message())
            .to_bytes(),
    );
    let mut envelope = HostedOwnerEnvelope {
        challenge,
        deployment_signature: [0; 64],
    };
    envelope.deployment_signature = f.deployment.sign(&envelope.deployment_message()).to_bytes();
    envelope.verify().unwrap();
    envelope
}

pub(super) async fn bytes(f: &Fixture) -> Vec<u8> {
    f.backend
        .get(
            crate::ownership::OWNERSHIP_NAMESPACE,
            crate::ownership::GRAPH_KEY,
        )
        .await
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn commit_and_reopen_publish_exact_owner_binding_and_payer_together() {
    let f = fixture();
    let envelope = envelope(&f).await;
    f.store
        .begin_hosted_owner(&envelope, || 1000)
        .await
        .unwrap();
    let pending = f.store.load().await.unwrap();
    assert!(pending.first_owner_state().is_pending());
    assert_eq!(pending.fleets().count(), 0);
    assert_eq!(pending.user_for_device(f.principal, &f.device), None);
    let result = f
        .store
        .commit_hosted_owner(&envelope, || 1000)
        .await
        .unwrap();
    let reopened = OwnershipStore::new(f.backend.clone(), f.directory).unwrap();
    let graph = reopened.load().await.unwrap();
    assert_eq!(
        graph.user_for_device(f.principal, &f.device),
        Some(f.user.uid)
    );
    assert_eq!(
        graph.principal_owner(f.principal).unwrap().fleet_uid,
        f.fleet.uid
    );
    assert_eq!(graph.fleets().count(), 1);
    assert_eq!(graph.users().count(), 1);
    assert!(graph.local_user_binding_initialized);
    assert_eq!(graph.accountable_users.get(&f.principal), Some(&f.user.uid));
    assert_eq!(
        graph.hosted_owner().unwrap().completion.as_ref(),
        Some(&result)
    );
}

#[tokio::test]
async fn retirement_and_expired_replay_never_recreate_binding_or_incarnation() {
    let f = fixture();
    let envelope = envelope(&f).await;
    f.store
        .begin_hosted_owner(&envelope, || 1000)
        .await
        .unwrap();
    let result = f
        .store
        .commit_hosted_owner(&envelope, || 1000)
        .await
        .unwrap();
    f.store
        .retire_hosted_owner_device(f.principal, f.device)
        .await
        .unwrap();
    let before = bytes(&f).await;
    f.store
        .begin_hosted_owner(&envelope, || 9000)
        .await
        .unwrap();
    assert_eq!(
        f.store
            .commit_hosted_owner(&envelope, || 9000)
            .await
            .unwrap(),
        result
    );
    assert_eq!(bytes(&f).await, before);
    let graph = f.store.load().await.unwrap();
    assert_eq!(graph.user_for_device(f.principal, &f.device), None);
    assert!(graph.hosted_owner().unwrap().device.is_none());
}

#[tokio::test]
async fn forged_and_substituted_envelopes_leave_graph_byte_exact() {
    let f = fixture();
    let good = envelope(&f).await;
    let before = bytes(&f).await;
    for mutation in 0..10 {
        let mut bad = good.clone();
        match mutation {
            0 => bad.deployment_signature = [0; 64],
            1 => bad.challenge.claim = bad.challenge.claim.with_signature([0; 64]),
            2 => bad.challenge.device.incarnation = Uuid::new_v4(),
            3 => bad.challenge.installation = Uuid::new_v4(),
            4 => bad.challenge.policy.deployment_key = f.owner.verifying_key().to_bytes(),
            5 => bad.challenge.artifact = [17; 32],
            6 => bad.challenge.session = Uuid::new_v4(),
            7 => bad.challenge.policy.generation = 2.try_into().unwrap(),
            8 => bad.challenge.policy.expires_at = 6000.try_into().unwrap(),
            _ => bad.challenge.version = 2,
        }
        assert!(f.store.begin_hosted_owner(&bad, || 1000).await.is_err());
        assert_eq!(bytes(&f).await, before);
    }
}

#[tokio::test]
async fn policy_rotation_and_device_retirement_fence_pending_proofs() {
    let f = fixture();
    let envelope = envelope(&f).await;
    f.store
        .begin_hosted_owner(&envelope, || 1000)
        .await
        .unwrap();
    f.store
        .retire_hosted_owner_device(f.principal, f.device)
        .await
        .unwrap();
    let before = bytes(&f).await;
    assert!(
        f.store
            .commit_hosted_owner(&envelope, || 1000)
            .await
            .is_err()
    );
    assert!(
        f.store
            .begin_hosted_owner(&envelope, || 1000)
            .await
            .is_err()
    );
    assert_eq!(bytes(&f).await, before);
    f.store
        .configure_hosted_owner(policy(&f, 2), [42; 32], || 1000)
        .await
        .unwrap();
    let before = bytes(&f).await;
    assert!(
        f.store
            .begin_hosted_owner(&envelope, || 1000)
            .await
            .is_err()
    );
    assert_eq!(bytes(&f).await, before);
}

#[tokio::test]
async fn expiry_is_checked_inside_admission_and_before_commit() {
    let f = fixture();
    let envelope = envelope(&f).await;
    let before = bytes(&f).await;
    assert!(
        f.store
            .begin_hosted_owner(&envelope, || 1500)
            .await
            .is_err()
    );
    assert_eq!(bytes(&f).await, before);
    f.store
        .begin_hosted_owner(&envelope, || 1000)
        .await
        .unwrap();
    let before = bytes(&f).await;
    assert!(
        f.store
            .commit_hosted_owner(&envelope, || 1500)
            .await
            .is_err()
    );
    assert_eq!(bytes(&f).await, before);
}

#[tokio::test]
async fn standalone_mutators_cannot_bypass_hosted_second_signature() {
    let f = fixture();
    let envelope = envelope(&f).await;
    let before = bytes(&f).await;
    assert!(
        f.store
            .begin_first_owner_at(envelope.challenge.claim, 1000)
            .await
            .is_err()
    );
    assert_eq!(bytes(&f).await, before);
}

#[tokio::test]
async fn configured_and_pending_records_fence_frozen_format_two_reader() {
    let f = fixture();
    let envelope = envelope(&f).await;
    for pending in [false, true] {
        if pending {
            f.store
                .begin_hosted_owner(&envelope, || 1000)
                .await
                .unwrap();
        }
        let raw = bytes(&f).await;
        let value: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(value["format_version"], 3);
        // Frozen pre-hosted reader denies unknown fields before accepting v2.
        let mut old_shape = value.as_object().unwrap().clone();
        old_shape.remove("hosted");
        let old_graph: OwnershipSnapshot =
            serde_json::from_value(serde_json::Value::Object(old_shape)).unwrap();
        assert!(old_graph.validate(&f.directory).is_err());
    }
}

#[tokio::test]
async fn expiry_after_waiting_for_mutation_lock_cannot_become_pending() {
    use std::sync::atomic::{AtomicU64, Ordering};
    let f = fixture();
    let envelope = envelope(&f).await;
    let before = bytes(&f).await;
    let now = Arc::new(AtomicU64::new(1000));
    let guard = f.store.mutation_lock.lock().await;
    let clock = Arc::clone(&now);
    let pending = f
        .store
        .begin_hosted_owner(&envelope, move || clock.load(Ordering::SeqCst));
    tokio::pin!(pending);
    tokio::select! { biased; result = &mut pending => panic!("operation escaped held lock: {result:?}"), () = std::future::ready(()) => {} }
    now.store(1500, Ordering::SeqCst);
    drop(guard);
    assert!(pending.await.is_err());
    assert_eq!(bytes(&f).await, before);
}

#[tokio::test]
async fn cancelled_session_cannot_be_resurrected_by_same_registered_public_key() {
    let f = fixture();
    let old = envelope(&f).await;
    f.store.begin_hosted_owner(&old, || 1000).await.unwrap();
    f.store
        .cancel_hosted_owner(f.principal, f.device)
        .await
        .unwrap();
    let next = f
        .store
        .challenge_hosted_owner(
            f.principal,
            f.device,
            f.user.clone(),
            f.fleet.clone(),
            1500,
            || 1000,
        )
        .await
        .unwrap();
    assert_ne!(old.challenge.session, next.session);
    assert_ne!(old.challenge.device.incarnation, next.device.incarnation);
    let before = bytes(&f).await;
    assert!(f.store.begin_hosted_owner(&old, || 1000).await.is_err());
    assert_eq!(bytes(&f).await, before);
}

#[tokio::test]
async fn every_hosted_device_retirement_revokes_binding_and_captured_delegation() {
    let f = fixture();
    let envelope = envelope(&f).await;
    f.store
        .begin_hosted_owner(&envelope, || 1000)
        .await
        .unwrap();
    f.store
        .commit_hosted_owner(&envelope, || 1000)
        .await
        .unwrap();
    let second = SigningKey::from_bytes(&[10; 32]).verifying_key().to_bytes();
    f.store
        .bind_user_device(f.principal, second, f.user.uid, f.user.uid)
        .await
        .unwrap();
    let old = f
        .store
        .capture_creation_delegation(f.principal, &second)
        .await
        .unwrap();
    f.store
        .retire_hosted_owner_device(f.principal, second)
        .await
        .unwrap();
    assert_eq!(
        f.store
            .load()
            .await
            .unwrap()
            .user_for_device(f.principal, &second),
        None
    );
    // Re-registering the same transport public key cannot create a graph grant.
    assert!(
        f.store
            .capture_creation_delegation(f.principal, &second)
            .await
            .is_err()
    );
    let child = PrincipalUid::from_bytes([11; 32]);
    f.directory
        .register(PrincipalId::new("child").unwrap(), child)
        .unwrap();
    assert!(
        !f.store
            .commit_enrolled_principal(child, &old, vec![], vec![])
            .await
            .unwrap()
    );
    f.store
        .bind_user_device(f.principal, second, f.user.uid, f.user.uid)
        .await
        .unwrap();
    assert!(
        !f.store
            .commit_enrolled_principal(child, &old, vec![], vec![])
            .await
            .unwrap()
    );
    let new = f
        .store
        .capture_creation_delegation(f.principal, &second)
        .await
        .unwrap();
    assert!(
        f.store
            .commit_enrolled_principal(child, &new, vec![], vec![])
            .await
            .unwrap()
    );
    assert_eq!(
        f.store
            .load()
            .await
            .unwrap()
            .principal_owner(child)
            .unwrap()
            .fleet_uid,
        f.fleet.uid
    );
}

#[tokio::test]
async fn other_registered_device_cannot_capture_or_replace_configured_target() {
    let f = fixture();
    let good = envelope(&f).await;
    let before = bytes(&f).await;
    let other = SigningKey::from_bytes(&[12; 32]).verifying_key().to_bytes();
    assert!(
        f.store
            .challenge_hosted_owner(
                f.principal,
                other,
                f.user.clone(),
                f.fleet.clone(),
                1500,
                || 1000
            )
            .await
            .is_err()
    );
    assert_eq!(bytes(&f).await, before);
    let other_principal = PrincipalUid::from_bytes([13; 32]);
    f.directory
        .register(PrincipalId::new("other").unwrap(), other_principal)
        .unwrap();
    assert!(
        f.store
            .challenge_hosted_owner(
                other_principal,
                f.device,
                f.user.clone(),
                f.fleet.clone(),
                1500,
                || 1000
            )
            .await
            .is_err()
    );
    assert_eq!(bytes(&f).await, before);
    f.store.begin_hosted_owner(&good, || 1000).await.unwrap();
    f.store.commit_hosted_owner(&good, || 1000).await.unwrap();
}

#[tokio::test]
async fn emit_exact_graph_fixtures_and_reopen_every_hosted_phase() {
    let f = fixture();
    let envelope = envelope(&f).await;
    for phase in ["configured", "pending", "enrolled"] {
        if phase == "pending" {
            f.store
                .begin_hosted_owner(&envelope, || 1000)
                .await
                .unwrap();
        }
        if phase == "enrolled" {
            f.store
                .commit_hosted_owner(&envelope, || 1000)
                .await
                .unwrap();
        }
        let raw = bytes(&f).await;
        let reopened = OwnershipStore::new(f.backend.clone(), f.directory.clone()).unwrap();
        reopened.load().await.unwrap();
        // Opt-in test artifacts contain public facts only. Production never
        // reads this variable; it permits the frozen prior crate to decode
        // exact new-writer output without changing that old source tree.
        if let Some(directory) = std::env::var_os("ASTRID_HOSTED_READER_FIXTURES") {
            std::fs::write(
                std::path::Path::new(&directory).join(format!("{phase}.json")),
                raw,
            )
            .unwrap();
        }
    }
}
