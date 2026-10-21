//! Reconcile extracted ownership operations with the signed enrollment boundary.

use super::*;
use crate::ownership::user_bindings::CreationDelegation;

async fn enrolled() -> Fixture {
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
    fixture
}

async fn delegation(fixture: &Fixture) -> CreationDelegation {
    fixture
        .store
        .bind_user_device(
            fixture.principal_uid,
            [5; 32],
            fixture.user.uid,
            fixture.user.uid,
        )
        .await
        .unwrap();
    fixture
        .store
        .capture_creation_delegation(fixture.principal_uid, &[5; 32])
        .await
        .unwrap()
}

fn admit_child(fixture: &Fixture) -> astrid_core::PrincipalUid {
    let child = astrid_core::PrincipalUid::from_bytes([77; 32]);
    fixture
        .principals
        .register(astrid_core::PrincipalId::new("child").unwrap(), child)
        .unwrap();
    child
}

async fn advance_authority(fixture: &Fixture) -> Vec<u8> {
    let claim = signed_claim_with_expiry(fixture, 2, u64::MAX, 2).unwrap();
    let mut graph = fixture.store.load().await.unwrap();
    graph.authority_epoch = claim.authority_epoch();
    graph.authority_generation = claim.authority_generation();
    graph.set_first_owner_state(&FirstOwnerEnrollment::Enrolled { claim });
    let bytes = serde_json::to_vec(&graph).unwrap();
    fixture
        .backend
        .set(OWNERSHIP_NAMESPACE, GRAPH_KEY, bytes.clone())
        .await
        .unwrap();
    bytes
}

#[tokio::test]
async fn derived_assignment_cannot_adopt_authority_changed_after_capture() {
    let fixture = enrolled().await;
    let child = admit_child(&fixture);
    let captured = fixture
        .store
        .capture_derived_ownership(fixture.principal_uid)
        .await
        .unwrap();
    let before = advance_authority(&fixture).await;
    assert!(matches!(
        fixture
            .store
            .assign_derived_principal(child, &captured)
            .await,
        Err(OwnershipError::AuthorityStale)
    ));
    assert_eq!(
        fixture
            .backend
            .get(OWNERSHIP_NAMESPACE, GRAPH_KEY)
            .await
            .unwrap(),
        Some(before)
    );
    let fresh = fixture
        .store
        .capture_derived_ownership(fixture.principal_uid)
        .await
        .unwrap();
    fixture
        .store
        .assign_derived_principal(child, &fresh)
        .await
        .unwrap();
    assert!(
        fixture
            .store
            .load()
            .await
            .unwrap()
            .principal_owner(child)
            .is_some()
    );
}

#[tokio::test]
async fn interrupted_deletion_retains_original_authority_until_finish() {
    let fixture = enrolled().await;
    let child = admit_child(&fixture);
    let alias = astrid_core::PrincipalId::new("child").unwrap();
    let guard = fixture
        .store
        .guard_principal_deletion_for_alias(child, alias.clone())
        .await
        .unwrap();
    drop(guard);
    fixture.principals.unregister(&alias, child);
    let guard = fixture
        .store
        .resume_principal_deletion_by_alias(&alias)
        .await
        .unwrap()
        .unwrap();
    let before = advance_authority(&fixture).await;
    assert!(matches!(
        guard.finish().await,
        Err(OwnershipError::AuthorityStale)
    ));
    assert_eq!(
        fixture
            .backend
            .get(OWNERSHIP_NAMESPACE, GRAPH_KEY)
            .await
            .unwrap(),
        Some(before)
    );
    let reopened = OwnershipStore::new(fixture.backend, fixture.principals).unwrap();
    reopened
        .resume_principal_deletion_by_alias(&alias)
        .await
        .unwrap()
        .unwrap()
        .finish()
        .await
        .unwrap();
    reopened.ensure_alias_available(&alias).await.unwrap();
}

#[tokio::test]
async fn extracted_mutations_refuse_unenrolled_store_without_writes() {
    let fixture = fixture();
    assert!(matches!(
        fixture.store.create_user(fixture.user.clone()).await,
        Err(OwnershipError::AuthorityNotEnrolled)
    ));
    assert!(matches!(
        fixture.store.create_fleet(fixture.fleet.clone()).await,
        Err(OwnershipError::AuthorityNotEnrolled)
    ));
    assert!(matches!(
        fixture
            .store
            .capture_creation_delegation(fixture.principal_uid, &[5; 32])
            .await,
        Err(OwnershipError::AuthorityNotEnrolled)
    ));
    assert!(
        fixture
            .backend
            .get(OWNERSHIP_NAMESPACE, GRAPH_KEY)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn first_owner_sets_payer_and_replay_preserves_explicit_reassignment() {
    let fixture = enrolled().await;
    assert_eq!(
        fixture
            .store
            .load()
            .await
            .unwrap()
            .accountable_user(fixture.principal_uid),
        Some(fixture.user.uid)
    );
    let other = UserIdentity::from_genesis(UserGenesis::from_parts(
        Uuid::from_u128(99),
        at(1_700_003_000),
        [8; 32],
    ))
    .unwrap();
    fixture.store.create_user(other.clone()).await.unwrap();
    fixture
        .store
        .assign_accountable_user(fixture.principal_uid, Some(fixture.user.uid), other.uid)
        .await
        .unwrap();
    fixture
        .store
        .commit_first_owner(fixture.claim, fixture.user.clone(), fixture.fleet.clone())
        .await
        .unwrap();
    let reopened = OwnershipStore::new(fixture.backend, fixture.principals).unwrap();
    assert_eq!(
        reopened
            .load()
            .await
            .unwrap()
            .accountable_user(fixture.principal_uid),
        Some(other.uid)
    );
}

#[tokio::test]
async fn serialized_delegation_redeems_after_store_reopen() {
    let fixture = enrolled().await;
    let original = delegation(&fixture).await;
    let encoded = serde_json::to_vec(&original).unwrap();
    let restored = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(original, restored);
    let child = admit_child(&fixture);
    let reopened = OwnershipStore::new(fixture.backend, fixture.principals).unwrap();
    assert!(
        reopened
            .commit_enrolled_principal(child, &restored, vec![], vec![])
            .await
            .unwrap()
    );
    let graph = reopened.load().await.unwrap();
    assert_eq!(
        graph.principal_owner(child).unwrap().fleet_uid,
        fixture.fleet.uid
    );
    assert_eq!(graph.accountable_user(child), Some(fixture.user.uid));
}

#[tokio::test]
async fn legacy_delegation_without_stamp_cannot_mutate_graph_or_token() {
    let fixture = enrolled().await;
    let original = delegation(&fixture).await;
    let mut encoded = serde_json::to_value(original).unwrap();
    encoded.as_object_mut().unwrap().remove("enrollment");
    let legacy = serde_json::from_value(encoded).unwrap();
    let child = admit_child(&fixture);
    fixture
        .backend
        .set("test:enrollment", "token", vec![1])
        .await
        .unwrap();
    let before = fixture
        .backend
        .get(OWNERSHIP_NAMESPACE, GRAPH_KEY)
        .await
        .unwrap();
    let key = crate::KvEntryKey::new("test:enrollment", "token").unwrap();
    assert!(matches!(
        fixture
            .store
            .commit_enrolled_principal(
                child,
                &legacy,
                vec![],
                vec![crate::KvBatchMutation::Delete { key }],
            )
            .await,
        Err(OwnershipError::AuthorityStale)
    ));
    assert_eq!(
        fixture
            .backend
            .get(OWNERSHIP_NAMESPACE, GRAPH_KEY)
            .await
            .unwrap(),
        before
    );
    assert_eq!(
        fixture
            .backend
            .get("test:enrollment", "token")
            .await
            .unwrap(),
        Some(vec![1])
    );
}

#[tokio::test]
async fn different_signed_ceremony_with_same_counters_does_not_revive_invite() {
    let fixture = enrolled().await;
    let saved = delegation(&fixture).await;
    let child = admit_child(&fixture);
    // Same identity, key, epoch and generation; only the signed nonce differs.
    let replacement = super::fixture();
    assert_ne!(fixture.claim, replacement.claim);
    let mut graph = fixture.store.load().await.unwrap();
    graph.set_first_owner_state(&FirstOwnerEnrollment::Enrolled {
        claim: replacement.claim,
    });
    let bytes = serde_json::to_vec(&graph).unwrap();
    fixture
        .backend
        .set(OWNERSHIP_NAMESPACE, GRAPH_KEY, bytes.clone())
        .await
        .unwrap();
    let reopened = OwnershipStore::new(fixture.backend.clone(), fixture.principals).unwrap();
    assert!(matches!(
        reopened
            .commit_enrolled_principal(child, &saved, vec![], vec![])
            .await,
        Err(OwnershipError::AuthorityStale)
    ));
    assert_eq!(
        fixture
            .backend
            .get(OWNERSHIP_NAMESPACE, GRAPH_KEY)
            .await
            .unwrap(),
        Some(bytes)
    );
}
