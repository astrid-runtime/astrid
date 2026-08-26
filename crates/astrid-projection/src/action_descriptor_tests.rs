extern crate alloc;

use super::*;
use crate::presentation::{PresentationLabel, PresentationMetadata};
use crate::snapshot::ProjectionSnapshot;
use alloc::string::ToString;
use astrid_resource_types::{ResourceId, ResourceTypeId};

fn object(byte: u8) -> SemanticObjectId {
    SemanticObjectId::for_resource(ResourceId::from_bytes([byte; 32]))
}

fn descriptor() -> ActionDescriptor {
    ActionDescriptor::new(
        object(0x44),
        ActionDigest::from_bytes([0x11; ACTION_BINDING_BYTES]),
        ProjectionRevision::from_raw(7).unwrap(),
        ActionScope::from_bytes([0x22; ACTION_BINDING_BYTES]),
        ActionGeneration::from_raw(3).unwrap(),
        ActionExpiry::from_raw(100),
        ActionPrincipal::from_bytes([0x33; ACTION_BINDING_BYTES]),
    )
}

fn observation() -> ActionObservation {
    ActionObservation::new(
        object(0x44),
        ActionDigest::from_bytes([0x11; ACTION_BINDING_BYTES]),
        ProjectionRevision::from_raw(7).unwrap(),
        ActionScope::from_bytes([0x22; ACTION_BINDING_BYTES]),
        ActionGeneration::from_raw(3).unwrap(),
        ActionPrincipal::from_bytes([0x33; ACTION_BINDING_BYTES]),
        99,
    )
}

fn snapshot(object_byte: u8, label: &[u8], metadata: &PresentationMetadata) -> ProjectionSnapshot {
    ProjectionSnapshot::new(
        object(object_byte),
        ResourceTypeId::from_bytes([0x55; 32]),
        ProjectionRevision::from_raw(7).unwrap(),
        PresentationLabel::from_utf8(label).unwrap(),
        *metadata,
    )
}

#[test]
fn descriptor_roundtrip_is_fixed_and_debug_is_opaque() {
    let descriptor = descriptor();
    let mut encoded = [0_u8; ACTION_DESCRIPTOR_ENCODED_LEN];
    assert_eq!(descriptor.encoded_len(), ACTION_DESCRIPTOR_ENCODED_LEN);
    descriptor.encode_descriptor(&mut encoded).unwrap();
    assert_eq!(
        ActionDescriptor::decode_descriptor(&encoded),
        Ok(descriptor)
    );
    assert_eq!(
        format_args!("{descriptor:?}").to_string(),
        "ActionDescriptor"
    );
    assert_eq!(
        format_args!("{:?}", descriptor.facts()).to_string(),
        "ActionDescriptorFacts"
    );
    assert_eq!(
        format_args!("{:?}", observation()).to_string(),
        "ActionObservation"
    );
    assert_eq!(
        ActionDescriptor::decode_descriptor(&encoded[..125]),
        Err(ProjectionError::InvalidLength)
    );
    let mut with_trailing = [0_u8; ACTION_DESCRIPTOR_ENCODED_LEN + 1];
    with_trailing[..ACTION_DESCRIPTOR_ENCODED_LEN].copy_from_slice(&encoded);
    assert_eq!(
        ActionDescriptor::decode_descriptor(&with_trailing),
        Err(ProjectionError::InvalidLength)
    );
    let mut wrong_outer_tag = encoded;
    wrong_outer_tag[1..3]
        .copy_from_slice(&ProjectionTypeTag::SemanticObjectId.code().to_le_bytes());
    assert_eq!(
        ActionDescriptor::decode_descriptor(&wrong_outer_tag),
        Err(ProjectionError::WrongTypeTag {
            expected: ProjectionTypeTag::ActionDescriptor.code(),
            actual: ProjectionTypeTag::SemanticObjectId.code(),
        })
    );
    let mut wrong_object_tag = encoded;
    wrong_object_tag[4..6]
        .copy_from_slice(&ProjectionTypeTag::ProjectionRevision.code().to_le_bytes());
    assert_eq!(
        ActionDescriptor::decode_descriptor(&wrong_object_tag),
        Err(ProjectionError::WrongTypeTag {
            expected: ProjectionTypeTag::SemanticObjectId.code(),
            actual: ProjectionTypeTag::ProjectionRevision.code(),
        })
    );
    assert_eq!(
        SemanticObjectId::decode_descriptor(&encoded[3..41]),
        Ok(descriptor.object())
    );
    encoded[116..124].fill(0);
    assert_eq!(
        ActionDescriptor::decode_descriptor(&encoded),
        Err(ProjectionError::InvalidActionGeneration)
    );
}

#[test]
fn descriptor_rejects_stale_expired_drift_and_cross_principal_observations() {
    let descriptor = descriptor();
    let honest = observation();
    assert_eq!(descriptor.eligibility(&honest), ActionEligibility::Eligible);
    assert!(descriptor.is_eligible(&honest));
    assert_eq!(descriptor.check(&honest), Ok(()));

    let digest = ActionObservation::new(
        honest.object(),
        ActionDigest::from_bytes([0xee; ACTION_BINDING_BYTES]),
        honest.revision(),
        honest.scope(),
        honest.generation(),
        honest.principal(),
        honest.now(),
    );
    assert_eq!(
        descriptor.check(&digest),
        Err(ProjectionError::ActionDigestMismatch)
    );

    let stale = ActionObservation::new(
        honest.object(),
        honest.digest(),
        ProjectionRevision::from_raw(8).unwrap(),
        honest.scope(),
        honest.generation(),
        honest.principal(),
        honest.now(),
    );
    assert_eq!(
        descriptor.eligibility(&stale),
        ActionEligibility::StaleRevision
    );
    assert_eq!(
        descriptor.check(&stale),
        Err(ProjectionError::StaleRevision {
            found: 7,
            requested: 8,
        })
    );

    let scope = ActionObservation::new(
        honest.object(),
        honest.digest(),
        honest.revision(),
        ActionScope::from_bytes([0xef; ACTION_BINDING_BYTES]),
        honest.generation(),
        honest.principal(),
        honest.now(),
    );
    assert_eq!(
        descriptor.check(&scope),
        Err(ProjectionError::ActionScopeMismatch)
    );

    let generation = ActionObservation::new(
        honest.object(),
        honest.digest(),
        honest.revision(),
        honest.scope(),
        ActionGeneration::from_raw(4).unwrap(),
        honest.principal(),
        honest.now(),
    );
    assert_eq!(
        descriptor.check(&generation),
        Err(ProjectionError::ActionGenerationDrift)
    );

    let principal = ActionObservation::new(
        honest.object(),
        honest.digest(),
        honest.revision(),
        honest.scope(),
        honest.generation(),
        ActionPrincipal::from_bytes([0xaa; ACTION_BINDING_BYTES]),
        honest.now(),
    );
    assert_eq!(
        descriptor.check(&principal),
        Err(ProjectionError::ActionCrossPrincipal)
    );

    let expired = ActionObservation::new(
        honest.object(),
        honest.digest(),
        honest.revision(),
        honest.scope(),
        honest.generation(),
        honest.principal(),
        100,
    );
    assert_eq!(
        descriptor.check(&expired),
        Err(ProjectionError::ActionExpired)
    );
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PresenterResult {
    eligible: bool,
    label: PresentationLabel,
    metadata: PresentationMetadata,
    facts: ActionDescriptorFacts,
}

// This consumer is presentation-shaped: it carries labels and metadata,
// and treats descriptor eligibility as an opaque boolean decision.
fn presenter_consumer(
    snapshot: &ProjectionSnapshot,
    descriptor: &ActionDescriptor,
    observation: &ActionObservation,
) -> PresenterResult {
    let object_matches =
        snapshot.object() == descriptor.object() && snapshot.object() == observation.object();
    PresenterResult {
        eligible: object_matches && descriptor.is_eligible(observation),
        label: snapshot.label(),
        metadata: snapshot.metadata(),
        facts: descriptor.facts(),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct EligibilityResult {
    eligible: bool,
    facts: ActionDescriptorFacts,
}

// This consumer is structurally different: it reads each bound fact and
// derives eligibility without consulting presentation values.
fn eligibility_consumer(
    snapshot: &ProjectionSnapshot,
    descriptor: &ActionDescriptor,
    observation: &ActionObservation,
) -> EligibilityResult {
    let facts = descriptor.facts();
    let eligible = snapshot.object() == facts.object()
        && snapshot.object() == observation.object()
        && snapshot.revision() == facts.revision()
        && facts.principal() == observation.principal()
        && facts.object() == observation.object()
        && facts.digest() == observation.digest()
        && facts.revision() == observation.revision()
        && facts.scope() == observation.scope()
        && facts.generation() == observation.generation()
        && !facts.expiry().is_expired_at(observation.now());
    EligibilityResult { eligible, facts }
}

#[test]
fn independent_consumers_agree_and_presentation_cannot_mint_or_widen() {
    let descriptor = descriptor();
    let observation = observation();
    let plain = snapshot(0x44, b"safe", &PresentationMetadata::EMPTY);
    let hostile_metadata = PresentationMetadata::try_from_pairs(&[
        ("action_handle", "forged"),
        ("invoke", "true"),
        ("rights", "root"),
    ])
    .unwrap();
    let hostile = snapshot(0x44, b"ADMIN GRANT", &hostile_metadata);

    let first = presenter_consumer(&plain, &descriptor, &observation);
    let second = eligibility_consumer(&plain, &descriptor, &observation);
    assert!(first.eligible);
    assert_eq!(first.eligible, second.eligible);
    assert_eq!(first.facts, second.facts);

    // A malicious presentation changes only display fields; eligibility
    // and all descriptor facts remain exactly those of the bound action.
    let hostile_result = presenter_consumer(&hostile, &descriptor, &observation);
    assert!(hostile_result.eligible);
    assert_eq!(hostile_result.facts, first.facts);
    assert_eq!(hostile_result.label.as_str(), "ADMIN GRANT");
    assert!(
        hostile_result
            .metadata
            .iter()
            .any(|(key, value)| key == "action_handle" && value == "forged")
    );

    // A copied descriptor cannot refresh itself after the projection moves
    // to a new revision; replay fails against the new observation.
    let replayed = descriptor;
    let moved = ActionObservation::new(
        observation.object(),
        observation.digest(),
        observation.revision().checked_next().unwrap(),
        observation.scope(),
        observation.generation(),
        observation.principal(),
        observation.now(),
    );
    assert_eq!(
        replayed.check(&moved),
        Err(ProjectionError::StaleRevision {
            found: 7,
            requested: 8,
        })
    );
}

#[test]
fn object_identity_joins_snapshots_and_rejects_cross_object_replay() {
    let first_snapshot = snapshot(0x44, b"first", &PresentationMetadata::EMPTY);
    let second_snapshot = snapshot(0x66, b"second", &PresentationMetadata::EMPTY);
    assert_ne!(first_snapshot.object(), second_snapshot.object());
    assert_eq!(first_snapshot.type_id(), second_snapshot.type_id());
    assert_eq!(first_snapshot.revision(), second_snapshot.revision());

    let descriptor = ActionDescriptor::for_snapshot(
        first_snapshot,
        ActionDigest::from_bytes([0x11; ACTION_BINDING_BYTES]),
        ActionScope::from_bytes([0x22; ACTION_BINDING_BYTES]),
        ActionGeneration::from_raw(3).unwrap(),
        ActionExpiry::from_raw(100),
        ActionPrincipal::from_bytes([0x33; ACTION_BINDING_BYTES]),
    );
    let matching = ActionObservation::for_snapshot(
        first_snapshot,
        descriptor.digest(),
        descriptor.scope(),
        descriptor.generation(),
        descriptor.principal(),
        99,
    );
    let cross_object = ActionObservation::for_snapshot(
        second_snapshot,
        descriptor.digest(),
        descriptor.scope(),
        descriptor.generation(),
        descriptor.principal(),
        99,
    );

    assert_eq!(
        descriptor.eligibility(&matching),
        ActionEligibility::Eligible
    );
    assert_eq!(descriptor.check(&matching), Ok(()));
    assert_eq!(
        descriptor.eligibility(&cross_object),
        ActionEligibility::ObjectMismatch
    );
    assert_eq!(
        descriptor.check(&cross_object),
        Err(ProjectionError::ActionObjectMismatch)
    );

    let first_presenter = presenter_consumer(&first_snapshot, &descriptor, &matching);
    let second_presenter = presenter_consumer(&second_snapshot, &descriptor, &cross_object);
    assert!(first_presenter.eligible);
    assert!(!second_presenter.eligible);
    assert_eq!(first_presenter.facts, second_presenter.facts);

    let first_eligibility = eligibility_consumer(&first_snapshot, &descriptor, &matching);
    let second_eligibility = eligibility_consumer(&second_snapshot, &descriptor, &cross_object);
    assert!(first_eligibility.eligible);
    assert!(!second_eligibility.eligible);
    assert_eq!(first_eligibility.facts, second_eligibility.facts);
}
