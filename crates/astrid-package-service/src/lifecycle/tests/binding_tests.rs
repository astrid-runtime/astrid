use super::*;
use crate::identity::{BoundedEvidence, ProvenanceClass};

fn validated_artifact_with(
    artifact_identity: ArtifactIdentity,
    manifest_identity: ManifestIdentity,
    content: u8,
    evidence: Blake3Digest,
) -> ValidatedArtifact {
    let bounded = BoundedEvidence::new(vec![1, 2, 3])
        .unwrap_or_else(|error| panic!("test evidence is valid: {error:?}"));
    let provenance = ProvenanceEvidence::new(ProvenanceClass::LocalArtifact, evidence, bounded)
        .unwrap_or_else(|error| panic!("test provenance is valid: {error:?}"));
    ValidatedArtifact::new(
        artifact_identity,
        manifest_identity,
        digest(content),
        provenance,
    )
    .unwrap_or_else(|error| panic!("test artifact is valid: {error:?}"))
}

#[test]
fn changed_authority_or_content_cannot_stage_or_mutate_a_record() {
    let fixture = Fixture::new();
    let mut model = PackageServiceModel::new(policy(8));
    let artifact = validated_artifact(12);
    let binding_context = fixture.context(
        Operation::Install,
        ExpectedPackageState::Absent,
        plan_digest(20),
        (fixture.owner, fixture.caller),
        1,
        Nonce::from_bytes([1; 32]),
    );
    let unified_plan = crate::context::operation_commit_plan_digest(
        Operation::Install,
        binding_context.artifact(),
        binding_context.manifest(),
        artifact.content_root(),
        &provenance_digest(artifact.provenance()),
        None,
    );
    let context = fixture.context_with_expiry(&ContextOptions {
        operation: Operation::Install,
        expected: ExpectedPackageState::Absent,
        plan: unified_plan,
        participants: (fixture.owner, fixture.caller),
        generation: 1,
        nonce: Nonce::from_bytes([1; 32]),
        expiry: Timestamp::new(1_000),
    });
    let unbound_context = fixture.context(
        Operation::Install,
        ExpectedPackageState::Absent,
        unified_plan,
        (fixture.other_owner, fixture.caller),
        1,
        Nonce::from_bytes([2; 32]),
    );
    let wrong_authority = fixture.authority(&unbound_context);
    let error = model
        .begin(
            context.clone(),
            &wrong_authority,
            fixture.ingress,
            &fixture.service_at(1),
            Timestamp::new(100),
        )
        .err()
        .unwrap_or_else(|| panic!("unbound authority must not admit"));
    assert!(matches!(
        error,
        PackageServiceError::AuthorityContextMismatch
    ));

    let nonce = fixture
        .begin(&mut model, context.clone(), 100)
        .unwrap_or_else(|error| panic!("bound install should admit: {error:?}"));
    model
        .begin_work(&nonce, Timestamp::new(110))
        .unwrap_or_else(|error| panic!("install should start: {error:?}"));
    let wrong_content = validated_artifact_with(
        *context.artifact(),
        context.manifest().clone(),
        13,
        digest(5),
    );
    assert_changed_content_is_rejected(
        &mut model,
        &fixture,
        &nonce,
        &context,
        &wrong_content,
        &artifact,
    );
}

fn assert_changed_content_is_rejected(
    model: &mut PackageServiceModel,
    fixture: &Fixture,
    nonce: &Nonce,
    context: &OperationContext,
    wrong_content: &ValidatedArtifact,
    artifact: &ValidatedArtifact,
) {
    let staged_before = model
        .slot_record(&fixture.slot(fixture.owner))
        .and_then(|record| record.journal_record(nonce))
        .and_then(OperationJournalRecord::staged_commit_plan)
        .copied();
    assert_eq!(staged_before, None);
    let error = model
        .stage_commit_artifact(nonce, wrong_content)
        .err()
        .unwrap_or_else(|| panic!("changed content must not stage"));
    assert!(matches!(error, PackageServiceError::BindingMismatch));
    let staged_after = model
        .slot_record(&fixture.slot(fixture.owner))
        .and_then(|record| record.journal_record(nonce))
        .and_then(OperationJournalRecord::staged_commit_plan)
        .copied();
    assert_eq!(staged_before, staged_after);

    model
        .stage_commit_artifact(nonce, artifact)
        .unwrap_or_else(|error| panic!("authoritative content should stage: {error:?}"));
    let committed = model
        .slot_record(&fixture.slot(fixture.owner))
        .and_then(|record| record.journal_record(nonce))
        .map_or_else(
            || panic!("journal should exist"),
            OperationJournalRecord::staged_commit_plan,
        );
    assert_eq!(committed, Some(*context.commit_plan_digest()).as_ref());
    let error = model
        .complete(nonce, Some(wrong_content), None, true, Timestamp::new(120))
        .err()
        .unwrap_or_else(|| panic!("changed content must not commit"));
    assert!(matches!(error, PackageServiceError::BindingMismatch));
}

#[test]
fn changed_lifecycle_plans_and_expectations_fail_before_transition() {
    let fixture = Fixture::new();
    let mut model = PackageServiceModel::new(policy(8));
    install(&mut model, &fixture, 1);
    let state = model
        .slot_record(&fixture.slot(fixture.owner))
        .and_then(|record| record.state())
        .map_or_else(
            || panic!("installed state should exist"),
            CanonicalInstalledState::digest,
        );

    let wrong_deadline_plan = DrainPlan::new(
        DrainDestination::Replacement,
        ExpectedPackageState::Exact(state),
        Timestamp::new(250),
        Nonce::from_bytes([2; 32]),
    )
    .unwrap_or_else(|error| panic!("wrong deadline plan is valid: {error:?}"));
    let wrong_deadline_context = fixture.context(
        Operation::Update,
        ExpectedPackageState::Exact(state),
        wrong_deadline_plan.digest(),
        (fixture.owner, fixture.caller),
        1,
        Nonce::from_bytes([2; 32]),
    );
    let nonce = fixture
        .begin(&mut model, wrong_deadline_context, 130)
        .unwrap_or_else(|error| panic!("update with its exact plan should admit: {error:?}"));
    let error = model
        .begin_drain(
            &nonce,
            DrainDestination::Replacement,
            Timestamp::new(300),
            1,
            Timestamp::new(140),
        )
        .err()
        .unwrap_or_else(|| panic!("changed drain deadline must fail"));
    assert!(matches!(error, PackageServiceError::BindingMismatch));

    model
        .cancel(&nonce, Timestamp::new(150))
        .unwrap_or_else(|error| panic!("rejected deadline work should cancel: {error:?}"));
    let current_digest = model
        .slot_record(&fixture.slot(fixture.owner))
        .and_then(|record| record.state())
        .map_or_else(
            || panic!("state should remain after cancellation"),
            CanonicalInstalledState::digest,
        );
    let replacement_plan = DrainPlan::new(
        DrainDestination::Replacement,
        ExpectedPackageState::Exact(current_digest),
        Timestamp::new(300),
        Nonce::from_bytes([6; 32]),
    )
    .unwrap_or_else(|error| panic!("replacement plan is valid: {error:?}"));
    let replacement_context = fixture.context(
        Operation::Update,
        ExpectedPackageState::Exact(current_digest),
        replacement_plan.digest(),
        (fixture.owner, fixture.caller),
        1,
        Nonce::from_bytes([6; 32]),
    );
    let replacement_nonce = fixture
        .begin(&mut model, replacement_context, 130)
        .unwrap_or_else(|error| panic!("exact update should admit: {error:?}"));
    model
        .begin_drain(
            &replacement_nonce,
            DrainDestination::Replacement,
            Timestamp::new(300),
            1,
            Timestamp::new(140),
        )
        .unwrap_or_else(|error| panic!("exact replacement should drain: {error:?}"));

    let wrong_destination = model
        .context_for(&replacement_nonce)
        .unwrap_or_else(|error| panic!("{error:?}"));
    let error = model
        .begin_drain(
            &replacement_nonce,
            DrainDestination::Removal,
            Timestamp::new(300),
            0,
            Timestamp::new(140),
        )
        .err()
        .unwrap_or_else(|| panic!("changed drain destination must fail"));
    assert!(matches!(error, PackageServiceError::BindingMismatch));
    drop(wrong_destination);
}

#[test]
fn changed_expected_state_is_refused_before_admission() {
    let fixture = Fixture::new();
    let mut model = PackageServiceModel::new(policy(8));
    install(&mut model, &fixture, 1);
    let state = model
        .slot_record(&fixture.slot(fixture.owner))
        .and_then(|record| record.state())
        .map_or_else(
            || panic!("installed state should exist"),
            CanonicalInstalledState::digest,
        );
    let plan = DrainPlan::new(
        DrainDestination::Replacement,
        ExpectedPackageState::Exact(state),
        Timestamp::new(300),
        Nonce::from_bytes([2; 32]),
    )
    .unwrap_or_else(|error| panic!("replacement plan is valid: {error:?}"));
    let stale_update = fixture.context(
        Operation::Update,
        ExpectedPackageState::Exact(StateDigest::from_bytes([90; 32])),
        plan.digest(),
        (fixture.owner, fixture.caller),
        1,
        Nonce::from_bytes([5; 32]),
    );
    let error = fixture
        .begin(&mut model, stale_update, 140)
        .err()
        .unwrap_or_else(|| panic!("stale expected state must fail"));
    assert!(matches!(error, PackageServiceError::ExpectedStateMismatch));
}

#[test]
fn changed_removal_and_activation_plans_fail_before_effect() {
    let fixture = Fixture::new();
    let mut model = PackageServiceModel::new(policy(8));
    install(&mut model, &fixture, 1);
    let state_value = model
        .slot_record(&fixture.slot(fixture.owner))
        .and_then(|record| record.state().cloned())
        .unwrap_or_else(|| panic!("state should remain"));
    let state = state_value.digest();
    let wrong_removal_plan = DrainPlan::new(
        DrainDestination::Removal,
        ExpectedPackageState::Exact(state),
        Timestamp::new(500),
        Nonce::from_bytes([3; 32]),
    )
    .unwrap_or_else(|error| panic!("removal plan is valid: {error:?}"));
    let removal_context = fixture.context_for_state(
        Operation::Remove,
        ExpectedPackageState::Exact(state),
        wrong_removal_plan.digest(),
        (fixture.owner, fixture.caller),
        &state_value,
        Nonce::from_bytes([3; 32]),
    );
    let removal_nonce = fixture
        .begin(&mut model, removal_context, 140)
        .unwrap_or_else(|error| panic!("removal may admit before drain authorization: {error:?}"));
    let error = model
        .begin_drain(
            &removal_nonce,
            DrainDestination::Removal,
            Timestamp::new(400),
            1,
            Timestamp::new(140),
        )
        .err()
        .unwrap_or_else(|| panic!("changed removal deadline must fail"));
    assert!(matches!(error, PackageServiceError::BindingMismatch));
    let status = model
        .slot_record(&fixture.slot(fixture.owner))
        .and_then(|record| record.journal_record(&removal_nonce))
        .map_or_else(
            || panic!("removal record should remain"),
            OperationJournalRecord::status,
        );
    assert_eq!(status, JournalStatus::Intent);

    model
        .cancel(&removal_nonce, Timestamp::new(150))
        .unwrap_or_else(|error| panic!("rejected removal should cancel: {error:?}"));

    let wrong_activation_plan = plan_digest(31);
    let activation_context = fixture.context(
        Operation::Activate,
        ExpectedPackageState::Exact(state),
        wrong_activation_plan,
        (fixture.owner, fixture.caller),
        1,
        Nonce::from_bytes([6; 32]),
    );
    let error = fixture
        .begin(&mut model, activation_context, 140)
        .err()
        .unwrap_or_else(|| panic!("changed activation plan must fail"));
    assert!(matches!(error, PackageServiceError::BindingMismatch));
}
