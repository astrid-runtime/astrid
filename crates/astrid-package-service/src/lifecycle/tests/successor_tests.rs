use super::cure_tests::begin_activation;
use super::*;
use crate::digest::{AuthorityDecisionDigest, ProvenanceDigest};
use crate::journal::RecoveryEvidence;
use crate::state::InstalledStateSpec;

fn recovery_evidence_for(
    token: RecoveryToken,
    observed: StateDigest,
    generation: NonZeroU64,
    activation_receipt: Option<Blake3Digest>,
) -> PackageServiceResult<RecoveryEvidence> {
    RecoveryEvidence::new(token, observed, generation, activation_receipt, true)
}

fn activation_state(
    context: &OperationContext,
    authority_digest: AuthorityDecisionDigest,
    generation: NonZeroU64,
) -> PackageServiceResult<CanonicalInstalledState> {
    new_installed_state(
        context,
        authority_digest,
        &validated_artifact(12),
        LifecycleState::Active,
        generation,
    )
}

enum ObservedMutation {
    Owner(PrincipalUid),
    PackageObject(PackageObject),
    Artifact(ArtifactIdentity),
    Content(Blake3Digest),
    Manifest(ManifestIdentity),
    Authority(AuthorityDecisionDigest),
    Provenance(ProvenanceDigest),
    Lifecycle(LifecycleState),
    Plan(PlanDigest),
    Generation(NonZeroU64),
    Nonce(Nonce),
}

#[derive(Clone, Copy)]
enum ExpectedRecoveryFailure {
    Unresolved,
    BindingMismatch,
}

fn mutated_state(
    base: &CanonicalInstalledState,
    mutation: ObservedMutation,
) -> PackageServiceResult<CanonicalInstalledState> {
    let mut owner = base.slot().owner();
    let mut package_object = base.slot().package_object();
    let mut artifact = *base.artifact();
    let mut content_root = *base.content_root();
    let mut manifest = base.manifest().clone();
    let mut authority = *base.authority_digest();
    let mut provenance = *base.provenance();
    let mut lifecycle = *base.lifecycle_state();
    let mut plan = *base.lifecycle_plan();
    let mut generation = base.generation_value();
    let mut nonce = base.completing_nonce();
    match mutation {
        ObservedMutation::Owner(value) => owner = value,
        ObservedMutation::PackageObject(value) => package_object = value,
        ObservedMutation::Artifact(value) => artifact = value,
        ObservedMutation::Content(value) => content_root = value,
        ObservedMutation::Manifest(value) => manifest = value,
        ObservedMutation::Authority(value) => authority = value,
        ObservedMutation::Provenance(value) => provenance = value,
        ObservedMutation::Lifecycle(value) => lifecycle = value,
        ObservedMutation::Plan(value) => plan = value,
        ObservedMutation::Generation(value) => generation = value,
        ObservedMutation::Nonce(value) => nonce = value,
    }
    CanonicalInstalledState::new(InstalledStateSpec {
        owner,
        package_object,
        artifact,
        content_root,
        manifest,
        authority_digest: authority,
        provenance,
        lifecycle_state: lifecycle,
        lifecycle_plan: plan,
        generation,
        completing_nonce: nonce,
    })
}

fn begin_lifecycle_without_commit(
    model: &mut PackageServiceModel,
    fixture: &Fixture,
    operation: Operation,
    nonce_byte: u8,
) -> Nonce {
    let state = model
        .slot_record(&fixture.slot(fixture.owner))
        .and_then(|record| record.state().map(CanonicalInstalledState::digest))
        .unwrap_or_else(|| panic!("installed state should exist"));
    let plan = ExpectedPackageState::Exact(state)
        .lifecycle_plan_digest(operation)
        .unwrap_or_else(|_| panic!("activation plan is valid"));
    let context = fixture.context(
        operation,
        ExpectedPackageState::Exact(state),
        plan,
        (fixture.owner, fixture.caller),
        1,
        Nonce::from_bytes([nonce_byte; 32]),
    );
    let nonce = fixture
        .begin(model, context, 130)
        .unwrap_or_else(|error| panic!("activation should be admitted: {error:?}"));
    model
        .begin_work(&nonce, Timestamp::new(140))
        .unwrap_or_else(|_| panic!("activation work should start"));
    model
        .mark_unknown(&nonce, Timestamp::new(150))
        .unwrap_or_else(|_| panic!("activation should become unknown"));
    nonce
}

fn current_state(model: &PackageServiceModel, fixture: &Fixture) -> CanonicalInstalledState {
    model
        .slot_record(&fixture.slot(fixture.owner))
        .and_then(PackageSlotRecord::state)
        .cloned()
        .unwrap_or_else(|| panic!("canonical state should exist"))
}

fn reject_observed_recovery(
    model: &mut PackageServiceModel,
    fixture: &Fixture,
    nonce: &Nonce,
    observed: &CanonicalInstalledState,
    evidence: &RecoveryEvidence,
    expected: ExpectedRecoveryFailure,
) {
    let before = current_state(model, fixture);
    let error = model
        .recover_observed(nonce, evidence, Some(observed), Timestamp::new(220))
        .err()
        .unwrap_or_else(|| panic!("invalid observed state must fail closed"));
    let correct = match expected {
        ExpectedRecoveryFailure::Unresolved => {
            matches!(error, PackageServiceError::RecoveryUnresolved)
        },
        ExpectedRecoveryFailure::BindingMismatch => {
            matches!(error, PackageServiceError::BindingMismatch)
        },
    };
    assert!(correct, "unexpected recovery failure: {error:?}");
    assert_eq!(current_state(model, fixture), before);
}

#[test]
fn recorded_drain_deadline_blocks_success_at_and_after_boundary() {
    let fixture = Fixture::new();
    let mut model = PackageServiceModel::new(policy(8));
    install(&mut model, &fixture, 1);
    let nonce = begin_update(&mut model, &fixture);
    let draining = current_state(&model, &fixture);

    for now in [200, 201] {
        let error = model
            .prove_drain_leases(&nonce, 0, Timestamp::new(now))
            .err()
            .unwrap_or_else(|| panic!("late proof must fail"));
        assert!(matches!(error, PackageServiceError::AuthorityExpired));
    }

    model
        .prove_drain_leases(&nonce, 0, Timestamp::new(199))
        .unwrap_or_else(|_| panic!("proof before the deadline should succeed"));
    let proved = current_state(&model, &fixture);
    assert_eq!(
        proved.generation_value().get(),
        draining.generation_value().get() + 1
    );
    for now in [200, 201] {
        let error = model
            .complete(
                &nonce,
                Some(&validated_artifact(13)),
                None,
                true,
                Timestamp::new(now),
            )
            .err()
            .unwrap_or_else(|| panic!("late replacement must fail"));
        assert!(matches!(error, PackageServiceError::AuthorityExpired));
    }
    assert_eq!(current_state(&model, &fixture), proved);

    let error = model
        .cancel(&nonce, Timestamp::new(200))
        .err()
        .unwrap_or_else(|| panic!("late cancellation must not restore content"));
    assert!(matches!(error, PackageServiceError::LifecycleTransition));
    assert_eq!(current_state(&model, &fixture), proved);

    let result = model
        .expire_drain(&nonce, Timestamp::new(200), true)
        .unwrap_or_else(|_| panic!("exact-boundary expiry should be explicit"));
    assert_eq!(result, DrainResult::Completed);
    let restored = current_state(&model, &fixture);
    assert_eq!(restored.lifecycle_state(), &LifecycleState::Inactive);
    assert_eq!(
        restored.generation_value().get(),
        proved.generation_value().get() + 1
    );
}

#[test]
fn activation_cancellation_without_a_drain_preserves_content() {
    let fixture = Fixture::new();
    let mut model = PackageServiceModel::new(policy(8));
    install(&mut model, &fixture, 1);
    let before = current_state(&model, &fixture);
    let state = before.digest();
    let plan = ExpectedPackageState::Exact(state)
        .lifecycle_plan_digest(Operation::Activate)
        .unwrap_or_else(|_| panic!("activation plan is valid"));
    let context = fixture.context(
        Operation::Activate,
        ExpectedPackageState::Exact(state),
        plan,
        (fixture.owner, fixture.caller),
        1,
        Nonce::from_bytes([7; 32]),
    );
    let nonce = fixture
        .begin(&mut model, context, 130)
        .unwrap_or_else(|error| panic!("activation should be admitted: {error:?}"));
    model
        .begin_work(&nonce, Timestamp::new(140))
        .unwrap_or_else(|error| panic!("activation work should start: {error:?}"));

    model
        .cancel(&nonce, Timestamp::new(150))
        .unwrap_or_else(|error| panic!("non-drain cancellation should abort: {error:?}"));

    assert_eq!(current_state(&model, &fixture), before);
    assert_eq!(
        model
            .slot_record(&fixture.slot(fixture.owner))
            .and_then(|record| record.journal_record(&nonce))
            .map(OperationJournalRecord::status),
        Some(JournalStatus::Aborted)
    );
}

#[test]
fn exact_boundary_expiry_proves_absence_without_late_completion() {
    let fixture = Fixture::new();
    let mut model = PackageServiceModel::new(policy(8));
    install(&mut model, &fixture, 1);
    let nonce = begin_remove(&mut model, &fixture);
    model
        .prove_drain_leases(&nonce, 0, Timestamp::new(399))
        .unwrap_or_else(|_| panic!("removal proof should succeed before deadline"));
    let error = model
        .complete(&nonce, None, None, true, Timestamp::new(400))
        .err()
        .unwrap_or_else(|| panic!("late removal completion must fail"));
    assert!(matches!(error, PackageServiceError::AuthorityExpired));
    let result = model
        .expire_drain(&nonce, Timestamp::new(400), true)
        .unwrap_or_else(|_| panic!("exact-boundary absence proof should be explicit"));
    assert_eq!(result, DrainResult::Completed);
    assert!(
        model
            .slot_record(&fixture.slot(fixture.owner))
            .and_then(PackageSlotRecord::state)
            .is_none()
    );
}

#[test]
fn zero_activation_evidence_is_refused_at_every_boundary() {
    assert!(
        RecoveryEvidence::new(
            RecoveryToken::from_bytes([1; 32]),
            StateDigest::from_bytes([2; 32]),
            non_zero(1),
            Some(digest(0)),
            false,
        )
        .is_err(),
        "zero activation receipt must be rejected at construction"
    );

    let fixture = Fixture::new();
    let mut model = PackageServiceModel::new(policy(8));
    install(&mut model, &fixture, 1);
    let state = current_state(&model, &fixture).digest();
    let plan = ExpectedPackageState::Exact(state)
        .lifecycle_plan_digest(Operation::Activate)
        .unwrap_or_else(|_| panic!("activation plan is valid"));
    let context = fixture.context(
        Operation::Activate,
        ExpectedPackageState::Exact(state),
        plan,
        (fixture.owner, fixture.caller),
        1,
        Nonce::from_bytes([4; 32]),
    );
    let nonce = fixture
        .begin(&mut model, context, 130)
        .unwrap_or_else(|_| panic!("activation should be admitted"));
    model
        .begin_work(&nonce, Timestamp::new(140))
        .unwrap_or_else(|_| panic!("activation work should start"));
    let error = model
        .complete(&nonce, None, Some(digest(0)), true, Timestamp::new(150))
        .err()
        .unwrap_or_else(|| panic!("zero runtime receipt must fail"));
    assert!(matches!(error, PackageServiceError::BindingMismatch));
}

#[test]
fn lifecycle_transitions_rebind_the_completing_nonce() {
    let fixture = Fixture::new();
    let mut model = PackageServiceModel::new(policy(8));
    let install_nonce = Nonce::from_bytes([1; 32]);
    install(&mut model, &fixture, 1);
    let installed = current_state(&model, &fixture);
    assert_eq!(installed.completing_nonce(), install_nonce);

    let activation_nonce = begin_activation(&mut model, &fixture, 4);
    let active = current_state(&model, &fixture);
    assert_eq!(active.completing_nonce(), activation_nonce);
    assert_eq!(active.generation_value().get(), 2);

    let state = active.digest();
    let plan = ExpectedPackageState::Exact(state)
        .lifecycle_plan_digest(Operation::Deactivate)
        .unwrap_or_else(|_| panic!("deactivation plan is valid"));
    let context = fixture.context(
        Operation::Deactivate,
        ExpectedPackageState::Exact(state),
        plan,
        (fixture.owner, fixture.caller),
        1,
        Nonce::from_bytes([5; 32]),
    );
    let nonce = fixture
        .begin(&mut model, context, 130)
        .unwrap_or_else(|_| panic!("deactivation should be admitted"));
    model
        .begin_work(&nonce, Timestamp::new(140))
        .unwrap_or_else(|_| panic!("deactivation work should start"));
    model
        .complete(&nonce, None, None, true, Timestamp::new(150))
        .unwrap_or_else(|_| panic!("deactivation should commit"));
    let inactive = current_state(&model, &fixture);
    assert_eq!(inactive.completing_nonce(), nonce);
    assert_eq!(inactive.generation_value().get(), 3);
}

#[test]
fn observed_recovery_boundary_accepts_only_the_exact_successor() {
    let fixture = Fixture::new();
    let mut model = PackageServiceModel::new(policy(8));
    install(&mut model, &fixture, 1);
    let draining = current_state(&model, &fixture);
    let nonce = begin_lifecycle_without_commit(&mut model, &fixture, Operation::Activate, 4);
    let context = model
        .context_for(&nonce)
        .unwrap_or_else(|_| panic!("unknown context should remain"));
    let slot = fixture.slot(fixture.owner);
    let authority_digest = model
        .slot_record(&slot)
        .and_then(|record| record.journal_record(&nonce))
        .map_or_else(
            || panic!("unknown authority should remain"),
            |record| *record.authority_digest(),
        );
    let token = model
        .slot_record(&slot)
        .and_then(|record| record.journal_record(&nonce))
        .map_or_else(
            || panic!("unknown token should remain"),
            OperationJournalRecord::recovery_token,
        );
    let valid_generation = non_zero(draining.generation_value().get() + 1);
    let valid = activation_state(&context, authority_digest, valid_generation)
        .unwrap_or_else(|_| panic!("valid activation state should construct"));
    let valid_evidence = recovery_evidence_for(
        token,
        valid.digest(),
        valid.generation_value(),
        Some(digest(31)),
    )
    .unwrap_or_else(|_| panic!("valid evidence should construct"));
    let receipt = model
        .recover_observed(&nonce, &valid_evidence, Some(&valid), Timestamp::new(220))
        .unwrap_or_else(|error| panic!("exact observed state should recover: {error:?}"))
        .unwrap_or_else(|| panic!("exact observed state should produce a receipt"));
    assert_eq!(receipt.outcome(), ReceiptOutcome::Activated);
    assert_eq!(current_state(&model, &fixture), valid);
}

#[test]
fn deactivation_recovery_rejects_stale_and_skipped_states() {
    let fixture = Fixture::new();
    let mut model = PackageServiceModel::new(policy(8));
    install(&mut model, &fixture, 1);
    let slot = fixture.slot(fixture.owner);
    begin_activation(&mut model, &fixture, 4);
    let activation = begin_lifecycle_without_commit(&mut model, &fixture, Operation::Deactivate, 6);
    let authority_digest = model
        .slot_record(&slot)
        .and_then(|record| record.journal_record(&activation))
        .map_or_else(
            || panic!("second unknown authority should remain"),
            |record| *record.authority_digest(),
        );
    let token = model
        .slot_record(&slot)
        .and_then(|record| record.journal_record(&activation))
        .map_or_else(
            || panic!("second unknown token should remain"),
            OperationJournalRecord::recovery_token,
        );
    let deactivation_context = model
        .context_for(&activation)
        .unwrap_or_else(|_| panic!("second unknown context should remain"));
    let current = current_state(&model, &fixture);
    let skipped = new_installed_state(
        &deactivation_context,
        authority_digest,
        &validated_artifact(12),
        LifecycleState::Inactive,
        non_zero(current.generation_value().get() + 2),
    )
    .unwrap_or_else(|_| panic!("skipped activation state should construct"));

    let mismatched_evidence = recovery_evidence_for(
        token,
        StateDigest::from_bytes([90; 32]),
        skipped.generation_value(),
        None,
    )
    .unwrap_or_else(|_| panic!("mismatched evidence should construct"));
    reject_observed_recovery(
        &mut model,
        &fixture,
        &activation,
        &skipped,
        &mismatched_evidence,
        ExpectedRecoveryFailure::Unresolved,
    );

    let skipped_evidence =
        recovery_evidence_for(token, skipped.digest(), skipped.generation_value(), None)
            .unwrap_or_else(|_| panic!("skipped evidence should construct"));
    reject_observed_recovery(
        &mut model,
        &fixture,
        &activation,
        &skipped,
        &skipped_evidence,
        ExpectedRecoveryFailure::Unresolved,
    );

    let stale = new_installed_state(
        &deactivation_context,
        authority_digest,
        &validated_artifact(12),
        LifecycleState::Inactive,
        non_zero(current.generation_value().get()),
    )
    .unwrap_or_else(|_| panic!("stale activation state should construct"));
    let stale_evidence =
        recovery_evidence_for(token, stale.digest(), stale.generation_value(), None)
            .unwrap_or_else(|_| panic!("stale evidence should construct"));
    reject_observed_recovery(
        &mut model,
        &fixture,
        &activation,
        &stale,
        &stale_evidence,
        ExpectedRecoveryFailure::Unresolved,
    );

    let wrong_token_evidence = recovery_evidence_for(
        RecoveryToken::from_bytes([9; 32]),
        stale.digest(),
        stale.generation_value(),
        None,
    )
    .unwrap_or_else(|_| panic!("wrong-token evidence should construct"));
    reject_observed_recovery(
        &mut model,
        &fixture,
        &activation,
        &stale,
        &wrong_token_evidence,
        ExpectedRecoveryFailure::Unresolved,
    );

    let zero_receipt_evidence = RecoveryEvidence::new(
        token,
        stale.digest(),
        stale.generation_value(),
        Some(digest(0)),
        true,
    );
    assert!(zero_receipt_evidence.is_err());
}

#[test]
fn observed_boundary_rejects_each_mutated_recovery_binding() {
    let fixture = Fixture::new();
    let mut model = PackageServiceModel::new(policy(8));
    install(&mut model, &fixture, 1);
    let nonce = begin_update_with_deadline(&mut model, &fixture, Timestamp::new(400));
    model
        .mark_unknown(&nonce, Timestamp::new(150))
        .unwrap_or_else(|_| panic!("unknown boundary should be recorded"));
    let slot = fixture.slot(fixture.owner);
    let context = model
        .context_for(&nonce)
        .unwrap_or_else(|_| panic!("unknown context should remain"));
    let authority = model
        .slot_record(&slot)
        .and_then(|record| record.journal_record(&nonce))
        .map_or_else(
            || panic!("unknown authority should remain"),
            |record| *record.authority_digest(),
        );
    let token = model
        .slot_record(&slot)
        .and_then(|record| record.journal_record(&nonce))
        .map_or_else(
            || panic!("unknown token should remain"),
            OperationJournalRecord::recovery_token,
        );
    let valid = new_installed_state(
        &context,
        authority,
        &validated_artifact(13),
        LifecycleState::Inactive,
        non_zero(3),
    )
    .unwrap_or_else(|error| panic!("valid update state should construct: {error:?}"));

    reject_mutated_update_bindings(&mut model, &fixture, &nonce, token, &valid);

    let runtime_mismatch = recovery_evidence_for(token, valid.digest(), non_zero(2), None)
        .unwrap_or_else(|error| panic!("{error:?}"));
    reject_observed_recovery(
        &mut model,
        &fixture,
        &nonce,
        &valid,
        &runtime_mismatch,
        ExpectedRecoveryFailure::Unresolved,
    );

    let unexpected_receipt =
        recovery_evidence_for(token, valid.digest(), non_zero(3), Some(digest(31)))
            .unwrap_or_else(|error| panic!("{error:?}"));
    reject_observed_recovery(
        &mut model,
        &fixture,
        &nonce,
        &valid,
        &unexpected_receipt,
        ExpectedRecoveryFailure::BindingMismatch,
    );

    let wrong_token = recovery_evidence_for(
        RecoveryToken::from_bytes([28; 32]),
        valid.digest(),
        non_zero(3),
        None,
    )
    .unwrap_or_else(|error| panic!("{error:?}"));
    reject_observed_recovery(
        &mut model,
        &fixture,
        &nonce,
        &valid,
        &wrong_token,
        ExpectedRecoveryFailure::Unresolved,
    );

    let evidence_digest_mismatch =
        recovery_evidence_for(token, StateDigest::from_bytes([29; 32]), non_zero(3), None)
            .unwrap_or_else(|error| panic!("{error:?}"));
    reject_observed_recovery(
        &mut model,
        &fixture,
        &nonce,
        &valid,
        &evidence_digest_mismatch,
        ExpectedRecoveryFailure::Unresolved,
    );
}

fn reject_mutated_update_bindings(
    model: &mut PackageServiceModel,
    fixture: &Fixture,
    nonce: &Nonce,
    token: RecoveryToken,
    valid: &CanonicalInstalledState,
) {
    let alternate_artifact = ArtifactIdentity::new(format(1), non_zero(129), sha(21), digest(21))
        .unwrap_or_else(|error| panic!("alternate artifact should construct: {error:?}"));
    let alternate_manifest = ManifestIdentity::new(
        manifest_format(1),
        base_manifest_name(valid),
        base_manifest_version(valid),
        digest(22),
    )
    .unwrap_or_else(|error| panic!("alternate manifest should construct: {error:?}"));
    let mutations = [
        ObservedMutation::Owner(fixture.other_owner),
        ObservedMutation::PackageObject(PackageObject::from_bytes([45; 32])),
        ObservedMutation::Artifact(alternate_artifact),
        ObservedMutation::Content(digest(23)),
        ObservedMutation::Manifest(alternate_manifest),
        ObservedMutation::Authority(AuthorityDecisionDigest::from_bytes([24; 32])),
        ObservedMutation::Provenance(ProvenanceDigest::from_bytes([25; 32])),
        ObservedMutation::Lifecycle(LifecycleState::Active),
        ObservedMutation::Plan(plan_digest(26)),
        ObservedMutation::Generation(non_zero(2)),
        ObservedMutation::Generation(non_zero(4)),
        ObservedMutation::Nonce(Nonce::from_bytes([27; 32])),
    ];
    for mutation in mutations {
        let mutated = mutated_state(valid, mutation).unwrap_or_else(|error| panic!("{error:?}"));
        let evidence =
            recovery_evidence_for(token, mutated.digest(), mutated.generation_value(), None)
                .unwrap_or_else(|error| panic!("{error:?}"));
        reject_observed_recovery(
            model,
            fixture,
            nonce,
            &mutated,
            &evidence,
            ExpectedRecoveryFailure::Unresolved,
        );
    }
}

fn base_manifest_name(state: &CanonicalInstalledState) -> crate::identity::PackageName {
    state.manifest().package_name().clone()
}

fn base_manifest_version(state: &CanonicalInstalledState) -> crate::identity::PackageVersion {
    state.manifest().package_version().clone()
}
