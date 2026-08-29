use super::*;
use crate::journal::RecoveryEvidence;

fn recovery_evidence(
    token: RecoveryToken,
    observed: StateDigest,
    generation: u64,
) -> RecoveryEvidence {
    match RecoveryEvidence::new(token, observed, non_zero(generation), None, false) {
        Ok(value) => value,
        Err(error) => panic!("test recovery evidence is valid: {error:?}"),
    }
}

pub(super) fn begin_activation(
    model: &mut PackageServiceModel,
    fixture: &Fixture,
    nonce_byte: u8,
) -> Nonce {
    let state = model
        .slot_record(&fixture.slot(fixture.owner))
        .and_then(|record| record.state().map(CanonicalInstalledState::digest))
        .unwrap_or_else(|| panic!("installed state should exist"));
    let activation_plan = ExpectedPackageState::Exact(state)
        .lifecycle_plan_digest(Operation::Activate)
        .unwrap_or_else(|_| panic!("activation plan is valid"));
    let context = fixture.context(
        Operation::Activate,
        ExpectedPackageState::Exact(state),
        activation_plan,
        (fixture.owner, fixture.caller),
        1,
        Nonce::from_bytes([nonce_byte; 32]),
    );
    let nonce = fixture
        .begin(model, context, 130)
        .unwrap_or_else(|error| panic!("activation should be admitted: {error:?}"));
    model
        .begin_work(&nonce, Timestamp::new(140))
        .unwrap_or_else(|_| panic!("activation should start"));
    model
        .complete(&nonce, None, Some(digest(31)), true, Timestamp::new(150))
        .unwrap_or_else(|_| panic!("activation should commit"));
    nonce
}

#[test]
fn mid_drain_recovery_does_not_infer_update_success() {
    let fixture = Fixture::new();
    let mut model = PackageServiceModel::new(policy(8));
    install(&mut model, &fixture, 1);
    let prior = model
        .slot_record(&fixture.slot(fixture.owner))
        .and_then(|record| record.state())
        .cloned()
        .unwrap_or_else(|| panic!("prior state should exist"));
    let nonce = begin_update(&mut model, &fixture);
    model
        .mark_unknown(&nonce, Timestamp::new(180))
        .unwrap_or_else(|_| panic!("mid-drain boundary should become unknown"));
    let draining = model
        .slot_record(&fixture.slot(fixture.owner))
        .and_then(|record| record.state().map(CanonicalInstalledState::digest))
        .unwrap_or_else(|| panic!("draining state should exist"));
    let draining_generation = model
        .slot_record(&fixture.slot(fixture.owner))
        .and_then(|record| record.state())
        .map(|state| state.generation_value())
        .unwrap_or_else(|| panic!("draining generation should exist"));
    let token = model
        .slot_record(&fixture.slot(fixture.owner))
        .and_then(|record| record.journal_record(&nonce))
        .map(OperationJournalRecord::recovery_token)
        .unwrap_or_else(|| panic!("recovery record should exist"));
    let false_success = recovery_evidence(token, draining, draining_generation.get());
    let error = model
        .recover(&nonce, &false_success, Timestamp::new(190))
        .err()
        .unwrap_or_else(|| panic!("mid-drain evidence must not prove an update"));
    assert!(matches!(error, PackageServiceError::RecoveryUnresolved));
    assert_eq!(
        model
            .slot_record(&fixture.slot(fixture.owner))
            .and_then(|record| record.journal_record(&nonce))
            .map(OperationJournalRecord::status),
        Some(JournalStatus::Unknown)
    );

    let old_evidence = recovery_evidence(token, prior.digest(), 1);
    model
        .recover(&nonce, &old_evidence, Timestamp::new(200))
        .unwrap_or_else(|error| panic!("exact old-state evidence should resolve: {error:?}"));
    let restored = model
        .slot_record(&fixture.slot(fixture.owner))
        .and_then(|record| record.state())
        .cloned()
        .unwrap_or_else(|| panic!("restored state should exist"));
    assert_eq!(restored.lifecycle_state(), &LifecycleState::Inactive,);
    assert_eq!(restored.generation_value().get(), 3);
    assert_eq!(restored.completing_nonce(), nonce);
}

#[test]
fn recovery_rejects_a_token_mismatch() {
    let fixture = Fixture::new();
    let mut model = PackageServiceModel::new(policy(8));
    install(&mut model, &fixture, 1);
    let prior = model
        .slot_record(&fixture.slot(fixture.owner))
        .and_then(|record| record.state())
        .cloned()
        .unwrap_or_else(|| panic!("prior state should exist"));
    let nonce = begin_update(&mut model, &fixture);
    model
        .mark_unknown(&nonce, Timestamp::new(180))
        .unwrap_or_else(|_| panic!("unknown boundary should be recorded"));
    assert!(
        RecoveryEvidence::new(
            RecoveryToken::from_bytes([0; 32]),
            prior.digest(),
            non_zero(1),
            None,
            false,
        )
        .is_err()
    );
    let evidence = recovery_evidence(RecoveryToken::from_bytes([8; 32]), prior.digest(), 1);
    let error = model
        .recover(&nonce, &evidence, Timestamp::new(190))
        .err()
        .unwrap_or_else(|| panic!("token mismatch must not resolve recovery"));
    assert!(matches!(error, PackageServiceError::RecoveryUnresolved));
    assert_eq!(
        model
            .slot_record(&fixture.slot(fixture.owner))
            .and_then(|record| record.journal_record(&nonce))
            .map(OperationJournalRecord::status),
        Some(JournalStatus::Unknown)
    );
}

#[test]
fn recovery_accepts_structurally_proven_new_update_state() {
    let fixture = Fixture::new();
    let mut model = PackageServiceModel::new(policy(8));
    install(&mut model, &fixture, 1);
    let nonce = begin_update(&mut model, &fixture);
    let slot = fixture.slot(fixture.owner);
    model
        .mark_unknown(&nonce, Timestamp::new(180))
        .unwrap_or_else(|_| panic!("unknown boundary should be recorded"));
    let context = model
        .context_for(&nonce)
        .unwrap_or_else(|_| panic!("unknown context should remain"));
    let authority_digest = model
        .slot_record(&slot)
        .and_then(|record| record.journal_record(&nonce))
        .map(|record| *record.authority_digest())
        .unwrap_or_else(|| panic!("unknown authority should remain"));
    let new_state = new_installed_state(
        &context,
        authority_digest,
        &validated_artifact(13),
        LifecycleState::Inactive,
        non_zero(3),
    )
    .unwrap_or_else(|_| panic!("new update state should construct"));
    let token = model
        .slot_record(&slot)
        .and_then(|record| record.journal_record(&nonce))
        .map(OperationJournalRecord::recovery_token)
        .unwrap_or_else(|| panic!("recovery token should remain"));
    let evidence = match RecoveryEvidence::new(
        token,
        new_state.digest(),
        new_state.generation_value(),
        None,
        true,
    ) {
        Ok(value) => value,
        Err(error) => panic!("new-state recovery evidence is valid: {error:?}"),
    };
    let state_before_recovery = model
        .slot_record(&slot)
        .and_then(|record| record.state())
        .cloned()
        .unwrap_or_else(|| panic!("draining state should remain"));
    for now in [200, 201] {
        let error = model
            .recover_observed(&nonce, &evidence, Some(&new_state), Timestamp::new(now))
            .err()
            .unwrap_or_else(|| panic!("late replacement recovery must fail"));
        assert!(matches!(error, PackageServiceError::AuthorityExpired));
        assert_eq!(
            model.slot_record(&slot).and_then(|record| record.state()),
            Some(&state_before_recovery)
        );
    }
    let receipt = model
        .recover_observed(&nonce, &evidence, Some(&new_state), Timestamp::new(199))
        .unwrap_or_else(|_| panic!("structural new-state proof should recover"))
        .unwrap_or_else(|| panic!("new-state proof should produce a receipt"));
    assert_eq!(receipt.outcome(), ReceiptOutcome::Updated);
    assert_eq!(receipt.after_state(), new_state.digest());
    assert_eq!(receipt.state_generation().get(), 3);
}

#[test]
fn active_drain_abort_and_expiry_restore_inactive_content() {
    let fixture = Fixture::new();
    let mut model = PackageServiceModel::new(policy(8));
    install(&mut model, &fixture, 1);
    begin_activation(&mut model, &fixture, 8);
    let active_before = model
        .slot_record(&fixture.slot(fixture.owner))
        .and_then(|record| record.state())
        .cloned()
        .unwrap_or_else(|| panic!("active state should exist"));

    let update_nonce = begin_update(&mut model, &fixture);
    let recovery_token = model
        .slot_record(&fixture.slot(fixture.owner))
        .and_then(|record| record.journal_record(&update_nonce))
        .map(OperationJournalRecord::recovery_token)
        .unwrap_or_else(|| panic!("recovery record should exist"));
    model
        .expire_drain(&update_nonce, Timestamp::new(250), false)
        .unwrap_or_else(|_| panic!("drain expiry should be observable"));
    assert!(matches!(
        model
            .slot_record(&fixture.slot(fixture.owner))
            .and_then(|record| record.state())
            .map(CanonicalInstalledState::lifecycle_state),
        Some(LifecycleState::Draining { live_leases: 1, .. })
    ));
    let blocked_evidence = recovery_evidence(
        recovery_token,
        active_before.digest(),
        active_before.generation_value().get(),
    );
    model
        .recover(&update_nonce, &blocked_evidence, Timestamp::new(260))
        .unwrap_or_else(|error| panic!("blocked drain should recover old content: {error:?}"));
    let expired = model
        .slot_record(&fixture.slot(fixture.owner))
        .and_then(|record| record.state())
        .cloned()
        .unwrap_or_else(|| panic!("cancelled state should remain"));
    assert_eq!(expired.artifact(), active_before.artifact());
    assert_eq!(expired.manifest(), active_before.manifest());
    assert_eq!(expired.content_root(), active_before.content_root());
    assert_eq!(expired.lifecycle_state(), &LifecycleState::Inactive);
    assert!(expired.generation_value().get() > active_before.generation_value().get());

    let remove_nonce = begin_remove(&mut model, &fixture);
    model
        .cancel(&remove_nonce, Timestamp::new(320))
        .unwrap_or_else(|_| panic!("drain cancellation should succeed"));
    let cancelled = model
        .slot_record(&fixture.slot(fixture.owner))
        .and_then(|record| record.state())
        .cloned()
        .unwrap_or_else(|| panic!("cancelled state should remain"));
    assert_eq!(cancelled.content_root(), expired.content_root());
    assert_eq!(cancelled.lifecycle_state(), &LifecycleState::Inactive);
    assert!(cancelled.generation_value().get() > expired.generation_value().get());
}

#[test]
fn lifecycle_contexts_must_match_canonical_state() {
    let fixture = Fixture::new();
    let mut model = PackageServiceModel::new(policy(8));
    install(&mut model, &fixture, 1);
    let state = model
        .slot_record(&fixture.slot(fixture.owner))
        .and_then(|record| record.state().map(CanonicalInstalledState::digest))
        .unwrap_or_else(|| panic!("installed state should exist"));
    let unrelated_activation = fixture.context(
        Operation::Activate,
        ExpectedPackageState::Exact(state),
        plan_digest(30),
        (fixture.owner, fixture.caller),
        1,
        Nonce::from_bytes([4; 32]),
    );
    let error = fixture
        .begin(&mut model, unrelated_activation, 130)
        .err()
        .unwrap_or_else(|| panic!("unrelated activation bindings must fail"));
    assert!(matches!(error, PackageServiceError::BindingMismatch));

    let unrelated_removal = fixture.context(
        Operation::Remove,
        ExpectedPackageState::Exact(state),
        plan_digest(31),
        (fixture.owner, fixture.caller),
        1,
        Nonce::from_bytes([5; 32]),
    );
    let removal_nonce = fixture
        .begin(&mut model, unrelated_removal, 130)
        .unwrap_or_else(|_| panic!("removal admission is separate from drain authorization"));
    let error = model
        .begin_drain(
            &removal_nonce,
            DrainDestination::Removal,
            Timestamp::new(200),
            0,
            Timestamp::new(140),
        )
        .err()
        .unwrap_or_else(|| panic!("unrelated removal plan must not authorize a drain"));
    assert!(matches!(error, PackageServiceError::BindingMismatch));
}

#[test]
fn repeated_updates_monotonically_bump_package_generation() {
    let fixture = Fixture::new();
    let mut model = PackageServiceModel::new(policy(8));
    install(&mut model, &fixture, 1);
    let installed_generation = model
        .slot_record(&fixture.slot(fixture.owner))
        .and_then(|record| record.state())
        .map(|state| state.generation_value().get())
        .unwrap_or_else(|| panic!("installed state should exist"));
    assert_eq!(installed_generation, 1);

    let first = begin_update(&mut model, &fixture);
    model
        .prove_drain_leases(&first, 0, Timestamp::new(199))
        .unwrap_or_else(|_| panic!("first drain should complete"));
    model
        .complete(
            &first,
            Some(&validated_artifact(13)),
            None,
            true,
            Timestamp::new(199),
        )
        .unwrap_or_else(|_| panic!("first update should commit"));
    let first_generation = model
        .slot_record(&fixture.slot(fixture.owner))
        .and_then(|record| record.state())
        .map(|state| state.generation_value().get())
        .unwrap_or_else(|| panic!("first updated state should exist"));
    assert!(first_generation > installed_generation);

    let second_state = model
        .slot_record(&fixture.slot(fixture.owner))
        .and_then(|record| record.state().map(CanonicalInstalledState::digest))
        .unwrap_or_else(|| panic!("updated state should exist"));
    let replacement_plan = match DrainPlan::new(
        DrainDestination::Replacement,
        ExpectedPackageState::Exact(second_state),
        Timestamp::new(350),
        Nonce::from_bytes([6; 32]),
    ) {
        Ok(value) => value,
        Err(_) => panic!("replacement plan is valid"),
    };
    let second_context = fixture.context(
        Operation::Update,
        ExpectedPackageState::Exact(second_state),
        replacement_plan.digest(),
        (fixture.owner, fixture.caller),
        1,
        Nonce::from_bytes([6; 32]),
    );
    let second = fixture
        .begin(&mut model, second_context, 300)
        .unwrap_or_else(|_| panic!("second update should be admitted"));
    model
        .begin_drain(
            &second,
            DrainDestination::Replacement,
            Timestamp::new(350),
            0,
            Timestamp::new(310),
        )
        .unwrap_or_else(|_| panic!("second drain should start"));
    model
        .complete(
            &second,
            Some(&validated_artifact(14)),
            None,
            true,
            Timestamp::new(320),
        )
        .unwrap_or_else(|_| panic!("second update should commit"));
    let second_generation = model
        .slot_record(&fixture.slot(fixture.owner))
        .and_then(|record| record.state())
        .map(|state| state.generation_value().get())
        .unwrap_or_else(|| panic!("second updated state should exist"));
    assert!(second_generation > first_generation);
}

#[test]
fn expired_intent_reaches_terminal_and_releases_slot() {
    let fixture = Fixture::new();
    let mut model = PackageServiceModel::new(policy_short_retention(1, 128));
    let context = fixture.context_with_expiry(ContextOptions {
        operation: Operation::Install,
        expected: ExpectedPackageState::Absent,
        plan: plan_digest(20),
        participants: (fixture.owner, fixture.caller),
        generation: 1,
        nonce: Nonce::from_bytes([1; 32]),
        expiry: Timestamp::new(400),
    });
    let nonce = fixture
        .begin(&mut model, context, 100)
        .unwrap_or_else(|_| panic!("intent should be admitted"));
    model
        .expire_unresolved(&nonce, Timestamp::new(500))
        .unwrap_or_else(|_| panic!("expired intent should be terminal"));
    assert_eq!(
        model
            .slot_record(&fixture.slot(fixture.owner))
            .and_then(|record| record.journal_record(&nonce))
            .map(OperationJournalRecord::status),
        Some(JournalStatus::Expired)
    );

    let replacement = fixture.context_with_expiry(ContextOptions {
        operation: Operation::Install,
        expected: ExpectedPackageState::Absent,
        plan: plan_digest(21),
        participants: (fixture.owner, fixture.caller),
        generation: 1,
        nonce: Nonce::from_bytes([2; 32]),
        expiry: Timestamp::new(1_400),
    });
    fixture
        .begin(&mut model, replacement, 700)
        .unwrap_or_else(|_| panic!("terminal expiry must not fence admission"));
}
