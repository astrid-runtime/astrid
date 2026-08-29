use super::cure_tests::begin_activation;
use super::*;
use crate::digest::ProvenanceDigest;
use crate::journal::RecoveryEvidence;
use crate::state::InstalledStateSpec;

#[derive(Clone, Copy)]
enum DrainResolution {
    Cancel,
    Expire,
    Recover,
}

fn recovery_evidence_for(
    token: RecoveryToken,
    observed: StateDigest,
    generation: NonZeroU64,
) -> PackageServiceResult<RecoveryEvidence> {
    RecoveryEvidence::new(token, observed, generation, None, true)
}

fn current_state(model: &PackageServiceModel, fixture: &Fixture) -> CanonicalInstalledState {
    model
        .slot_record(&fixture.slot(fixture.owner))
        .and_then(PackageSlotRecord::state)
        .cloned()
        .unwrap_or_else(|| panic!("canonical state should exist"))
}

fn drain_to_boundary(
    proof_count: usize,
) -> (Fixture, PackageServiceModel, CanonicalInstalledState, Nonce) {
    let fixture = Fixture::new();
    let mut model = PackageServiceModel::new(policy(8));
    install(&mut model, &fixture, 1);
    let base = current_state(&model, &fixture);
    assert_eq!(base.generation_value().get(), 1);
    let nonce = begin_update(&mut model, &fixture);
    for proof in 0..proof_count {
        model
            .prove_drain_leases(
                &nonce,
                u32::try_from(proof + 10).unwrap_or(u32::MAX),
                Timestamp::new(150),
            )
            .unwrap_or_else(|error| panic!("drain proof should advance: {error:?}"));
        let expected_boundary = 2 + proof as u64 + 1;
        let proved = current_state(&model, &fixture);
        assert_eq!(proved.generation_value().get(), expected_boundary);
        let lineage = model
            .slot_record(&fixture.slot(fixture.owner))
            .and_then(|record| record.journal_record(&nonce))
            .and_then(OperationJournalRecord::drain_lineage)
            .unwrap_or_else(|| panic!("drain lineage should remain"));
        assert_eq!(lineage.boundary_generation().get(), expected_boundary);
    }
    (fixture, model, base, nonce)
}

fn assert_base_content(
    restored: &CanonicalInstalledState,
    base: &CanonicalInstalledState,
    nonce: &Nonce,
    generation: u64,
) {
    assert_eq!(restored.artifact(), base.artifact());
    assert_eq!(restored.content_root(), base.content_root());
    assert_eq!(restored.manifest(), base.manifest());
    assert_eq!(restored.authority_digest(), base.authority_digest());
    assert_eq!(restored.provenance(), base.provenance());
    assert_eq!(restored.lifecycle_plan(), base.lifecycle_plan());
    assert_eq!(restored.lifecycle_state(), &LifecycleState::Inactive);
    assert_eq!(restored.completing_nonce(), *nonce);
    assert_eq!(restored.generation_value().get(), generation);
}

#[test]
fn drain_resolution_restores_the_exact_successor_of_the_boundary() {
    for proof_count in [0, 1, 3] {
        for resolution in [
            DrainResolution::Cancel,
            DrainResolution::Expire,
            DrainResolution::Recover,
        ] {
            let (fixture, mut model, base, nonce) = drain_to_boundary(proof_count);
            let expected_generation = 2 + proof_count as u64 + 1;
            let token = model
                .slot_record(&fixture.slot(fixture.owner))
                .and_then(|record| record.journal_record(&nonce))
                .map(OperationJournalRecord::recovery_token)
                .unwrap_or_else(|| panic!("drain record should remain"));

            match resolution {
                DrainResolution::Cancel => {
                    model
                        .cancel(&nonce, Timestamp::new(150))
                        .unwrap_or_else(|error| panic!("drain cancel should resolve: {error:?}"));
                },
                DrainResolution::Expire => {
                    let result = model
                        .expire_drain(&nonce, Timestamp::new(250), true)
                        .unwrap_or_else(|error| panic!("drain expiry should resolve: {error:?}"));
                    assert_eq!(result, DrainResult::Completed);
                },
                DrainResolution::Recover => {
                    model
                        .mark_unknown(&nonce, Timestamp::new(160))
                        .unwrap_or_else(|error| panic!("drain should become unknown: {error:?}"));
                    let evidence =
                        recovery_evidence_for(token, base.digest(), base.generation_value())
                            .unwrap_or_else(|error| panic!("{error:?}"));
                    model
                        .recover(&nonce, &evidence, Timestamp::new(190))
                        .unwrap_or_else(|error| {
                            panic!("old-state recovery should resolve: {error:?}")
                        });
                },
            }

            let restored = current_state(&model, &fixture);
            assert_base_content(&restored, &base, &nonce, expected_generation);
            assert_eq!(
                model
                    .slot_record(&fixture.slot(fixture.owner))
                    .and_then(|record| record.journal_record(&nonce))
                    .map(OperationJournalRecord::state_generation),
                Some(Some(non_zero(expected_generation)))
            );
        }
    }
}

#[test]
fn proof_oracle_refuses_a_reset_on_each_proof() {
    let (fixture, model, _base, nonce) = drain_to_boundary(2);
    let lineage = model
        .slot_record(&fixture.slot(fixture.owner))
        .and_then(|record| record.journal_record(&nonce))
        .and_then(OperationJournalRecord::drain_lineage)
        .unwrap_or_else(|| panic!("drain lineage should remain"));
    assert_eq!(lineage.boundary_generation().get(), 4);
    assert_ne!(lineage.boundary_generation().get(), 3);
}

fn reject_old_evidence(
    model: &mut PackageServiceModel,
    fixture: &Fixture,
    nonce: &Nonce,
    observed: Option<&CanonicalInstalledState>,
    generation: NonZeroU64,
) {
    let token = model
        .slot_record(&fixture.slot(fixture.owner))
        .and_then(|record| record.journal_record(nonce))
        .map(OperationJournalRecord::recovery_token)
        .unwrap_or_else(|| panic!("recovery token should remain"));
    let base_digest = model
        .slot_record(&fixture.slot(fixture.owner))
        .and_then(|record| record.journal_record(nonce))
        .map(OperationJournalRecord::before_state)
        .unwrap_or_else(|| panic!("operation boundary should remain"));
    let evidence = recovery_evidence_for(token, base_digest, generation)
        .unwrap_or_else(|error| panic!("{error:?}"));
    let before = current_state(model, fixture);
    let error = match observed {
        Some(observed) => model
            .recover_observed(nonce, &evidence, Some(observed), Timestamp::new(190))
            .err()
            .unwrap_or_else(|| panic!("non-canonical generation must fail closed")),
        None => model
            .recover(nonce, &evidence, Timestamp::new(190))
            .err()
            .unwrap_or_else(|| panic!("non-canonical generation must fail closed")),
    };
    assert!(matches!(error, PackageServiceError::RecoveryUnresolved));
    assert_eq!(current_state(model, fixture), before);
    assert_eq!(
        model
            .slot_record(&fixture.slot(fixture.owner))
            .and_then(|record| record.journal_record(nonce))
            .map(OperationJournalRecord::status),
        Some(JournalStatus::Unknown)
    );
}

#[test]
fn old_state_recovery_rejects_every_noncanonical_generation_claim() {
    let fixture = Fixture::new();
    let mut model = PackageServiceModel::new(policy(8));
    install(&mut model, &fixture, 1);
    begin_activation(&mut model, &fixture, 8);
    let lifecycle_plan = ExpectedPackageState::Exact(current_state(&model, &fixture).digest())
        .lifecycle_plan_digest(Operation::Deactivate)
        .unwrap_or_else(|error| panic!("{error:?}"));
    let state = current_state(&model, &fixture).digest();
    let context = fixture.context(
        Operation::Deactivate,
        ExpectedPackageState::Exact(state),
        lifecycle_plan,
        (fixture.owner, fixture.caller),
        1,
        Nonce::from_bytes([9; 32]),
    );
    let lifecycle_nonce = fixture
        .begin(&mut model, context, 125)
        .unwrap_or_else(|error| panic!("{error:?}"));
    model
        .begin_work(&lifecycle_nonce, Timestamp::new(130))
        .unwrap_or_else(|error| panic!("{error:?}"));
    model
        .complete(&lifecycle_nonce, None, None, true, Timestamp::new(135))
        .unwrap_or_else(|error| panic!("{error:?}"));

    let base = current_state(&model, &fixture);
    assert_eq!(base.generation_value().get(), 3);
    let nonce = begin_update(&mut model, &fixture);
    model
        .prove_drain_leases(&nonce, 17, Timestamp::new(145))
        .unwrap_or_else(|error| panic!("{error:?}"));
    model
        .prove_drain_leases(&nonce, 0, Timestamp::new(150))
        .unwrap_or_else(|error| panic!("{error:?}"));
    model
        .mark_unknown(&nonce, Timestamp::new(160))
        .unwrap_or_else(|error| panic!("{error:?}"));
    let boundary = 1 + 2 + 1 + 2;
    assert_eq!(boundary, 6);
    assert_eq!(
        current_state(&model, &fixture).generation_value().get(),
        boundary
    );
    let service_generation = model
        .slot_record(&fixture.slot(fixture.owner))
        .and_then(|record| record.journal_record(&nonce))
        .map(|record| non_zero(record.context().service_generation().get()))
        .unwrap_or_else(|| panic!("service generation should remain"));

    reject_old_evidence(&mut model, &fixture, &nonce, None, non_zero(2));
    reject_old_evidence(&mut model, &fixture, &nonce, None, non_zero(4));
    reject_old_evidence(&mut model, &fixture, &nonce, None, non_zero(boundary + 2));
    reject_old_evidence(&mut model, &fixture, &nonce, None, service_generation);
}

#[test]
fn absence_recovery_requires_the_recorded_removal_lineage() {
    let fixture = Fixture::new();
    let mut model = PackageServiceModel::new(policy(8));
    install(&mut model, &fixture, 1);
    let state = current_state(&model, &fixture).digest();
    let plan = match DrainPlan::new(
        DrainDestination::Removal,
        ExpectedPackageState::Exact(state),
        Timestamp::new(400),
        Nonce::from_bytes([3; 32]),
    ) {
        Ok(value) => value,
        Err(error) => panic!("{error:?}"),
    };
    let context = fixture.context(
        Operation::Remove,
        ExpectedPackageState::Exact(state),
        plan.digest(),
        (fixture.owner, fixture.caller),
        1,
        Nonce::from_bytes([3; 32]),
    );
    let nonce = fixture
        .begin(&mut model, context, 300)
        .unwrap_or_else(|error| panic!("{error:?}"));
    model
        .begin_work(&nonce, Timestamp::new(310))
        .unwrap_or_else(|error| panic!("{error:?}"));
    model
        .mark_unknown(&nonce, Timestamp::new(320))
        .unwrap_or_else(|error| panic!("{error:?}"));
    let token = model
        .slot_record(&fixture.slot(fixture.owner))
        .and_then(|record| record.journal_record(&nonce))
        .map(OperationJournalRecord::recovery_token)
        .unwrap_or_else(|| panic!("no-drain token should remain"));
    let evidence = match RecoveryEvidence::new(
        token,
        StateDigest::from_bytes([0; 32]),
        non_zero(2),
        None,
        true,
    ) {
        Ok(value) => value,
        Err(error) => panic!("{error:?}"),
    };
    let error = model
        .recover_observed(&nonce, &evidence, None, Timestamp::new(330))
        .err()
        .unwrap_or_else(|| panic!("absence without drain lineage must fail"));
    assert!(matches!(error, PackageServiceError::RecoveryUnresolved));
}

#[test]
fn exact_removal_recovery_clears_lineage_and_retains_terminal_receipt() {
    let fixture = Fixture::new();
    let mut model = PackageServiceModel::new(policy(8));
    install(&mut model, &fixture, 1);
    let base = current_state(&model, &fixture);
    let nonce = begin_remove(&mut model, &fixture);
    model
        .prove_drain_leases(&nonce, 0, Timestamp::new(399))
        .unwrap_or_else(|error| panic!("{error:?}"));
    model
        .mark_unknown(&nonce, Timestamp::new(399))
        .unwrap_or_else(|error| panic!("{error:?}"));
    let token = model
        .slot_record(&fixture.slot(fixture.owner))
        .and_then(|record| record.journal_record(&nonce))
        .map(OperationJournalRecord::recovery_token)
        .unwrap_or_else(|| panic!("removal token should remain"));
    let old_receipt = match RecoveryEvidence::new(
        token,
        base.digest(),
        base.generation_value(),
        Some(digest(31)),
        true,
    ) {
        Ok(value) => value,
        Err(error) => panic!("{error:?}"),
    };
    let error = model
        .recover_observed(&nonce, &old_receipt, Some(&base), Timestamp::new(399))
        .err()
        .unwrap_or_else(|| panic!("unexpected old-state receipt must fail"));
    assert!(matches!(error, PackageServiceError::BindingMismatch));

    let receipt_evidence = match RecoveryEvidence::new(
        token,
        StateDigest::from_bytes([0; 32]),
        non_zero(4),
        Some(digest(31)),
        true,
    ) {
        Ok(value) => value,
        Err(error) => panic!("{error:?}"),
    };
    let error = model
        .recover_observed(&nonce, &receipt_evidence, None, Timestamp::new(399))
        .err()
        .unwrap_or_else(|| panic!("unexpected absence receipt must fail"));
    assert!(matches!(error, PackageServiceError::BindingMismatch));

    let evidence = match RecoveryEvidence::new(
        token,
        StateDigest::from_bytes([0; 32]),
        non_zero(4),
        None,
        true,
    ) {
        Ok(value) => value,
        Err(error) => panic!("{error:?}"),
    };
    let receipt = model
        .recover_observed(&nonce, &evidence, None, Timestamp::new(399))
        .unwrap_or_else(|error| panic!("{error:?}"))
        .unwrap_or_else(|| panic!("exact absence proof should commit"));
    assert_eq!(receipt.outcome(), ReceiptOutcome::Retired);
    let journal = model
        .slot_record(&fixture.slot(fixture.owner))
        .and_then(|record| record.journal_record(&nonce))
        .unwrap_or_else(|| panic!("terminal receipt should remain"));
    assert!(journal.drain_lineage().is_none());
    assert_eq!(journal.state_generation(), Some(non_zero(4)));
    assert_eq!(journal.status(), JournalStatus::Committed);
}

#[test]
fn old_state_recovery_rejects_a_mutated_spoof_of_the_base() {
    let fixture = Fixture::new();
    let mut model = PackageServiceModel::new(policy(8));
    install(&mut model, &fixture, 1);
    begin_activation(&mut model, &fixture, 8);
    let base = current_state(&model, &fixture);
    let nonce = begin_update(&mut model, &fixture);
    model
        .prove_drain_leases(&nonce, 0, Timestamp::new(150))
        .unwrap_or_else(|error| panic!("{error:?}"));
    model
        .mark_unknown(&nonce, Timestamp::new(160))
        .unwrap_or_else(|error| panic!("{error:?}"));

    let authority = model
        .slot_record(&fixture.slot(fixture.owner))
        .and_then(|record| record.journal_record(&nonce))
        .map(|record| *record.authority_digest())
        .unwrap_or_else(|| panic!("drain authority should remain"));
    let spoofed = CanonicalInstalledState::new(InstalledStateSpec {
        owner: base.slot().owner(),
        package_object: base.slot().package_object(),
        artifact: *base.artifact(),
        content_root: *base.content_root(),
        manifest: base.manifest().clone(),
        authority_digest: authority,
        provenance: ProvenanceDigest::from_bytes([25; 32]),
        lifecycle_state: *base.lifecycle_state(),
        lifecycle_plan: *base.lifecycle_plan(),
        generation: base.generation_value(),
        completing_nonce: base.completing_nonce(),
    })
    .unwrap_or_else(|error| panic!("{error:?}"));
    assert_ne!(spoofed.digest(), base.digest());
    reject_old_evidence(
        &mut model,
        &fixture,
        &nonce,
        Some(&spoofed),
        base.generation_value(),
    );
}
