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
    let nonce = begin_update(&mut model, &fixture);
    for proof in 0..proof_count {
        model
            .prove_drain_leases(
                &nonce,
                u32::try_from(proof + 10).unwrap_or(u32::MAX),
                Timestamp::new(150),
            )
            .unwrap_or_else(|error| panic!("drain proof should advance: {error:?}"));
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
            let boundary = current_state(&model, &fixture).generation_value().get();
            let expected_generation = boundary + 1;
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
    let boundary = current_state(&model, &fixture).generation_value().get();
    assert_eq!(boundary, 6);
    let service_generation = model
        .slot_record(&fixture.slot(fixture.owner))
        .and_then(|record| record.journal_record(&nonce))
        .map(|record| non_zero(record.context().service_generation().get()))
        .unwrap_or_else(|| panic!("service generation should remain"));

    reject_old_evidence(
        &mut model,
        &fixture,
        &nonce,
        None,
        non_zero(base.generation_value().get() - 1),
    );
    reject_old_evidence(
        &mut model,
        &fixture,
        &nonce,
        None,
        non_zero(base.generation_value().get() + 1),
    );
    reject_old_evidence(&mut model, &fixture, &nonce, None, non_zero(boundary + 2));
    reject_old_evidence(&mut model, &fixture, &nonce, None, service_generation);
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
