use super::*;
use crate::journal::RecoveryEvidence;

fn high_watermark(model: &PackageServiceModel, fixture: &Fixture) -> NonZeroU64 {
    model
        .slot_record(&fixture.slot(fixture.owner))
        .and_then(PackageSlotRecord::generation_high_watermark)
        .unwrap_or_else(|| panic!("absence must retain the slot high-watermark"))
}

fn install_after_removal(model: &mut PackageServiceModel, fixture: &Fixture) -> OperationReceipt {
    install(model, fixture, 4)
}

#[test]
fn direct_removal_then_reinstall_uses_the_high_watermark_successor() {
    let fixture = Fixture::new();
    let mut model = PackageServiceModel::new(policy(8));
    install(&mut model, &fixture, 1);
    assert_eq!(high_watermark(&model, &fixture).get(), 1);

    let nonce = begin_remove(&mut model, &fixture);
    model
        .prove_drain_leases(&nonce, 0, Timestamp::new(399))
        .unwrap_or_else(|error| panic!("zero leases should prove: {error:?}"));
    assert_eq!(high_watermark(&model, &fixture).get(), 3);
    model
        .complete(&nonce, None, None, true, Timestamp::new(399))
        .unwrap_or_else(|error| panic!("direct removal should commit: {error:?}"));
    assert!(model.slot_record(&fixture.slot(fixture.owner)).is_some());
    assert!(
        model
            .slot_record(&fixture.slot(fixture.owner))
            .and_then(PackageSlotRecord::state)
            .is_none()
    );
    assert_eq!(high_watermark(&model, &fixture).get(), 4);

    install_after_removal(&mut model, &fixture);
    let reinstalled = model
        .slot_record(&fixture.slot(fixture.owner))
        .and_then(PackageSlotRecord::state)
        .unwrap_or_else(|| panic!("reinstalled state should exist"));
    assert_eq!(reinstalled.generation_value().get(), 5);
    assert_eq!(high_watermark(&model, &fixture).get(), 5);
}

#[test]
fn removal_deadline_expiry_then_reinstall_uses_the_high_watermark_successor() {
    let fixture = Fixture::new();
    let mut model = PackageServiceModel::new(policy(8));
    install(&mut model, &fixture, 1);
    let nonce = begin_remove(&mut model, &fixture);
    model
        .prove_drain_leases(&nonce, 0, Timestamp::new(399))
        .unwrap_or_else(|error| panic!("zero leases should prove: {error:?}"));
    let result = model
        .expire_drain(&nonce, Timestamp::new(400), true)
        .unwrap_or_else(|error| panic!("removal deadline should expire: {error:?}"));
    assert_eq!(result, DrainResult::Completed);
    assert_eq!(high_watermark(&model, &fixture).get(), 4);

    install_after_removal(&mut model, &fixture);
    let reinstalled = model
        .slot_record(&fixture.slot(fixture.owner))
        .and_then(PackageSlotRecord::state)
        .unwrap_or_else(|| panic!("reinstalled state should exist"));
    assert_eq!(reinstalled.generation_value().get(), 5);
    assert_eq!(high_watermark(&model, &fixture).get(), 5);
}

#[test]
fn unknown_removal_recovery_then_reinstall_uses_the_high_watermark_successor() {
    let fixture = Fixture::new();
    let mut model = PackageServiceModel::new(policy(8));
    install(&mut model, &fixture, 1);
    let nonce = begin_remove(&mut model, &fixture);
    model
        .prove_drain_leases(&nonce, 0, Timestamp::new(399))
        .unwrap_or_else(|error| panic!("zero leases should prove: {error:?}"));
    model
        .mark_unknown(&nonce, Timestamp::new(399))
        .unwrap_or_else(|error| panic!("removal should become unknown: {error:?}"));
    let token = model
        .slot_record(&fixture.slot(fixture.owner))
        .and_then(|record| record.journal_record(&nonce))
        .map_or_else(
            || panic!("unknown removal should retain its token"),
            OperationJournalRecord::recovery_token,
        );
    let evidence = RecoveryEvidence::new(
        token,
        StateDigest::from_bytes([0; 32]),
        non_zero(4),
        None,
        true,
    )
    .unwrap_or_else(|error| panic!("absence evidence should construct: {error:?}"));
    let receipt = model
        .recover_observed(&nonce, &evidence, None, Timestamp::new(399))
        .unwrap_or_else(|error| panic!("unknown removal should recover: {error:?}"))
        .unwrap_or_else(|| panic!("absence recovery should produce a receipt"));
    assert_eq!(receipt.state_generation().get(), 4);
    assert_eq!(high_watermark(&model, &fixture).get(), 4);

    install_after_removal(&mut model, &fixture);
    let reinstalled = model
        .slot_record(&fixture.slot(fixture.owner))
        .and_then(PackageSlotRecord::state)
        .unwrap_or_else(|| panic!("reinstalled state should exist"));
    assert_eq!(reinstalled.generation_value().get(), 5);
    assert_eq!(high_watermark(&model, &fixture).get(), 5);
}

#[test]
fn collection_retains_the_high_watermark_for_reinstall() {
    let fixture = Fixture::new();
    let mut model = PackageServiceModel::new(policy_short_retention(8, 128));
    install(&mut model, &fixture, 1);
    let nonce = begin_remove(&mut model, &fixture);
    model
        .prove_drain_leases(&nonce, 0, Timestamp::new(399))
        .unwrap_or_else(|error| panic!("zero leases should prove: {error:?}"));
    model
        .complete(&nonce, None, None, true, Timestamp::new(399))
        .unwrap_or_else(|error| panic!("removal should commit: {error:?}"));
    assert_eq!(high_watermark(&model, &fixture).get(), 4);

    let collected = model
        .collect(Timestamp::new(600), 8)
        .unwrap_or_else(|error| panic!("terminal records should collect: {error:?}"));
    assert_eq!(collected, 1);
    assert!(
        model
            .slot_record(&fixture.slot(fixture.owner))
            .and_then(|record| record.journal_values().next())
            .is_none()
    );
    assert_eq!(high_watermark(&model, &fixture).get(), 4);

    install_after_removal(&mut model, &fixture);
    let reinstalled = model
        .slot_record(&fixture.slot(fixture.owner))
        .and_then(PackageSlotRecord::state)
        .unwrap_or_else(|| panic!("reinstalled state should exist"));
    assert_eq!(reinstalled.generation_value().get(), 5);
    assert_eq!(high_watermark(&model, &fixture).get(), 5);
}

#[test]
fn max_high_watermark_refuses_every_successor_before_transition() {
    let max = non_zero(u64::MAX);
    let install_error = next_generation_from_high_watermark(Some(max), Operation::Install)
        .err()
        .unwrap_or_else(|| panic!("install successor must overflow"));
    let lifecycle_error = next_generation_from_high_watermark(Some(max), Operation::Remove)
        .err()
        .unwrap_or_else(|| panic!("lifecycle successor must overflow"));
    assert!(matches!(
        install_error,
        PackageServiceError::GenerationOverflow
    ));
    assert!(matches!(
        lifecycle_error,
        PackageServiceError::GenerationOverflow
    ));
}

#[test]
fn max_watermark_admission_fails_without_state_or_journal_effect() {
    let fixture = Fixture::new();
    let mut model = PackageServiceModel::new(policy(8));
    let slot = fixture.slot(fixture.owner);
    let mut record = PackageSlotRecord::default();
    record.force_generation_high_watermark_for_test(non_zero(u64::MAX));
    model.slots.insert(slot, record);
    let context = fixture.context(
        Operation::Install,
        ExpectedPackageState::Absent,
        plan_digest(20),
        (fixture.owner, fixture.caller),
        1,
        Nonce::from_bytes([1; 32]),
    );
    let authority = fixture.authority(&context);

    let error = model
        .begin(
            context,
            &authority,
            fixture.ingress,
            &fixture.service_at(1),
            Timestamp::new(100),
        )
        .err()
        .unwrap_or_else(|| panic!("maximum watermark must refuse a successor"));
    assert!(matches!(error, PackageServiceError::GenerationOverflow));
    let Some(record) = model.slots.get(&slot) else {
        panic!("failed admission must retain the slot record");
    };
    assert_eq!(record.generation_high_watermark(), Some(non_zero(u64::MAX)));
    assert!(record.state().is_none());
    assert!(record.journal_values().next().is_none());
    assert!(model.nonce_locations.is_empty());
    assert!(model.tombstones.is_empty());
    assert_eq!(model.occupancy(), Occupancy::default());
}
