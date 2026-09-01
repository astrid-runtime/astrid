//! Full transition, recovery, drain, quota, and replay falsifiers.

use astrid_core::PrincipalUid;
use astrid_package_service::{
    AuthenticatedAuthority, AuthorityClass, AuthorityIssuerIdentity, BudgetIdentity, DigestWriter,
    DrainProof, ExpectedPackageState, JournalPolicy, JournalStatus, LifecyclePlan,
    ManifestIdentity, Nonce, Operation, OperationContext, OperationContextSpec, PackageObject,
    PackageServiceError, PackageServiceModel, RecoveryEvidence, ReplayOutcome,
    RuntimeReceiptDigest, ServiceIdentity, StateDigest, ValidatedArtifact,
};
use astrid_resource_types::OwnerId;
use core::num::{NonZeroU64, NonZeroUsize};
use ed25519_dalek::{Signer, SigningKey};

fn bytes(value: u8) -> [u8; 32] {
    [value; 32]
}

fn principal(value: u8) -> PrincipalUid {
    PrincipalUid::from_bytes(bytes(value))
}

fn package() -> PackageObject {
    PackageObject::from_bytes(bytes(10)).unwrap()
}

fn artifact(tag: u8) -> ValidatedArtifact {
    ValidatedArtifact::new(
        astrid_package_service::ArtifactIdentity::from_bytes(bytes(tag)).unwrap(),
        ManifestIdentity::from_bytes(bytes(tag.wrapping_add(20))).unwrap(),
        NonZeroU64::new(128).unwrap(),
        bytes(tag.wrapping_add(40)),
    )
    .unwrap()
}

fn authority(context: &OperationContext) -> AuthenticatedAuthority {
    let issuer = AuthorityIssuerIdentity::from_bytes(bytes(30)).unwrap();
    let key = SigningKey::from_bytes(&bytes(31));
    let signature = key
        .sign(&AuthenticatedAuthority::signing_payload(
            AuthorityClass::ExplicitApproval,
            issuer,
            context,
        ))
        .to_bytes();
    AuthenticatedAuthority::verify(
        context,
        AuthorityClass::ExplicitApproval,
        issuer,
        key.verifying_key().to_bytes(),
        signature,
        10,
    )
    .unwrap()
}

fn alternate_authority(context: &OperationContext) -> AuthenticatedAuthority {
    let issuer = AuthorityIssuerIdentity::from_bytes(bytes(32)).unwrap();
    let key = SigningKey::from_bytes(&bytes(33));
    let signature = key
        .sign(&AuthenticatedAuthority::signing_payload(
            AuthorityClass::ExplicitApproval,
            issuer,
            context,
        ))
        .to_bytes();
    AuthenticatedAuthority::verify(
        context,
        AuthorityClass::ExplicitApproval,
        issuer,
        key.verifying_key().to_bytes(),
        signature,
        10,
    )
    .unwrap()
}

fn context(
    nonce: u8,
    operation: Operation,
    content: ValidatedArtifact,
    expected: ExpectedPackageState,
    deadline: u64,
) -> OperationContext {
    let plan = match operation {
        Operation::Install | Operation::Activate => LifecyclePlan::Activate,
        Operation::Deactivate => LifecyclePlan::Deactivate,
        Operation::Update => LifecyclePlan::ReplacementDrain { deadline },
        Operation::Remove => LifecyclePlan::RemovalDrain { deadline },
    };
    OperationContext::new(OperationContextSpec {
        caller: principal(1),
        approver: principal(2),
        target_owner: OwnerId::Principal(bytes(11)),
        service: ServiceIdentity::from_bytes(bytes(12)).unwrap(),
        service_generation: NonZeroU64::new(5).unwrap(),
        operation,
        package: package(),
        artifact: content,
        expected,
        plan,
        budget: astrid_package_service::ResourceBudget::new(
            BudgetIdentity::from_bytes(bytes(13)).unwrap(),
            NonZeroU64::new(256).unwrap(),
        ),
        expiry: 100,
        nonce: Nonce::from_bytes([nonce; 32]).unwrap(),
        runtime_receipt: RuntimeReceiptDigest::from_bytes(bytes(90)),
        drain_receipt: RuntimeReceiptDigest::from_bytes(bytes(91)),
    })
    .unwrap()
}

fn model(records: usize) -> PackageServiceModel {
    PackageServiceModel::new(JournalPolicy::new(
        NonZeroUsize::new(records).unwrap(),
        NonZeroU64::new(8_192).unwrap(),
    ))
}

fn install(model: &mut PackageServiceModel, nonce: u8, tag: u8) {
    let context = context(
        nonce,
        Operation::Install,
        artifact(tag),
        ExpectedPackageState::Absent,
        0,
    );
    let authenticated = authority(&context);
    let receipt_nonce = model.begin(context, &authenticated, 10).unwrap();
    model.begin_work(&receipt_nonce, 20).unwrap();
    model
        .commit(
            &receipt_nonce,
            RuntimeReceiptDigest::from_bytes(bytes(90)),
            30,
        )
        .unwrap();
}

fn begin_update(
    model: &mut PackageServiceModel,
    nonce: u8,
    tag: u8,
    before: StateDigest,
) -> (Nonce, AuthenticatedAuthority) {
    let context = context(
        nonce,
        Operation::Update,
        artifact(tag),
        ExpectedPackageState::Exact(before),
        90,
    );
    let authenticated = authority(&context);
    let receipt_nonce = model.begin(context, &authenticated, 10).unwrap();
    model.begin_work(&receipt_nonce, 20).unwrap();
    model.begin_drain(&receipt_nonce, 20).unwrap();
    (receipt_nonce, authenticated)
}

fn proof(nonce: u8, count: u8) -> DrainProof {
    let _ = (nonce, count);
    DrainProof::new(RuntimeReceiptDigest::from_bytes(bytes(91)), 80)
}

fn owner_slot() -> astrid_package_service::PackageSlot {
    astrid_package_service::PackageSlot::new(OwnerId::Principal(bytes(11)), package())
}

#[test]
fn full_lifecycle_and_reinstall_preserve_absent_then_monotonic_generations() {
    let mut state_model = model(16);
    install(&mut state_model, 1, 1);
    let slot = owner_slot();
    let installed = state_model.slot(&slot).unwrap().current().unwrap();
    assert_eq!(
        installed.lifecycle(),
        astrid_package_service::LifecycleState::Inactive
    );
    assert_eq!(state_model.high_watermark(&slot), Some(1));

    let installed_digest = installed.digest();
    let (update, _) = begin_update(&mut state_model, 2, 2, installed_digest);
    state_model.prove_drain(&update, proof(2, 1), 80).unwrap();
    state_model
        .commit(&update, RuntimeReceiptDigest::from_bytes(bytes(90)), 80)
        .unwrap();
    let replacement = state_model.slot(&slot).unwrap().current().unwrap();
    assert_eq!(replacement.artifact(), &artifact(2));
    assert_eq!(state_model.high_watermark(&slot), Some(3));

    let activate = context(
        3,
        Operation::Activate,
        artifact(2),
        ExpectedPackageState::Exact(replacement.digest()),
        0,
    );
    let activate_nonce = state_model
        .begin(activate, &authority(&activate), 10)
        .unwrap();
    state_model.begin_work(&activate_nonce, 20).unwrap();
    state_model
        .commit(
            &activate_nonce,
            RuntimeReceiptDigest::from_bytes(bytes(90)),
            30,
        )
        .unwrap();
    assert_eq!(
        state_model
            .slot(&slot)
            .unwrap()
            .current()
            .unwrap()
            .lifecycle(),
        astrid_package_service::LifecycleState::Active
    );

    let deactivate = context(
        4,
        Operation::Deactivate,
        artifact(2),
        ExpectedPackageState::Exact(state_model.slot(&slot).unwrap().current().unwrap().digest()),
        0,
    );
    let deactivate_nonce = state_model
        .begin(deactivate, &authority(&deactivate), 10)
        .unwrap();
    state_model.begin_work(&deactivate_nonce, 20).unwrap();
    state_model
        .commit(
            &deactivate_nonce,
            RuntimeReceiptDigest::from_bytes(bytes(90)),
            30,
        )
        .unwrap();

    let remove = context(
        5,
        Operation::Remove,
        artifact(2),
        ExpectedPackageState::Exact(state_model.slot(&slot).unwrap().current().unwrap().digest()),
        90,
    );
    let remove_nonce = state_model.begin(remove, &authority(&remove), 10).unwrap();
    state_model.begin_work(&remove_nonce, 20).unwrap();
    state_model.begin_drain(&remove_nonce, 20).unwrap();
    state_model
        .prove_drain(&remove_nonce, proof(5, 1), 80)
        .unwrap();
    let receipt = state_model
        .commit(
            &remove_nonce,
            RuntimeReceiptDigest::from_bytes(bytes(90)),
            80,
        )
        .unwrap();
    assert!(state_model.slot(&slot).unwrap().current().is_none());
    assert_eq!(state_model.high_watermark(&slot), Some(4));
    assert_eq!(
        state_model.replay(&remove_nonce),
        Ok(ReplayOutcome::Committed(Box::new(receipt)))
    );

    install(&mut state_model, 6, 3);
    assert_eq!(state_model.high_watermark(&slot), Some(5));
    assert_eq!(
        state_model
            .slot(&slot)
            .unwrap()
            .current()
            .unwrap()
            .generation(),
        5
    );
}

#[test]
fn drain_expiry_after_zero_one_and_many_proofs_restores_exact_successor() {
    for proof_count in [0_u8, 1, 2, 7] {
        let mut state_model = model(16);
        install(&mut state_model, 1, 1);
        let before = state_model
            .slot(&owner_slot())
            .unwrap()
            .current()
            .unwrap()
            .digest();
        let (update, _) = begin_update(&mut state_model, 2, 2, before);
        for count in 0..proof_count {
            state_model
                .prove_drain(&update, proof(2, count), 80)
                .unwrap();
        }
        let boundary = u64::from(proof_count).saturating_add(1);
        let successor = boundary + 1;
        assert_eq!(state_model.expire(&update, 91).unwrap(), successor);
        let restored = state_model.slot(&owner_slot()).unwrap().current().unwrap();
        assert_eq!(restored.artifact(), &artifact(1));
        assert_eq!(restored.generation(), successor);
        assert_eq!(state_model.high_watermark(&owner_slot()), Some(successor));
        assert_eq!(state_model.replay(&update), Ok(ReplayOutcome::Expired));
        assert!(
            state_model
                .prove_drain(&update, proof(2, proof_count), 92)
                .is_err()
        );
        assert!(
            state_model
                .commit(&update, RuntimeReceiptDigest::from_bytes(bytes(90)), 92)
                .is_err()
        );
    }
}

#[test]
fn late_drain_proof_and_completion_fail_after_authoritative_deadline() {
    let mut state_model = model(8);
    install(&mut state_model, 1, 1);
    let before = state_model
        .slot(&owner_slot())
        .unwrap()
        .current()
        .unwrap()
        .digest();
    let (update, _) = begin_update(&mut state_model, 2, 2, before);
    assert_eq!(
        state_model
            .prove_drain(&update, proof(2, 1), 91)
            .unwrap_err(),
        PackageServiceError::InvalidDrain
    );
    assert_eq!(
        state_model
            .commit(&update, RuntimeReceiptDigest::from_bytes(bytes(90)), 91)
            .unwrap_err(),
        PackageServiceError::InvalidDrain
    );
}

#[test]
fn unknown_remove_without_zero_lease_lineage_cannot_become_absent() {
    let mut state_model = model(8);
    install(&mut state_model, 1, 1);
    let before = state_model.slot(&owner_slot()).unwrap().current().unwrap();
    let before_digest = before.digest();
    let remove = context(
        2,
        Operation::Remove,
        artifact(1),
        ExpectedPackageState::Exact(before_digest),
        90,
    );
    let authenticated = authority(&remove);
    let nonce = state_model.begin(remove, &authenticated, 10).unwrap();
    state_model.begin_work(&nonce, 20).unwrap();
    state_model.begin_drain(&nonce, 20).unwrap();
    state_model.report_unknown(&nonce, 30).unwrap();
    let evidence = RecoveryEvidence::new(
        before_digest,
        false,
        RuntimeReceiptDigest::from_bytes(bytes(91)),
    );
    assert_eq!(
        state_model
            .recover(&nonce, &authenticated, evidence, 40)
            .unwrap(),
        None
    );
    assert!(state_model.slot(&owner_slot()).unwrap().current().is_some());
    assert_eq!(
        state_model.record(&nonce).unwrap().status(),
        JournalStatus::Expired
    );
    assert_eq!(state_model.replay(&nonce), Ok(ReplayOutcome::Expired));
}

#[test]
fn unknown_recovery_cannot_infer_success_from_mid_drain_observation() {
    let mut state_model = model(8);
    install(&mut state_model, 1, 1);
    let before = state_model.slot(&owner_slot()).unwrap().current().unwrap();
    let before_digest = before.digest();
    let (update, update_authority) = begin_update(&mut state_model, 2, 2, before_digest);
    state_model.report_unknown(&update, 30).unwrap();
    let evidence = RecoveryEvidence::new(
        before_digest,
        false,
        RuntimeReceiptDigest::from_bytes(bytes(91)),
    );
    assert_eq!(
        state_model
            .recover(&update, &update_authority, evidence, 40)
            .unwrap(),
        None
    );
    assert_eq!(
        state_model.record(&update).unwrap().status(),
        JournalStatus::Expired
    );
    assert!(state_model.slot(&owner_slot()).unwrap().current().is_some());
}

#[test]
fn unknown_remove_recovery_terminates_after_recorded_proof() {
    let mut state_model = model(8);
    install(&mut state_model, 1, 1);
    let before = state_model.slot(&owner_slot()).unwrap().current().unwrap();
    let before_digest = before.digest();
    let remove = context(
        2,
        Operation::Remove,
        artifact(1),
        ExpectedPackageState::Exact(before_digest),
        90,
    );
    let authenticated = authority(&remove);
    let nonce = state_model.begin(remove, &authenticated, 10).unwrap();
    state_model.begin_work(&nonce, 20).unwrap();
    state_model.begin_drain(&nonce, 20).unwrap();
    state_model.prove_drain(&nonce, proof(2, 1), 80).unwrap();
    state_model.report_unknown(&nonce, 30).unwrap();
    let evidence = RecoveryEvidence::new(
        before_digest,
        true,
        RuntimeReceiptDigest::from_bytes(bytes(91)),
    );
    assert_eq!(
        state_model
            .recover(&nonce, &authenticated, evidence, 40)
            .unwrap(),
        None
    );
    assert!(state_model.slot(&owner_slot()).unwrap().current().is_some());
    assert_eq!(
        state_model.record(&nonce).unwrap().status(),
        JournalStatus::Expired
    );
    assert_eq!(state_model.replay(&nonce), Ok(ReplayOutcome::Expired));
    assert_eq!(state_model.high_watermark(&owner_slot()), Some(3));
}
#[test]
fn cancel_before_drain_but_not_after_boundary() {
    let mut state_model = model(8);
    install(&mut state_model, 1, 1);
    let before = state_model
        .slot(&owner_slot())
        .unwrap()
        .current()
        .unwrap()
        .digest();
    let (update, update_authority) = begin_update(&mut state_model, 2, 2, before);
    assert!(state_model.cancel(&update, &update_authority, 30).is_err());
    state_model.expire(&update, 91).unwrap();

    let next = context(
        3,
        Operation::Update,
        artifact(2),
        ExpectedPackageState::Exact(
            state_model
                .slot(&owner_slot())
                .unwrap()
                .current()
                .unwrap()
                .digest(),
        ),
        90,
    );
    let nonce = state_model.begin(next, &authority(&next), 10).unwrap();
    assert!(state_model.cancel(&nonce, &authority(&next), 30).is_ok());
}

#[test]
fn zero_runtime_receipt_is_never_authoritative() {
    let mut state_model = model(8);
    install(&mut state_model, 1, 1);
    let before = state_model
        .slot(&owner_slot())
        .unwrap()
        .current()
        .unwrap()
        .digest();
    let (nonce, _) = begin_update(&mut state_model, 2, 2, before);
    state_model.prove_drain(&nonce, proof(2, 1), 80).unwrap();
    assert_eq!(
        state_model
            .commit(&nonce, RuntimeReceiptDigest::from_bytes([0; 32]), 80)
            .unwrap_err(),
        PackageServiceError::BindingMismatch
    );
}

#[test]
fn explicit_unknown_is_retained_when_history_is_full() {
    let mut state_model = model(1);
    install(&mut state_model, 1, 1);
    let before = state_model
        .slot(&owner_slot())
        .unwrap()
        .current()
        .unwrap()
        .digest();
    let (update, _) = begin_update(&mut state_model, 2, 2, before);
    state_model.report_unknown(&update, 30).unwrap();
    let other_owner =
        astrid_package_service::PackageSlot::new(OwnerId::Principal(bytes(99)), package());
    let next = OperationContext::new(OperationContextSpec {
        caller: principal(1),
        approver: principal(2),
        target_owner: OwnerId::Principal(bytes(99)),
        service: ServiceIdentity::from_bytes(bytes(12)).unwrap(),
        service_generation: NonZeroU64::new(5).unwrap(),
        operation: Operation::Install,
        package: package(),
        artifact: artifact(1),
        expected: ExpectedPackageState::Absent,
        plan: LifecyclePlan::Activate,
        budget: astrid_package_service::ResourceBudget::new(
            BudgetIdentity::from_bytes(bytes(13)).unwrap(),
            NonZeroU64::new(256).unwrap(),
        ),
        expiry: 100,
        nonce: Nonce::from_bytes([3; 32]).unwrap(),
        runtime_receipt: RuntimeReceiptDigest::from_bytes(bytes(90)),
        drain_receipt: RuntimeReceiptDigest::from_bytes(bytes(91)),
    })
    .unwrap();
    assert_eq!(
        state_model.begin(next, &authority(&next), 10).unwrap_err(),
        PackageServiceError::JournalFull
    );
    assert_eq!(
        state_model.record(&update).unwrap().status(),
        JournalStatus::Unknown
    );
    assert_eq!(state_model.high_watermark(&other_owner), None);
}

#[test]
fn terminal_replay_reports_expired_nonce() {
    let mut state_model = model(8);
    install(&mut state_model, 1, 1);
    let before = state_model
        .slot(&owner_slot())
        .unwrap()
        .current()
        .unwrap()
        .digest();
    let (update, _) = begin_update(&mut state_model, 2, 2, before);
    state_model.expire(&update, 91).unwrap();
    assert_eq!(state_model.replay(&update), Ok(ReplayOutcome::Expired));
}

#[test]
fn fresh_install_budget_is_enforced_before_first_slot_admission() {
    let mut state_model = model(8);
    let context = OperationContext::new(OperationContextSpec {
        caller: principal(1),
        approver: principal(2),
        target_owner: OwnerId::Principal(bytes(11)),
        service: ServiceIdentity::from_bytes(bytes(12)).unwrap(),
        service_generation: NonZeroU64::new(5).unwrap(),
        operation: Operation::Install,
        package: package(),
        artifact: artifact(1),
        expected: ExpectedPackageState::Absent,
        plan: LifecyclePlan::Activate,
        budget: astrid_package_service::ResourceBudget::new(
            BudgetIdentity::from_bytes(bytes(13)).unwrap(),
            NonZeroU64::new(64).unwrap(),
        ),
        expiry: 100,
        nonce: Nonce::from_bytes([9; 32]).unwrap(),
        runtime_receipt: RuntimeReceiptDigest::from_bytes(bytes(90)),
        drain_receipt: RuntimeReceiptDigest::from_bytes(bytes(91)),
    })
    .unwrap();
    assert_eq!(
        state_model
            .begin(context, &authority(&context), 10)
            .unwrap_err(),
        PackageServiceError::BudgetExceeded
    );
    assert!(state_model.record(context.nonce()).is_none());
    assert!(state_model.slot(&owner_slot()).is_none());
}

#[test]
fn stale_authority_admission_fails_without_durable_nonce() {
    let mut state_model = model(8);
    let context = context(
        9,
        Operation::Install,
        artifact(1),
        ExpectedPackageState::Absent,
        0,
    );
    let authenticated = authority(&context);
    assert_eq!(
        state_model.begin(context, &authenticated, 100).unwrap_err(),
        PackageServiceError::AuthorityExpired
    );
    assert!(state_model.record(context.nonce()).is_none());
    assert!(state_model.slot(&owner_slot()).is_none());
}

#[test]
fn admitted_authority_bounds_follow_on_cancel_and_recovery() {
    let mut state_model = model(8);
    install(&mut state_model, 1, 1);
    let before = state_model
        .slot(&owner_slot())
        .unwrap()
        .current()
        .unwrap()
        .digest();
    let (update, admitted) = begin_update(&mut state_model, 2, 2, before);
    let other = alternate_authority(state_model.record(&update).unwrap().context());
    assert_eq!(
        state_model.cancel(&update, &other, 30).unwrap_err(),
        PackageServiceError::AuthorityMismatch
    );
    state_model.report_unknown(&update, 30).unwrap();
    let evidence =
        RecoveryEvidence::new(before, false, RuntimeReceiptDigest::from_bytes(bytes(91)));
    assert_eq!(
        state_model
            .recover(&update, &other, evidence, 40)
            .unwrap_err(),
        PackageServiceError::AuthorityMismatch
    );
    assert_eq!(
        state_model
            .recover(&update, &admitted, evidence, 40)
            .unwrap(),
        None
    );
    assert_eq!(
        state_model.record(&update).unwrap().status(),
        JournalStatus::Expired
    );
}

#[test]
fn drain_proofs_bind_exact_receipt_and_consult_proof_time() {
    let mut state_model = model(8);
    install(&mut state_model, 1, 1);
    let before = state_model
        .slot(&owner_slot())
        .unwrap()
        .current()
        .unwrap()
        .digest();
    let (update, _) = begin_update(&mut state_model, 2, 2, before);
    assert_eq!(
        state_model
            .prove_drain(
                &update,
                DrainProof::new(RuntimeReceiptDigest::from_bytes(bytes(92)), 80),
                80
            )
            .unwrap_err(),
        PackageServiceError::InvalidDrain
    );
    assert_eq!(
        state_model
            .prove_drain(
                &update,
                DrainProof::new(RuntimeReceiptDigest::from_bytes(bytes(91)), 90),
                80
            )
            .unwrap_err(),
        PackageServiceError::InvalidDrain
    );
    state_model.prove_drain(&update, proof(2, 1), 80).unwrap();
    let receipt = state_model
        .commit(&update, RuntimeReceiptDigest::from_bytes(bytes(90)), 80)
        .unwrap();
    assert_eq!(
        receipt.runtime_receipt(),
        &RuntimeReceiptDigest::from_bytes(bytes(90))
    );
}

#[test]
fn active_drain_expiry_restores_an_inactive_exact_successor() {
    let mut state_model = model(8);
    install(&mut state_model, 1, 1);
    let installed = state_model.slot(&owner_slot()).unwrap().current().unwrap();
    let activate = context(
        2,
        Operation::Activate,
        artifact(1),
        ExpectedPackageState::Exact(installed.digest()),
        0,
    );
    let nonce = state_model
        .begin(activate, &authority(&activate), 10)
        .unwrap();
    state_model.begin_work(&nonce, 20).unwrap();
    state_model
        .commit(&nonce, RuntimeReceiptDigest::from_bytes(bytes(90)), 30)
        .unwrap();
    let active = state_model.slot(&owner_slot()).unwrap().current().unwrap();
    let active_digest = active.digest();
    let (update, _) = begin_update(&mut state_model, 3, 2, active_digest);
    state_model.prove_drain(&update, proof(3, 1), 80).unwrap();
    assert_eq!(state_model.expire(&update, 91).unwrap(), 3);
    let restored = state_model.slot(&owner_slot()).unwrap().current().unwrap();
    assert_eq!(restored.artifact(), &artifact(1));
    assert_eq!(restored.generation(), 3);
    assert_eq!(
        restored.lifecycle(),
        astrid_package_service::LifecycleState::Inactive
    );
}

#[test]
fn old_state_recovery_restores_exact_successor_after_zero_one_and_many_proofs() {
    for proof_count in [0_u8, 1, 3] {
        let mut state_model = model(8);
        install(&mut state_model, 1, 1);
        let before = state_model
            .slot(&owner_slot())
            .unwrap()
            .current()
            .unwrap()
            .digest();
        let (update, admitted) = begin_update(&mut state_model, 2, 2, before);
        for count in 0..proof_count {
            state_model
                .prove_drain(&update, proof(2, count), 80)
                .unwrap();
        }
        state_model.report_unknown(&update, 30).unwrap();
        let evidence = RecoveryEvidence::new(
            before,
            proof_count > 0,
            RuntimeReceiptDigest::from_bytes(bytes(91)),
        );
        assert_eq!(
            state_model
                .recover(&update, &admitted, evidence, 40)
                .unwrap(),
            None
        );
        let boundary = u64::from(proof_count) + 2;
        let restored = state_model.slot(&owner_slot()).unwrap().current().unwrap();
        assert_eq!(restored.artifact(), &artifact(1));
        assert_eq!(restored.generation(), boundary);
        assert_eq!(
            restored.lifecycle(),
            astrid_package_service::LifecycleState::Inactive
        );
        assert_eq!(state_model.high_watermark(&owner_slot()), Some(boundary));
        assert_eq!(state_model.replay(&update), Ok(ReplayOutcome::Expired));
    }
}

#[test]
fn plan_digest_is_domain_separate_from_state_digest() {
    let mut writer = DigestWriter::new();
    writer.u64(1);
    let state_like = writer.finish::<2>("astrid.package.state.v1");
    let plan_like = writer.finish::<3>("astrid.package.plan.v1");
    assert_ne!(state_like.as_bytes(), plan_like.as_bytes());
}
