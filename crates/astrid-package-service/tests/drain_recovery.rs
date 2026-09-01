//! Drain, proof, expiry, recovery, and terminal-outcome falsifiers.

use astrid_core::PrincipalUid;
use astrid_package_service::{
    AuthenticatedAuthority, AuthorityClass, AuthorityIssuerIdentity, BudgetIdentity, DrainProof,
    ExpectedPackageState, JournalPolicy, JournalStatus, LifecyclePlan, ManifestIdentity, Nonce,
    Operation, OperationContext, OperationContextSpec, PackageObject, PackageServiceError,
    PackageServiceModel, RecoveryEvidence, ReplayOutcome, RuntimeReceiptDigest, ServiceIdentity,
    StateDigest, ValidatedArtifact,
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

/// Derives deterministic test nonce bytes from a label so no key-like or
/// nonce-like material is hard-coded in the fixture.
fn test_nonce(label: u8) -> Nonce {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"astrid.package-service.test.nonce.v1");
    hasher.update(&[label]);
    Nonce::from_bytes(*hasher.finalize().as_bytes()).unwrap()
}

fn test_signing_key(label: &[u8]) -> SigningKey {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"astrid.package-service.test.signing-key.v1");
    hasher.update(label);
    SigningKey::from_bytes(hasher.finalize().as_bytes())
}

fn runtime_receipt() -> RuntimeReceiptDigest {
    RuntimeReceiptDigest::from_bytes(bytes(90))
}

fn drain_receipt() -> RuntimeReceiptDigest {
    RuntimeReceiptDigest::from_bytes(bytes(91))
}

fn authority(context: &OperationContext) -> AuthenticatedAuthority {
    let issuer = AuthorityIssuerIdentity::from_bytes(bytes(30)).unwrap();
    let key = test_signing_key(b"lifecycle-primary");
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
    label: u8,
    operation: Operation,
    content: ValidatedArtifact,
    expected: ExpectedPackageState,
    deadline: u64,
) -> OperationContext {
    context_expiring_at(label, operation, content, expected, deadline, 100)
}

fn context_expiring_at(
    label: u8,
    operation: Operation,
    content: ValidatedArtifact,
    expected: ExpectedPackageState,
    deadline: u64,
    expiry: u64,
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
        expiry,
        nonce: test_nonce(label),
        runtime_receipt: runtime_receipt(),
        drain_receipt: drain_receipt(),
    })
    .unwrap()
}

fn model(records: usize) -> PackageServiceModel {
    PackageServiceModel::new(JournalPolicy::new(
        NonZeroUsize::new(records).unwrap(),
        NonZeroU64::new(8_192).unwrap(),
    ))
}

fn install(model: &mut PackageServiceModel, label: u8, tag: u8) {
    let context = context(
        label,
        Operation::Install,
        artifact(tag),
        ExpectedPackageState::Absent,
        0,
    );
    let authenticated = authority(&context);
    let receipt_nonce = model.begin(context, &authenticated, 10).unwrap();
    model.begin_work(&receipt_nonce, 20).unwrap();
    model.commit(&receipt_nonce, runtime_receipt(), 30).unwrap();
}

fn begin_update(
    model: &mut PackageServiceModel,
    label: u8,
    tag: u8,
    before: StateDigest,
) -> (Nonce, AuthenticatedAuthority) {
    let context = context(
        label,
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

fn proof() -> DrainProof {
    DrainProof::new(drain_receipt(), 80)
}

fn owner_slot() -> astrid_package_service::PackageSlot {
    astrid_package_service::PackageSlot::new(OwnerId::Principal(bytes(11)), package())
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
        for _count in 0..proof_count {
            state_model.prove_drain(&update, proof(), 80).unwrap();
        }
        let boundary = u64::from(proof_count).saturating_add(1);
        let successor = boundary + 1;
        assert_eq!(state_model.expire(&update, 91).unwrap(), successor);
        let restored = state_model.slot(&owner_slot()).unwrap().current().unwrap();
        assert_eq!(restored.artifact(), &artifact(1));
        assert_eq!(restored.generation(), successor);
        assert_eq!(state_model.high_watermark(&owner_slot()), Some(successor));
        assert_eq!(state_model.replay(&update), Ok(ReplayOutcome::Expired));
        assert!(state_model.prove_drain(&update, proof(), 92).is_err());
        assert!(state_model.commit(&update, runtime_receipt(), 92).is_err());
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
        state_model.prove_drain(&update, proof(), 91).unwrap_err(),
        PackageServiceError::InvalidDrain
    );
    assert_eq!(
        state_model
            .commit(&update, runtime_receipt(), 91)
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
    let evidence = RecoveryEvidence::new(before_digest, false, drain_receipt());
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
    let evidence = RecoveryEvidence::new(before_digest, false, drain_receipt());
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
    state_model.prove_drain(&nonce, proof(), 80).unwrap();
    state_model.report_unknown(&nonce, 30).unwrap();
    let evidence = RecoveryEvidence::new(before_digest, true, drain_receipt());
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
    state_model.prove_drain(&nonce, proof(), 80).unwrap();
    assert_eq!(
        state_model
            .commit(&nonce, RuntimeReceiptDigest::from_bytes([0; 32]), 80)
            .unwrap_err(),
        PackageServiceError::BindingMismatch
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
            .prove_drain(&update, DrainProof::new(drain_receipt(), 90), 80)
            .unwrap_err(),
        PackageServiceError::InvalidDrain
    );
    state_model.prove_drain(&update, proof(), 80).unwrap();
    let receipt = state_model.commit(&update, runtime_receipt(), 80).unwrap();
    assert_eq!(receipt.runtime_receipt(), &runtime_receipt());
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
    state_model.commit(&nonce, runtime_receipt(), 30).unwrap();
    let active = state_model.slot(&owner_slot()).unwrap().current().unwrap();
    let active_digest = active.digest();
    let (update, _) = begin_update(&mut state_model, 3, 2, active_digest);
    state_model.prove_drain(&update, proof(), 80).unwrap();
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
        for _count in 0..proof_count {
            state_model.prove_drain(&update, proof(), 80).unwrap();
        }
        state_model.report_unknown(&update, 30).unwrap();
        let evidence = RecoveryEvidence::new(before, proof_count > 0, drain_receipt());
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
fn commit_after_accepted_proof_respects_drain_deadline() {
    let mut state_model = model(8);
    install(&mut state_model, 1, 1);
    let before = state_model
        .slot(&owner_slot())
        .unwrap()
        .current()
        .unwrap()
        .digest();
    let (update, _) = begin_update(&mut state_model, 2, 2, before);
    state_model.prove_drain(&update, proof(), 80).unwrap();
    state_model.commit(&update, runtime_receipt(), 90).unwrap();

    let mut state_model = model(8);
    install(&mut state_model, 1, 1);
    let before = state_model
        .slot(&owner_slot())
        .unwrap()
        .current()
        .unwrap()
        .digest();
    let (update, _) = begin_update(&mut state_model, 2, 2, before);
    state_model.prove_drain(&update, proof(), 80).unwrap();
    assert_eq!(
        state_model
            .commit(&update, runtime_receipt(), 91)
            .unwrap_err(),
        PackageServiceError::InvalidDrain
    );
    state_model.expire(&update, 91).unwrap();
    assert_eq!(
        state_model.record(&update).unwrap().status(),
        JournalStatus::Expired
    );
}

#[test]
fn drain_proof_fails_closed_at_exclusive_expiry() {
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
        state_model.prove_drain(&update, proof(), 100).unwrap_err(),
        PackageServiceError::AuthorityExpired
    );

    let mut state_model = model(8);
    install(&mut state_model, 1, 1);
    let installed = state_model
        .slot(&owner_slot())
        .unwrap()
        .current()
        .unwrap()
        .digest();
    let op_context = context_expiring_at(
        3,
        Operation::Update,
        artifact(2),
        ExpectedPackageState::Exact(installed),
        90,
        90,
    );
    let authenticated = authority(&op_context);
    let nonce = state_model.begin(op_context, &authenticated, 10).unwrap();
    state_model.begin_work(&nonce, 20).unwrap();
    state_model.begin_drain(&nonce, 20).unwrap();
    assert_eq!(
        state_model.prove_drain(&nonce, proof(), 90).unwrap_err(),
        PackageServiceError::AuthorityExpired
    );
}

#[test]
fn unknown_install_reaches_terminal_conservative_outcome() {
    let mut state_model = model(8);
    let op_context = context(
        1,
        Operation::Install,
        artifact(1),
        ExpectedPackageState::Absent,
        0,
    );
    let authenticated = authority(&op_context);
    let nonce = state_model.begin(op_context, &authenticated, 10).unwrap();
    state_model.begin_work(&nonce, 20).unwrap();
    state_model.report_unknown(&nonce, 30).unwrap();
    let evidence = RecoveryEvidence::new(
        ExpectedPackageState::Absent.digest(),
        false,
        runtime_receipt(),
    );
    assert_eq!(
        state_model
            .recover(&nonce, &authenticated, evidence, 40)
            .unwrap(),
        None
    );
    assert_eq!(
        state_model.record(&nonce).unwrap().status(),
        JournalStatus::Expired
    );
    assert_eq!(state_model.replay(&nonce), Ok(ReplayOutcome::Expired));
    assert!(state_model.slot(&owner_slot()).unwrap().current().is_none());
    assert_eq!(state_model.high_watermark(&owner_slot()), Some(0));

    let next = context(
        2,
        Operation::Install,
        artifact(2),
        ExpectedPackageState::Absent,
        0,
    );
    state_model.begin(next, &authority(&next), 40).unwrap();
}

#[test]
fn drain_unknown_before_begin_drain_terminates_without_fencing() {
    let mut state_model = model(8);
    install(&mut state_model, 1, 1);
    let before = state_model
        .slot(&owner_slot())
        .unwrap()
        .current()
        .unwrap()
        .digest();
    let op_context = context(
        2,
        Operation::Update,
        artifact(2),
        ExpectedPackageState::Exact(before),
        90,
    );
    let authenticated = authority(&op_context);
    let nonce = state_model.begin(op_context, &authenticated, 10).unwrap();
    state_model.begin_work(&nonce, 20).unwrap();
    state_model.report_unknown(&nonce, 30).unwrap();
    let evidence = RecoveryEvidence::new(before, false, drain_receipt());
    assert_eq!(
        state_model
            .recover(&nonce, &authenticated, evidence, 40)
            .unwrap(),
        None
    );
    assert_eq!(
        state_model.record(&nonce).unwrap().status(),
        JournalStatus::Expired
    );
    let installed = state_model.slot(&owner_slot()).unwrap().current().unwrap();
    assert_eq!(installed.artifact(), &artifact(1));
    assert_eq!(installed.generation(), 1);
    assert_eq!(state_model.high_watermark(&owner_slot()), Some(1));

    let next = context(
        3,
        Operation::Update,
        artifact(2),
        ExpectedPackageState::Exact(installed.digest()),
        90,
    );
    state_model.begin(next, &authority(&next), 50).unwrap();
}

#[test]
fn executing_past_drain_deadline_terminates_without_lineage() {
    let mut state_model = model(8);
    install(&mut state_model, 1, 1);
    let before = state_model
        .slot(&owner_slot())
        .unwrap()
        .current()
        .unwrap()
        .digest();
    let op_context = context(
        2,
        Operation::Update,
        artifact(2),
        ExpectedPackageState::Exact(before),
        90,
    );
    let authenticated = authority(&op_context);
    let nonce = state_model.begin(op_context, &authenticated, 10).unwrap();
    state_model.begin_work(&nonce, 20).unwrap();
    assert_eq!(
        state_model.begin_drain(&nonce, 91).unwrap_err(),
        PackageServiceError::InvalidDrain
    );
    assert_eq!(
        state_model.report_unknown(&nonce, 91).unwrap_err(),
        PackageServiceError::InvalidDrain
    );
    assert_eq!(state_model.expire(&nonce, 91).unwrap(), 1);
    assert_eq!(
        state_model.record(&nonce).unwrap().status(),
        JournalStatus::Expired
    );
    assert_eq!(state_model.replay(&nonce), Ok(ReplayOutcome::Expired));
    assert_eq!(
        state_model
            .slot(&owner_slot())
            .unwrap()
            .current()
            .unwrap()
            .digest(),
        before
    );
    let next = context(
        3,
        Operation::Update,
        artifact(2),
        ExpectedPackageState::Exact(before),
        90,
    );
    state_model.begin(next, &authority(&next), 50).unwrap();
}

#[test]
fn begin_work_after_drain_deadline_fails_closed() {
    let mut state_model = model(8);
    install(&mut state_model, 1, 1);
    let before = state_model
        .slot(&owner_slot())
        .unwrap()
        .current()
        .unwrap()
        .digest();
    let op_context = context(
        2,
        Operation::Update,
        artifact(2),
        ExpectedPackageState::Exact(before),
        90,
    );
    let authenticated = authority(&op_context);
    let nonce = state_model.begin(op_context, &authenticated, 10).unwrap();
    assert_eq!(
        state_model.begin_work(&nonce, 90).unwrap_err(),
        PackageServiceError::InvalidDrain
    );
    assert_eq!(
        state_model.record(&nonce).unwrap().status(),
        JournalStatus::Intent
    );
    assert_eq!(state_model.expire(&nonce, 91).unwrap(), 1);
    assert_eq!(
        state_model.record(&nonce).unwrap().status(),
        JournalStatus::Expired
    );
}

#[test]
fn intent_past_expiry_terminates_and_unfences_slot() {
    let mut state_model = model(8);
    let op_context = context(
        1,
        Operation::Install,
        artifact(1),
        ExpectedPackageState::Absent,
        0,
    );
    let authenticated = authority(&op_context);
    let nonce = state_model.begin(op_context, &authenticated, 10).unwrap();
    assert_eq!(
        state_model.begin_work(&nonce, 100).unwrap_err(),
        PackageServiceError::AuthorityExpired
    );
    assert_eq!(
        state_model.cancel(&nonce, &authenticated, 100).unwrap_err(),
        PackageServiceError::AuthorityExpired
    );
    assert_eq!(state_model.expire(&nonce, 100).unwrap(), 0);
    assert_eq!(
        state_model.record(&nonce).unwrap().status(),
        JournalStatus::Expired
    );
    assert_eq!(state_model.replay(&nonce), Ok(ReplayOutcome::Expired));

    let next = context_expiring_at(
        2,
        Operation::Install,
        artifact(2),
        ExpectedPackageState::Absent,
        0,
        200,
    );
    let next_nonce = state_model.begin(next, &authority(&next), 150).unwrap();
    state_model.begin_work(&next_nonce, 160).unwrap();
    state_model
        .commit(&next_nonce, runtime_receipt(), 170)
        .unwrap();
    assert_eq!(state_model.high_watermark(&owner_slot()), Some(1));
}
