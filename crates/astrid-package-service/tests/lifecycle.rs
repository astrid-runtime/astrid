//! Lifecycle transition, cancel, quota, authority, and replay falsifiers.

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

fn alternate_authority(context: &OperationContext) -> AuthenticatedAuthority {
    let issuer = AuthorityIssuerIdentity::from_bytes(bytes(32)).unwrap();
    let key = test_signing_key(b"lifecycle-alternate");
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
    state_model.prove_drain(&update, proof(), 80).unwrap();
    state_model.commit(&update, runtime_receipt(), 80).unwrap();
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
        .commit(&activate_nonce, runtime_receipt(), 30)
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
        .commit(&deactivate_nonce, runtime_receipt(), 30)
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
    state_model.prove_drain(&remove_nonce, proof(), 80).unwrap();
    let receipt = state_model
        .commit(&remove_nonce, runtime_receipt(), 80)
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
        nonce: test_nonce(3),
        runtime_receipt: runtime_receipt(),
        drain_receipt: drain_receipt(),
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
        nonce: test_nonce(9),
        runtime_receipt: runtime_receipt(),
        drain_receipt: drain_receipt(),
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
    let evidence = RecoveryEvidence::new(before, false, drain_receipt());
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
fn plan_digest_is_domain_separate_from_state_digest() {
    let mut writer = DigestWriter::new();
    writer.u64(1);
    let state_like = writer.finish::<2>("astrid.package.state.v1");
    let plan_like = writer.finish::<3>("astrid.package.plan.v1");
    assert_ne!(state_like.as_bytes(), plan_like.as_bytes());
}

#[test]
fn digest_writer_hashes_the_exact_length_delimited_field_stream() {
    let mut writer = DigestWriter::new();
    writer.tag(7);
    writer.bytes(&[1, 2, 3]);
    writer.u64(258);

    let actual = writer.finish::<2>("astrid.package.writer.v1");
    let mut fields = vec![7_u8];
    fields.extend_from_slice(&3_u64.to_le_bytes());
    fields.extend_from_slice(&[1, 2, 3]);
    fields.extend_from_slice(&258_u64.to_le_bytes());

    let mut expected_hasher = blake3::Hasher::new();
    let domain = b"astrid.package.writer.v1";
    expected_hasher.update(&(domain.len() as u64).to_le_bytes());
    expected_hasher.update(domain);
    expected_hasher.update(&(fields.len() as u64).to_le_bytes());
    expected_hasher.update(&fields);
    assert_eq!(actual.as_bytes(), expected_hasher.finalize().as_bytes());
}
