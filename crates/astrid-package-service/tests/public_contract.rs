//! Public-boundary regression tests exercised outside the crate.

use astrid_core::PrincipalUid;
use astrid_package_service::{
    AuthenticatedAuthority, AuthorityClass, ExpectedPackageState, JournalPolicy, LifecyclePlan,
    Nonce, Operation, OperationContext, OperationContextSpec, PackageObject, PackageServiceModel,
    ResourceBudget, ServiceIdentity, ValidatedArtifact,
};
use astrid_resource_types::OwnerId;
use core::num::{NonZeroU64, NonZeroUsize};
use ed25519_dalek::{Signer, SigningKey};

fn bytes(value: u8) -> [u8; 32] {
    [value; 32]
}

fn identity(value: u8) -> PackageObject {
    PackageObject::from_bytes(bytes(value)).unwrap()
}

fn service_identity(value: u8) -> ServiceIdentity {
    ServiceIdentity::from_bytes(bytes(value)).unwrap()
}

fn principal(value: u8) -> PrincipalUid {
    PrincipalUid::from_bytes(bytes(value))
}

fn artifact(tag: u8) -> ValidatedArtifact {
    ValidatedArtifact::new(
        astrid_package_service::ArtifactIdentity::from_bytes(bytes(tag)).unwrap(),
        astrid_package_service::ManifestIdentity::from_bytes(bytes(tag.wrapping_add(0x40)))
            .unwrap(),
        NonZeroU64::new(128).unwrap(),
        bytes(tag.wrapping_add(0x80)),
    )
    .unwrap()
}

fn runtime_receipt() -> astrid_package_service::RuntimeReceiptDigest {
    astrid_package_service::RuntimeReceiptDigest::from_bytes(bytes(30))
}

fn drain_receipt() -> astrid_package_service::RuntimeReceiptDigest {
    astrid_package_service::RuntimeReceiptDigest::from_bytes(bytes(31))
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

fn context(
    operation: Operation,
    nonce_value: u8,
    content: ValidatedArtifact,
    expected: ExpectedPackageState,
    owner: OwnerId,
) -> OperationContext {
    let plan = match operation {
        Operation::Update => LifecyclePlan::ReplacementDrain { deadline: 90 },
        Operation::Install | Operation::Activate | Operation::Deactivate => LifecyclePlan::Activate,
        Operation::Remove => LifecyclePlan::RemovalDrain { deadline: 90 },
    };
    OperationContext::new(OperationContextSpec {
        caller: principal(1),
        approver: principal(2),
        target_owner: owner,
        service: service_identity(3),
        service_generation: NonZeroU64::new(7).unwrap(),
        operation,
        package: identity(4),
        artifact: content,
        expected,
        plan,
        budget: ResourceBudget::new(
            astrid_package_service::BudgetIdentity::from_bytes(bytes(5)).unwrap(),
            NonZeroU64::new(256).unwrap(),
        ),
        expiry: 100,
        nonce: test_nonce(nonce_value),
        runtime_receipt: runtime_receipt(),
        drain_receipt: drain_receipt(),
    })
    .unwrap()
}

fn signature(context: &OperationContext) -> [u8; 64] {
    let issuer = astrid_package_service::AuthorityIssuerIdentity::from_bytes(bytes(6)).unwrap();
    let key = test_signing_key(b"public-contract");
    key.sign(&AuthenticatedAuthority::signing_payload(
        AuthorityClass::ExplicitApproval,
        issuer,
        context,
    ))
    .to_bytes()
}

fn authority(context: &OperationContext) -> AuthenticatedAuthority {
    let issuer = astrid_package_service::AuthorityIssuerIdentity::from_bytes(bytes(6)).unwrap();
    let key = test_signing_key(b"public-contract");
    AuthenticatedAuthority::verify(
        context,
        AuthorityClass::ExplicitApproval,
        issuer,
        key.verifying_key().to_bytes(),
        signature(context),
        10,
    )
    .unwrap()
}

fn model() -> PackageServiceModel {
    PackageServiceModel::new(JournalPolicy::new(
        NonZeroUsize::new(8).unwrap(),
        NonZeroU64::new(4_096).unwrap(),
    ))
}

#[test]
fn provenance_is_public_deterministic_and_substitution_sensitive() {
    let first = artifact(1);
    let second = artifact(2);
    assert_eq!(first.provenance_digest(), first.provenance_digest());
    assert_ne!(first.provenance_digest(), second.provenance_digest());
}

#[test]
fn external_consumer_signs_derived_context_without_hidden_hashing() {
    let content = artifact(1);
    let installed = context(
        Operation::Install,
        1,
        content,
        ExpectedPackageState::Absent,
        OwnerId::Principal(bytes(8)),
    );
    let authenticated = authority(&installed);
    let mut state_model = model();
    state_model.begin(installed, &authenticated, 10).unwrap();
}

#[test]
fn authority_does_not_replay_across_any_changed_bound_field() {
    let original = context(
        Operation::Install,
        1,
        artifact(1),
        ExpectedPackageState::Absent,
        OwnerId::Principal(bytes(8)),
    );
    let issuer = astrid_package_service::AuthorityIssuerIdentity::from_bytes(bytes(6)).unwrap();
    let key = test_signing_key(b"public-contract");
    let old_signature = key
        .sign(&AuthenticatedAuthority::signing_payload(
            AuthorityClass::ExplicitApproval,
            issuer,
            &original,
        ))
        .to_bytes();
    assert!(
        AuthenticatedAuthority::verify(
            &original,
            AuthorityClass::ExplicitApproval,
            issuer,
            key.verifying_key().to_bytes(),
            old_signature,
            10
        )
        .is_ok()
    );
    let substitutions = [
        context(
            Operation::Update,
            1,
            artifact(1),
            ExpectedPackageState::Absent,
            OwnerId::Principal(bytes(8)),
        ),
        context(
            Operation::Install,
            2,
            artifact(1),
            ExpectedPackageState::Absent,
            OwnerId::Principal(bytes(8)),
        ),
        context(
            Operation::Install,
            1,
            artifact(2),
            ExpectedPackageState::Absent,
            OwnerId::Principal(bytes(8)),
        ),
        context(
            Operation::Install,
            1,
            artifact(1),
            ExpectedPackageState::Exact(astrid_package_service::StateDigest::from_bytes(bytes(9))),
            OwnerId::Principal(bytes(8)),
        ),
        context(
            Operation::Install,
            1,
            artifact(1),
            ExpectedPackageState::Absent,
            OwnerId::Principal(bytes(9)),
        ),
    ];
    for changed in substitutions {
        assert!(
            AuthenticatedAuthority::verify(
                &changed,
                AuthorityClass::ExplicitApproval,
                issuer,
                key.verifying_key().to_bytes(),
                old_signature,
                10
            )
            .is_err()
        );
    }
}

#[test]
fn zero_content_root_is_rejected_at_public_boundary() {
    let result = ValidatedArtifact::new(
        astrid_package_service::ArtifactIdentity::from_bytes(bytes(1)).unwrap(),
        astrid_package_service::ManifestIdentity::from_bytes(bytes(2)).unwrap(),
        NonZeroU64::new(1).unwrap(),
        [0; 32],
    );
    assert_eq!(
        result.unwrap_err(),
        astrid_package_service::PackageServiceError::ZeroValue
    );
}

#[test]
fn owner_slots_are_isolated_and_budget_is_enforced() {
    let owner_a = OwnerId::Principal(bytes(8));
    let owner_b = OwnerId::Principal(bytes(9));
    let content = artifact(1);
    let first = context(
        Operation::Install,
        1,
        content,
        ExpectedPackageState::Absent,
        owner_a,
    );
    let second = context(
        Operation::Install,
        2,
        content,
        ExpectedPackageState::Absent,
        owner_b,
    );
    let mut state_model = model();
    state_model.begin(first, &authority(&first), 10).unwrap();
    state_model.begin(second, &authority(&second), 10).unwrap();
    assert_ne!(
        state_model.high_watermark(&astrid_package_service::PackageSlot::new(
            owner_a,
            identity(4)
        )),
        None
    );
    let under_budget = OperationContext::new(OperationContextSpec {
        caller: principal(1),
        approver: principal(2),
        target_owner: owner_a,
        service: service_identity(3),
        service_generation: NonZeroU64::new(7).unwrap(),
        operation: Operation::Install,
        package: identity(4),
        artifact: content,
        expected: ExpectedPackageState::Absent,
        plan: LifecyclePlan::Activate,
        budget: ResourceBudget::new(
            astrid_package_service::BudgetIdentity::from_bytes(bytes(5)).unwrap(),
            NonZeroU64::new(64).unwrap(),
        ),
        expiry: 100,
        nonce: test_nonce(3),
        runtime_receipt: runtime_receipt(),
        drain_receipt: drain_receipt(),
    })
    .unwrap();
    assert_eq!(
        state_model
            .begin(under_budget, &authority(&under_budget), 10)
            .unwrap_err(),
        astrid_package_service::PackageServiceError::BudgetExceeded
    );
}

#[test]
fn nonce_cannot_replay_after_terminal_commit_history() {
    let owner = OwnerId::Principal(bytes(8));
    let content = artifact(1);
    let installed = context(
        Operation::Install,
        1,
        content,
        ExpectedPackageState::Absent,
        owner,
    );
    let mut state_model = model();
    let nonce = state_model
        .begin(installed, &authority(&installed), 10)
        .unwrap();
    state_model.begin_work(&nonce, 20).unwrap();
    state_model.commit(&nonce, runtime_receipt(), 30).unwrap();
    let replay = context(
        Operation::Install,
        1,
        content,
        ExpectedPackageState::Absent,
        owner,
    );
    assert_eq!(
        state_model
            .begin(replay, &authority(&replay), 40)
            .unwrap_err(),
        astrid_package_service::PackageServiceError::NonceReplay
    );
}

#[test]
fn stale_expected_state_is_rejected() {
    let owner = OwnerId::Principal(bytes(8));
    let content = artifact(1);
    let stale = context(
        Operation::Install,
        1,
        content,
        ExpectedPackageState::Absent,
        owner,
    );
    let mut state_model = model();
    state_model.begin(stale, &authority(&stale), 10).unwrap();
    let wrong = OperationContext::new(OperationContextSpec {
        caller: principal(1),
        approver: principal(2),
        target_owner: owner,
        service: service_identity(3),
        service_generation: NonZeroU64::new(7).unwrap(),
        operation: Operation::Install,
        package: identity(4),
        artifact: content,
        expected: ExpectedPackageState::Exact(astrid_package_service::StateDigest::from_bytes(
            bytes(20),
        )),
        plan: LifecyclePlan::Activate,
        budget: ResourceBudget::new(
            astrid_package_service::BudgetIdentity::from_bytes(bytes(5)).unwrap(),
            NonZeroU64::new(256).unwrap(),
        ),
        expiry: 100,
        nonce: test_nonce(2),
        runtime_receipt: runtime_receipt(),
        drain_receipt: drain_receipt(),
    })
    .unwrap();
    assert_eq!(
        state_model
            .begin(wrong, &authority(&wrong), 20)
            .unwrap_err(),
        astrid_package_service::PackageServiceError::ExpectedStateMismatch
    );
}

#[test]
fn signature_mutation_fails_closed() {
    let context = context(
        Operation::Install,
        1,
        artifact(1),
        ExpectedPackageState::Absent,
        OwnerId::Principal(bytes(8)),
    );
    let issuer = astrid_package_service::AuthorityIssuerIdentity::from_bytes(bytes(6)).unwrap();
    let key = test_signing_key(b"public-contract");
    let mut signature = key
        .sign(&AuthenticatedAuthority::signing_payload(
            AuthorityClass::ExplicitApproval,
            issuer,
            &context,
        ))
        .to_bytes();
    signature[0] ^= 1;
    assert!(
        AuthenticatedAuthority::verify(
            &context,
            AuthorityClass::ExplicitApproval,
            issuer,
            key.verifying_key().to_bytes(),
            signature,
            10,
        )
        .is_err()
    );
}

#[test]
fn exact_zero_expected_state_is_rejected_as_absence_collision() {
    assert_eq!(
        OperationContext::new(OperationContextSpec {
            caller: principal(1),
            approver: principal(2),
            target_owner: OwnerId::Principal(bytes(8)),
            service: service_identity(3),
            service_generation: NonZeroU64::new(7).unwrap(),
            operation: Operation::Update,
            package: identity(4),
            artifact: artifact(1),
            expected: ExpectedPackageState::Exact(astrid_package_service::StateDigest::from_bytes(
                [0; 32]
            )),
            plan: LifecyclePlan::ReplacementDrain { deadline: 90 },
            budget: ResourceBudget::new(
                astrid_package_service::BudgetIdentity::from_bytes(bytes(5)).unwrap(),
                NonZeroU64::new(256).unwrap(),
            ),
            expiry: 100,
            nonce: test_nonce(9),
            runtime_receipt: runtime_receipt(),
            drain_receipt: drain_receipt(),
        })
        .unwrap_err(),
        astrid_package_service::PackageServiceError::ZeroValue
    );
}

#[test]
fn authority_class_is_bound_to_the_signed_decision() {
    let context = context(
        Operation::Install,
        1,
        artifact(1),
        ExpectedPackageState::Absent,
        OwnerId::Principal(bytes(8)),
    );
    let issuer = astrid_package_service::AuthorityIssuerIdentity::from_bytes(bytes(6)).unwrap();
    let key = test_signing_key(b"public-contract");
    let signature = key
        .sign(&AuthenticatedAuthority::signing_payload(
            AuthorityClass::ExplicitApproval,
            issuer,
            &context,
        ))
        .to_bytes();
    assert!(
        AuthenticatedAuthority::verify(
            &context,
            AuthorityClass::ExplicitApproval,
            issuer,
            key.verifying_key().to_bytes(),
            signature,
            10,
        )
        .is_ok()
    );
    assert!(
        AuthenticatedAuthority::verify(
            &context,
            AuthorityClass::OperatorPolicy,
            issuer,
            key.verifying_key().to_bytes(),
            signature,
            10,
        )
        .is_err()
    );
}

#[test]
fn plan_operation_conflict_has_a_named_public_transition_failure() {
    assert_eq!(
        OperationContext::new(OperationContextSpec {
            caller: principal(1),
            approver: principal(2),
            target_owner: OwnerId::Principal(bytes(8)),
            service: service_identity(3),
            service_generation: NonZeroU64::new(7).unwrap(),
            operation: Operation::Install,
            package: identity(4),
            artifact: artifact(1),
            expected: ExpectedPackageState::Absent,
            plan: LifecyclePlan::ReplacementDrain { deadline: 90 },
            budget: ResourceBudget::new(
                astrid_package_service::BudgetIdentity::from_bytes(bytes(5)).unwrap(),
                NonZeroU64::new(256).unwrap(),
            ),
            expiry: 100,
            nonce: test_nonce(10),
            runtime_receipt: runtime_receipt(),
            drain_receipt: drain_receipt(),
        })
        .unwrap_err(),
        astrid_package_service::PackageServiceError::PlanConflict
    );
}

#[test]
fn terminal_replay_protection_expires_with_quota_eviction() {
    let first_owner = OwnerId::Principal(bytes(8));
    let second_owner = OwnerId::Principal(bytes(9));
    let first = context(
        Operation::Install,
        1,
        artifact(1),
        ExpectedPackageState::Absent,
        first_owner,
    );
    let second = context(
        Operation::Install,
        2,
        artifact(1),
        ExpectedPackageState::Absent,
        second_owner,
    );
    let mut state_model = PackageServiceModel::new(JournalPolicy::new(
        NonZeroUsize::new(1).unwrap(),
        NonZeroU64::new(4_096).unwrap(),
    ));
    let nonce = state_model.begin(first, &authority(&first), 10).unwrap();
    state_model.begin_work(&nonce, 20).unwrap();
    state_model.commit(&nonce, runtime_receipt(), 30).unwrap();
    state_model.begin(second, &authority(&second), 40).unwrap();
    assert!(state_model.record(&nonce).is_none());
    assert_eq!(
        state_model.replay(&nonce).unwrap_err(),
        astrid_package_service::PackageServiceError::RecordUnavailable
    );
}
