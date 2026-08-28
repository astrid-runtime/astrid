use astrid_package_service::{
    ArtifactFormatVersion, ArtifactIdentity, AuthenticatedAuthority, AuthorityIssuer,
    AuthorityIssuerClass, AuthorityIssuerIdentity, Blake3Digest, CanonicalInstalledState,
    ComponentIdentity, DrainDestination, DrainPlan, ExpectedPackageState, InstalledStateSpec,
    LifecycleState, ManifestFormatVersion, ManifestIdentity, Nonce, OperationReceipt, PackageName,
    PackageObject, PackageServiceError, PackageVersion, PrincipalUid, ProvenanceDigest,
    ServiceGeneration, StateDigest, Timestamp,
};
use std::any::TypeId;
use std::num::{NonZeroU32, NonZeroU64};

fn non_zero_u32(value: u32) -> NonZeroU32 {
    match NonZeroU32::new(value) {
        Some(value) => value,
        None => panic!("test format is non-zero"),
    }
}

fn non_zero_u64(value: u64) -> NonZeroU64 {
    match NonZeroU64::new(value) {
        Some(value) => value,
        None => panic!("test generation is non-zero"),
    }
}

fn digest(byte: u8) -> Blake3Digest {
    Blake3Digest::from_bytes([byte; 32])
}

fn package_name() -> PackageName {
    match PackageName::new("example-package") {
        Ok(value) => value,
        Err(_) => panic!("fixed package name is valid"),
    }
}

fn package_version() -> PackageVersion {
    match PackageVersion::new("1.2.3") {
        Ok(value) => value,
        Err(_) => panic!("fixed package version is valid"),
    }
}

fn artifact_identity() -> ArtifactIdentity {
    match ArtifactIdentity::new(
        ArtifactFormatVersion::new(non_zero_u32(1)),
        non_zero_u64(128),
        astrid_package_service::Sha256Digest::from_bytes([2; 32]),
        digest(3),
    ) {
        Ok(value) => value,
        Err(_) => panic!("fixed artifact identity is valid"),
    }
}

fn manifest_identity() -> ManifestIdentity {
    match ManifestIdentity::new(
        ManifestFormatVersion::new(non_zero_u32(1)),
        package_name(),
        package_version(),
        digest(4),
    ) {
        Ok(value) => value,
        Err(_) => panic!("fixed manifest identity is valid"),
    }
}

fn installed_state_spec(
    authority: astrid_package_service::AuthorityDecisionDigest,
    provenance: ProvenanceDigest,
    content_root: Blake3Digest,
) -> InstalledStateSpec {
    InstalledStateSpec {
        owner: PrincipalUid::from_bytes([1; 32]),
        package_object: PackageObject::from_bytes([2; 32]),
        artifact: artifact_identity(),
        content_root,
        manifest: manifest_identity(),
        authority_digest: authority,
        provenance,
        lifecycle_state: LifecycleState::Inactive,
        lifecycle_plan: astrid_package_service::PlanDigest::from_bytes([7; 32]),
        generation: non_zero_u64(1),
        completing_nonce: Nonce::from_bytes([3; 32]),
    }
}

#[test]
fn public_drain_plan_constructor_preserves_state_binding() {
    let state = ExpectedPackageState::Exact(StateDigest::from_bytes([1; 32]));
    let plan = match DrainPlan::new(
        DrainDestination::Replacement,
        state,
        Timestamp::new(20),
        Nonce::from_bytes([2; 32]),
    ) {
        Ok(value) => value,
        Err(_) => panic!("valid drain plan should construct"),
    };
    assert_eq!(plan.destination(), DrainDestination::Replacement);
    assert_eq!(plan.deadline(), Timestamp::new(20));
    assert!(matches!(
        DrainPlan::new(
            DrainDestination::Removal,
            ExpectedPackageState::Absent,
            Timestamp::new(20),
            Nonce::from_bytes([2; 32]),
        ),
        Err(PackageServiceError::InvalidValue(_))
    ));
    assert!(matches!(
        DrainPlan::new(
            DrainDestination::Removal,
            ExpectedPackageState::Exact(StateDigest::from_bytes([1; 32])),
            Timestamp::new(20),
            Nonce::from_bytes([0; 32]),
        ),
        Err(PackageServiceError::InvalidValue(_))
    ));
    assert!(matches!(
        DrainPlan::new(
            DrainDestination::Removal,
            ExpectedPackageState::Exact(StateDigest::from_bytes([1; 32])),
            Timestamp::ZERO,
            Nonce::from_bytes([2; 32]),
        ),
        Err(PackageServiceError::InvalidValue(_))
    ));
}

#[test]
fn public_state_constructor_rejects_zero_binding_digests() {
    let authority = astrid_package_service::AuthorityDecisionDigest::from_bytes([4; 32]);
    let provenance = ProvenanceDigest::from_bytes([5; 32]);
    let content_root = digest(6);
    let valid = installed_state_spec(authority, provenance, content_root);
    assert!(
        CanonicalInstalledState::new(valid).is_ok(),
        "valid installed state should construct"
    );
    for spec in [
        installed_state_spec(
            astrid_package_service::AuthorityDecisionDigest::from_bytes([0; 32]),
            provenance,
            content_root,
        ),
        installed_state_spec(
            authority,
            ProvenanceDigest::from_bytes([0; 32]),
            content_root,
        ),
        installed_state_spec(authority, provenance, Blake3Digest::from_bytes([0; 32])),
    ] {
        assert!(
            matches!(
                CanonicalInstalledState::new(spec),
                Err(PackageServiceError::InvalidValue(_))
            ),
            "zero binding digest must be rejected"
        );
    }
}

#[test]
fn public_authority_constructors_reject_zero_evidence() {
    assert!(matches!(
        AuthorityIssuer::new(
            AuthorityIssuerClass::ExplicitApproval,
            AuthorityIssuerIdentity::from_bytes([1; 32]),
            AuthorityIssuerIdentity::from_bytes([2; 32]),
            Blake3Digest::from_bytes([0; 32]),
        ),
        Err(PackageServiceError::AuthorityIssuerRejected)
    ));
    let issuer = match AuthorityIssuer::new(
        AuthorityIssuerClass::ExplicitApproval,
        AuthorityIssuerIdentity::from_bytes([1; 32]),
        AuthorityIssuerIdentity::from_bytes([2; 32]),
        digest(3),
    ) {
        Ok(value) => value,
        Err(_) => panic!("fixed issuer is valid"),
    };
    let context = astrid_package_service::OperationContextSpec {
        nonce: Nonce::from_bytes([4; 32]),
        operation: astrid_package_service::Operation::Install,
        expected_state: ExpectedPackageState::Absent,
        effective_caller: PrincipalUid::from_bytes([5; 32]),
        approver: astrid_package_service::ApproverIdentity::Principal(PrincipalUid::from_bytes(
            [5; 32],
        )),
        target_owner: PrincipalUid::from_bytes([6; 32]),
        package_object: PackageObject::from_bytes([7; 32]),
        artifact: artifact_identity(),
        manifest: manifest_identity(),
        plan_digest: astrid_package_service::PlanDigest::from_bytes([8; 32]),
        budget: astrid_package_service::ResourceBudget::new(
            non_zero_u64(4_096),
            astrid_package_service::ResourceClasses::new(true, true, true, true),
        ),
        expiry: Timestamp::new(1_000),
    };
    let service = astrid_package_service::AdmittedService::new(
        ComponentIdentity::from_bytes([9; 32]),
        ServiceGeneration::new(non_zero_u64(1)),
        digest(10),
    );
    let context =
        match astrid_package_service::OperationContext::new(context, &service, Timestamp::ZERO) {
            Ok(value) => value,
            Err(_) => panic!("fixed context is valid"),
        };
    assert!(matches!(
        AuthenticatedAuthority::bind(&context, issuer, Blake3Digest::from_bytes([0; 32])),
        Err(PackageServiceError::AuthorityIssuerRejected)
    ));
}

#[test]
fn next_tranche_types_are_publicly_addressable() {
    assert_eq!(
        TypeId::of::<OperationReceipt>(),
        TypeId::of::<OperationReceipt>()
    );
    assert_ne!(LifecycleState::Active, LifecycleState::Inactive);
    assert_ne!(DrainDestination::Replacement, DrainDestination::Removal);
    assert_eq!(Timestamp::ZERO.get(), 0);
    assert_eq!(package_name().as_str(), "example-package");
    assert_eq!(package_version().as_str(), "1.2.3");
}
