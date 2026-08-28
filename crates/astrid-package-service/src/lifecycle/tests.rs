use super::*;
use crate::authority::{AuthorityIssuer, AuthorityIssuerClass};
use crate::bytes::PrincipalUid;
use crate::context::{
    ApproverIdentity, IngressChannel, OperationContextSpec, ResourceBudget, ResourceClasses,
};
use crate::digest::{Blake3Digest, DigestWriter, PlanDigest, Sha256Digest, TypedDigest};
use crate::identity::{
    ArtifactFormatVersion, ArtifactIdentity, AuthorityIssuerIdentity, BoundedEvidence,
    ComponentIdentity, ManifestFormatVersion, ManifestIdentity, Nonce, PackageName, PackageObject,
    PackageVersion, ProvenanceClass, ServiceGeneration,
};
use crate::policy::{JournalPolicy, JournalRetention, RetentionWindow};
use crate::state::PackageSlot;
use std::num::{NonZeroU32, NonZeroU64};
use std::time::Duration;

fn non_zero(value: u64) -> NonZeroU64 {
    match NonZeroU64::new(value) {
        Some(value) => value,
        None => panic!("test value is non-zero"),
    }
}

fn format(value: u32) -> ArtifactFormatVersion {
    ArtifactFormatVersion::new(match NonZeroU32::new(value) {
        Some(value) => value,
        None => panic!("test format is non-zero"),
    })
}

fn manifest_format(value: u32) -> ManifestFormatVersion {
    ManifestFormatVersion::new(match NonZeroU32::new(value) {
        Some(value) => value,
        None => panic!("test format is non-zero"),
    })
}

fn digest(byte: u8) -> Blake3Digest {
    Blake3Digest::from_bytes([byte; 32])
}

fn sha(byte: u8) -> Sha256Digest {
    Sha256Digest::from_bytes([byte; 32])
}

fn plan_digest(byte: u8) -> PlanDigest {
    PlanDigest::from_bytes([byte; 32])
}

fn artifact() -> ArtifactIdentity {
    match ArtifactIdentity::new(format(1), non_zero(128), sha(2), digest(3)) {
        Ok(value) => value,
        Err(_) => panic!("fixed artifact identity is valid"),
    }
}

fn manifest() -> ManifestIdentity {
    let name = match PackageName::new("example-package") {
        Ok(value) => value,
        Err(_) => panic!("fixed test name is valid"),
    };
    let version = match PackageVersion::new("1.2.3") {
        Ok(value) => value,
        Err(_) => panic!("fixed test version is valid"),
    };
    match ManifestIdentity::new(manifest_format(1), name, version, digest(4)) {
        Ok(value) => value,
        Err(_) => panic!("fixed manifest identity is valid"),
    }
}

fn validated_artifact(content: u8) -> ValidatedArtifact {
    let bounded = match BoundedEvidence::new(vec![1, 2, 3]) {
        Ok(value) => value,
        Err(_) => panic!("fixed evidence is valid"),
    };
    let provenance =
        match ProvenanceEvidence::new(ProvenanceClass::LocalArtifact, digest(5), bounded) {
            Ok(value) => value,
            Err(_) => panic!("fixed provenance is valid"),
        };
    match ValidatedArtifact::new(artifact(), manifest(), digest(content), provenance) {
        Ok(value) => value,
        Err(_) => panic!("fixed validated artifact is valid"),
    }
}

struct Fixture {
    caller: PrincipalUid,
    owner: PrincipalUid,
    other_owner: PrincipalUid,
    object: PackageObject,
    service: AdmittedService,
    ingress: AuthenticatedIngress,
    issuer: AuthorityIssuer,
    evidence: Blake3Digest,
    budget: ResourceBudget,
}

impl Fixture {
    fn new() -> Self {
        Self {
            caller: PrincipalUid::from_bytes([1; 32]),
            owner: PrincipalUid::from_bytes([2; 32]),
            other_owner: PrincipalUid::from_bytes([3; 32]),
            object: PackageObject::from_bytes([4; 32]),
            service: AdmittedService::new(
                ComponentIdentity::from_bytes([5; 32]),
                ServiceGeneration::new(non_zero(1)),
                digest(6),
            ),
            ingress: AuthenticatedIngress::new(
                PrincipalUid::from_bytes([1; 32]),
                IngressChannel::AuthenticatedIpc,
                digest(7),
            ),
            issuer: match AuthorityIssuer::new(
                AuthorityIssuerClass::ExplicitApproval,
                AuthorityIssuerIdentity::from_bytes([8; 32]),
                AuthorityIssuerIdentity::from_bytes([9; 32]),
                digest(10),
            ) {
                Ok(value) => value,
                Err(_) => panic!("fixed issuer is valid"),
            },
            evidence: digest(11),
            budget: ResourceBudget::new(
                non_zero(4_096),
                ResourceClasses::new(true, true, true, true),
            ),
        }
    }

    fn context(
        &self,
        operation: Operation,
        expected: ExpectedPackageState,
        plan: PlanDigest,
        participants: (PrincipalUid, PrincipalUid),
        generation: u64,
        nonce: Nonce,
    ) -> OperationContext {
        match OperationContext::new(
            OperationContextSpec {
                nonce,
                operation,
                expected_state: expected,
                effective_caller: participants.1,
                approver: ApproverIdentity::Principal(participants.1),
                target_owner: participants.0,
                package_object: self.object,
                artifact: artifact(),
                manifest: manifest(),
                plan_digest: plan,
                budget: self.budget,
                expiry: Timestamp::new(1_000),
            },
            &self.service_at(generation),
            Timestamp::new(100),
        ) {
            Ok(value) => value,
            Err(_) => panic!("fixed operation context is valid"),
        }
    }

    fn service_at(&self, generation: u64) -> AdmittedService {
        AdmittedService::new(
            *self.service.component(),
            ServiceGeneration::new(non_zero(generation)),
            digest(6),
        )
    }

    fn authority(&self, context: &OperationContext) -> AuthenticatedAuthority {
        AuthenticatedAuthority::bind(context, self.issuer, self.evidence)
    }

    fn begin(
        &self,
        model: &mut PackageServiceModel,
        context: OperationContext,
        now: u64,
    ) -> PackageServiceResult<Nonce> {
        let authority = self.authority_for(&context);
        model.begin(
            context,
            &authority,
            self.ingress,
            &self.service_at(1),
            Timestamp::new(now),
        )
    }

    fn authority_for(&self, context: &OperationContext) -> AuthenticatedAuthority {
        AuthenticatedAuthority::bind(context, self.issuer, self.evidence)
    }

    fn slot(&self, owner: PrincipalUid) -> PackageSlot {
        PackageSlot::new(owner, self.object)
    }
}

fn policy(capacity: u64) -> JournalPolicy {
    policy_with_tombstone_capacity(capacity, 128)
}

fn policy_with_tombstone_capacity(capacity: u64, tombstone_capacity: u64) -> JournalPolicy {
    let receipts = match RetentionWindow::new(Duration::from_hours(1), Duration::from_hours(2)) {
        Ok(value) => value,
        Err(_) => panic!("test retention is valid"),
    };
    let failures = match RetentionWindow::new(Duration::from_hours(1), Duration::from_hours(2)) {
        Ok(value) => value,
        Err(_) => panic!("test retention is valid"),
    };
    JournalPolicy::new(
        non_zero(capacity),
        non_zero(1_048_576),
        non_zero(tombstone_capacity),
        non_zero(8),
        JournalRetention::new(receipts, failures),
    )
}

fn policy_short_retention(capacity: u64, tombstone_capacity: u64) -> JournalPolicy {
    let receipts = match RetentionWindow::new(Duration::from_secs(50), Duration::from_secs(100)) {
        Ok(value) => value,
        Err(_) => panic!("short test retention is valid"),
    };
    let failures = match RetentionWindow::new(Duration::from_secs(50), Duration::from_secs(100)) {
        Ok(value) => value,
        Err(_) => panic!("short test retention is valid"),
    };
    JournalPolicy::new(
        non_zero(capacity),
        non_zero(1_048_576),
        non_zero(tombstone_capacity),
        non_zero(8),
        JournalRetention::new(receipts, failures),
    )
}

fn install(model: &mut PackageServiceModel, fixture: &Fixture, nonce_byte: u8) -> OperationReceipt {
    let context = fixture.context(
        Operation::Install,
        ExpectedPackageState::Absent,
        plan_digest(20),
        (fixture.owner, fixture.caller),
        1,
        Nonce::from_bytes([nonce_byte; 32]),
    );
    let nonce = match fixture.begin(model, context, 100) {
        Ok(value) => value,
        Err(_) => panic!("install admission should succeed"),
    };
    model
        .begin_work(&nonce, Timestamp::new(110))
        .unwrap_or_else(|_| panic!("work should start"));
    model
        .complete(
            &nonce,
            Some(&validated_artifact(12)),
            None,
            true,
            Timestamp::new(120),
        )
        .unwrap_or_else(|_| panic!("install should commit"))
}

fn begin_update(model: &mut PackageServiceModel, fixture: &Fixture) -> Nonce {
    let state = match model
        .slot_record(&fixture.slot(fixture.owner))
        .and_then(|record| record.state())
    {
        Some(state) => state.digest(),
        None => panic!("installed state should exist"),
    };
    let replacement_plan = DrainPlan::new(
        DrainDestination::Replacement,
        Timestamp::new(200),
        Nonce::from_bytes([2; 32]),
    );
    let context = fixture.context(
        Operation::Update,
        ExpectedPackageState::Exact(state),
        replacement_plan.digest(),
        (fixture.owner, fixture.caller),
        1,
        Nonce::from_bytes([2; 32]),
    );
    let nonce = match fixture.begin(model, context, 130) {
        Ok(value) => value,
        Err(_) => panic!("update admission should succeed"),
    };
    model
        .begin_drain(
            &nonce,
            DrainDestination::Replacement,
            Timestamp::new(200),
            1,
            Timestamp::new(140),
        )
        .unwrap_or_else(|_| panic!("replacement drain should start"));
    nonce
}

fn begin_remove(model: &mut PackageServiceModel, fixture: &Fixture) -> Nonce {
    let state = match model
        .slot_record(&fixture.slot(fixture.owner))
        .and_then(|record| record.state())
    {
        Some(state) => state.digest(),
        None => panic!("installed state should exist"),
    };
    let removal_plan = DrainPlan::new(
        DrainDestination::Removal,
        Timestamp::new(400),
        Nonce::from_bytes([3; 32]),
    );
    let context = fixture.context(
        Operation::Remove,
        ExpectedPackageState::Exact(state),
        removal_plan.digest(),
        (fixture.owner, fixture.caller),
        1,
        Nonce::from_bytes([3; 32]),
    );
    let nonce = match fixture.begin(model, context, 300) {
        Ok(value) => value,
        Err(_) => panic!("remove admission should succeed"),
    };
    model
        .begin_drain(
            &nonce,
            DrainDestination::Removal,
            Timestamp::new(400),
            1,
            Timestamp::new(310),
        )
        .unwrap_or_else(|_| panic!("removal drain should start"));
    nonce
}

#[test]
fn authority_replay_rejects_changed_context_fields() {
    let fixture = Fixture::new();
    let mut model = PackageServiceModel::new(policy(8));
    let base = fixture.context(
        Operation::Install,
        ExpectedPackageState::Absent,
        plan_digest(20),
        (fixture.owner, fixture.caller),
        1,
        Nonce::from_bytes([7; 32]),
    );
    let authority = fixture.authority(&base);
    let changed = [
        fixture.context(
            Operation::Install,
            ExpectedPackageState::Absent,
            plan_digest(21),
            (fixture.owner, fixture.caller),
            1,
            Nonce::from_bytes([7; 32]),
        ),
        fixture.context(
            Operation::Install,
            ExpectedPackageState::Absent,
            plan_digest(20),
            (fixture.other_owner, fixture.caller),
            1,
            Nonce::from_bytes([7; 32]),
        ),
        fixture.context(
            Operation::Install,
            ExpectedPackageState::Absent,
            plan_digest(20),
            (fixture.owner, fixture.other_owner),
            1,
            Nonce::from_bytes([7; 32]),
        ),
        fixture.context(
            Operation::Install,
            ExpectedPackageState::Absent,
            plan_digest(20),
            (fixture.owner, fixture.caller),
            2,
            Nonce::from_bytes([7; 32]),
        ),
    ];
    for context in changed {
        let error = model
            .begin(
                context,
                &authority,
                fixture.ingress,
                &fixture.service_at(1),
                Timestamp::new(100),
            )
            .err()
            .unwrap_or_else(|| panic!("changed authority context must fail"));
        assert!(matches!(
            error,
            PackageServiceError::AuthorityContextMismatch
        ));
    }
    assert!(model.slot_record(&fixture.slot(fixture.owner)).is_none());
}

#[test]
fn terminal_receipt_replays_after_update_and_removal() {
    let fixture = Fixture::new();
    let mut model = PackageServiceModel::new(policy(8));
    install(&mut model, &fixture, 1);
    let update_nonce = begin_update(&mut model, &fixture);
    model
        .prove_drain_leases(&update_nonce, 0, Timestamp::new(200))
        .unwrap_or_else(|_| panic!("zero leases should be provable"));
    model
        .complete(
            &update_nonce,
            Some(&validated_artifact(13)),
            None,
            true,
            Timestamp::new(220),
        )
        .unwrap_or_else(|_| panic!("update should commit"));
    let remove_nonce = begin_remove(&mut model, &fixture);
    model
        .prove_drain_leases(&remove_nonce, 0, Timestamp::new(400))
        .unwrap_or_else(|_| panic!("zero leases should be provable"));
    let retired = model
        .complete(&remove_nonce, None, None, true, Timestamp::new(420))
        .unwrap_or_else(|_| panic!("removal should commit"));
    assert_eq!(retired.outcome(), ReceiptOutcome::Retired);
    assert_eq!(retired.protocol_version().get(), 1);
    assert_eq!(retired.operation(), Operation::Remove);
    assert_eq!(retired.slot(), fixture.slot(fixture.owner));
    assert!(
        model
            .slot_record(&fixture.slot(fixture.owner))
            .and_then(|record| record.state())
            .is_none()
    );

    let original = fixture.context(
        Operation::Install,
        ExpectedPackageState::Absent,
        plan_digest(20),
        (fixture.owner, fixture.caller),
        1,
        Nonce::from_bytes([1; 32]),
    );
    match model.replay(&original.nonce(), Some(*original.digest())) {
        Ok(ReplayOutcome::Receipt(receipt)) => {
            assert_eq!(receipt.outcome(), ReceiptOutcome::Installed)
        },
        _ => panic!("original receipt must remain replayable"),
    }
}

#[test]
fn cross_owner_nonce_use_is_isolated() {
    let fixture = Fixture::new();
    let mut model = PackageServiceModel::new(policy(8));
    let first = fixture.context(
        Operation::Install,
        ExpectedPackageState::Absent,
        plan_digest(20),
        (fixture.owner, fixture.caller),
        1,
        Nonce::from_bytes([9; 32]),
    );
    fixture
        .begin(&mut model, first, 100)
        .unwrap_or_else(|_| panic!("first owner admission should succeed"));
    let second = fixture.context(
        Operation::Install,
        ExpectedPackageState::Absent,
        plan_digest(20),
        (fixture.other_owner, fixture.caller),
        1,
        Nonce::from_bytes([9; 32]),
    );
    let error = fixture
        .begin(&mut model, second, 100)
        .err()
        .unwrap_or_else(|| panic!("cross-owner nonce must fail"));
    assert!(matches!(error, PackageServiceError::ReplayRejected));
    assert!(
        model
            .slot_record(&fixture.slot(fixture.other_owner))
            .is_none()
    );
}

#[test]
fn nonce_replay_after_later_commits_is_rejected_and_bound() {
    let fixture = Fixture::new();
    let mut model = PackageServiceModel::new(policy_short_retention(8, 128));
    install(&mut model, &fixture, 1);
    let update_nonce = begin_update(&mut model, &fixture);
    model
        .prove_drain_leases(&update_nonce, 0, Timestamp::new(200))
        .unwrap_or_else(|_| panic!("zero leases should be provable"));
    model
        .complete(
            &update_nonce,
            Some(&validated_artifact(13)),
            None,
            true,
            Timestamp::new(220),
        )
        .unwrap_or_else(|_| panic!("update should commit"));

    let collected = model
        .collect(Timestamp::new(900), 8)
        .unwrap_or_else(|_| panic!("eligible terminal records should collect"));
    assert_eq!(collected, 2);

    let original = fixture.context(
        Operation::Install,
        ExpectedPackageState::Absent,
        plan_digest(20),
        (fixture.owner, fixture.caller),
        1,
        Nonce::from_bytes([1; 32]),
    );
    let current_state = model
        .slot_record(&fixture.slot(fixture.owner))
        .and_then(|record| record.state().map(CanonicalInstalledState::digest))
        .unwrap_or_else(|| panic!("updated state should exist"));
    let replay_context = fixture.context(
        Operation::Update,
        ExpectedPackageState::Exact(current_state),
        plan_digest(22),
        (fixture.owner, fixture.caller),
        1,
        Nonce::from_bytes([1; 32]),
    );
    let replay_error = fixture
        .begin(&mut model, replay_context, 910)
        .err()
        .unwrap_or_else(|| panic!("collected nonce must not execute again"));
    assert!(
        matches!(replay_error, PackageServiceError::ReplayRejected),
        "unexpected replay error: {replay_error:?}"
    );
    match model.replay(&original.nonce(), Some(*original.digest())) {
        Ok(ReplayOutcome::Tombstoned(tombstone)) => {
            assert_eq!(tombstone.terminal_status(), JournalStatus::Committed);
            assert_eq!(tombstone.outcome(), Some(ReceiptOutcome::Installed));
            assert_eq!(tombstone.context_digest(), *original.digest());
        },
        _ => panic!("collected receipt must remain distinguishable from loss"),
    }

    let other_context = fixture.context(
        Operation::Install,
        ExpectedPackageState::Absent,
        plan_digest(21),
        (fixture.owner, fixture.caller),
        1,
        Nonce::from_bytes([1; 32]),
    );
    let error = model
        .replay(&other_context.nonce(), Some(*other_context.digest()))
        .err()
        .unwrap_or_else(|| panic!("tombstone must reject a different context"));
    assert!(matches!(error, PackageServiceError::ReplayRejected));
}

#[test]
fn stale_expected_state_is_rejected() {
    let fixture = Fixture::new();
    let mut model = PackageServiceModel::new(policy(8));
    install(&mut model, &fixture, 1);
    let stale = fixture.context(
        Operation::Update,
        ExpectedPackageState::Exact(StateDigest::from_bytes([99; 32])),
        plan_digest(21),
        (fixture.owner, fixture.caller),
        1,
        Nonce::from_bytes([2; 32]),
    );
    let error = fixture
        .begin(&mut model, stale, 130)
        .err()
        .unwrap_or_else(|| panic!("stale expectation must fail"));
    assert!(matches!(error, PackageServiceError::ExpectedStateMismatch));
}

#[test]
fn unresolved_records_never_expire() {
    let fixture = Fixture::new();
    let mut model = PackageServiceModel::new(policy(1));
    let context = fixture.context(
        Operation::Install,
        ExpectedPackageState::Absent,
        plan_digest(20),
        (fixture.owner, fixture.caller),
        1,
        Nonce::from_bytes([1; 32]),
    );
    let nonce = fixture
        .begin(&mut model, context, 100)
        .unwrap_or_else(|_| panic!("intent should be admitted"));
    let collected = model
        .collect(Timestamp::new(u64::MAX), 64)
        .unwrap_or_else(|_| panic!("collection should not fail"));
    assert_eq!(collected, 0);
    let record = model
        .slot_record(&fixture.slot(fixture.owner))
        .and_then(|record| record.journal_record(&nonce))
        .unwrap_or_else(|| panic!("record should remain"));
    assert_eq!(record.status(), JournalStatus::Intent);
}

#[test]
fn drain_expiry_blocks_and_abort_is_coherent() {
    let fixture = Fixture::new();
    let mut model = PackageServiceModel::new(policy(8));
    install(&mut model, &fixture, 1);
    let original = model
        .slot_record(&fixture.slot(fixture.owner))
        .and_then(|record| record.state().map(CanonicalInstalledState::digest))
        .unwrap_or_else(|| panic!("installed state should exist"));
    let nonce = begin_update(&mut model, &fixture);
    let blocked = model
        .expire_drain(&nonce, Timestamp::new(250), false)
        .unwrap_or_else(|_| panic!("expired drain should be observable"));
    assert_eq!(blocked, DrainResult::Blocked);
    assert!(matches!(
        model.slot_record(&fixture.slot(fixture.owner)).and_then(|record| record.state()),
        Some(state) if matches!(state.lifecycle_state(), LifecycleState::Draining { live_leases: 1, .. })
    ));

    let abort_fixture = Fixture::new();
    let mut abort_model = PackageServiceModel::new(policy(8));
    install(&mut abort_model, &abort_fixture, 1);
    let remove_nonce = begin_remove(&mut abort_model, &abort_fixture);
    abort_model
        .cancel(&remove_nonce, Timestamp::new(320))
        .unwrap_or_else(|_| panic!("pre-commit cancellation should succeed"));
    assert!(matches!(
        abort_model.slot_record(&abort_fixture.slot(abort_fixture.owner)).and_then(|record| record.state()),
        Some(state) if *state.lifecycle_state() == LifecycleState::Inactive
    ));
    assert_eq!(
        abort_model
            .slot_record(&abort_fixture.slot(abort_fixture.owner))
            .and_then(|record| record.state().map(CanonicalInstalledState::digest)),
        Some(original)
    );
}

#[test]
fn retired_receipt_keeps_absent_canonical_state() {
    let fixture = Fixture::new();
    let mut model = PackageServiceModel::new(policy(8));
    install(&mut model, &fixture, 1);
    let nonce = begin_remove(&mut model, &fixture);
    model
        .prove_drain_leases(&nonce, 0, Timestamp::new(400))
        .unwrap_or_else(|_| panic!("zero leases should be provable"));
    let receipt = model
        .complete(&nonce, None, None, true, Timestamp::new(420))
        .unwrap_or_else(|_| panic!("zero-lease removal should commit"));
    assert_eq!(receipt.outcome(), ReceiptOutcome::Retired);
    assert!(
        model
            .slot_record(&fixture.slot(fixture.owner))
            .and_then(|record| record.state())
            .is_none()
    );
}

#[test]
fn canonical_state_digests_are_deterministic_and_domain_separated() {
    let fixture = Fixture::new();
    let context = fixture.context(
        Operation::Install,
        ExpectedPackageState::Absent,
        plan_digest(20),
        (fixture.owner, fixture.caller),
        1,
        Nonce::from_bytes([1; 32]),
    );
    let authority_digest = fixture.authority(&context).decision_digest();
    let first = new_installed_state(
        &context,
        authority_digest,
        &validated_artifact(12),
        LifecycleState::Inactive,
    )
    .unwrap_or_else(|_| panic!("state should construct"));
    let second = new_installed_state(
        &context,
        authority_digest,
        &validated_artifact(12),
        LifecycleState::Inactive,
    )
    .unwrap_or_else(|_| panic!("state should construct"));
    assert_eq!(first.digest(), second.digest());
    let different_owner_context = fixture.context(
        Operation::Install,
        ExpectedPackageState::Absent,
        plan_digest(20),
        (fixture.other_owner, fixture.caller),
        1,
        Nonce::from_bytes([1; 32]),
    );
    let different = new_installed_state(
        &different_owner_context,
        fixture
            .authority(&different_owner_context)
            .decision_digest(),
        &validated_artifact(12),
        LifecycleState::Inactive,
    )
    .unwrap_or_else(|_| panic!("state should construct"));
    assert_ne!(first.digest(), different.digest());

    let mut writer = DigestWriter::new();
    writer.u64(1);
    let left: TypedDigest<100> = writer.finish("astrid.test.left");
    let right: TypedDigest<101> = writer.finish("astrid.test.right");
    assert_ne!(left.as_bytes(), right.as_bytes());
}

#[test]
fn quota_fails_closed_without_evicting_live_or_terminal_records() {
    let fixture = Fixture::new();
    let mut model = PackageServiceModel::new(policy(1));
    install(&mut model, &fixture, 1);
    let state = match model
        .slot_record(&fixture.slot(fixture.owner))
        .and_then(|record| record.state())
    {
        Some(state) => state.digest(),
        None => panic!("installed state should exist"),
    };
    let update = fixture.context(
        Operation::Update,
        ExpectedPackageState::Exact(state),
        plan_digest(21),
        (fixture.owner, fixture.caller),
        1,
        Nonce::from_bytes([2; 32]),
    );
    let error = fixture
        .begin(&mut model, update, 130)
        .err()
        .unwrap_or_else(|| panic!("full journal must fail closed"));
    assert!(matches!(error, PackageServiceError::QuotaExhausted));

    let unknown_fixture = Fixture::new();
    let mut unknown_model = PackageServiceModel::new(policy(1));
    let context = unknown_fixture.context(
        Operation::Install,
        ExpectedPackageState::Absent,
        plan_digest(20),
        (unknown_fixture.owner, unknown_fixture.caller),
        1,
        Nonce::from_bytes([1; 32]),
    );
    let nonce = unknown_fixture
        .begin(&mut unknown_model, context, 100)
        .unwrap_or_else(|_| panic!("unknown fixture should start"));
    unknown_model
        .begin_work(&nonce, Timestamp::new(110))
        .unwrap_or_else(|_| panic!("work should start"));
    unknown_model
        .mark_unknown(&nonce, Timestamp::new(120))
        .unwrap_or_else(|_| panic!("unknown should mark"));
    let collected = unknown_model
        .collect(Timestamp::new(u64::MAX), 64)
        .unwrap_or_else(|_| panic!("collection should not fail"));
    assert_eq!(collected, 0);
}

#[test]
fn quota_collection_is_atomic_when_tombstone_capacity_is_short() {
    let fixture = Fixture::new();
    let mut model = PackageServiceModel::new(policy_short_retention(8, 1));
    install(&mut model, &fixture, 1);
    let update_nonce = begin_update(&mut model, &fixture);
    model
        .prove_drain_leases(&update_nonce, 0, Timestamp::new(200))
        .unwrap_or_else(|_| panic!("zero leases should be provable"));
    model
        .complete(
            &update_nonce,
            Some(&validated_artifact(13)),
            None,
            true,
            Timestamp::new(220),
        )
        .unwrap_or_else(|_| panic!("update should commit"));
    let before = model.occupancy();

    let error = model
        .collect(Timestamp::new(900), 8)
        .err()
        .unwrap_or_else(|| panic!("short tombstone capacity must fail closed"));
    assert!(matches!(error, PackageServiceError::QuotaExhausted));
    assert_eq!(model.occupancy(), before);
    let slot_record = model
        .slot_record(&fixture.slot(fixture.owner))
        .unwrap_or_else(|| panic!("slot should remain intact"));
    assert!(
        slot_record
            .journal_record(&Nonce::from_bytes([1; 32]))
            .is_some()
    );
    assert!(
        slot_record
            .journal_record(&Nonce::from_bytes([2; 32]))
            .is_some()
    );
}

#[test]
fn activation_requires_exact_installed_state_and_produces_active_generation() {
    let fixture = Fixture::new();
    let mut model = PackageServiceModel::new(policy(8));
    install(&mut model, &fixture, 1);
    let state = match model
        .slot_record(&fixture.slot(fixture.owner))
        .and_then(|record| record.state())
    {
        Some(state) => state.digest(),
        None => panic!("installed state should exist"),
    };
    let context = fixture.context(
        Operation::Activate,
        ExpectedPackageState::Exact(state),
        plan_digest(30),
        (fixture.owner, fixture.caller),
        1,
        Nonce::from_bytes([4; 32]),
    );
    let nonce = fixture
        .begin(&mut model, context, 130)
        .unwrap_or_else(|_| panic!("activation should be admitted"));
    model
        .begin_work(&nonce, Timestamp::new(140))
        .unwrap_or_else(|_| panic!("activation should start"));
    let missing_receipt = model
        .complete(&nonce, None, None, true, Timestamp::new(145))
        .err()
        .unwrap_or_else(|| panic!("activation without runtime receipt must fail"));
    assert!(matches!(
        missing_receipt,
        PackageServiceError::BindingMismatch
    ));
    assert!(matches!(
        model.slot_record(&fixture.slot(fixture.owner)).and_then(|record| record.state()),
        Some(state) if *state.lifecycle_state() == LifecycleState::Inactive
    ));
    let receipt = model
        .complete(&nonce, None, Some(digest(31)), true, Timestamp::new(150))
        .unwrap_or_else(|_| panic!("activation should commit"));
    assert_eq!(receipt.outcome(), ReceiptOutcome::Activated);
    assert!(matches!(
        model.slot_record(&fixture.slot(fixture.owner)).and_then(|record| record.state()),
        Some(state) if *state.lifecycle_state() == LifecycleState::Active
    ));
}
