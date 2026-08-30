use crate::bytes::PrincipalUid;
use crate::digest::{
    Blake3Digest, BudgetDigest, ContextDigest, DigestWriter, PlanDigest, ProvenanceDigest,
};
use crate::error::{PackageServiceError, PackageServiceResult};
use crate::identity::{
    ArtifactIdentity, ComponentIdentity, ManifestIdentity, Nonce, PROTOCOL_VERSION, PackageObject,
    ProtocolVersion, ServiceGeneration,
};
use std::num::NonZeroU64;
use std::time::Duration as StdDuration;

/// Finite monotonic duration used by policy and leases.
pub type Duration = StdDuration;

/// Finite monotonic timestamp in seconds.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Timestamp(u64);

impl Timestamp {
    /// The beginning of the monotonic domain.
    pub const ZERO: Self = Self(0);

    /// Constructs a timestamp.
    #[must_use]
    pub const fn new(seconds: u64) -> Self {
        Self(seconds)
    }

    /// Returns the timestamp seconds.
    #[must_use]
    pub const fn get(&self) -> u64 {
        self.0
    }

    /// Adds finite seconds, refusing overflow.
    #[must_use]
    pub const fn checked_add(&self, seconds: u64) -> Option<Self> {
        match self.0.checked_add(seconds) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    /// Returns the elapsed whole seconds, refusing time inversion.
    #[must_use]
    pub const fn seconds_since(&self, earlier: Self) -> Option<u64> {
        self.0.checked_sub(earlier.0)
    }
}

/// Neutral operation class in the private contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    /// Create the absent owner/package slot.
    Install,
    /// Replace the exact prior owner/package state.
    Update,
    /// Publish the exact installed state to the runtime.
    Activate,
    /// Stop publication of the exact installed state.
    Deactivate,
    /// Drain and retire the exact installed state.
    Remove,
    /// Reconcile an existing operation record.
    Recover,
}

impl Operation {
    pub(crate) const fn tag(self) -> u8 {
        match self {
            Self::Install => 1,
            Self::Update => 2,
            Self::Activate => 3,
            Self::Deactivate => 4,
            Self::Remove => 5,
            Self::Recover => 6,
        }
    }
}

/// Authenticated ingress channel class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IngressChannel {
    /// Authenticated local IPC.
    AuthenticatedIpc,
    /// Authenticated hosted-service transport.
    HostedService,
    /// Authenticated system-generation transport.
    SystemGeneration,
}

impl IngressChannel {
    const fn tag(self) -> u8 {
        match self {
            Self::AuthenticatedIpc => 1,
            Self::HostedService => 2,
            Self::SystemGeneration => 3,
        }
    }
}

/// Identity stamped by authenticated transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticatedIngress {
    caller: PrincipalUid,
    channel: IngressChannel,
    evidence: Blake3Digest,
}

impl AuthenticatedIngress {
    /// Constructs ingress from trusted transport data.
    #[must_use]
    pub fn new(caller: PrincipalUid, channel: IngressChannel, evidence: Blake3Digest) -> Self {
        Self {
            caller,
            channel,
            evidence,
        }
    }

    /// Returns the stamped effective caller.
    #[must_use]
    pub const fn caller(&self) -> PrincipalUid {
        self.caller
    }

    pub(crate) const fn channel_tag(&self) -> u8 {
        self.channel.tag()
    }

    pub(crate) const fn evidence(&self) -> &Blake3Digest {
        &self.evidence
    }
}

/// Identity and evidence stamped by the admitted-service lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdmittedService {
    component: ComponentIdentity,
    generation: ServiceGeneration,
    evidence: Blake3Digest,
}

impl AdmittedService {
    /// Constructs service admission from trusted lifecycle data.
    #[must_use]
    pub const fn new(
        component: ComponentIdentity,
        generation: ServiceGeneration,
        evidence: Blake3Digest,
    ) -> Self {
        Self {
            component,
            generation,
            evidence,
        }
    }

    /// Returns the admitted component identity.
    #[must_use]
    pub const fn component(&self) -> &ComponentIdentity {
        &self.component
    }

    /// Returns the admitted immutable generation.
    #[must_use]
    pub const fn generation(&self) -> ServiceGeneration {
        self.generation
    }

    pub(crate) const fn evidence(&self) -> &Blake3Digest {
        &self.evidence
    }
}

/// Principal or authenticated policy approver identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApproverIdentity {
    /// An immutable authenticated principal.
    Principal(PrincipalUid),
    /// A digest naming an authenticated policy.
    Policy(Blake3Digest),
}

impl ApproverIdentity {
    pub(crate) fn write(self, writer: &mut DigestWriter) {
        match self {
            Self::Principal(uid) => {
                writer.tag(1);
                writer.bytes(uid.as_bytes());
            },
            Self::Policy(policy) => {
                writer.tag(2);
                writer.digest(&policy);
            },
        }
    }
}

/// Resource classes admitted by the kernel/resource authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceClasses {
    classes: [bool; 4],
}

impl ResourceClasses {
    /// Constructs admitted classes in canonical `ResourceClass` order.
    #[must_use]
    pub const fn new(classes: [bool; 4]) -> Self {
        Self { classes }
    }

    /// Returns whether a class is admitted.
    #[must_use]
    pub const fn contains(&self, class: ResourceClass) -> bool {
        match class {
            ResourceClass::ArtifactStorage => self.classes[0],
            ResourceClass::Lifecycle => self.classes[1],
            ResourceClass::Activation => self.classes[2],
            ResourceClass::Audit => self.classes[3],
        }
    }

    fn write(self, writer: &mut DigestWriter) {
        for admitted in self.classes {
            writer.bool(admitted);
        }
    }
}

/// Neutral resource class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceClass {
    /// Immutable artifact retention.
    ArtifactStorage,
    /// Journal and lifecycle execution.
    Lifecycle,
    /// Runtime activation work.
    Activation,
    /// Audit emission.
    Audit,
}

/// Canonical resource budget with its semantic digest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceBudget {
    reservation_bytes: NonZeroU64,
    classes: ResourceClasses,
    digest: BudgetDigest,
}

impl ResourceBudget {
    /// Computes the canonical budget and its domain-separated digest.
    #[must_use]
    pub fn new(reservation_bytes: NonZeroU64, classes: ResourceClasses) -> Self {
        let mut writer = DigestWriter::new();
        writer.u64(reservation_bytes.get());
        classes.write(&mut writer);
        let digest = writer.finish("astrid.package.budget.v1");
        Self {
            reservation_bytes,
            classes,
            digest,
        }
    }

    /// Returns the reserved byte count.
    #[must_use]
    pub const fn reservation_bytes(&self) -> u64 {
        self.reservation_bytes.get()
    }

    /// Returns the canonical budget digest.
    #[must_use]
    pub const fn digest(&self) -> &BudgetDigest {
        &self.digest
    }

    pub(crate) const fn classes(&self) -> &ResourceClasses {
        &self.classes
    }
}

/// Complete authority-bearing context for one mutating operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationContext {
    protocol_version: ProtocolVersion,
    nonce: Nonce,
    operation: Operation,
    expected_state: crate::state::ExpectedPackageState,
    effective_caller: PrincipalUid,
    approver: ApproverIdentity,
    target_owner: PrincipalUid,
    package_object: PackageObject,
    artifact: ArtifactIdentity,
    manifest: ManifestIdentity,
    content_root: Blake3Digest,
    provenance: ProvenanceDigest,
    plan_digest: PlanDigest,
    commit_plan_digest: PlanDigest,
    budget: ResourceBudget,
    service_component: ComponentIdentity,
    service_generation: ServiceGeneration,
    expiry: Timestamp,
    digest: ContextDigest,
}

/// Validated input needed to construct one canonical operation context.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationContextSpec {
    /// Global operation nonce.
    pub nonce: Nonce,
    /// Mutation class.
    pub operation: Operation,
    /// Exact current state accepted by the operation.
    pub expected_state: crate::state::ExpectedPackageState,
    /// Effective stamped caller.
    pub effective_caller: PrincipalUid,
    /// Authenticated approver or policy.
    pub approver: ApproverIdentity,
    /// Effective target owner.
    pub target_owner: PrincipalUid,
    /// Immutable owner-neutral package object.
    pub package_object: PackageObject,
    /// Exact-byte artifact identity.
    pub artifact: ArtifactIdentity,
    /// Exact manifest identity.
    pub manifest: ManifestIdentity,
    /// Exact content root admitted for replacement or retained-state work.
    pub content_root: Blake3Digest,
    /// Exact provenance digest admitted for replacement or retained-state work.
    pub provenance: ProvenanceDigest,
    /// Activation, replacement, or removal plan digest.
    pub plan_digest: PlanDigest,
    /// Exact staged-and-committed plan bound by authority.
    pub commit_plan_digest: PlanDigest,
    /// Canonical resource budget.
    pub budget: ResourceBudget,
    /// Authority-owned expiry.
    pub expiry: Timestamp,
}

impl OperationContext {
    /// Validates and binds a complete operation context.
    ///
    /// # Errors
    /// Returns typed binding, expiry, identity, resource, and expectation failures.
    pub fn new(
        spec: OperationContextSpec,
        service: &AdmittedService,
        now: Timestamp,
    ) -> PackageServiceResult<Self> {
        let OperationContextSpec {
            nonce,
            operation,
            expected_state,
            effective_caller,
            approver,
            target_owner,
            package_object,
            artifact,
            manifest,
            content_root,
            provenance,
            plan_digest,
            commit_plan_digest,
            budget,
            expiry,
        } = spec;
        if expiry <= now {
            return Err(PackageServiceError::AuthorityExpired);
        }
        if nonce.as_bytes() == &[0; 32]
            || package_object.as_bytes() == &[0; 32]
            || service.component.as_bytes() == &[0; 32]
            || plan_digest.as_bytes() == &[0; 32]
            || content_root.as_bytes() == &[0; 32]
            || provenance.as_bytes() == &[0; 32]
        {
            return Err(PackageServiceError::InvalidValue("operation identity"));
        }
        Self::validate_participants(&approver, &effective_caller, &target_owner)?;
        let expected_commit_plan = if matches!(operation, Operation::Install | Operation::Update) {
            operation_commit_plan_digest(
                operation,
                &artifact,
                &manifest,
                &content_root,
                &provenance,
                (operation == Operation::Update).then_some(plan_digest),
            )
        } else {
            plan_digest
        };
        let plan_kind_matches = matches!(operation, Operation::Install | Operation::Update)
            || commit_plan_digest == plan_digest;
        if commit_plan_digest != expected_commit_plan || !plan_kind_matches {
            return Err(PackageServiceError::BindingMismatch);
        }
        Self::validate_expectations_and_budget(operation, &expected_state, &budget)?;

        let digest = ContextDigestParts {
            nonce: &nonce,
            operation,
            expected_state: &expected_state,
            effective_caller: &effective_caller,
            approver: &approver,
            target_owner: &target_owner,
            package_object: &package_object,
            artifact: &artifact,
            manifest: &manifest,
            content_root: &content_root,
            provenance: &provenance,
            plan_digest: &plan_digest,
            commit_plan_digest: &commit_plan_digest,
            budget: &budget,
            service,
            expiry,
        }
        .digest();

        Ok(Self {
            protocol_version: PROTOCOL_VERSION,
            nonce,
            operation,
            expected_state,
            effective_caller,
            approver,
            target_owner,
            package_object,
            artifact,
            manifest,
            content_root,
            provenance,
            plan_digest,
            commit_plan_digest,
            budget,
            service_component: *service.component(),
            service_generation: service.generation(),
            expiry,
            digest,
        })
    }

    fn validate_expectations_and_budget(
        operation: Operation,
        expected_state: &crate::state::ExpectedPackageState,
        budget: &ResourceBudget,
    ) -> PackageServiceResult<()> {
        let expected_matches = match operation {
            Operation::Install => {
                matches!(expected_state, crate::state::ExpectedPackageState::Absent)
            },
            Operation::Update => {
                matches!(expected_state, crate::state::ExpectedPackageState::Exact(_))
            },
            _ => true,
        };
        if !expected_matches {
            return Err(PackageServiceError::ExpectedStateMismatch);
        }
        let storage_required = matches!(operation, Operation::Install | Operation::Update);
        if storage_required && !budget.classes().contains(ResourceClass::ArtifactStorage) {
            return Err(PackageServiceError::BindingMismatch);
        }
        if !budget.classes().contains(ResourceClass::Lifecycle)
            || (operation == Operation::Activate
                && !budget.classes().contains(ResourceClass::Activation))
        {
            return Err(PackageServiceError::BindingMismatch);
        }
        Ok(())
    }

    fn validate_participants(
        approver: &ApproverIdentity,
        effective_caller: &PrincipalUid,
        target_owner: &PrincipalUid,
    ) -> PackageServiceResult<()> {
        let zero_approver = matches!(
            approver,
            ApproverIdentity::Principal(uid) if uid.as_bytes() == &[0; 32]
        ) || matches!(
            approver,
            ApproverIdentity::Policy(policy) if policy.as_bytes() == &[0; 32]
        );
        if zero_approver {
            return Err(PackageServiceError::InvalidValue("approver"));
        }
        if effective_caller.as_bytes() == &[0; 32] || target_owner.as_bytes() == &[0; 32] {
            return Err(PackageServiceError::InvalidValue("principal"));
        }
        Ok(())
    }
}

struct ContextDigestParts<'a> {
    nonce: &'a Nonce,
    operation: Operation,
    expected_state: &'a crate::state::ExpectedPackageState,
    effective_caller: &'a PrincipalUid,
    approver: &'a ApproverIdentity,
    target_owner: &'a PrincipalUid,
    package_object: &'a PackageObject,
    artifact: &'a ArtifactIdentity,
    manifest: &'a ManifestIdentity,
    content_root: &'a Blake3Digest,
    provenance: &'a ProvenanceDigest,
    plan_digest: &'a PlanDigest,
    commit_plan_digest: &'a PlanDigest,
    budget: &'a ResourceBudget,
    service: &'a AdmittedService,
    expiry: Timestamp,
}

impl ContextDigestParts<'_> {
    fn digest(self) -> ContextDigest {
        let mut writer = DigestWriter::new();
        writer.u64(u64::from(PROTOCOL_VERSION.get()));
        writer.bytes(self.nonce.as_bytes());
        writer.tag(self.operation.tag());
        match self.expected_state {
            crate::state::ExpectedPackageState::Absent => writer.tag(0),
            crate::state::ExpectedPackageState::Exact(state_digest) => {
                writer.tag(1);
                writer.digest(state_digest);
            },
        }
        writer.bytes(self.effective_caller.as_bytes());
        self.approver.write(&mut writer);
        writer.bytes(self.target_owner.as_bytes());
        writer.bytes(self.package_object.as_bytes());
        writer.u64(u64::from(self.artifact.format_version()));
        writer.u64(self.artifact.size_bytes());
        writer.digest(self.artifact.sha256());
        writer.digest(self.artifact.blake3());
        writer.u64(u64::from(self.manifest.format_version()));
        writer.bytes(self.manifest.package_name().as_str().as_bytes());
        writer.bytes(self.manifest.package_version().as_str().as_bytes());
        writer.digest(self.manifest.manifest_digest());
        writer.digest(self.content_root);
        writer.digest(self.provenance);
        writer.digest(self.plan_digest);
        writer.digest(self.commit_plan_digest);
        writer.digest(self.budget.digest());
        writer.bytes(self.service.component.as_bytes());
        writer.u64(self.service.generation.get());
        writer.u64(self.expiry.get());
        writer.finish("astrid.package.operation-context.v1")
    }
}

impl OperationContext {
    /// Returns the canonical context digest covered by authority.
    #[must_use]
    pub const fn digest(&self) -> &ContextDigest {
        &self.digest
    }

    pub(crate) const fn budget_digest(&self) -> &crate::digest::BudgetDigest {
        self.budget.digest()
    }

    pub(crate) const fn reservation_bytes(&self) -> u64 {
        self.budget.reservation_bytes()
    }

    /// Returns the operation nonce.
    #[must_use]
    pub const fn nonce(&self) -> Nonce {
        self.nonce
    }

    /// Returns the operation class.
    #[must_use]
    pub const fn operation(&self) -> Operation {
        self.operation
    }

    /// Returns the expected canonical state.
    #[must_use]
    pub const fn expected_state(&self) -> &crate::state::ExpectedPackageState {
        &self.expected_state
    }

    /// Returns the exact artifact identity.
    #[must_use]
    pub const fn artifact(&self) -> &ArtifactIdentity {
        &self.artifact
    }

    /// Returns the exact manifest identity.
    #[must_use]
    pub const fn manifest(&self) -> &ManifestIdentity {
        &self.manifest
    }

    /// Returns the exact committed content root.
    #[must_use]
    pub const fn content_root(&self) -> &Blake3Digest {
        &self.content_root
    }

    /// Returns the exact committed provenance digest.
    #[must_use]
    pub const fn provenance(&self) -> &ProvenanceDigest {
        &self.provenance
    }

    /// Returns the activation or removal plan digest.
    #[must_use]
    pub const fn plan_digest(&self) -> &PlanDigest {
        &self.plan_digest
    }

    /// Returns the unified content and lifecycle plan admitted by authority.
    #[must_use]
    pub const fn commit_plan_digest(&self) -> &PlanDigest {
        &self.commit_plan_digest
    }

    /// Returns the expiry owned by the canonical context.
    #[must_use]
    pub const fn expiry(&self) -> Timestamp {
        self.expiry
    }

    pub(crate) const fn approver_identity(&self) -> &ApproverIdentity {
        &self.approver
    }

    pub(crate) const fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }

    pub(crate) const fn effective_caller(&self) -> PrincipalUid {
        self.effective_caller
    }

    pub(crate) const fn target_owner(&self) -> PrincipalUid {
        self.target_owner
    }

    pub(crate) const fn package_object(&self) -> PackageObject {
        self.package_object
    }

    pub(crate) const fn service_component(&self) -> &ComponentIdentity {
        &self.service_component
    }

    pub(crate) const fn service_generation(&self) -> ServiceGeneration {
        self.service_generation
    }
}

/// Derives the exact committed plan admitted by an Install or Update context.
#[must_use]
pub fn operation_commit_plan_digest(
    operation: Operation,
    artifact: &ArtifactIdentity,
    manifest: &ManifestIdentity,
    content_root: &Blake3Digest,
    provenance: &ProvenanceDigest,
    lifecycle_plan: Option<PlanDigest>,
) -> PlanDigest {
    let mut writer = DigestWriter::new();
    writer.u64(u64::from(artifact.format_version()));
    writer.u64(artifact.size_bytes());
    writer.digest(artifact.sha256());
    writer.digest(artifact.blake3());
    writer.u64(u64::from(manifest.format_version()));
    writer.bytes(manifest.package_name().as_str().as_bytes());
    writer.bytes(manifest.package_version().as_str().as_bytes());
    writer.digest(manifest.manifest_digest());
    writer.digest(content_root);
    writer.digest(provenance);
    writer.tag(operation.tag());
    if operation == Operation::Update
        && let Some(plan) = lifecycle_plan
    {
        writer.digest(&plan);
    }
    writer.finish("astrid.package.commit-plan.v1")
}
