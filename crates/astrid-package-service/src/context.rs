//! Exact authority-bound operation contexts and lifecycle plans.

use crate::digest::{
    BudgetDigest, ContextDigest, DigestWriter, PlanDigest, RuntimeReceiptDigest, StateDigest,
};
use crate::error::{PackageServiceError, PackageServiceResult};
use crate::identity::{
    BudgetIdentity, Nonce, PROTOCOL_VERSION, PackageObject, ServiceIdentity, ValidatedArtifact,
};
use astrid_core::PrincipalUid;
use astrid_resource_types::{CanonicalEncode, OwnerId};
use core::num::NonZeroU64;

/// Closed private package lifecycle operation vocabulary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    /// Install a package into an absent owner/package slot.
    Install,
    /// Replace one installed package after a bounded drain.
    Update,
    /// Publish an installed package to its runtime.
    Activate,
    /// Stop runtime publication without changing installed content.
    Deactivate,
    /// Drain and retire installed content.
    Remove,
}

impl Operation {
    /// Returns the stable private discriminator.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Install => 1,
            Self::Update => 2,
            Self::Activate => 3,
            Self::Deactivate => 4,
            Self::Remove => 5,
        }
    }
}

/// Canonical absence or an exact installed-state requirement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExpectedPackageState {
    /// The owner/package slot has no authoritative installed state.
    Absent,
    /// The slot still has the exact canonical state.
    Exact(StateDigest),
}

impl ExpectedPackageState {
    /// Returns the canonical sentinel used for absence.
    #[must_use]
    pub const fn digest(&self) -> StateDigest {
        match self {
            Self::Absent => ABSENT_STATE_DIGEST,
            Self::Exact(digest) => *digest,
        }
    }
}

const ABSENT_STATE_DIGEST: StateDigest = StateDigest::from_bytes([0; 32]);

/// Authoritative lifecycle plan bound by an operation context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecyclePlan {
    /// Publish the exact installed state.
    Activate,
    /// Stop publication of the exact installed state.
    Deactivate,
    /// Drain before installing the context-bound replacement.
    ReplacementDrain {
        /// Last instant at which drain work or proof is valid.
        deadline: u64,
    },
    /// Drain before final retirement.
    RemovalDrain {
        /// Last instant at which drain work or proof is valid.
        deadline: u64,
    },
}

impl LifecyclePlan {
    /// Returns the authoritative drain deadline, if any.
    #[must_use]
    pub const fn drain_deadline(self) -> Option<u64> {
        match self {
            Self::Activate | Self::Deactivate => None,
            Self::ReplacementDrain { deadline } | Self::RemovalDrain { deadline } => Some(deadline),
        }
    }

    /// Derives the canonical plan digest.
    #[must_use]
    pub fn digest(self, operation: Operation, expected: ExpectedPackageState) -> PlanDigest {
        let mut writer = DigestWriter::new();
        writer.tag(operation.tag());
        writer.digest(&expected.digest());
        match self {
            Self::Activate => writer.tag(1),
            Self::Deactivate => writer.tag(2),
            Self::ReplacementDrain { deadline } => {
                writer.tag(3);
                writer.u64(deadline);
            },
            Self::RemovalDrain { deadline } => {
                writer.tag(4);
                writer.u64(deadline);
            },
        }
        writer.finish("astrid.package.plan.v1")
    }
}

/// Budget admitted by the accounting authority for one operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceBudget {
    identity: BudgetIdentity,
    maximum_artifact_bytes: NonZeroU64,
}

impl ResourceBudget {
    /// Binds a budget identity and positive artifact-byte ceiling.
    #[must_use]
    pub const fn new(identity: BudgetIdentity, maximum_artifact_bytes: NonZeroU64) -> Self {
        Self {
            identity,
            maximum_artifact_bytes,
        }
    }

    /// Returns the admitted budget identity.
    #[must_use]
    pub const fn identity(&self) -> &BudgetIdentity {
        &self.identity
    }

    /// Returns the positive artifact byte ceiling.
    #[must_use]
    pub const fn maximum_artifact_bytes(self) -> u64 {
        self.maximum_artifact_bytes.get()
    }

    fn digest(&self) -> BudgetDigest {
        let mut writer = DigestWriter::new();
        writer.bytes(self.identity.as_bytes());
        writer.u64(self.maximum_artifact_bytes.get());
        writer.finish("astrid.package.budget.v1")
    }
}

/// Complete immutable input authenticated by an authority decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationContextSpec {
    /// Authenticated caller.
    pub caller: PrincipalUid,
    /// Authenticated approver.
    pub approver: PrincipalUid,
    /// Target owner.
    pub target_owner: OwnerId,
    /// Admitted service identity.
    pub service: ServiceIdentity,
    /// Admitted service generation.
    pub service_generation: NonZeroU64,
    /// Requested operation.
    pub operation: Operation,
    /// Target package object.
    pub package: PackageObject,
    /// Exact validated content.
    pub artifact: ValidatedArtifact,
    /// Required current state.
    pub expected: ExpectedPackageState,
    /// Exact lifecycle plan.
    pub plan: LifecyclePlan,
    /// Admitted budget.
    pub budget: ResourceBudget,
    /// Exclusive expiry instant.
    pub expiry: u64,
    /// Unique operation nonce.
    pub nonce: Nonce,
    /// Exact runtime receipt admitted for a successful operation.
    pub runtime_receipt: RuntimeReceiptDigest,
    /// Exact runtime receipt admitted for zero-lease drain proof.
    pub drain_receipt: RuntimeReceiptDigest,
}

/// Complete immutable input authenticated by an authority decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationContext {
    caller: PrincipalUid,
    approver: PrincipalUid,
    target_owner: OwnerId,
    service: ServiceIdentity,
    service_generation: NonZeroU64,
    operation: Operation,
    package: PackageObject,
    artifact: ValidatedArtifact,
    expected: ExpectedPackageState,
    plan_digest: PlanDigest,
    plan: LifecyclePlan,
    budget: ResourceBudget,
    expiry: u64,
    nonce: Nonce,
    runtime_receipt: RuntimeReceiptDigest,
    drain_receipt: RuntimeReceiptDigest,
    digest: ContextDigest,
}

impl OperationContext {
    /// Constructs and canonically digests one exact context.
    ///
    /// # Errors
    /// Returns typed failures for the wrong protocol, zero identities, System
    /// ownership, or a plan digest that does not match the operation.
    pub fn new(spec: OperationContextSpec) -> PackageServiceResult<Self> {
        let OperationContextSpec {
            caller,
            approver,
            target_owner,
            service,
            service_generation,
            operation,
            package,
            artifact,
            expected,
            plan,
            budget,
            expiry,
            nonce,
            runtime_receipt,
            drain_receipt,
        } = spec;
        let target_owner_bytes = Self::owner_id_bytes(target_owner)?;
        if caller.as_bytes() == &[0; 32]
            || approver.as_bytes() == &[0; 32]
            || target_owner == OwnerId::System
        {
            return Err(PackageServiceError::ZeroValue);
        }
        let plan_digest = plan.digest(operation, expected);
        let mut value = Self {
            caller,
            approver,
            target_owner,
            service,
            service_generation,
            operation,
            package,
            artifact,
            expected,
            plan_digest,
            plan,
            budget,
            expiry,
            nonce,
            runtime_receipt,
            drain_receipt,
            digest: ContextDigest::from_bytes([0; 32]),
        };
        if !runtime_receipt.is_present() || !drain_receipt.is_present() {
            return Err(PackageServiceError::ZeroValue);
        }
        if matches!(expected, ExpectedPackageState::Exact(digest) if !digest.is_present()) {
            return Err(PackageServiceError::ZeroValue);
        }
        Self::validate_plan(operation, &plan)?;
        let mut writer = DigestWriter::new();
        value.write(&mut writer, &target_owner_bytes);
        value.digest = writer.finish("astrid.package.context.v1");
        Ok(value)
    }

    fn write(&self, writer: &mut DigestWriter, target_owner_bytes: &[u8; 36]) {
        writer.u64(u64::from(PROTOCOL_VERSION));
        writer.bytes(self.caller.as_bytes());
        writer.bytes(self.approver.as_bytes());
        writer.bytes(target_owner_bytes);
        writer.bytes(self.service.as_bytes());
        writer.u64(self.service_generation.get());
        writer.tag(self.operation.tag());
        writer.bytes(self.package.as_bytes());
        writer.bytes(self.artifact.artifact().as_bytes());
        writer.bytes(self.artifact.manifest().as_bytes());
        writer.u64(self.artifact.artifact_size());
        writer.bytes(self.artifact.content_root());
        writer.digest(&self.artifact.provenance_digest());
        writer.digest(&self.expected.digest());
        writer.digest(&self.plan_digest);
        writer.digest(&self.budget.digest());
        writer.u64(self.expiry);
        writer.bytes(self.nonce.as_bytes());
        writer.digest(&self.runtime_receipt);
        writer.digest(&self.drain_receipt);
    }

    fn validate_plan(operation: Operation, plan: &LifecyclePlan) -> PackageServiceResult<()> {
        let authorized = match operation {
            Operation::Install | Operation::Activate => matches!(plan, LifecyclePlan::Activate),
            Operation::Deactivate => matches!(plan, LifecyclePlan::Deactivate),
            Operation::Update => matches!(plan, LifecyclePlan::ReplacementDrain { .. }),
            Operation::Remove => matches!(plan, LifecyclePlan::RemovalDrain { .. }),
        };
        if authorized {
            Ok(())
        } else {
            Err(PackageServiceError::PlanConflict)
        }
    }

    fn owner_id_bytes(owner: OwnerId) -> PackageServiceResult<[u8; 36]> {
        // Output scratch for the canonical encoder, not a nonce, key, or IV:
        // `encode_canonical` overwrites every byte of an exactly sized buffer.
        let mut encoded: [u8; OwnerId::ENCODED_LEN] = core::array::from_fn(|_| 0);
        owner
            .encode_canonical(&mut encoded)
            .map_err(|_| PackageServiceError::ZeroValue)?;
        Ok(encoded)
    }

    /// Returns the canonical digest signed by authority.
    #[must_use]
    pub const fn digest(&self) -> &ContextDigest {
        &self.digest
    }

    /// Returns the authenticated caller.
    #[must_use]
    pub const fn caller(&self) -> &PrincipalUid {
        &self.caller
    }

    /// Returns the authenticated approver.
    #[must_use]
    pub const fn approver(&self) -> &PrincipalUid {
        &self.approver
    }

    /// Returns the target owner.
    #[must_use]
    pub const fn target_owner(&self) -> OwnerId {
        self.target_owner
    }

    /// Returns the admitted service identity.
    #[must_use]
    pub const fn service(&self) -> &ServiceIdentity {
        &self.service
    }

    /// Returns the admitted service generation.
    #[must_use]
    pub const fn service_generation(self) -> u64 {
        self.service_generation.get()
    }

    /// Returns the operation.
    #[must_use]
    pub const fn operation(self) -> Operation {
        self.operation
    }

    /// Returns the owner-neutral package object.
    #[must_use]
    pub const fn package(&self) -> &PackageObject {
        &self.package
    }

    /// Returns the exact validated artifact.
    #[must_use]
    pub const fn artifact(&self) -> &ValidatedArtifact {
        &self.artifact
    }

    /// Returns the expected state.
    #[must_use]
    pub const fn expected(&self) -> &ExpectedPackageState {
        &self.expected
    }

    /// Returns the lifecycle-plan digest.
    #[must_use]
    pub const fn plan_digest(&self) -> &PlanDigest {
        &self.plan_digest
    }

    /// Returns the exact lifecycle plan.
    #[must_use]
    pub const fn plan(&self) -> LifecyclePlan {
        self.plan
    }

    /// Returns the admitted budget.
    #[must_use]
    pub const fn budget(&self) -> &ResourceBudget {
        &self.budget
    }

    /// Returns the exclusive authority expiry instant.
    #[must_use]
    pub const fn expiry(self) -> u64 {
        self.expiry
    }

    /// Returns the at-most-once operation nonce.
    #[must_use]
    pub const fn nonce(&self) -> &Nonce {
        &self.nonce
    }

    /// Returns the exact runtime receipt required by a successful commit.
    #[must_use]
    pub const fn runtime_receipt(&self) -> &RuntimeReceiptDigest {
        &self.runtime_receipt
    }

    /// Returns the exact runtime receipt required by every drain proof.
    #[must_use]
    pub const fn drain_receipt(&self) -> &RuntimeReceiptDigest {
        &self.drain_receipt
    }
}
