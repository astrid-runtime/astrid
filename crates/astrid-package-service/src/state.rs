//! Canonical owner/package state and bounded drain lineage.

use crate::context::{ExpectedPackageState, Operation};
use crate::digest::{AuthorityDigest, DigestWriter, PlanDigest, ProvenanceDigest, StateDigest};
use crate::error::{PackageServiceError, PackageServiceResult};
use crate::identity::{Nonce, PROTOCOL_VERSION, PackageObject, ValidatedArtifact};
use astrid_resource_types::OwnerId;
use core::num::NonZeroU64;

/// Runtime publication state of exact installed content.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleState {
    /// Installed but not published.
    Inactive,
    /// Installed and published under an admitted service generation.
    Active,
}

/// One immutable canonical installed package state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InstalledStateSpec {
    /// Target owner.
    pub owner: OwnerId,
    /// Target package.
    pub package: PackageObject,
    /// Exact validated content.
    pub artifact: ValidatedArtifact,
    /// Canonical authority evidence.
    pub authority: AuthorityDigest,
    /// Runtime publication state.
    pub lifecycle: LifecycleState,
    /// Lifecycle plan that completed this state.
    pub plan: PlanDigest,
    /// Canonical state generation.
    pub generation: NonZeroU64,
    /// Terminal nonce.
    pub completing_nonce: Nonce,
}

/// One immutable canonical installed package state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CanonicalInstalledState {
    owner: OwnerId,
    package: PackageObject,
    artifact: ValidatedArtifact,
    authority: AuthorityDigest,
    lifecycle: LifecycleState,
    plan: PlanDigest,
    generation: NonZeroU64,
    completing_nonce: Nonce,
    digest: StateDigest,
}

impl CanonicalInstalledState {
    /// Validates and digests installed state.
    ///
    /// # Errors
    /// Returns [`PackageServiceError::ZeroValue`] for zero authority evidence.
    pub fn new(spec: InstalledStateSpec) -> PackageServiceResult<Self> {
        let InstalledStateSpec {
            owner,
            package,
            artifact,
            authority,
            lifecycle,
            plan,
            generation,
            completing_nonce,
        } = spec;
        if owner == OwnerId::System || !authority.is_present() || plan.as_bytes() == &[0; 32] {
            return Err(PackageServiceError::ZeroValue);
        }
        let mut value = Self {
            owner,
            package,
            artifact,
            authority,
            lifecycle,
            plan,
            generation,
            completing_nonce,
            digest: StateDigest::from_bytes([0; 32]),
        };
        let mut writer = DigestWriter::new();
        value.write(&mut writer);
        value.digest = writer.finish("astrid.package.state.v1");
        Ok(value)
    }

    fn write(&self, writer: &mut DigestWriter) {
        writer.u64(u64::from(PROTOCOL_VERSION));
        match self.owner {
            OwnerId::System => writer.bytes(&[0_u8; 36]),
            OwnerId::Principal(bytes) => {
                writer.tag(1);
                writer.bytes(&bytes);
            },
            OwnerId::Fleet(bytes) => {
                writer.tag(2);
                writer.bytes(&bytes);
            },
        }
        writer.bytes(self.package.as_bytes());
        writer.bytes(self.artifact.artifact().as_bytes());
        writer.bytes(self.artifact.manifest().as_bytes());
        writer.u64(self.artifact.artifact_size());
        writer.bytes(self.artifact.content_root());
        let provenance = self.artifact.provenance_digest();
        writer.digest(&provenance);
        writer.digest(&self.authority);
        writer.tag(match self.lifecycle {
            LifecycleState::Inactive => 1,
            LifecycleState::Active => 2,
        });
        writer.digest(&self.plan);
        writer.u64(self.generation.get());
        writer.bytes(self.completing_nonce.as_bytes());
    }

    /// Returns the exact canonical state digest.
    #[must_use]
    pub const fn digest(&self) -> StateDigest {
        self.digest
    }

    /// Returns the target owner.
    #[must_use]
    pub const fn owner(&self) -> OwnerId {
        self.owner
    }

    /// Returns the package object.
    #[must_use]
    pub const fn package(&self) -> &PackageObject {
        &self.package
    }

    /// Returns the exact staged artifact evidence.
    #[must_use]
    pub const fn artifact(&self) -> &ValidatedArtifact {
        &self.artifact
    }

    /// Returns the canonical installed-state provenance digest.
    #[must_use]
    pub fn provenance(&self) -> ProvenanceDigest {
        self.artifact.provenance_digest()
    }

    /// Returns the lifecycle state.
    #[must_use]
    pub const fn lifecycle(&self) -> LifecycleState {
        self.lifecycle
    }

    /// Returns the canonical state generation.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation.get()
    }

    /// Returns the terminal intent that created this state.
    #[must_use]
    pub const fn completing_nonce(&self) -> &Nonce {
        &self.completing_nonce
    }

    pub(crate) fn with_generation(&self, generation: NonZeroU64) -> PackageServiceResult<Self> {
        Self::new(InstalledStateSpec {
            owner: self.owner,
            package: self.package,
            artifact: self.artifact,
            authority: self.authority,
            lifecycle: self.lifecycle,
            plan: self.plan,
            generation,
            completing_nonce: self.completing_nonce,
        })
    }
}

/// Exact prior content and monotonic boundary retained during a drain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DrainLineage {
    base: CanonicalInstalledState,
    boundary: NonZeroU64,
    zero_lease_proofs: u32,
    destination: DrainDestination,
}

/// Destination selected by the authoritative drain plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DrainDestination {
    /// Restore or replace with context-bound content.
    Replacement,
    /// Restore on failure or retire on zero-lease success.
    Removal,
}

impl DrainLineage {
    pub(crate) fn new(
        base: &CanonicalInstalledState,
        boundary: NonZeroU64,
        destination: DrainDestination,
    ) -> Self {
        Self {
            base: *base,
            boundary,
            zero_lease_proofs: 0,
            destination,
        }
    }

    pub(crate) fn advance(&mut self) -> PackageServiceResult<()> {
        let raw = self
            .boundary
            .get()
            .checked_add(1)
            .ok_or(PackageServiceError::GenerationExhausted)?;
        self.boundary =
            NonZeroU64::try_from(raw).map_err(|_| PackageServiceError::GenerationExhausted)?;
        self.zero_lease_proofs = self.zero_lease_proofs.saturating_add(1);
        Ok(())
    }

    pub(crate) const fn base(&self) -> &CanonicalInstalledState {
        &self.base
    }

    pub(crate) const fn boundary(self) -> NonZeroU64 {
        self.boundary
    }
}

/// The single authoritative value for one owner/package slot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SlotRecord {
    current: Option<CanonicalInstalledState>,
    high_watermark: u64,
    drain: Option<DrainLineage>,
}

impl SlotRecord {
    /// Creates an absent slot with generation one reserved as the first boundary.
    #[must_use]
    pub fn absent() -> Self {
        Self {
            current: None,
            high_watermark: 0,
            drain: None,
        }
    }

    /// Creates a slot with canonical installed state.
    ///
    /// # Errors
    /// Returns state-validation failures without creating a slot.
    pub fn installed(state: CanonicalInstalledState) -> PackageServiceResult<Self> {
        let generation = state.generation_value();
        Ok(Self {
            current: Some(state),
            high_watermark: generation.get(),
            drain: None,
        })
    }

    /// Returns the current canonical state.
    #[must_use]
    pub const fn current(&self) -> Option<&CanonicalInstalledState> {
        self.current.as_ref()
    }

    /// Returns the durable generation high-watermark.
    #[must_use]
    pub const fn high_watermark(&self) -> u64 {
        self.high_watermark
    }

    /// Returns the next unused generation without mutating the slot.
    pub(crate) fn next_generation(&self) -> PackageServiceResult<NonZeroU64> {
        NonZeroU64::try_from(
            self.high_watermark
                .checked_add(1)
                .ok_or(PackageServiceError::GenerationExhausted)?,
        )
        .map_err(|_| PackageServiceError::GenerationExhausted)
    }

    pub(crate) fn set_state(&mut self, state: &CanonicalInstalledState) {
        self.current = Some(*state);
        if state.generation_value().get() > self.high_watermark {
            self.high_watermark = state.generation_value().get();
        }
        self.drain = None;
    }

    pub(crate) fn set_absent(&mut self, boundary: NonZeroU64) {
        self.current = None;
        self.high_watermark = boundary.get();
        self.drain = None;
    }

    pub(crate) fn begin_drain(
        &mut self,
        destination: DrainDestination,
    ) -> PackageServiceResult<DrainLineage> {
        if self.drain.is_some() {
            return Err(PackageServiceError::InvalidDrain);
        }
        let Some(current) = self.current else {
            return Err(PackageServiceError::InvalidTransition);
        };
        let lineage = DrainLineage::new(&current, current.generation_value(), destination);
        self.drain = Some(lineage);
        Ok(lineage)
    }

    pub(crate) fn drain_mut(&mut self) -> Option<&mut DrainLineage> {
        self.drain.as_mut()
    }

    pub(crate) fn drain(&self) -> Option<&DrainLineage> {
        self.drain.as_ref()
    }

    pub(crate) const fn draining(&self) -> bool {
        self.drain.is_some()
    }

    pub(crate) fn restore_boundary(&mut self) -> PackageServiceResult<NonZeroU64> {
        let Some(lineage) = self.drain else {
            return Err(PackageServiceError::InvalidDrain);
        };
        let boundary = lineage.boundary();
        self.current = Some(lineage.base().with_generation(boundary)?);
        self.high_watermark = boundary.get();
        self.drain = None;
        Ok(boundary)
    }

    pub(crate) fn matches_expected(&self, expected: &ExpectedPackageState) -> bool {
        let actual = self.current.as_ref().map_or_else(
            || ExpectedPackageState::Absent.digest(),
            CanonicalInstalledState::digest,
        );
        expected.digest().as_bytes() == actual.as_bytes()
    }
}

impl CanonicalInstalledState {
    pub(crate) const fn generation_value(self) -> NonZeroU64 {
        self.generation
    }
}

/// Immutable owner/package slot identity.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PackageSlot {
    owner: OwnerId,
    package: crate::identity::PackageObject,
}

impl PackageSlot {
    /// Creates the canonical owner/package key.
    #[must_use]
    pub const fn new(owner: OwnerId, package: crate::identity::PackageObject) -> Self {
        Self { owner, package }
    }

    /// Returns the owner half of the key.
    #[must_use]
    pub const fn owner(&self) -> OwnerId {
        self.owner
    }

    /// Returns the package half of the key.
    #[must_use]
    pub const fn package(&self) -> &crate::identity::PackageObject {
        &self.package
    }
}

/// Returns whether an operation may begin from a slot state.
pub(crate) fn valid_transition(operation: Operation, installed: bool) -> bool {
    match operation {
        Operation::Install => !installed,
        Operation::Update | Operation::Remove | Operation::Activate | Operation::Deactivate => {
            installed
        },
    }
}
