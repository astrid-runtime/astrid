use crate::bytes::PrincipalUid;
use crate::context::Operation;
use crate::context::Timestamp;
use crate::digest::{
    AuthorityDecisionDigest, Blake3Digest, DigestWriter, PlanDigest, ProvenanceDigest, StateDigest,
};
use crate::error::{PackageServiceError, PackageServiceResult};
use crate::identity::{
    ArtifactIdentity, ManifestIdentity, Nonce, PackageObject, STATE_SCHEMA_VERSION,
    StateSchemaVersion,
};
use std::num::NonZeroU64;

/// Canonical absence or exact canonical installed-state digest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExpectedPackageState {
    /// No authoritative installed state exists.
    Absent,
    /// The exact canonical digest must remain visible.
    Exact(StateDigest),
}

impl ExpectedPackageState {
    /// Returns the digest used for stale-state checks; absent is a fixed zero digest.
    #[must_use]
    pub const fn digest(&self) -> StateDigest {
        match self {
            Self::Absent => StateDigest::from_bytes([0; 32]),
            Self::Exact(digest) => *digest,
        }
    }

    pub(crate) fn matches_digest(&self, actual: StateDigest) -> bool {
        matches!(self, Self::Exact(expected) if expected.as_bytes() == actual.as_bytes())
            || matches!(self, Self::Absent if actual.as_bytes() == &[0; 32])
    }

    /// Derives the state-bound plan digest for a canonical lifecycle action.
    pub fn lifecycle_plan_digest(&self, operation: Operation) -> PackageServiceResult<PlanDigest> {
        let Self::Exact(state_digest) = self else {
            return Err(PackageServiceError::ExpectedStateMismatch);
        };
        if !matches!(
            operation,
            Operation::Activate | Operation::Deactivate | Operation::Remove
        ) {
            return Err(PackageServiceError::LifecycleTransition);
        }
        let mut writer = DigestWriter::new();
        writer.tag(match operation {
            Operation::Activate => 1,
            Operation::Deactivate => 2,
            Operation::Remove => 3,
            _ => 0,
        });
        writer.digest(state_digest);
        Ok(writer.finish("astrid.package.lifecycle-plan.v1"))
    }
}

/// Immutable owner/package slot identity.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PackageSlot {
    owner: PrincipalUid,
    package_object: PackageObject,
}

impl PackageSlot {
    /// Creates an owner-scoped slot.
    #[must_use]
    pub const fn new(owner: PrincipalUid, package_object: PackageObject) -> Self {
        Self {
            owner,
            package_object,
        }
    }

    /// Returns the immutable owner.
    #[must_use]
    pub const fn owner(&self) -> PrincipalUid {
        self.owner
    }

    /// Returns the immutable package object.
    #[must_use]
    pub const fn package_object(&self) -> PackageObject {
        self.package_object
    }
}

/// Drain destination recorded while old leases disappear.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DrainDestination {
    /// Drain before a replacement commit.
    Replacement,
    /// Drain before final removal.
    Removal,
}

/// Canonical lifecycle state, including bounded drain details.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleState {
    /// No active runtime generation.
    Inactive,
    /// Canonical state and runtime generation agree.
    Active,
    /// A bounded drain is durable and activation is refused.
    Draining {
        /// The recorded destination.
        destination: DrainDestination,
        /// The bounded drain deadline.
        deadline: Timestamp,
        /// The operation nonce that owns the drain.
        nonce: Nonce,
        /// The exact number of live leases still draining.
        live_leases: u32,
    },
}

impl LifecycleState {
    const fn tag(&self) -> u8 {
        match self {
            Self::Inactive => 1,
            Self::Active => 2,
            Self::Draining { .. } => 3,
        }
    }

    fn write(&self, writer: &mut DigestWriter) {
        writer.tag(self.tag());
        if let Self::Draining {
            destination,
            deadline,
            nonce,
            live_leases,
        } = self
        {
            writer.tag(match destination {
                DrainDestination::Replacement => 1,
                DrainDestination::Removal => 2,
            });
            writer.u64(deadline.get());
            writer.bytes(nonce.as_bytes());
            writer.u64(u64::from(*live_leases));
        }
    }
}

/// The single authoritative installed-state object for one owner/package slot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalInstalledState {
    schema_version: StateSchemaVersion,
    owner: PrincipalUid,
    package_object: PackageObject,
    artifact: ArtifactIdentity,
    content_root: Blake3Digest,
    manifest: ManifestIdentity,
    authority_digest: AuthorityDecisionDigest,
    provenance: ProvenanceDigest,
    lifecycle_state: LifecycleState,
    lifecycle_plan: PlanDigest,
    generation: NonZeroU64,
    completing_nonce: Nonce,
    digest: StateDigest,
}

/// The immutable prior content and authoritative boundary of an active drain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DrainLineage {
    base_state: CanonicalInstalledState,
    boundary_generation: NonZeroU64,
}

impl DrainLineage {
    pub(crate) fn new(
        base_state: CanonicalInstalledState,
        boundary_generation: NonZeroU64,
    ) -> PackageServiceResult<Self> {
        if !base_state.has_valid_digest()
            || matches!(
                base_state.lifecycle_state(),
                LifecycleState::Draining { .. }
            )
            || boundary_generation.get() <= base_state.generation_value().get()
        {
            return Err(PackageServiceError::InvalidValue("drain lineage"));
        }
        Ok(Self {
            base_state,
            boundary_generation,
        })
    }

    pub(crate) fn advanced(&self) -> PackageServiceResult<Self> {
        let generation = self
            .boundary_generation
            .get()
            .checked_add(1)
            .ok_or(PackageServiceError::GenerationOverflow)?;
        let generation = NonZeroU64::try_from(generation).map_err(PackageServiceError::from)?;
        Ok(Self {
            base_state: self.base_state.clone(),
            boundary_generation: generation,
        })
    }

    pub(crate) const fn base_state(&self) -> &CanonicalInstalledState {
        &self.base_state
    }

    pub(crate) const fn boundary_generation(&self) -> NonZeroU64 {
        self.boundary_generation
    }
}

impl CanonicalInstalledState {
    /// Constructs, validates, and digests a canonical installed state.
    pub fn new(spec: InstalledStateSpec) -> PackageServiceResult<Self> {
        let InstalledStateSpec {
            owner,
            package_object,
            artifact,
            content_root,
            manifest,
            authority_digest,
            provenance,
            lifecycle_state,
            lifecycle_plan,
            generation,
            completing_nonce,
        } = spec;
        if authority_digest.as_bytes() == &[0; 32]
            || provenance.as_bytes() == &[0; 32]
            || content_root.as_bytes() == &[0; 32]
        {
            return Err(PackageServiceError::InvalidValue("installed-state digest"));
        }
        let mut value = Self {
            schema_version: STATE_SCHEMA_VERSION,
            owner,
            package_object,
            artifact,
            content_root,
            manifest,
            authority_digest,
            provenance,
            lifecycle_state,
            lifecycle_plan,
            generation,
            completing_nonce,
            digest: StateDigest::from_bytes([0; 32]),
        };
        let mut writer = DigestWriter::new();
        value.write(&mut writer);
        value.digest = writer.finish("astrid.package.installed-state.v1");
        Ok(value)
    }

    fn write(&self, writer: &mut DigestWriter) {
        writer.u64(u64::from(self.schema_version.get()));
        writer.bytes(self.owner.as_bytes());
        writer.bytes(self.package_object.as_bytes());
        writer.u64(u64::from(self.artifact.format_version()));
        writer.u64(self.artifact.size_bytes());
        writer.digest(self.artifact.sha256());
        writer.digest(self.artifact.blake3());
        writer.digest(&self.content_root);
        writer.u64(u64::from(self.manifest.format_version()));
        writer.bytes(self.manifest.package_name().as_str().as_bytes());
        writer.bytes(self.manifest.package_version().as_str().as_bytes());
        writer.digest(self.manifest.manifest_digest());
        writer.digest(&self.authority_digest);
        writer.digest(&self.provenance);
        self.lifecycle_state.write(writer);
        writer.digest(&self.lifecycle_plan);
        writer.u64(self.generation.get());
        writer.bytes(self.completing_nonce.as_bytes());
    }

    /// Returns the canonical state digest.
    #[must_use]
    pub const fn digest(&self) -> StateDigest {
        self.digest
    }

    /// Returns the owner/package identity.
    #[must_use]
    pub const fn slot(&self) -> PackageSlot {
        PackageSlot::new(self.owner, self.package_object)
    }

    /// Returns the lifecycle state.
    #[must_use]
    pub const fn lifecycle_state(&self) -> &LifecycleState {
        &self.lifecycle_state
    }

    /// Returns the canonical state generation.
    #[must_use]
    pub const fn generation_value(&self) -> NonZeroU64 {
        self.generation
    }

    /// Returns the exact-byte artifact identity.
    #[must_use]
    pub const fn artifact(&self) -> &ArtifactIdentity {
        &self.artifact
    }

    /// Returns the immutable content root.
    #[must_use]
    pub const fn content_root(&self) -> &Blake3Digest {
        &self.content_root
    }

    /// Returns the exact manifest identity.
    #[must_use]
    pub const fn manifest(&self) -> &ManifestIdentity {
        &self.manifest
    }

    /// Returns the lifecycle plan bound by the completing operation.
    #[must_use]
    pub const fn lifecycle_plan(&self) -> &PlanDigest {
        &self.lifecycle_plan
    }

    /// Returns the nonce that completed this canonical state.
    #[must_use]
    pub const fn completing_nonce(&self) -> Nonce {
        self.completing_nonce
    }

    /// Returns the canonical state schema version.
    #[must_use]
    pub(crate) const fn schema_version(&self) -> StateSchemaVersion {
        self.schema_version
    }

    /// Returns the canonical authenticated-authority decision digest.
    #[must_use]
    pub const fn authority_digest(&self) -> &AuthorityDecisionDigest {
        &self.authority_digest
    }

    /// Returns the attribution evidence digest retained with canonical state.
    #[must_use]
    pub const fn provenance(&self) -> &ProvenanceDigest {
        &self.provenance
    }

    /// Returns whether the retained digest covers the retained canonical fields.
    pub(crate) fn has_valid_digest(&self) -> bool {
        let mut writer = DigestWriter::new();
        self.write(&mut writer);
        let candidate: StateDigest = writer.finish("astrid.package.installed-state.v1");
        candidate == self.digest
    }

    pub(crate) fn set_lifecycle_result(
        &mut self,
        lifecycle_state: LifecycleState,
        plan: PlanDigest,
        generation: NonZeroU64,
        completing_nonce: Nonce,
    ) {
        self.lifecycle_state = lifecycle_state;
        self.lifecycle_plan = plan;
        self.generation = generation;
        self.completing_nonce = completing_nonce;
        self.redigest();
    }

    pub(crate) fn redigest(&mut self) {
        let mut writer = DigestWriter::new();
        self.write(&mut writer);
        self.digest = writer.finish("astrid.package.installed-state.v1");
    }
}

/// Input for one canonical installed-state value before digesting.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstalledStateSpec {
    /// Immutable owner UID.
    pub owner: PrincipalUid,
    /// Immutable package object identity.
    pub package_object: PackageObject,
    /// Exact-byte artifact identity.
    pub artifact: ArtifactIdentity,
    /// Immutable content root.
    pub content_root: Blake3Digest,
    /// Exact manifest identity.
    pub manifest: ManifestIdentity,
    /// Canonical authenticated-authority decision digest.
    pub authority_digest: AuthorityDecisionDigest,
    /// Attribution evidence digest.
    pub provenance: ProvenanceDigest,
    /// Canonical lifecycle state.
    pub lifecycle_state: LifecycleState,
    /// Lifecycle plan digest.
    pub lifecycle_plan: PlanDigest,
    /// Canonical generation.
    pub generation: NonZeroU64,
    /// Completing operation nonce.
    pub completing_nonce: Nonce,
}
