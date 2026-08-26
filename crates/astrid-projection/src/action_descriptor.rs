//! Private, non-authoritative action eligibility descriptors.
//!
//! [`ActionDescriptor`] binds a [`SemanticObjectId`], opaque action digest,
//! projection revision, scope, principal, generation, and expiry. It is an
//! observation contract only: it has no handle, lease, issuer, refresh
//! operation, or path to a live invocation. A caller must supply the current
//! object-bound observation context to [`ActionDescriptor::eligibility`];
//! presentation labels and metadata are deliberately absent from that context.

use core::fmt;
use core::num::NonZeroU64;

use crate::encoding::{
    DescriptorDecode, DescriptorEncode, ProjectionTypeTag, check_header, write_header,
};
use crate::error::ProjectionError;
use crate::object::SemanticObjectId;
use crate::revision::ProjectionRevision;
use crate::snapshot::ProjectionSnapshot;

/// Width of an opaque action binding value.
pub const ACTION_BINDING_BYTES: usize = 32;

/// Exact version-one encoded size of an [`ActionDescriptor`].
pub const ACTION_DESCRIPTOR_ENCODED_LEN: usize = 164;

macro_rules! opaque_binding {
    ($(#[$meta:meta])* $name:ident, $debug:literal) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; ACTION_BINDING_BYTES]);

        impl $name {
            /// Construct the binding from its exact opaque bytes.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; ACTION_BINDING_BYTES]) -> Self {
                Self(bytes)
            }

            /// Borrow the exact opaque bytes without interpreting them.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; ACTION_BINDING_BYTES] {
                &self.0
            }
        }

        impl From<[u8; ACTION_BINDING_BYTES]> for $name {
            fn from(bytes: [u8; ACTION_BINDING_BYTES]) -> Self {
                Self::from_bytes(bytes)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                let _ = self;
                formatter.write_str($debug)
            }
        }
    };
}

opaque_binding!(
    /// Opaque digest of the action arguments and target.
    ActionDigest,
    "ActionDigest"
);

opaque_binding!(
    /// Opaque scope binding for one action observation domain.
    ActionScope,
    "ActionScope"
);

opaque_binding!(
    /// Opaque principal binding. It is descriptive identity, not authority.
    ActionPrincipal,
    "ActionPrincipal"
);

/// Non-zero incarnation generation bound into an action descriptor.
///
/// This is a projection-local generation domain. It must not be confused with
/// an authority table generation, provider generation, or lifecycle counter.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ActionGeneration(NonZeroU64);

impl ActionGeneration {
    /// First valid generation.
    pub const INITIAL: Self = Self(NonZeroU64::MIN);

    /// Construct a non-zero generation.
    #[must_use]
    pub const fn from_raw(raw: u64) -> Option<Self> {
        match NonZeroU64::new(raw) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    /// Return the raw generation value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    /// Return the next generation without wrapping.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectionError::ExhaustedRevision`] at `u64::MAX` so this
    /// private domain has the same no-wrap invariant as projection revisions.
    pub fn checked_next(self) -> Result<Self, ProjectionError> {
        self.get()
            .checked_add(1)
            .and_then(Self::from_raw)
            .ok_or(ProjectionError::ExhaustedRevision)
    }
}

impl fmt::Debug for ActionGeneration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = self;
        formatter.write_str("ActionGeneration")
    }
}

/// Observation time used when checking descriptor expiry.
///
/// The projection crate does not read a clock. A host supplies this value as
/// part of an observation context, so tests and consumers remain deterministic.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ActionExpiry(u64);

impl ActionExpiry {
    /// Construct an expiry at the supplied monotonic observation tick.
    #[must_use]
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    /// Return the raw expiry tick.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Whether an observation at `now` is at or after expiry.
    #[must_use]
    pub const fn is_expired_at(self, now: u64) -> bool {
        now >= self.0
    }
}

impl From<u64> for ActionExpiry {
    fn from(raw: u64) -> Self {
        Self::from_raw(raw)
    }
}

impl fmt::Debug for ActionExpiry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = self;
        formatter.write_str("ActionExpiry")
    }
}

/// Current context supplied by a non-authoritative consumer.
///
/// Every field is required. There is no default context and no method that
/// derives one from presentation text, so omission or substitution fails
/// closed at the descriptor boundary.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ActionObservation {
    object: SemanticObjectId,
    digest: ActionDigest,
    revision: ProjectionRevision,
    scope: ActionScope,
    generation: ActionGeneration,
    principal: ActionPrincipal,
    now: u64,
}

impl ActionObservation {
    /// Bind an observation to one semantic object and all descriptor-controlled
    /// identity facts.
    #[must_use]
    pub const fn new(
        object: SemanticObjectId,
        digest: ActionDigest,
        revision: ProjectionRevision,
        scope: ActionScope,
        generation: ActionGeneration,
        principal: ActionPrincipal,
        now: u64,
    ) -> Self {
        Self {
            object,
            digest,
            revision,
            scope,
            generation,
            principal,
            now,
        }
    }

    /// Alternate constructor with principal first for call sites that resolve
    /// caller identity before the projected action fields.
    #[must_use]
    pub const fn for_principal(
        principal: ActionPrincipal,
        object: SemanticObjectId,
        digest: ActionDigest,
        revision: ProjectionRevision,
        scope: ActionScope,
        generation: ActionGeneration,
        now: u64,
    ) -> Self {
        Self::new(object, digest, revision, scope, generation, principal, now)
    }

    /// Bind an observation directly to a typed projection snapshot.
    #[must_use]
    pub const fn for_snapshot(
        snapshot: ProjectionSnapshot,
        digest: ActionDigest,
        scope: ActionScope,
        generation: ActionGeneration,
        principal: ActionPrincipal,
        now: u64,
    ) -> Self {
        Self::new(
            snapshot.object(),
            digest,
            snapshot.revision(),
            scope,
            generation,
            principal,
            now,
        )
    }

    /// Semantic object observed at this projection boundary.
    #[must_use]
    pub const fn object(self) -> SemanticObjectId {
        self.object
    }

    /// Digest observed for the action arguments and target.
    #[must_use]
    pub const fn digest(self) -> ActionDigest {
        self.digest
    }

    /// Projection revision observed by the consumer.
    #[must_use]
    pub const fn revision(self) -> ProjectionRevision {
        self.revision
    }

    /// Scope observed by the consumer.
    #[must_use]
    pub const fn scope(self) -> ActionScope {
        self.scope
    }

    /// Incarnation generation observed by the consumer.
    #[must_use]
    pub const fn generation(self) -> ActionGeneration {
        self.generation
    }

    /// Principal observed on the current invocation boundary.
    #[must_use]
    pub const fn principal(self) -> ActionPrincipal {
        self.principal
    }

    /// Monotonic observation tick supplied by the host.
    #[must_use]
    pub const fn now(self) -> u64 {
        self.now
    }
}

impl fmt::Debug for ActionObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = self;
        formatter.write_str("ActionObservation")
    }
}

/// Publicly inspectable, read-only facts carried by an action descriptor.
///
/// This is a value snapshot, not a minting request. Its fields remain private
/// and it has no constructor, refresh, or conversion into a live invocation.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ActionDescriptorFacts {
    object: SemanticObjectId,
    digest: ActionDigest,
    revision: ProjectionRevision,
    scope: ActionScope,
    generation: ActionGeneration,
    expiry: ActionExpiry,
    principal: ActionPrincipal,
}

impl ActionDescriptorFacts {
    /// Semantic object bound into this descriptor.
    #[must_use]
    pub const fn object(self) -> SemanticObjectId {
        self.object
    }

    /// Opaque action digest.
    #[must_use]
    pub const fn digest(self) -> ActionDigest {
        self.digest
    }

    /// Bound projection revision.
    #[must_use]
    pub const fn revision(self) -> ProjectionRevision {
        self.revision
    }

    /// Bound scope.
    #[must_use]
    pub const fn scope(self) -> ActionScope {
        self.scope
    }

    /// Bound incarnation generation.
    #[must_use]
    pub const fn generation(self) -> ActionGeneration {
        self.generation
    }

    /// Bound expiry tick.
    #[must_use]
    pub const fn expiry(self) -> ActionExpiry {
        self.expiry
    }

    /// Bound principal identity.
    #[must_use]
    pub const fn principal(self) -> ActionPrincipal {
        self.principal
    }
}

impl fmt::Debug for ActionDescriptorFacts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = self;
        formatter.write_str("ActionDescriptorFacts")
    }
}

/// Result of comparing a descriptor with a current observation context.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActionEligibility {
    /// Every descriptor binding matched and the observation precedes expiry.
    Eligible = 1,
    /// The caller principal differs from the descriptor principal.
    CrossPrincipal = 2,
    /// The opaque action digest differs.
    DigestMismatch = 3,
    /// The projection revision differs.
    StaleRevision = 4,
    /// The scope differs.
    ScopeMismatch = 5,
    /// The incarnation generation differs.
    GenerationDrift = 6,
    /// The observation is at or after expiry.
    Expired = 7,
    /// The semantic object differs.
    ObjectMismatch = 8,
}

/// Immutable, non-authoritative action description.
///
/// The descriptor contains no capability, handle, lease, issuer, or mutable
/// state. Cloning or decoding it only repeats an observation; eligibility is
/// recomputed against the caller-supplied context every time.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ActionDescriptor {
    object: SemanticObjectId,
    digest: ActionDigest,
    revision: ProjectionRevision,
    scope: ActionScope,
    generation: ActionGeneration,
    expiry: ActionExpiry,
    principal: ActionPrincipal,
}

impl fmt::Debug for ActionDescriptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = self;
        formatter.write_str("ActionDescriptor")
    }
}

impl ActionDescriptor {
    /// Bind an action digest to one semantic object, projection revision,
    /// scope, generation, expiry, and principal.
    #[must_use]
    pub const fn new(
        object: SemanticObjectId,
        digest: ActionDigest,
        revision: ProjectionRevision,
        scope: ActionScope,
        generation: ActionGeneration,
        expiry: ActionExpiry,
        principal: ActionPrincipal,
    ) -> Self {
        Self {
            object,
            digest,
            revision,
            scope,
            generation,
            expiry,
            principal,
        }
    }

    /// Bind a descriptor with principal-first argument order.
    #[must_use]
    pub const fn for_principal(
        principal: ActionPrincipal,
        object: SemanticObjectId,
        digest: ActionDigest,
        revision: ProjectionRevision,
        scope: ActionScope,
        generation: ActionGeneration,
        expiry: ActionExpiry,
    ) -> Self {
        Self::new(
            object, digest, revision, scope, generation, expiry, principal,
        )
    }

    /// Bind a descriptor directly to a typed projection snapshot.
    #[must_use]
    pub const fn for_snapshot(
        snapshot: ProjectionSnapshot,
        digest: ActionDigest,
        scope: ActionScope,
        generation: ActionGeneration,
        expiry: ActionExpiry,
        principal: ActionPrincipal,
    ) -> Self {
        Self::new(
            snapshot.object(),
            digest,
            snapshot.revision(),
            scope,
            generation,
            expiry,
            principal,
        )
    }

    /// Semantic object bound into this descriptor.
    #[must_use]
    pub const fn object(self) -> SemanticObjectId {
        self.object
    }

    /// Opaque action digest bound into this descriptor.
    #[must_use]
    pub const fn digest(self) -> ActionDigest {
        self.digest
    }

    /// Projection revision bound into this descriptor.
    #[must_use]
    pub const fn revision(self) -> ProjectionRevision {
        self.revision
    }

    /// Scope bound into this descriptor.
    #[must_use]
    pub const fn scope(self) -> ActionScope {
        self.scope
    }

    /// Incarnation generation bound into this descriptor.
    #[must_use]
    pub const fn generation(self) -> ActionGeneration {
        self.generation
    }

    /// Expiry tick bound into this descriptor.
    #[must_use]
    pub const fn expiry(self) -> ActionExpiry {
        self.expiry
    }

    /// Principal identity bound into this descriptor.
    #[must_use]
    pub const fn principal(self) -> ActionPrincipal {
        self.principal
    }

    /// Return a read-only copy of every descriptor fact.
    #[must_use]
    pub const fn facts(self) -> ActionDescriptorFacts {
        ActionDescriptorFacts {
            object: self.object,
            digest: self.digest,
            revision: self.revision,
            scope: self.scope,
            generation: self.generation,
            expiry: self.expiry,
            principal: self.principal,
        }
    }

    /// Compare this descriptor with one current observation context.
    #[must_use]
    pub fn eligibility(&self, observation: &ActionObservation) -> ActionEligibility {
        if self.principal != observation.principal {
            return ActionEligibility::CrossPrincipal;
        }
        if self.object != observation.object {
            return ActionEligibility::ObjectMismatch;
        }
        if self.digest != observation.digest {
            return ActionEligibility::DigestMismatch;
        }
        if self.revision != observation.revision {
            return ActionEligibility::StaleRevision;
        }
        if self.scope != observation.scope {
            return ActionEligibility::ScopeMismatch;
        }
        if self.generation != observation.generation {
            return ActionEligibility::GenerationDrift;
        }
        if self.expiry.is_expired_at(observation.now) {
            return ActionEligibility::Expired;
        }
        ActionEligibility::Eligible
    }

    /// Whether one current observation is eligible.
    #[must_use]
    pub fn is_eligible(&self, observation: &ActionObservation) -> bool {
        matches!(self.eligibility(observation), ActionEligibility::Eligible)
    }

    /// Validate one observation and retain a typed failure reason.
    ///
    /// # Errors
    ///
    /// Returns a projection error for stale, substituted, expired,
    /// cross-object, or cross-principal observations. Presentation values are
    /// not consulted.
    pub fn check(&self, observation: &ActionObservation) -> Result<(), ProjectionError> {
        match self.eligibility(observation) {
            ActionEligibility::Eligible => Ok(()),
            ActionEligibility::CrossPrincipal => Err(ProjectionError::ActionCrossPrincipal),
            ActionEligibility::ObjectMismatch => Err(ProjectionError::ActionObjectMismatch),
            ActionEligibility::DigestMismatch => Err(ProjectionError::ActionDigestMismatch),
            ActionEligibility::StaleRevision => Err(ProjectionError::ActionStaleRevision),
            ActionEligibility::ScopeMismatch => Err(ProjectionError::ActionScopeMismatch),
            ActionEligibility::GenerationDrift => Err(ProjectionError::ActionGenerationDrift),
            ActionEligibility::Expired => Err(ProjectionError::ActionExpired),
        }
    }
}

impl DescriptorEncode for ActionDescriptor {
    fn encoded_len(&self) -> usize {
        ACTION_DESCRIPTOR_ENCODED_LEN
    }

    fn encode_descriptor(&self, output: &mut [u8]) -> Result<(), ProjectionError> {
        if output.len() != ACTION_DESCRIPTOR_ENCODED_LEN {
            return Err(ProjectionError::InvalidLength);
        }
        write_header(output, ProjectionTypeTag::ActionDescriptor)?;
        self.object.encode_descriptor(&mut output[3..41])?;
        output[41..73].copy_from_slice(self.digest.as_bytes());
        self.revision.encode_descriptor(&mut output[73..84])?;
        output[84..116].copy_from_slice(self.scope.as_bytes());
        output[116..124].copy_from_slice(&self.generation.get().to_le_bytes());
        output[124..132].copy_from_slice(&self.expiry.get().to_le_bytes());
        output[132..164].copy_from_slice(self.principal.as_bytes());
        Ok(())
    }
}

impl DescriptorDecode for ActionDescriptor {
    fn decode_descriptor(input: &[u8]) -> Result<Self, ProjectionError> {
        if input.len() != ACTION_DESCRIPTOR_ENCODED_LEN {
            return Err(ProjectionError::InvalidLength);
        }
        check_header(input, ProjectionTypeTag::ActionDescriptor)?;

        let object = SemanticObjectId::decode_descriptor(&input[3..41])?;
        let mut digest = [0_u8; ACTION_BINDING_BYTES];
        digest.copy_from_slice(&input[41..73]);
        let revision = ProjectionRevision::decode_descriptor(&input[73..84])?;
        let mut scope = [0_u8; ACTION_BINDING_BYTES];
        scope.copy_from_slice(&input[84..116]);
        let generation_raw = u64::from_le_bytes(
            input[116..124]
                .try_into()
                .map_err(|_| ProjectionError::InvalidLength)?,
        );
        let generation = ActionGeneration::from_raw(generation_raw)
            .ok_or(ProjectionError::InvalidActionGeneration)?;
        let expiry = ActionExpiry::from_raw(u64::from_le_bytes(
            input[124..132]
                .try_into()
                .map_err(|_| ProjectionError::InvalidLength)?,
        ));
        let mut principal = [0_u8; ACTION_BINDING_BYTES];
        principal.copy_from_slice(&input[132..164]);
        Ok(Self::new(
            object,
            ActionDigest::from_bytes(digest),
            revision,
            ActionScope::from_bytes(scope),
            generation,
            expiry,
            ActionPrincipal::from_bytes(principal),
        ))
    }
}

#[cfg(test)]
#[path = "action_descriptor_tests.rs"]
mod tests;
