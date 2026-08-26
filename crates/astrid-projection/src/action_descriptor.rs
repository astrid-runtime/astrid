//! Private, non-authoritative action eligibility descriptors.
//!
//! [`ActionDescriptor`] binds an opaque action digest to one projection
//! revision, scope, principal, generation, and expiry. It is an observation
//! contract only: it has no handle, lease, issuer, refresh operation, or path
//! to a live invocation. A caller must supply the current observation context
//! to [`ActionDescriptor::eligibility`]; presentation labels and metadata are
//! deliberately absent from that context.

use core::fmt;
use core::num::NonZeroU64;

use crate::encoding::{
    DescriptorDecode, DescriptorEncode, ProjectionTypeTag, check_header, write_header,
};
use crate::error::ProjectionError;
use crate::revision::ProjectionRevision;

/// Width of an opaque action binding value.
pub const ACTION_BINDING_BYTES: usize = 32;

/// Exact version-one encoded size of an [`ActionDescriptor`].
pub const ACTION_DESCRIPTOR_ENCODED_LEN: usize = 126;

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
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
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

/// Current context supplied by a non-authoritative consumer.
///
/// Every field is required. There is no default context and no method that
/// derives one from presentation text, so omission or substitution fails
/// closed at the descriptor boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActionObservation {
    digest: ActionDigest,
    revision: ProjectionRevision,
    scope: ActionScope,
    generation: ActionGeneration,
    principal: ActionPrincipal,
    now: u64,
}

impl ActionObservation {
    /// Bind an observation to all descriptor-controlled identity facts.
    #[must_use]
    pub const fn new(
        digest: ActionDigest,
        revision: ProjectionRevision,
        scope: ActionScope,
        generation: ActionGeneration,
        principal: ActionPrincipal,
        now: u64,
    ) -> Self {
        Self {
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
        digest: ActionDigest,
        revision: ProjectionRevision,
        scope: ActionScope,
        generation: ActionGeneration,
        now: u64,
    ) -> Self {
        Self::new(digest, revision, scope, generation, principal, now)
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

/// Publicly inspectable, read-only facts carried by an action descriptor.
///
/// This is a value snapshot, not a minting request. Its fields remain private
/// and it has no constructor, refresh, or conversion into a live invocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActionDescriptorFacts {
    digest: ActionDigest,
    revision: ProjectionRevision,
    scope: ActionScope,
    generation: ActionGeneration,
    expiry: ActionExpiry,
    principal: ActionPrincipal,
}

impl ActionDescriptorFacts {
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
}

/// Immutable, non-authoritative action description.
///
/// The descriptor contains no capability, handle, lease, issuer, or mutable
/// state. Cloning or decoding it only repeats an observation; eligibility is
/// recomputed against the caller-supplied context every time.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ActionDescriptor {
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
    /// Bind an action digest to a projection revision, scope, generation,
    /// expiry, and principal.
    #[must_use]
    pub const fn new(
        digest: ActionDigest,
        revision: ProjectionRevision,
        scope: ActionScope,
        generation: ActionGeneration,
        expiry: ActionExpiry,
        principal: ActionPrincipal,
    ) -> Self {
        Self {
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
        digest: ActionDigest,
        revision: ProjectionRevision,
        scope: ActionScope,
        generation: ActionGeneration,
        expiry: ActionExpiry,
    ) -> Self {
        Self::new(digest, revision, scope, generation, expiry, principal)
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
    /// Returns a projection error for stale, substituted, expired, or
    /// cross-principal observations. Presentation values are not consulted.
    pub fn check(&self, observation: &ActionObservation) -> Result<(), ProjectionError> {
        match self.eligibility(observation) {
            ActionEligibility::Eligible => Ok(()),
            ActionEligibility::CrossPrincipal => Err(ProjectionError::ActionCrossPrincipal),
            ActionEligibility::DigestMismatch => Err(ProjectionError::ActionDigestMismatch),
            ActionEligibility::StaleRevision => Err(ProjectionError::StaleRevision {
                found: self.revision.get(),
                requested: observation.revision.get(),
            }),
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
        output[3..35].copy_from_slice(self.digest.as_bytes());
        self.revision.encode_descriptor(&mut output[35..46])?;
        output[46..78].copy_from_slice(self.scope.as_bytes());
        output[78..86].copy_from_slice(&self.generation.get().to_le_bytes());
        output[86..94].copy_from_slice(&self.expiry.get().to_le_bytes());
        output[94..126].copy_from_slice(self.principal.as_bytes());
        Ok(())
    }
}

impl DescriptorDecode for ActionDescriptor {
    fn decode_descriptor(input: &[u8]) -> Result<Self, ProjectionError> {
        if input.len() != ACTION_DESCRIPTOR_ENCODED_LEN {
            return Err(ProjectionError::InvalidLength);
        }
        check_header(input, ProjectionTypeTag::ActionDescriptor)?;

        let mut digest = [0_u8; ACTION_BINDING_BYTES];
        digest.copy_from_slice(&input[3..35]);
        let revision = ProjectionRevision::decode_descriptor(&input[35..46])?;
        let mut scope = [0_u8; ACTION_BINDING_BYTES];
        scope.copy_from_slice(&input[46..78]);
        let generation_raw = u64::from_le_bytes(
            input[78..86]
                .try_into()
                .map_err(|_| ProjectionError::InvalidLength)?,
        );
        let generation = ActionGeneration::from_raw(generation_raw)
            .ok_or(ProjectionError::InvalidActionGeneration)?;
        let expiry = ActionExpiry::from_raw(u64::from_le_bytes(
            input[86..94]
                .try_into()
                .map_err(|_| ProjectionError::InvalidLength)?,
        ));
        let mut principal = [0_u8; ACTION_BINDING_BYTES];
        principal.copy_from_slice(&input[94..126]);
        Ok(Self::new(
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
mod tests {
    extern crate alloc;

    use super::*;
    use crate::presentation::{PresentationLabel, PresentationMetadata};
    use crate::snapshot::ProjectionSnapshot;
    use alloc::string::ToString;
    use astrid_resource_types::{ResourceId, ResourceTypeId};

    fn descriptor() -> ActionDescriptor {
        ActionDescriptor::new(
            ActionDigest::from_bytes([0x11; ACTION_BINDING_BYTES]),
            ProjectionRevision::from_raw(7).unwrap(),
            ActionScope::from_bytes([0x22; ACTION_BINDING_BYTES]),
            ActionGeneration::from_raw(3).unwrap(),
            ActionExpiry::from_raw(100),
            ActionPrincipal::from_bytes([0x33; ACTION_BINDING_BYTES]),
        )
    }

    fn observation() -> ActionObservation {
        ActionObservation::new(
            ActionDigest::from_bytes([0x11; ACTION_BINDING_BYTES]),
            ProjectionRevision::from_raw(7).unwrap(),
            ActionScope::from_bytes([0x22; ACTION_BINDING_BYTES]),
            ActionGeneration::from_raw(3).unwrap(),
            ActionPrincipal::from_bytes([0x33; ACTION_BINDING_BYTES]),
            99,
        )
    }

    fn snapshot(label: &[u8], metadata: &PresentationMetadata) -> ProjectionSnapshot {
        ProjectionSnapshot::new(
            crate::SemanticObjectId::for_resource(ResourceId::from_bytes([0x44; 32])),
            ResourceTypeId::from_bytes([0x55; 32]),
            ProjectionRevision::from_raw(7).unwrap(),
            PresentationLabel::from_utf8(label).unwrap(),
            *metadata,
        )
    }

    #[test]
    fn descriptor_roundtrip_is_fixed_and_debug_is_opaque() {
        let descriptor = descriptor();
        let mut encoded = [0_u8; ACTION_DESCRIPTOR_ENCODED_LEN];
        assert_eq!(descriptor.encoded_len(), ACTION_DESCRIPTOR_ENCODED_LEN);
        descriptor.encode_descriptor(&mut encoded).unwrap();
        assert_eq!(
            ActionDescriptor::decode_descriptor(&encoded),
            Ok(descriptor)
        );
        assert_eq!(
            format_args!("{descriptor:?}").to_string(),
            "ActionDescriptor"
        );
        assert_eq!(
            ActionDescriptor::decode_descriptor(&encoded[..125]),
            Err(ProjectionError::InvalidLength)
        );
        encoded[78..86].fill(0);
        assert_eq!(
            ActionDescriptor::decode_descriptor(&encoded),
            Err(ProjectionError::InvalidActionGeneration)
        );
    }

    #[test]
    fn descriptor_rejects_stale_expired_drift_and_cross_principal_observations() {
        let descriptor = descriptor();
        let honest = observation();
        assert_eq!(descriptor.eligibility(&honest), ActionEligibility::Eligible);
        assert!(descriptor.is_eligible(&honest));
        assert_eq!(descriptor.check(&honest), Ok(()));

        let digest = ActionObservation::new(
            ActionDigest::from_bytes([0xee; ACTION_BINDING_BYTES]),
            honest.revision(),
            honest.scope(),
            honest.generation(),
            honest.principal(),
            honest.now(),
        );
        assert_eq!(
            descriptor.check(&digest),
            Err(ProjectionError::ActionDigestMismatch)
        );

        let stale = ActionObservation::new(
            honest.digest(),
            ProjectionRevision::from_raw(8).unwrap(),
            honest.scope(),
            honest.generation(),
            honest.principal(),
            honest.now(),
        );
        assert_eq!(
            descriptor.eligibility(&stale),
            ActionEligibility::StaleRevision
        );
        assert_eq!(
            descriptor.check(&stale),
            Err(ProjectionError::StaleRevision {
                found: 7,
                requested: 8,
            })
        );

        let scope = ActionObservation::new(
            honest.digest(),
            honest.revision(),
            ActionScope::from_bytes([0xef; ACTION_BINDING_BYTES]),
            honest.generation(),
            honest.principal(),
            honest.now(),
        );
        assert_eq!(
            descriptor.check(&scope),
            Err(ProjectionError::ActionScopeMismatch)
        );

        let generation = ActionObservation::new(
            honest.digest(),
            honest.revision(),
            honest.scope(),
            ActionGeneration::from_raw(4).unwrap(),
            honest.principal(),
            honest.now(),
        );
        assert_eq!(
            descriptor.check(&generation),
            Err(ProjectionError::ActionGenerationDrift)
        );

        let principal = ActionObservation::new(
            honest.digest(),
            honest.revision(),
            honest.scope(),
            honest.generation(),
            ActionPrincipal::from_bytes([0xaa; ACTION_BINDING_BYTES]),
            honest.now(),
        );
        assert_eq!(
            descriptor.check(&principal),
            Err(ProjectionError::ActionCrossPrincipal)
        );

        let expired = ActionObservation::new(
            honest.digest(),
            honest.revision(),
            honest.scope(),
            honest.generation(),
            honest.principal(),
            100,
        );
        assert_eq!(
            descriptor.check(&expired),
            Err(ProjectionError::ActionExpired)
        );
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct PresenterResult {
        eligible: bool,
        label: PresentationLabel,
        metadata: PresentationMetadata,
        facts: ActionDescriptorFacts,
    }

    // This consumer is presentation-shaped: it carries labels and metadata,
    // and treats descriptor eligibility as an opaque boolean decision.
    fn presenter_consumer(
        snapshot: &ProjectionSnapshot,
        descriptor: &ActionDescriptor,
        observation: &ActionObservation,
    ) -> PresenterResult {
        PresenterResult {
            eligible: descriptor.is_eligible(observation),
            label: snapshot.label(),
            metadata: snapshot.metadata(),
            facts: descriptor.facts(),
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct EligibilityResult {
        eligible: bool,
        facts: ActionDescriptorFacts,
    }

    // This consumer is structurally different: it reads each bound fact and
    // derives eligibility without consulting presentation values.
    fn eligibility_consumer(
        descriptor: &ActionDescriptor,
        observation: &ActionObservation,
    ) -> EligibilityResult {
        let facts = descriptor.facts();
        let eligible = facts.principal() == observation.principal()
            && facts.digest() == observation.digest()
            && facts.revision() == observation.revision()
            && facts.scope() == observation.scope()
            && facts.generation() == observation.generation()
            && !facts.expiry().is_expired_at(observation.now());
        EligibilityResult { eligible, facts }
    }

    #[test]
    fn independent_consumers_agree_and_presentation_cannot_mint_or_widen() {
        let descriptor = descriptor();
        let observation = observation();
        let plain = snapshot(b"safe", &PresentationMetadata::EMPTY);
        let hostile_metadata = PresentationMetadata::try_from_pairs(&[
            ("action_handle", "forged"),
            ("invoke", "true"),
            ("rights", "root"),
        ])
        .unwrap();
        let hostile = snapshot(b"ADMIN GRANT", &hostile_metadata);

        let first = presenter_consumer(&plain, &descriptor, &observation);
        let second = eligibility_consumer(&descriptor, &observation);
        assert!(first.eligible);
        assert_eq!(first.eligible, second.eligible);
        assert_eq!(first.facts, second.facts);

        // A malicious presentation changes only display fields; eligibility
        // and all descriptor facts remain exactly those of the bound action.
        let hostile_result = presenter_consumer(&hostile, &descriptor, &observation);
        assert!(hostile_result.eligible);
        assert_eq!(hostile_result.facts, first.facts);
        assert_eq!(hostile_result.label.as_str(), "ADMIN GRANT");
        assert!(
            hostile_result
                .metadata
                .iter()
                .any(|(key, value)| key == "action_handle" && value == "forged")
        );

        // A copied descriptor cannot refresh itself after the projection moves
        // to a new revision; replay fails against the new observation.
        let replayed = descriptor;
        let moved = ActionObservation::new(
            observation.digest(),
            observation.revision().checked_next().unwrap(),
            observation.scope(),
            observation.generation(),
            observation.principal(),
            observation.now(),
        );
        assert_eq!(
            replayed.check(&moved),
            Err(ProjectionError::StaleRevision {
                found: 7,
                requested: 8,
            })
        );
    }
}
