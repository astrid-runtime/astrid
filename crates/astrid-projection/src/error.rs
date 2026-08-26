//! Failures for projection descriptors and views.

use core::fmt;

/// Failure to construct, decode, lookup, or update a projection descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProjectionError {
    /// The destination or source has the wrong exact length.
    InvalidLength,
    /// The encoding version is not supported.
    UnknownVersion(u8),
    /// The type-domain tag is not part of this crate's closed registry.
    UnknownTypeTag(u16),
    /// The bytes belong to a different known projection domain.
    WrongTypeTag {
        /// Tag required by the requested decoder.
        expected: u16,
        /// Tag carried by the input.
        actual: u16,
    },
    /// The bytes have a second representation for the same value.
    NonCanonical,
    /// A revision value is zero or otherwise illegal at this constructor.
    InvalidRevision,
    /// Advancing the revision would wrap.
    ExhaustedRevision,
    /// The stored revision is not the requested one.
    StaleRevision {
        /// Revision currently stored.
        found: u64,
        /// Revision supplied by the caller.
        requested: u64,
    },
    /// The update named a different schema/type than the stored snapshot.
    TypeMismatch,
    /// Global listing by type, label, or catalog dump is refused.
    EnumerationRefused,
    /// A presentation label exceeds [`crate::LABEL_MAX_BYTES`].
    LabelTooLong,
    /// Metadata exceeded entry or field limits.
    MetadataLimit,
    /// Two metadata keys were the same.
    DuplicateMetadataKey,
    /// A metadata key was empty.
    EmptyMetadataKey,
    /// Presentation text was not UTF-8.
    InvalidUtf8,
    /// An initial snapshot already exists for this object.
    AlreadyProjected,
    /// No snapshot exists for this object.
    UnknownObject,
    /// The view has no free slot.
    ViewFull,
    /// Presentation cannot become a live invocation.
    NotAnInvocation,
    /// Nested `astrid-resource-types` bytes failed to decode.
    ResourceEncoding,
    /// An action descriptor carried an impossible zero generation.
    InvalidActionGeneration,
    /// An action descriptor's digest did not match the observed action.
    ActionDigestMismatch,
    /// An action descriptor's scope did not match the observed scope.
    ActionScopeMismatch,
    /// The observed action generation did not match the descriptor.
    ActionGenerationDrift,
    /// The descriptor was observed at or after its expiry.
    ActionExpired,
    /// The descriptor was presented by a different principal.
    ActionCrossPrincipal,
}

impl fmt::Display for ProjectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid projection descriptor: {self:?}")
    }
}

impl core::error::Error for ProjectionError {}
