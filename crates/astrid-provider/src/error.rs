//! Failures for provider descriptors, bindings, and receipts.

use core::fmt;

/// Failure to construct, decode, bind, or execute a provider descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProviderError {
    /// The destination or source has the wrong exact length.
    InvalidLength,
    /// The encoding version is not supported.
    UnknownVersion(u8),
    /// The type-domain tag is not part of this crate's closed registry.
    UnknownTypeTag(u16),
    /// The bytes belong to a different known provider domain.
    WrongTypeTag {
        /// Tag required by the requested decoder.
        expected: u16,
        /// Tag carried by the input.
        actual: u16,
    },
    /// A discriminant is not part of the closed vocabulary.
    UnknownDiscriminant(u16),
    /// The bytes have a second representation for the same value.
    NonCanonical,
    /// Nested `astrid-resource-types` bytes failed to decode.
    ResourceEncoding,
    /// Nested `astrid-projection` bytes failed to decode.
    ProjectionEncoding,
    /// Identity domains or closures do not refer to the same typed object.
    TypeMismatch,
    /// A generation does not match the bound descriptor.
    StaleGeneration {
        /// Generation currently bound.
        found: u64,
        /// Generation supplied by the caller.
        requested: u64,
    },
    /// Structured argv has no program-name token.
    EmptyArgv,
    /// A job argument exceeded [`crate::ARG_MAX_BYTES`].
    ArgTooLong,
    /// Argv exceeded [`crate::ARGV_MAX`].
    ArgvLimit,
    /// A job argument token was empty.
    EmptyArg,
    /// Attachments exceeded [`crate::ATTACHMENT_MAX`].
    AttachmentLimit,
    /// Streams exceeded [`crate::STREAM_MAX`].
    StreamLimit,
    /// Two attachments named the same object.
    DuplicateAttachment,
    /// Two streams named the same object.
    DuplicateStream,
    /// The owner is not the job principal.
    PrincipalMismatch,
    /// Receipts and descriptors cannot become a live handle.
    NotALiveHandle,
    /// The provider does not implement this operation.
    NotSupported,
}

impl fmt::Display for ProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid provider descriptor: {self:?}")
    }
}

impl core::error::Error for ProviderError {}
