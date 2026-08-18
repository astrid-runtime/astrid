//! Canonical, allocation-free byte encoding contracts.
//!
//! Every version-one representation is `version: u8`, then a little-endian
//! [`CanonicalTypeTag`] as `u16`, then the type-specific payload.

use core::fmt;

#[cfg(feature = "alloc")]
use alloc::vec;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// Closed registry of value domains used by canonical encodings.
///
/// Codes are stable wire and persistence identifiers. A decoder must validate
/// this tag before interpreting the payload, even when two types have the same
/// payload width.
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CanonicalTypeTag {
    /// [`crate::ResourceId`].
    ResourceId = 1,
    /// [`crate::ResourceTypeId`].
    ResourceTypeId = 2,
    /// [`crate::DerivationId`].
    DerivationId = 3,
    /// [`crate::ProviderId`].
    ProviderId = 4,
    /// [`crate::ApplicationGenerationRef`].
    ApplicationGenerationRef = 5,
    /// [`crate::SystemGenerationRef`].
    SystemGenerationRef = 6,
    /// [`crate::AccountId`].
    AccountId = 7,
    /// [`crate::BudgetId`].
    BudgetId = 8,
    /// [`crate::CausalRequestId`].
    CausalRequestId = 9,
    /// [`crate::OperationId`].
    OperationId = 10,
    /// [`crate::OwnerId`].
    OwnerId = 20,
    /// [`crate::Rights`].
    Rights = 30,
    /// [`crate::ObjectGeneration`].
    ObjectGeneration = 40,
    /// [`crate::AuthorityEpoch`].
    AuthorityEpoch = 41,
    /// [`crate::LifecycleGeneration`].
    LifecycleGeneration = 42,
    /// [`crate::ProviderGeneration`].
    ProviderGeneration = 43,
    /// [`crate::ResourceKind`].
    ResourceKind = 50,
    /// [`crate::ResourceLifecycleState`].
    ResourceLifecycleState = 51,
    /// [`crate::TransferClass`].
    TransferClass = 52,
    /// [`crate::ResourceErrorCode`].
    ResourceErrorCode = 53,
    /// [`crate::ResourceOutcomeCode`].
    ResourceOutcomeCode = 54,
}

impl CanonicalTypeTag {
    /// Stable numeric code included in the canonical header.
    #[must_use]
    pub const fn code(self) -> u16 {
        self as u16
    }

    /// Resolve a known canonical type tag.
    #[must_use]
    pub const fn from_code(code: u16) -> Option<Self> {
        match code {
            1 => Some(Self::ResourceId),
            2 => Some(Self::ResourceTypeId),
            3 => Some(Self::DerivationId),
            4 => Some(Self::ProviderId),
            5 => Some(Self::ApplicationGenerationRef),
            6 => Some(Self::SystemGenerationRef),
            7 => Some(Self::AccountId),
            8 => Some(Self::BudgetId),
            9 => Some(Self::CausalRequestId),
            10 => Some(Self::OperationId),
            20 => Some(Self::OwnerId),
            30 => Some(Self::Rights),
            40 => Some(Self::ObjectGeneration),
            41 => Some(Self::AuthorityEpoch),
            42 => Some(Self::LifecycleGeneration),
            43 => Some(Self::ProviderGeneration),
            50 => Some(Self::ResourceKind),
            51 => Some(Self::ResourceLifecycleState),
            52 => Some(Self::TransferClass),
            53 => Some(Self::ResourceErrorCode),
            54 => Some(Self::ResourceOutcomeCode),
            _ => None,
        }
    }
}

/// Failure to decode or encode a canonical portable value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EncodingError {
    /// The destination or source has the wrong exact length.
    InvalidLength,
    /// The encoding version is not supported.
    UnknownVersion(u8),
    /// The type-domain tag is not part of the closed registry.
    UnknownTypeTag(u16),
    /// The bytes belong to a different known value domain.
    WrongTypeTag {
        /// Tag required by the requested decoder.
        expected: CanonicalTypeTag,
        /// Tag carried by the input.
        actual: CanonicalTypeTag,
    },
    /// A discriminant is not part of the closed vocabulary.
    UnknownDiscriminant(u16),
    /// A bit is not part of the closed rights vocabulary.
    UnknownRights(u64),
    /// The bytes have a second representation for the same value.
    NonCanonical,
    /// A generation value is zero.
    InvalidGeneration,
}

impl fmt::Display for EncodingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid canonical resource encoding: {self:?}")
    }
}

/// Encode a portable value using its versioned canonical representation.
pub trait CanonicalEncode {
    /// Exact number of bytes emitted by this value.
    fn encoded_len(&self) -> usize;

    /// Encode into a destination of exactly [`Self::encoded_len`] bytes.
    ///
    /// # Errors
    ///
    /// Returns [`EncodingError::InvalidLength`] if `output` is not exact.
    fn encode_canonical(&self, output: &mut [u8]) -> Result<(), EncodingError>;

    /// Encode into a newly allocated vector.
    #[cfg(feature = "alloc")]
    fn to_canonical_vec(&self) -> Vec<u8> {
        let mut output = vec![0; self.encoded_len()];
        self.encode_canonical(&mut output)
            .expect("allocated the exact canonical length");
        output
    }
}

/// Decode a portable value from its versioned canonical representation.
pub trait CanonicalDecode: Sized {
    /// Decode an exact canonical byte sequence.
    ///
    /// # Errors
    ///
    /// Rejects unknown versions, malformed lengths, unknown closed-set values,
    /// and alternate encodings.
    fn decode_canonical(input: &[u8]) -> Result<Self, EncodingError>;
}

pub(crate) fn check_header(
    input: &[u8],
    length: usize,
    expected: CanonicalTypeTag,
) -> Result<(), EncodingError> {
    if input.len() != length {
        return Err(EncodingError::InvalidLength);
    }
    if input[0] != crate::CANONICAL_VERSION {
        return Err(EncodingError::UnknownVersion(input[0]));
    }
    let code = u16::from_le_bytes([input[1], input[2]]);
    let actual = CanonicalTypeTag::from_code(code).ok_or(EncodingError::UnknownTypeTag(code))?;
    if actual != expected {
        return Err(EncodingError::WrongTypeTag { expected, actual });
    }
    Ok(())
}

pub(crate) fn write_header(
    output: &mut [u8],
    length: usize,
    tag: CanonicalTypeTag,
) -> Result<(), EncodingError> {
    if output.len() != length {
        return Err(EncodingError::InvalidLength);
    }
    output[0] = crate::CANONICAL_VERSION;
    output[1..3].copy_from_slice(&tag.code().to_le_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_type_tag_registry_matches_golden_codes() {
        let golden = [
            (CanonicalTypeTag::ResourceId, 1),
            (CanonicalTypeTag::ResourceTypeId, 2),
            (CanonicalTypeTag::DerivationId, 3),
            (CanonicalTypeTag::ProviderId, 4),
            (CanonicalTypeTag::ApplicationGenerationRef, 5),
            (CanonicalTypeTag::SystemGenerationRef, 6),
            (CanonicalTypeTag::AccountId, 7),
            (CanonicalTypeTag::BudgetId, 8),
            (CanonicalTypeTag::CausalRequestId, 9),
            (CanonicalTypeTag::OperationId, 10),
            (CanonicalTypeTag::OwnerId, 20),
            (CanonicalTypeTag::Rights, 30),
            (CanonicalTypeTag::ObjectGeneration, 40),
            (CanonicalTypeTag::AuthorityEpoch, 41),
            (CanonicalTypeTag::LifecycleGeneration, 42),
            (CanonicalTypeTag::ProviderGeneration, 43),
            (CanonicalTypeTag::ResourceKind, 50),
            (CanonicalTypeTag::ResourceLifecycleState, 51),
            (CanonicalTypeTag::TransferClass, 52),
            (CanonicalTypeTag::ResourceErrorCode, 53),
            (CanonicalTypeTag::ResourceOutcomeCode, 54),
        ];

        for (tag, code) in golden {
            assert_eq!(tag.code(), code);
            assert_eq!(CanonicalTypeTag::from_code(code), Some(tag));
        }
        assert_eq!(CanonicalTypeTag::from_code(0), None);
        assert_eq!(CanonicalTypeTag::from_code(u16::MAX), None);
    }
}
