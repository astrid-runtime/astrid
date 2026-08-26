//! Projection-local descriptor encodings.
//!
//! Nested [`astrid_resource_types`] values keep their own tags. These tags are
//! not resource-type tags and are not authority.

use crate::error::ProjectionError;

/// Version used by this crate's descriptor encodings.
pub const CANONICAL_VERSION: u8 = 1;

/// Closed registry of projection descriptor domains.
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProjectionTypeTag {
    /// [`crate::SemanticObjectId`].
    SemanticObjectId = 1,
    /// [`crate::ProjectionRevision`].
    ProjectionRevision = 2,
    /// [`crate::PresentationLabel`].
    PresentationLabel = 3,
    /// [`crate::PresentationMetadata`].
    PresentationMetadata = 4,
    /// [`crate::ProjectionSnapshot`].
    ProjectionSnapshot = 5,
    /// [`crate::ProjectionUpdate`].
    ProjectionUpdate = 6,
    /// [`crate::ActionDescriptor`].
    ActionDescriptor = 7,
}

impl ProjectionTypeTag {
    /// Stable numeric code included in the descriptor header.
    #[must_use]
    pub const fn code(self) -> u16 {
        self as u16
    }

    /// Resolve a known projection type tag.
    #[must_use]
    pub const fn from_code(code: u16) -> Option<Self> {
        match code {
            1 => Some(Self::SemanticObjectId),
            2 => Some(Self::ProjectionRevision),
            3 => Some(Self::PresentationLabel),
            4 => Some(Self::PresentationMetadata),
            5 => Some(Self::ProjectionSnapshot),
            6 => Some(Self::ProjectionUpdate),
            7 => Some(Self::ActionDescriptor),
            _ => None,
        }
    }
}

/// Encode a projection descriptor using its versioned representation.
pub trait DescriptorEncode {
    /// Exact number of bytes emitted by this value.
    fn encoded_len(&self) -> usize;

    /// Encode into a destination of exactly [`Self::encoded_len`] bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectionError::InvalidLength`] if `output` is not exact.
    fn encode_descriptor(&self, output: &mut [u8]) -> Result<(), ProjectionError>;
}

/// Decode a projection descriptor from its versioned representation.
pub trait DescriptorDecode: Sized {
    /// Decode an exact descriptor byte sequence.
    ///
    /// # Errors
    ///
    /// Rejects unknown versions, malformed lengths, unknown closed-set values,
    /// leftover bytes, and alternate encodings.
    fn decode_descriptor(input: &[u8]) -> Result<Self, ProjectionError>;
}

pub(crate) fn write_header(
    output: &mut [u8],
    tag: ProjectionTypeTag,
) -> Result<(), ProjectionError> {
    let Some(header) = output.get_mut(..3) else {
        return Err(ProjectionError::InvalidLength);
    };
    header[0] = CANONICAL_VERSION;
    header[1..3].copy_from_slice(&tag.code().to_le_bytes());
    Ok(())
}

pub(crate) fn check_header(
    input: &[u8],
    expected: ProjectionTypeTag,
) -> Result<(), ProjectionError> {
    let Some(header) = input.get(..3) else {
        return Err(ProjectionError::InvalidLength);
    };
    if header[0] != CANONICAL_VERSION {
        return Err(ProjectionError::UnknownVersion(header[0]));
    }
    let code = u16::from_le_bytes([header[1], header[2]]);
    match ProjectionTypeTag::from_code(code) {
        Some(actual) if actual == expected => Ok(()),
        Some(actual) => Err(ProjectionError::WrongTypeTag {
            expected: expected.code(),
            actual: actual.code(),
        }),
        None => Err(ProjectionError::UnknownTypeTag(code)),
    }
}

pub(crate) fn take(
    input: &[u8],
    offset: usize,
    n: usize,
) -> Result<(&[u8], usize), ProjectionError> {
    let end = offset
        .checked_add(n)
        .ok_or(ProjectionError::InvalidLength)?;
    let slice = input
        .get(offset..end)
        .ok_or(ProjectionError::InvalidLength)?;
    Ok((slice, end))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn projection_type_tag_registry_matches_golden_codes() {
        let golden = [
            (ProjectionTypeTag::SemanticObjectId, 1),
            (ProjectionTypeTag::ProjectionRevision, 2),
            (ProjectionTypeTag::PresentationLabel, 3),
            (ProjectionTypeTag::PresentationMetadata, 4),
            (ProjectionTypeTag::ProjectionSnapshot, 5),
            (ProjectionTypeTag::ProjectionUpdate, 6),
            (ProjectionTypeTag::ActionDescriptor, 7),
        ];
        for (tag, code) in golden {
            assert_eq!(tag.code(), code);
            assert_eq!(ProjectionTypeTag::from_code(code), Some(tag));
        }
        assert_eq!(ProjectionTypeTag::from_code(0), None);
        assert_eq!(ProjectionTypeTag::from_code(u16::MAX), None);
    }
}
