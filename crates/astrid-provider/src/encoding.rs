//! Provider-local descriptor encodings.
//!
//! Nested [`astrid_resource_types`] and [`astrid_projection`] values keep their
//! own tags. These tags are not resource-type tags and are not authority.

use crate::error::ProviderError;

/// Version used by this crate's descriptor encodings.
pub const CANONICAL_VERSION: u8 = 1;

/// Closed registry of provider descriptor domains.
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderTypeTag {
    /// [`crate::HostPrincipal`].
    HostPrincipal = 1,
    /// [`crate::ApplicationClosure`].
    ApplicationClosure = 2,
    /// [`crate::InstanceId`].
    InstanceId = 3,
    /// [`crate::AdmittedInstance`].
    AdmittedInstance = 4,
    /// [`crate::JobArg`].
    JobArg = 5,
    /// [`crate::JobArgv`].
    JobArgv = 6,
    /// [`crate::AttachmentDescriptor`].
    AttachmentDescriptor = 7,
    /// [`crate::StreamDescriptor`].
    StreamDescriptor = 8,
    /// [`crate::AttachmentSet`].
    AttachmentSet = 9,
    /// [`crate::StreamSet`].
    StreamSet = 10,
    /// [`crate::Job`].
    Job = 11,
    /// [`crate::CheckpointBlobId`].
    CheckpointBlobId = 12,
    /// [`crate::Checkpoint`].
    Checkpoint = 13,
    /// [`crate::ExecutionOutcome`].
    ExecutionOutcome = 14,
    /// [`crate::ExecutionReceipt`].
    ExecutionReceipt = 15,
}

impl ProviderTypeTag {
    /// Stable numeric code included in the descriptor header.
    #[must_use]
    pub const fn code(self) -> u16 {
        self as u16
    }

    /// Resolve a known provider type tag.
    #[must_use]
    pub const fn from_code(code: u16) -> Option<Self> {
        match code {
            1 => Some(Self::HostPrincipal),
            2 => Some(Self::ApplicationClosure),
            3 => Some(Self::InstanceId),
            4 => Some(Self::AdmittedInstance),
            5 => Some(Self::JobArg),
            6 => Some(Self::JobArgv),
            7 => Some(Self::AttachmentDescriptor),
            8 => Some(Self::StreamDescriptor),
            9 => Some(Self::AttachmentSet),
            10 => Some(Self::StreamSet),
            11 => Some(Self::Job),
            12 => Some(Self::CheckpointBlobId),
            13 => Some(Self::Checkpoint),
            14 => Some(Self::ExecutionOutcome),
            15 => Some(Self::ExecutionReceipt),
            _ => None,
        }
    }
}

/// Encode a provider descriptor using its versioned representation.
pub trait DescriptorEncode {
    /// Exact number of bytes emitted by this value.
    fn encoded_len(&self) -> usize;

    /// Encode into a destination of exactly [`Self::encoded_len`] bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::InvalidLength`] if `output` is not exact.
    fn encode_descriptor(&self, output: &mut [u8]) -> Result<(), ProviderError>;
}

/// Decode a provider descriptor from its versioned representation.
pub trait DescriptorDecode: Sized {
    /// Decode an exact descriptor byte sequence.
    ///
    /// # Errors
    ///
    /// Rejects unknown versions, malformed lengths, unknown closed-set values,
    /// leftover bytes, and alternate encodings.
    fn decode_descriptor(input: &[u8]) -> Result<Self, ProviderError>;
}

pub(crate) fn write_header(output: &mut [u8], tag: ProviderTypeTag) -> Result<(), ProviderError> {
    let Some(header) = output.get_mut(..3) else {
        return Err(ProviderError::InvalidLength);
    };
    header[0] = CANONICAL_VERSION;
    header[1..3].copy_from_slice(&tag.code().to_le_bytes());
    Ok(())
}

pub(crate) fn check_header(input: &[u8], expected: ProviderTypeTag) -> Result<(), ProviderError> {
    let Some(header) = input.get(..3) else {
        return Err(ProviderError::InvalidLength);
    };
    if header[0] != CANONICAL_VERSION {
        return Err(ProviderError::UnknownVersion(header[0]));
    }
    let code = u16::from_le_bytes([header[1], header[2]]);
    match ProviderTypeTag::from_code(code) {
        Some(actual) if actual == expected => Ok(()),
        Some(actual) => Err(ProviderError::WrongTypeTag {
            expected: expected.code(),
            actual: actual.code(),
        }),
        None => Err(ProviderError::UnknownTypeTag(code)),
    }
}

pub(crate) fn take(input: &[u8], offset: usize, n: usize) -> Result<(&[u8], usize), ProviderError> {
    let end = offset.checked_add(n).ok_or(ProviderError::InvalidLength)?;
    let slice = input.get(offset..end).ok_or(ProviderError::InvalidLength)?;
    Ok((slice, end))
}

pub(crate) fn write_nested<T: DescriptorEncode>(
    output: &mut [u8],
    offset: usize,
    value: &T,
) -> Result<usize, ProviderError> {
    let len = value.encoded_len();
    let end = offset
        .checked_add(len)
        .ok_or(ProviderError::InvalidLength)?;
    value.encode_descriptor(
        output
            .get_mut(offset..end)
            .ok_or(ProviderError::InvalidLength)?,
    )?;
    Ok(end)
}

pub(crate) fn read_nested<T: DescriptorDecode>(
    input: &[u8],
    offset: usize,
    len: usize,
) -> Result<(T, usize), ProviderError> {
    let (bytes, end) = take(input, offset, len)?;
    Ok((T::decode_descriptor(bytes)?, end))
}

pub(crate) fn require_exact_len(bytes: &[u8], expected: usize) -> Result<(), ProviderError> {
    if bytes.len() == expected {
        Ok(())
    } else {
        Err(ProviderError::InvalidLength)
    }
}

pub(crate) fn require_zero_padding(bytes: &[u8]) -> Result<(), ProviderError> {
    if bytes.iter().all(|byte| *byte == 0) {
        Ok(())
    } else {
        Err(ProviderError::NonCanonical)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_type_tag_registry_matches_golden_codes() {
        let golden = [
            (ProviderTypeTag::HostPrincipal, 1),
            (ProviderTypeTag::ApplicationClosure, 2),
            (ProviderTypeTag::InstanceId, 3),
            (ProviderTypeTag::AdmittedInstance, 4),
            (ProviderTypeTag::JobArg, 5),
            (ProviderTypeTag::JobArgv, 6),
            (ProviderTypeTag::AttachmentDescriptor, 7),
            (ProviderTypeTag::StreamDescriptor, 8),
            (ProviderTypeTag::AttachmentSet, 9),
            (ProviderTypeTag::StreamSet, 10),
            (ProviderTypeTag::Job, 11),
            (ProviderTypeTag::CheckpointBlobId, 12),
            (ProviderTypeTag::Checkpoint, 13),
            (ProviderTypeTag::ExecutionOutcome, 14),
            (ProviderTypeTag::ExecutionReceipt, 15),
        ];
        for (tag, code) in golden {
            assert_eq!(tag.code(), code);
            assert_eq!(ProviderTypeTag::from_code(code), Some(tag));
        }
        assert_eq!(ProviderTypeTag::from_code(0), None);
        assert_eq!(ProviderTypeTag::from_code(u16::MAX), None);
    }
}
