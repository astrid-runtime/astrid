//! Checked projection revisions. Never wrap.

use core::{fmt, num::NonZeroU64};

use crate::encoding::{
    DescriptorDecode, DescriptorEncode, ProjectionTypeTag, check_header, write_header,
};
use crate::error::ProjectionError;

/// Generation of a projection snapshot stream.
///
/// Distinct from object, provider, lifecycle, and authority generations.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProjectionRevision(NonZeroU64);

impl fmt::Debug for ProjectionRevision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = self;
        formatter.write_str("ProjectionRevision")
    }
}

impl ProjectionRevision {
    /// First valid revision.
    pub const INITIAL: Self = Self(NonZeroU64::MIN);

    /// Construct from a non-zero raw value.
    #[must_use]
    pub const fn from_raw(raw: u64) -> Option<Self> {
        match NonZeroU64::new(raw) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    /// Return the raw non-zero value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    /// Return the next revision without wrapping.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectionError::ExhaustedRevision`] at `u64::MAX`.
    pub fn checked_next(self) -> Result<Self, ProjectionError> {
        self.get()
            .checked_add(1)
            .and_then(Self::from_raw)
            .ok_or(ProjectionError::ExhaustedRevision)
    }
}

impl DescriptorEncode for ProjectionRevision {
    fn encoded_len(&self) -> usize {
        11
    }

    fn encode_descriptor(&self, output: &mut [u8]) -> Result<(), ProjectionError> {
        if output.len() != 11 {
            return Err(ProjectionError::InvalidLength);
        }
        write_header(output, ProjectionTypeTag::ProjectionRevision)?;
        output[3..11].copy_from_slice(&self.get().to_le_bytes());
        Ok(())
    }
}

impl DescriptorDecode for ProjectionRevision {
    fn decode_descriptor(input: &[u8]) -> Result<Self, ProjectionError> {
        if input.len() != 11 {
            return Err(ProjectionError::InvalidLength);
        }
        check_header(input, ProjectionTypeTag::ProjectionRevision)?;
        let raw = u64::from_le_bytes(
            input[3..11]
                .try_into()
                .map_err(|_| ProjectionError::InvalidLength)?,
        );
        Self::from_raw(raw).ok_or(ProjectionError::InvalidRevision)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_revision_is_rejected_and_max_does_not_wrap() {
        assert_eq!(ProjectionRevision::from_raw(0), None);
        assert_eq!(
            ProjectionRevision::decode_descriptor(&[1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Err(ProjectionError::InvalidRevision)
        );
        let maximum = ProjectionRevision::from_raw(u64::MAX).unwrap();
        assert_eq!(
            maximum.checked_next(),
            Err(ProjectionError::ExhaustedRevision)
        );
        assert_eq!(ProjectionRevision::INITIAL.checked_next().unwrap().get(), 2);
    }
}
