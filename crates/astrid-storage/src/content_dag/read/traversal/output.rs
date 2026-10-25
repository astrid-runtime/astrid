//! Output ownership for the shared validating content traversal.

use crate::content_dag::ContentError;
use alloc::vec::Vec;

pub(super) enum RangeOutput<'a> {
    Buffer(&'a mut Vec<u8>),
    Count(usize),
}

impl RangeOutput<'_> {
    pub(super) fn prepare(&mut self, capacity: usize) -> Result<(), ContentError> {
        if let Self::Buffer(bytes) = self {
            bytes
                .try_reserve_exact(capacity)
                .map_err(|_| ContentError::LengthOverflow)?;
            #[cfg(test)]
            measurement::observe(capacity, 0);
        }
        Ok(())
    }

    pub(super) fn append(&mut self, bytes: &[u8]) -> Result<(), ContentError> {
        match self {
            Self::Buffer(output) => output.extend_from_slice(bytes),
            Self::Count(written) => {
                *written = written
                    .checked_add(bytes.len())
                    .ok_or(ContentError::LengthOverflow)?;
            },
        }
        #[cfg(test)]
        measurement::observe(0, bytes.len());
        Ok(())
    }

    pub(super) fn len(&self) -> usize {
        match self {
            Self::Buffer(bytes) => bytes.len(),
            Self::Count(written) => *written,
        }
    }
}

#[cfg(test)]
pub(crate) mod measurement;
