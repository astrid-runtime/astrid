//! Output ownership for the shared validating content traversal.

use crate::content_dag::ContentError;
pub(super) use crate::content_dag::chunk_range::RangeOutput;

impl RangeOutput<'_> {
    pub(super) fn prepare(&mut self, capacity: usize) -> Result<(), ContentError> {
        // Preserve Vec<u8>'s addressable byte bound before either mode loads content.
        if isize::try_from(capacity).is_err() {
            return Err(ContentError::LengthOverflow);
        }
        if let Self::Buffer(bytes) = self {
            bytes
                .try_reserve_exact(capacity)
                .map_err(|_| ContentError::LengthOverflow)?;
            #[cfg(test)]
            measurement::observe(capacity, 0);
        }
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
