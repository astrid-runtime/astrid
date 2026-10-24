//! Private bulk construction; no lookup can observe provisional duplicate counts.
use super::{ArenaLocation, DurableError, LocatorValue, NonZeroUsize, ObjectId, PagedLocations};
use crate::engine::durable::locations::ClosureProof;

pub(in crate::engine::durable) struct RebuildLocations {
    locations: PagedLocations,
    failed: bool,
    check: Box<super::CheckDuplicate<'static>>,
}

impl RebuildLocations {
    pub(in crate::engine::durable) fn new(limit: NonZeroUsize) -> Self {
        Self::checked(limit, |_, _, _| Ok(()))
    }

    /// Validate every duplicate before any merge or resident replacement drops
    /// its older location. The result is private until finish succeeds.
    pub(in crate::engine::durable) fn checked(
        limit: NonZeroUsize,
        check: impl FnMut(ObjectId, ArenaLocation, ArenaLocation) -> Result<(), DurableError> + 'static,
    ) -> Self {
        Self {
            locations: PagedLocations::new(limit),
            failed: false,
            check: Box::new(check),
        }
    }

    pub(in crate::engine::durable) fn push(
        &mut self,
        id: ObjectId,
        location: ArenaLocation,
        proof: ClosureProof,
    ) -> Result<(), DurableError> {
        self.require_healthy()?;
        // During construction every replacement supplies its entire row. The
        // ordered merge selects the newest duplicate; no prior lookup is needed.
        let result = self.locations.insert_row_checked(
            id,
            LocatorValue { location, proof },
            None,
            &mut self.check,
        );
        self.failed |= result.is_err();
        result
    }

    pub(in crate::engine::durable) fn finish(
        mut self,
    ) -> Result<(PagedLocations, usize), DurableError> {
        self.require_healthy()?;
        if self.locations.runs.is_empty() {
            // A small catalogue already fits the existing resident budget.
            // Replacement rows are unique here even when frame counts are not.
            self.locations.count = self.locations.resident.len();
            let complete = self
                .locations
                .resident
                .iter()
                .filter(|(_, row)| row.proof == ClosureProof::Complete)
                .count();
            return Ok((self.locations, complete));
        }
        self.locations.merged_runs(Some(&mut self.check))
    }

    fn require_healthy(&self) -> Result<(), DurableError> {
        if self.failed || self.locations.failed() {
            return Err(DurableError::InvalidRepresentationState(
                "locator rebuild failed",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
