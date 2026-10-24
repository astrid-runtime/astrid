//! Transactional streaming consolidation for long immutable locator walks.
use super::{
    Builder, CheckDuplicate, DurableError, LocatorValue, NonZeroUsize, ObjectId, Ordering,
    PagedLocations,
};
use crate::engine::durable::locations::ClosureProof;

impl PagedLocations {
    /// Remove per-node searches across older runs before a full checkpoint walk.
    /// Every historical row survives; newest locations and proof bits are exact.
    pub(in crate::engine::durable) fn consolidate(&mut self) -> Result<(), DurableError> {
        if self.failed() {
            return Err(DurableError::InvalidRepresentationState(
                "cannot consolidate failed locator",
            ));
        }
        if self.runs.is_empty()
            || (self.resident.is_empty() && self.runs.iter().flatten().count() == 1)
        {
            return Ok(());
        }
        let result = self.merged_runs(None).and_then(|(replacement, _)| {
            if replacement.count != self.count {
                return Err(DurableError::InvalidRepresentationState(
                    "consolidated locator count changed",
                ));
            }
            Ok(replacement)
        });
        let replacement = result.inspect_err(|_| self.failed.store(true, Ordering::Release))?;
        // No input owner is dropped until the complete output has been flushed.
        // Rebinding page memos precedes publication of the replacement run set.
        self.runs_epoch.fetch_add(1, Ordering::AcqRel);
        let epoch = self.runs_epoch.load(Ordering::Acquire);
        replacement.runs_epoch.store(epoch, Ordering::Release);
        *self = replacement;
        Ok(())
    }

    pub(super) fn merged_runs<'a>(
        &'a self,
        check: Option<&'a mut CheckDuplicate<'a>>,
    ) -> Result<(Self, usize), DurableError> {
        Self::from_sorted_rows(self.limit, self.rows_checked(check))
    }

    pub(super) fn from_sorted_rows(
        limit: NonZeroUsize,
        rows: impl IntoIterator<Item = Result<(ObjectId, LocatorValue), DurableError>>,
    ) -> Result<(Self, usize), DurableError> {
        let mut builder = Builder::new()?;
        let mut complete = 0_usize;
        for entry in rows {
            let (id, row) = entry?;
            complete = complete
                .checked_add(usize::from(row.proof == ClosureProof::Complete))
                .ok_or(DurableError::EncodingOverflow)?;
            builder.push_row(id, row)?;
        }
        let mut locations = PagedLocations::new(limit);
        if let Some(run) = builder.finish()? {
            locations.count = run.count;
            let mut capacity = locations.limit.get();
            let mut level = 0_usize;
            while capacity < run.count {
                capacity = capacity.saturating_mul(2);
                level = level.checked_add(1).ok_or(DurableError::EncodingOverflow)?;
            }
            locations.runs.resize_with(level.strict_add(1), || None);
            locations.runs[level] = Some(run);
        }
        Ok((locations, complete))
    }
}

#[cfg(test)]
mod tests;
