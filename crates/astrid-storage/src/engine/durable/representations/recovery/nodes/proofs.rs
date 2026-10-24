//! Disposable journal reachability, separate from immutable admitted locations.
//!
//! The absent private path-copy table lends its staging partition during replay.
//! Historical proofs spill to authenticated anonymous runs, never a resident set.

use super::{
    AuthenticatedPageMemo, DurableError, LocationIndexMemoryBudget, ObjectId, PagedLocations,
};

pub(super) struct JournalProofs {
    locations: PagedLocations,
    pages: AuthenticatedPageMemo,
    source_epoch: u64,
    budget: LocationIndexMemoryBudget,
    failed: bool,
}

impl JournalProofs {
    pub(super) fn new(budget: LocationIndexMemoryBudget, source_epoch: u64) -> Self {
        Self {
            locations: PagedLocations::new(budget.durable_entries()),
            pages: AuthenticatedPageMemo::default(),
            source_epoch,
            budget,
            failed: false,
        }
    }

    #[cfg(test)]
    pub(super) fn resident_capacity_bytes(&self) -> usize {
        self.locations.resident_capacity_bytes()
    }

    #[cfg(test)]
    pub(super) fn damage_run_after_inserts(&mut self, count: usize) {
        self.locations.damage_run_after_inserts(count);
    }

    #[cfg(test)]
    pub(super) fn truncate_test_run(&self) {
        self.locations.truncate_test_run();
    }

    pub(super) fn require_healthy(&self, source: &PagedLocations) -> Result<(), DurableError> {
        if self.failed || self.locations.failed() || source.failed() {
            return Err(DurableError::InvalidRepresentationState(
                "failed journal reachability locator",
            ));
        }
        Ok(())
    }

    pub(super) fn fence(&mut self) {
        self.failed = true;
    }

    fn sync(&mut self, source: &PagedLocations) -> Result<(), DurableError> {
        self.require_healthy(source)?;
        // Base run replacement revokes every dependent proof. Replacement of
        // a proof run itself rebinds pages through AuthenticatedPageMemo::sync.
        if self.source_epoch != source.runs_epoch() {
            *self = Self::new(self.budget, source.runs_epoch());
        }
        Ok(())
    }

    pub(super) fn complete(
        &mut self,
        id: ObjectId,
        source: &PagedLocations,
        source_pages: &mut AuthenticatedPageMemo,
    ) -> Result<bool, DurableError> {
        self.sync(source)?;
        let result = (|| {
            if self.locations.location_memo(id, &mut self.pages)?.is_some() {
                return Ok(true);
            }
            // An unproved query still authenticates its base path, including
            // absence. A missing proof must not hide previously unseen damage.
            source.location_memo(id, source_pages)?;
            Ok(false)
        })();
        self.failed |= result.is_err();
        result
    }

    pub(super) fn remember(
        &mut self,
        id: ObjectId,
        source: &PagedLocations,
        source_pages: &mut AuthenticatedPageMemo,
    ) -> Result<(), DurableError> {
        self.sync(source)?;
        let result = (|| {
            let location = source.location_memo(id, source_pages)?.ok_or(
                DurableError::InvalidRepresentationState("closure proof has no object locator"),
            )?;
            self.locations.insert_memo(id, location, &mut self.pages)
        })();
        self.failed |= result.is_err();
        result
    }
}
