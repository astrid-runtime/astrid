//! Rewrite only proof flags from an already ordered authenticated locator.
use super::{
    ClosureProof, DurableError, LocatorValue, NonZeroUsize, ObjectId, Ordering, PagedLocations,
};

impl PagedLocations {
    /// Preserve every selected identity/location while replacing its proof.
    /// Output remains private until the whole input and established count pass.
    pub(in crate::engine::durable) fn rebuild_proofs(
        &self,
        limit: NonZeroUsize,
        mut proof: impl FnMut(ObjectId) -> ClosureProof,
    ) -> Result<(Self, usize), DurableError> {
        if self.failed() {
            return Err(DurableError::InvalidRepresentationState(
                "cannot rewrite failed locator proofs",
            ));
        }
        let result = (|| {
            let mut replace = |id, mut row: LocatorValue| {
                row.proof = proof(id);
                (id, row)
            };
            let rebuilt = if self.runs.is_empty() && self.resident.len() < limit.get() {
                // Keep the existing bounded small-catalogue fast path. The
                // resident source and private output fit their staging quarters.
                let mut locations = Self::new(limit);
                locations
                    .resident
                    .try_reserve_exact(self.resident.len())
                    .map_err(|_| DurableError::EncodingOverflow)?;
                for (id, row) in &self.resident {
                    locations.resident.push(replace(*id, *row));
                }
                locations.count = locations.resident.len();
                let complete = locations
                    .resident
                    .iter()
                    .filter(|(_, row)| row.proof == ClosureProof::Complete)
                    .count();
                (locations, complete)
            } else {
                // rows() freshly authenticates every source run. The builder
                // enforces strict ordering and checks the final output flush.
                let rows = self
                    .rows()
                    .map(|entry| entry.map(|(id, row)| replace(id, row)));
                Self::from_sorted_rows(limit, rows)?
            };
            if rebuilt.0.count != self.count {
                return Err(DurableError::InvalidRepresentationState(
                    "rewritten locator count changed",
                ));
            }
            Ok(rebuilt)
        })();
        result.inspect_err(|_| self.failed.store(true, Ordering::Release))
    }

    pub(in crate::engine::durable) fn clear_proofs(&mut self) -> Result<(), DurableError> {
        let (replacement, _) = self.rebuild_proofs(self.limit, |_| ClosureProof::Unknown)?;
        // No old run owner is released until every output page and count pass.
        // A memo from the old proof generation must never satisfy the new one.
        self.runs_epoch.fetch_add(1, Ordering::AcqRel);
        replacement
            .runs_epoch
            .store(self.runs_epoch(), Ordering::Release);
        *self = replacement;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
