//! Bounded coverage requests; no query-sized node payload cache.
use super::super::super::ArenaLocation;
use super::super::super::locations::{LocationIndexMemoryBudget, LocationLookup};
use super::{
    Blake3PhysicalIdentity, DirectRecords, DurableError, ObjectId, PhysicalMapKey,
    RepresentationStore,
};
use std::collections::BTreeSet;

impl RepresentationStore {
    pub(in crate::engine::durable) fn missing_direct_records(
        &self,
        locations: &impl LocationLookup,
        excluded: &BTreeSet<ObjectId>,
        budget: LocationIndexMemoryBudget,
    ) -> Result<Vec<(ObjectId, ArenaLocation)>, DurableError> {
        // Request, selected reverse head and sorted key vectors together use
        // at most a quarter of the configured staging target (one row at the
        // historical minimum). Bodies remain transient, one tree node at a time.
        let row_bytes = std::mem::size_of::<(ObjectId, ArenaLocation)>()
            .strict_add(std::mem::size_of::<(PhysicalMapKey, ObjectId)>())
            .strict_add(std::mem::size_of::<PhysicalMapKey>());
        let capacity = usize::try_from(budget.bytes().get())
            .map_err(|_| DurableError::EncodingOverflow)?
            .checked_div(4)
            .and_then(|bytes| bytes.checked_div(row_bytes))
            .ok_or(DurableError::EncodingOverflow)?
            .max(1);
        let mut records = self.direct_records();
        let mut batch = Vec::new();
        batch
            .try_reserve_exact(capacity)
            .map_err(|_| DurableError::EncodingOverflow)?;
        let mut missing = Vec::new();
        for entry in locations.locations() {
            let (object, location) = entry?;
            if !excluded.contains(&object) {
                batch.push((object, location));
            }
            if batch.len() == capacity {
                records.visit_missing(&batch, |object, location| {
                    missing.push((object, location));
                })?;
                batch.clear();
            }
        }
        records.visit_missing(&batch, |object, location| {
            missing.push((object, location));
        })?;
        Ok(missing)
    }
}

impl DirectRecords<'_> {
    /// The caller bounds `objects` by its recovery workspace. Selected reverse
    /// heads are exact; only shared map ancestors are read once within a batch.
    pub(super) fn visit_missing(
        &mut self,
        objects: &[(ObjectId, ArenaLocation)],
        mut missing: impl FnMut(ObjectId, ArenaLocation),
    ) -> Result<(), DurableError> {
        if self.store.reverse.failed() || self.store.persisted_map_nodes.failed() {
            return Err(DurableError::InvalidRepresentationState(
                "failed direct-record scan",
            ));
        }
        let mut selected = Vec::new();
        selected
            .try_reserve_exact(objects.len())
            .map_err(|_| DurableError::EncodingOverflow)?;
        for &(object, location) in objects {
            if let Some(id) = self
                .store
                .reverse
                .first_memo(object, &mut self.reverse_pages)?
            {
                selected.push((PhysicalMapKey::from(id), object));
            } else {
                missing(object, location);
            }
        }
        selected.sort_unstable_by_key(|entry| entry.0);
        let mut keys = Vec::new();
        keys.try_reserve_exact(selected.len())
            .map_err(|_| DurableError::EncodingOverflow)?;
        keys.extend(selected.iter().map(|entry| entry.0));
        self.representations
            .try_visit_sorted(&Blake3PhysicalIdentity, &keys, |key, bytes| {
                let at = selected
                    .binary_search_by_key(&key, |entry| entry.0)
                    .map_err(|_| {
                        DurableError::InvalidRepresentationState(
                            "batch returned an unrequested record",
                        )
                    })?;
                self.validate(selected[at].1, bytes)?;
                Ok(())
            })
    }
}
