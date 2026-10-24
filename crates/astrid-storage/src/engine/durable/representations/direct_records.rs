//! Authentication-page reuse lasts only for an immutable direct-record scan.
use super::super::locations::AuthenticatedPageMemo;
use super::cold::ColdMemoNodes;
use super::{
    Blake3PhysicalIdentity, Coverage, DurableError, ObjectId, PhysicalMapKey, Recipe,
    RepresentationRecord, RepresentationStore,
};
use crate::storage_model::BackedPhysicalMap;

pub(in crate::engine::durable) struct DirectRecords<'a> {
    store: &'a RepresentationStore,
    reverse_pages: AuthenticatedPageMemo,
    representations: BackedPhysicalMap<ColdMemoNodes<'a>>,
}

impl RepresentationStore {
    pub(in crate::engine::durable) fn direct_records(&self) -> DirectRecords<'_> {
        DirectRecords {
            store: self,
            reverse_pages: AuthenticatedPageMemo::default(),
            representations: self
                .representations
                .with_node_provider(self.persisted_map_nodes.memoized_nodes()),
        }
    }
}

impl DirectRecords<'_> {
    pub(in crate::engine::durable) fn record(
        &mut self,
        object: ObjectId,
    ) -> Result<Option<RepresentationRecord>, DurableError> {
        if self.store.reverse.failed() || self.store.persisted_map_nodes.failed() {
            return Err(DurableError::InvalidRepresentationState(
                "failed direct-record scan",
            ));
        }
        let Some(id) = self
            .store
            .reverse
            .first_memo(object, &mut self.reverse_pages)?
        else {
            return Ok(None);
        };
        // The earliest admitted ID preserves selection order. Page evidence
        // never substitutes for freshly authenticated link and record bodies.
        let bytes = self
            .representations
            .try_get(&Blake3PhysicalIdentity, PhysicalMapKey::from(id))?
            .ok_or(DurableError::InvalidRepresentationState(
                "reverse index references a missing representation",
            ))?;
        let record = RepresentationRecord::decode(&bytes)?;
        if record.profile() != self.store.direct_profile
            || !matches!(record.coverage(), Coverage::Exact { object: covered, .. } if *covered == object)
            || !matches!(record.recipe(), Recipe::DirectCanonical { .. })
        {
            return Err(DurableError::InvalidRepresentationState(
                "direct profile has incompatible coverage or recipe",
            ));
        }
        Ok(Some(record))
    }
}

#[cfg(test)]
mod tests;
