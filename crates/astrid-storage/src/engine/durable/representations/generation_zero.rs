//! Streaming selected direct placements without retaining a corpus of locators.

use super::{
    ArenaLocation, BTreeMap, DurableError, FRAME_HEADER_LEN, ObjectId, PhysicalMapKey,
    PlacementEntry, Recipe, ReplicaLocator, RepresentationRecord, RepresentationStore,
    index_validation,
};

pub(super) fn locations(placement: &PlacementEntry) -> impl Iterator<Item = ArenaLocation> + '_ {
    placement.replicas().iter().filter_map(|replica| {
        if let ReplicaLocator::ArenaFrame {
            arena_generation: 0,
            offset,
            payload_length,
            frame_checksum,
        } = replica.locator()
        {
            Some(ArenaLocation {
                offset,
                payload_len: payload_length,
                checksum: frame_checksum,
            })
        } else {
            None
        }
    })
}

impl RepresentationStore {
    /// Return the arena prefix proven durable by published physical state.
    ///
    /// A malformed frame below this boundary is corruption, not a repairable
    /// uncommitted tail. Recovery consults this value before it may truncate
    /// the logical arena.
    pub(in crate::engine::durable) fn generation_zero_protected_len(
        &self,
    ) -> Result<u64, DurableError> {
        let mut protected = 0;
        self.visit_direct_placements(|_, placement| {
            for location in locations(placement) {
                let end = location
                    .offset
                    .checked_add(FRAME_HEADER_LEN)
                    .and_then(|value| value.checked_add(location.payload_len))
                    .ok_or(DurableError::EncodingOverflow)?;
                protected = protected.max(end);
            }
            Ok(())
        })?;
        Ok(protected)
    }

    /// Validate that generation-zero placements name the recovered arena
    /// index exactly.
    ///
    /// This is mount-time topology validation, not an implicit full-store
    /// scrub. Authoritative object reads verify the named frame checksum,
    /// canonical encoding, and logical identity before returning bytes. A
    /// scheduled refinery pass owns proactive full-corpus re-attestation.
    pub(in crate::engine::durable) fn validate_generation_zero_index(
        &self,
        index: &BTreeMap<ObjectId, ArenaLocation>,
    ) -> Result<(), DurableError> {
        self.visit_direct_placements(|object, placement| {
            index_validation::validate_object(object, locations(placement), index)
        })
    }

    // Selection and all placement decoding precede consumer errors in the old
    // collected path. Retain its first consumer error, but keep decoding so a
    // later selection/placement error keeps its existing precedence. Consumers
    // own only private temporary folds and never publish intermediate results.
    pub(super) fn visit_direct_placements(
        &self,
        mut visit: impl FnMut(&ObjectId, &PlacementEntry) -> Result<(), DurableError>,
    ) -> Result<(), DurableError> {
        let mut consumed = Ok(());
        for (object, records) in &self.reverse {
            let record = records
                .iter()
                .filter_map(|id| {
                    self.representations
                        .get(PhysicalMapKey::from(*id))
                        .and_then(|bytes| RepresentationRecord::decode(bytes).ok())
                })
                .find(|record| record.profile() == self.direct_profile)
                .ok_or(DurableError::InvalidRepresentationState(
                    "reverse index has no direct representation",
                ))?;
            let Recipe::DirectCanonical { blob } = record.recipe() else {
                return Err(DurableError::InvalidRepresentationState(
                    "direct profile uses a non-direct recipe",
                ));
            };
            let bytes = self
                .placement_entries
                .get(PhysicalMapKey::from(*blob))
                .ok_or(DurableError::InvalidRepresentationState(
                    "direct representation placement disappeared",
                ))?;
            let placement = PlacementEntry::decode(bytes)?;
            if locations(&placement).next().is_none() {
                return Err(DurableError::InvalidRepresentationState(
                    "direct representation has no generation-zero arena placement",
                ));
            }
            if consumed.is_ok() {
                consumed = visit(object, &placement);
            }
        }
        consumed
    }
}

#[cfg(test)]
mod tests;
