//! One authoritative direct updater for normal commits and checkpoint catch-up.

use super::super::{
    ArenaLocation, Blake3PhysicalIdentity, DirectArenaObject, DurableError, FRAME_HEADER_LEN,
    JOURNAL_MAGIC, JournalEntry, LOCAL_STORAGE_NODE, METADATA_MAGIC, MetadataFrame,
    PendingRepresentationUpdate, RepresentationStore, append_frame, append_frames,
    append_new_reachable_map_nodes, bulk_rebuild_is_cheaper, increment, residency,
};
use crate::engine::durable::format::{DurableFrameRange, DurablePrefixEnd};
use crate::storage_model::physical::{PlacementMap, RepresentationMap};
use crate::storage_model::{
    Coverage, ObjectId, PhysicalMapKey, PhysicalMapNodeId, PlacementEntry, PlacementSet, Recipe,
    Replica, ReplicaLocator, RepresentationCatalogueRoot, RepresentationProfile,
    RepresentationRecord, RepresentationRecordId, RepresentationState,
};
use std::collections::{BTreeMap, BTreeSet};

pub(in crate::engine::durable::representations) struct DirectUpdateEvidence {
    pub(in crate::engine::durable::representations) metadata: DurableFrameRange,
    pub(in crate::engine::durable::representations) appended_map_nodes: BTreeSet<PhysicalMapNodeId>,
}

struct DirectMapEntry {
    object: ObjectId,
    representation: (PhysicalMapKey, Vec<u8>),
    representation_id: RepresentationRecordId,
    placement: (PhysicalMapKey, Vec<u8>),
}

impl RepresentationStore {
    pub(in crate::engine::durable) fn append_direct_update(
        &mut self,
        objects: &[DirectArenaObject],
    ) -> Result<Option<PendingRepresentationUpdate>, DurableError> {
        self.append_direct_update_with(objects, |_, _| Ok(()))
            .map(|result| result.map(|(update, ())| update))
    }

    pub(in crate::engine::durable::representations) fn append_direct_update_observed(
        &mut self,
        objects: &[DirectArenaObject],
    ) -> Result<Option<(PendingRepresentationUpdate, DirectUpdateEvidence)>, DurableError> {
        self.append_direct_update_with(objects, |locations, appended| {
            Ok(DirectUpdateEvidence {
                metadata: written_range(locations)?,
                appended_map_nodes: appended.clone(),
            })
        })
    }

    pub(in crate::engine::durable::representations) fn direct_update_is_nonbulk(
        &self,
        additions: usize,
    ) -> Result<bool, DurableError> {
        Ok(
            !bulk_rebuild_is_cheaper(self.representations.entry_count(), additions)?
                && !bulk_rebuild_is_cheaper(self.placement_entries.entry_count(), additions)?,
        )
    }

    fn append_direct_update_with<T>(
        &mut self,
        objects: &[DirectArenaObject],
        observe: impl FnOnce(&[ArenaLocation], &BTreeSet<PhysicalMapNodeId>) -> Result<T, DurableError>,
    ) -> Result<Option<(PendingRepresentationUpdate, T)>, DurableError> {
        let mut metadata = Vec::new();
        let profile = RepresentationProfile::decode(
            self.profiles
                .get(PhysicalMapKey::from(self.direct_profile))
                .ok_or(DurableError::InvalidRepresentationState(
                    "direct representation profile disappeared",
                ))?,
        )?;
        let mut entries = Vec::new();
        for object in objects {
            if !self.contains_direct(object.object) {
                entries.push(self.prepare_direct_entry(object, &profile)?);
            }
        }
        if entries.is_empty() {
            return Ok(None);
        }
        let rebuild_representations =
            bulk_rebuild_is_cheaper(self.representations.entry_count(), entries.len())?;
        let rebuild_placements =
            bulk_rebuild_is_cheaper(self.placement_entries.entry_count(), entries.len())?;
        let representation_entries = entries
            .iter()
            .map(|entry| entry.representation.clone())
            .collect::<Vec<_>>();
        let placement_entries = entries
            .iter()
            .map(|entry| entry.placement.clone())
            .collect::<Vec<_>>();
        if rebuild_representations {
            self.representations
                .rebuild_with_entries(representation_entries)?;
        } else {
            for (key, value) in representation_entries {
                self.representations.insert(key, value)?;
            }
        }
        if rebuild_placements {
            self.placement_entries
                .rebuild_with_entries(placement_entries)?;
        } else {
            for (key, value) in placement_entries {
                self.placement_entries.insert(key, value)?;
            }
        }
        let reverse_additions = entries
            .into_iter()
            .map(|entry| (entry.object, entry.representation_id))
            .collect();
        let mut appended_map_nodes = BTreeSet::new();
        append_new_reachable_map_nodes(
            &mut metadata,
            self.representations.as_canonical(),
            &mut self.persisted_map_nodes,
            &mut appended_map_nodes,
            &mut self.complete_map_subtrees,
        )?;
        append_new_reachable_map_nodes(
            &mut metadata,
            self.placement_entries.as_canonical(),
            &mut self.persisted_map_nodes,
            &mut appended_map_nodes,
            &mut self.complete_map_subtrees,
        )?;
        let (catalogue, placements, state) = self.next_authority()?;
        let state_id = state.identify(&Blake3PhysicalIdentity);
        metadata.push(MetadataFrame::catalogue(&Blake3PhysicalIdentity, catalogue));
        metadata.push(MetadataFrame::placement(
            &Blake3PhysicalIdentity,
            placements,
        ));
        metadata.push(MetadataFrame::state(&Blake3PhysicalIdentity, state));
        let payloads = metadata
            .iter()
            .map(MetadataFrame::encode)
            .collect::<Result<Vec<_>, _>>()?;
        let map_frames =
            u64::try_from(appended_map_nodes.len()).map_err(|_| DurableError::EncodingOverflow)?;
        let locations = append_frames(&mut self.metadata, METADATA_MAGIC, &payloads)?;
        let evidence = observe(&locations, &appended_map_nodes)?;
        self.persisted_map_nodes.extend(appended_map_nodes);
        self.map_frame_count = self
            .map_frame_count
            .checked_add(map_frames)
            .ok_or(DurableError::EncodingOverflow)?;
        Ok(Some((
            PendingRepresentationUpdate {
                state,
                state_id,
                catalogue,
                placements,
                reverse_additions,
                replacement_reverse: None,
            },
            evidence,
        )))
    }

    /// Replace every active physical representation with the supplied direct
    /// arena placement after compaction has materialized all live objects.
    pub(in crate::engine::durable) fn rebase_all_direct(
        &mut self,
        objects: &[DirectArenaObject],
    ) -> Result<(), DurableError> {
        if self.direct_authority_matches(objects)? {
            return Ok(());
        }
        let profile = RepresentationProfile::decode(
            self.profiles
                .get(PhysicalMapKey::from(self.direct_profile))
                .ok_or(DurableError::InvalidRepresentationState(
                    "direct representation profile disappeared",
                ))?,
        )?;
        let entries = objects
            .iter()
            .map(|object| self.prepare_direct_entry(object, &profile))
            .collect::<Result<Vec<_>, _>>()?;
        let representation_entries = entries
            .iter()
            .map(|entry| entry.representation.clone())
            .collect();
        let placement_entries = entries
            .iter()
            .map(|entry| entry.placement.clone())
            .collect();
        self.representations = RepresentationMap::build_dense(representation_entries)?;
        self.placement_entries = PlacementMap::build_dense(placement_entries)?;
        self.residency = residency::MapResidency::new(
            self.profiles.as_canonical(),
            self.representations.as_canonical(),
            self.placement_entries.as_canonical(),
        );
        let replacement_reverse = entries
            .into_iter()
            .map(|entry| (entry.object, vec![entry.representation_id]))
            .collect();

        let mut metadata = Vec::new();
        let mut appended_map_nodes = BTreeSet::new();
        for map in [
            self.representations.as_canonical(),
            self.placement_entries.as_canonical(),
        ] {
            append_new_reachable_map_nodes(
                &mut metadata,
                map,
                &mut self.persisted_map_nodes,
                &mut appended_map_nodes,
                &mut self.complete_map_subtrees,
            )?;
        }
        let (catalogue, placements, state) = self.next_authority()?;
        let state_id = state.identify(&Blake3PhysicalIdentity);
        metadata.extend([
            MetadataFrame::catalogue(&Blake3PhysicalIdentity, catalogue),
            MetadataFrame::placement(&Blake3PhysicalIdentity, placements),
            MetadataFrame::state(&Blake3PhysicalIdentity, state),
        ]);
        let payloads = metadata
            .iter()
            .map(MetadataFrame::encode)
            .collect::<Result<Vec<_>, _>>()?;
        let map_frames =
            u64::try_from(appended_map_nodes.len()).map_err(|_| DurableError::EncodingOverflow)?;
        append_frames(&mut self.metadata, METADATA_MAGIC, &payloads)?;
        self.persisted_map_nodes.extend(appended_map_nodes);
        self.map_frame_count = self
            .map_frame_count
            .checked_add(map_frames)
            .ok_or(DurableError::EncodingOverflow)?;
        let update = PendingRepresentationUpdate {
            state,
            state_id,
            catalogue,
            placements,
            reverse_additions: Vec::new(),
            replacement_reverse: Some(replacement_reverse),
        };
        self.publish_direct_update(update)?;
        self.flush()
    }

    fn direct_authority_matches(
        &self,
        objects: &[DirectArenaObject],
    ) -> Result<bool, DurableError> {
        let expected = objects
            .iter()
            .map(|object| (object.object, object.location))
            .collect::<BTreeMap<_, _>>();
        if expected.len() != objects.len()
            || self.representations.entry_count()
                != u64::try_from(objects.len()).map_err(|_| DurableError::EncodingOverflow)?
            || self.placement_entries.entry_count()
                != u64::try_from(objects.len()).map_err(|_| DurableError::EncodingOverflow)?
        {
            return Ok(false);
        }
        Ok(self
            .direct_arena_locations()?
            .into_iter()
            .collect::<BTreeMap<_, _>>()
            == expected)
    }

    fn prepare_direct_entry(
        &self,
        object: &DirectArenaObject,
        profile: &RepresentationProfile,
    ) -> Result<DirectMapEntry, DurableError> {
        let record = RepresentationRecord::new(
            self.direct_profile,
            Coverage::exact(object.object, object.canonical_length)?,
            Recipe::DirectCanonical { blob: object.blob },
            object.canonical_length,
            object.canonical_length,
            None,
        )?;
        record.validate_against_profile(&Blake3PhysicalIdentity, profile)?;
        let record_id = record.identify(&Blake3PhysicalIdentity)?;
        let replica = Replica::new(
            LOCAL_STORAGE_NODE,
            ReplicaLocator::ArenaFrame {
                arena_generation: 0,
                offset: object.location.offset,
                payload_length: object.location.payload_len,
                frame_checksum: object.location.checksum,
            },
        )?;
        let placement = PlacementEntry::new(
            object.blob,
            self.direct_profile,
            object.canonical_length,
            vec![replica],
        )?;
        Ok(DirectMapEntry {
            object: object.object,
            representation: (PhysicalMapKey::from(record_id), record.encode()?),
            representation_id: record_id,
            placement: (PhysicalMapKey::from(object.blob), placement.encode()?),
        })
    }

    fn next_authority(
        &self,
    ) -> Result<
        (
            RepresentationCatalogueRoot,
            PlacementSet,
            RepresentationState,
        ),
        DurableError,
    > {
        let catalogue = RepresentationCatalogueRoot::new(
            increment(self.catalogue.generation())?,
            self.profiles.root(),
            self.profiles.entry_count(),
            self.representations.root(),
            self.representations.entry_count(),
        )?;
        let placements = PlacementSet::new(
            increment(self.placements.epoch())?,
            self.placement_entries.root(),
            self.placement_entries.entry_count(),
            self.placement_entries.entry_count(),
        )?;
        let state = RepresentationState::new(
            increment(self.state.generation())?,
            Some(self.active),
            catalogue.identify(&Blake3PhysicalIdentity),
            placements.identify(&Blake3PhysicalIdentity),
        )?;
        Ok((catalogue, placements, state))
    }

    pub(in crate::engine::durable) fn publish_direct_update(
        &mut self,
        update: PendingRepresentationUpdate,
    ) -> Result<(), DurableError> {
        self.publish_direct_update_inner(update).map(|_| ())
    }

    pub(in crate::engine::durable::representations) fn publish_direct_update_observed(
        &mut self,
        update: PendingRepresentationUpdate,
    ) -> Result<DurableFrameRange, DurableError> {
        let location = self.publish_direct_update_inner(update)?;
        written_range(&[location])
    }

    fn publish_direct_update_inner(
        &mut self,
        update: PendingRepresentationUpdate,
    ) -> Result<ArenaLocation, DurableError> {
        self.flush_metadata()?;
        let cas = JournalEntry::StateCas {
            journal_generation: self.journal_generation,
            expected: Some(self.active),
            replacement: update.state_id,
        }
        .encode();
        let location = append_frame(&mut self.journal, JOURNAL_MAGIC, &cas)?;
        self.flush_journal()?;
        self.active = update.state_id;
        self.state = update.state;
        self.catalogue = update.catalogue;
        self.placements = update.placements;
        if let Some(replacement) = update.replacement_reverse {
            self.reverse = replacement;
        } else {
            for (object, representation) in update.reverse_additions {
                self.reverse.entry(object).or_default().push(representation);
            }
        }
        // These maps came from canonical recovery or checked model mutations.
        // Reclaim cannot fail on a valid trie. Propagate an invariant failure
        // rather than hiding corruption, even though authority is now durable.
        self.reclaim_map_history()?;
        Ok(location)
    }
}

/// Expected bounds come from the writer's produced frame locations, never a
/// post-write file-length observation that could bless a whole-frame omission.
fn written_range(locations: &[ArenaLocation]) -> Result<DurableFrameRange, DurableError> {
    let (Some(first), Some(last)) = (locations.first(), locations.last()) else {
        return Err(DurableError::InvalidRepresentationState(
            "direct update emitted no frames",
        ));
    };
    let end = last
        .offset
        .checked_add(FRAME_HEADER_LEN)
        .and_then(|end| end.checked_add(last.payload_len))
        .ok_or(DurableError::EncodingOverflow)?;
    DurableFrameRange::try_new(
        DurablePrefixEnd::exclusive(first.offset),
        DurablePrefixEnd::exclusive(end),
    )
}
