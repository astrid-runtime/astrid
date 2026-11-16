//! Replay captured direct-publication tails through the ordinary map updater.
//!
//! The source journal remains in its original epoch. The ordinary publisher
//! writes the same state transition in the prepared generation's new epoch;
//! copying journal bytes would instead create invalid generation-bound CASes.
//!
//! Journal CAS frames are streamed one framed read at a time via
//! `read_frame_in_range`. Preflight inspects at most two CAS frames under the
//! writer fence and returns before metadata work when the residual is wider.
//! Destination unique map-node IDs come from the shared observed updater and a
//! fresh scan of that writer-produced metadata range; source binding is the
//! CAS/root compare plus the final maps/reverse fence. Catch-up does not retain
//! an all-CAS RAM queue or a separate observed-append index.

use super::super::CheckpointCancellation;
use std::collections::BTreeMap;

use crate::storage_model::{
    BlobId, Coverage, PhysicalMapDomain, PhysicalMapKey, PhysicalMapNode, PlacementEntry,
    PlacementSet, Recipe, ReplicaLocator, RepresentationCatalogueRoot, RepresentationRecord,
    RepresentationRecordId, RepresentationState, RepresentationStateId,
};

use super::super::super::format::{
    DurableFrameRange, DurablePrefixEnd, read_frame_in_range, scan_frames_range_with_source,
};
use super::super::{
    ArenaLocation, Blake3PhysicalIdentity, DirectArenaObject, DurableError, DurableFile,
    JOURNAL_MAGIC, JournalEntry, LOCAL_STORAGE_NODE, METADATA_MAGIC, MetadataFrame, MetadataKind,
    RecoveryLimits, RepresentationStore, format,
};
use super::adoption::ensure_not_cancelled;

/// A captured suffix of one source generation, before any worker publication.
pub(in crate::engine::durable) struct CheckpointTail {
    pub(in crate::engine::durable) metadata: DurableFrameRange,
    pub(in crate::engine::durable) journal: DurableFrameRange,
    pub(in crate::engine::durable) source_generation: u64,
    pub(in crate::engine::durable) expected_active: RepresentationStateId,
}

#[derive(Default)]
struct DirectPublication {
    records: BTreeMap<RepresentationRecordId, RepresentationRecord>,
    placements: BTreeMap<BlobId, PlacementEntry>,
    catalogue: Option<RepresentationCatalogueRoot>,
    placement_set: Option<PlacementSet>,
}

fn invalid(reason: &'static str) -> DurableError {
    DurableError::InvalidRepresentationState(reason)
}

impl RepresentationStore {
    /// Apply only committed, add-only direct publications. Rebase/compaction
    /// must cancel preparation through the engine's checkpoint owner first.
    /// All decoding, checked map mutation and possible dense rebuilds run on
    /// the worker, never during the final writer handover.
    pub(in crate::engine::durable) fn replay_checkpoint_tail(
        &mut self,
        source_metadata: &mut DurableFile,
        source_journal: &mut DurableFile,
        tail: &CheckpointTail,
        limits: RecoveryLimits,
        cancel: &impl CheckpointCancellation,
    ) -> Result<(), DurableError> {
        ensure_not_cancelled(cancel)?;
        if tail_is_empty(tail) {
            return if self.active == tail.expected_active {
                Ok(())
            } else {
                Err(invalid(
                    "empty checkpoint tail missed its captured authority",
                ))
            };
        }

        let mut cas = SourceJournalCas::open(source_journal, tail.journal, limits);
        let mut publication = DirectPublication::default();
        let mut state_count = 0_usize;
        scan_frames_range_with_source(
            source_metadata,
            format::METADATA_FILE,
            METADATA_MAGIC,
            limits,
            tail.metadata,
            |_, payload, _source| {
                ensure_not_cancelled(cancel)?;
                let frame = MetadataFrame::decode(payload)?;
                // Map nodes are decoded and authenticated together in accept,
                // which also consumes that same owned node's entries.
                if frame.kind != MetadataKind::MapNode {
                    frame.verify(&Blake3PhysicalIdentity)?;
                }
                if frame.kind == MetadataKind::State {
                    let state = RepresentationState::decode(frame.value)?;
                    let transition = cas.next(tail.source_generation)?;
                    if transition != (Some(self.active), state.identify(&Blake3PhysicalIdentity)) {
                        return Err(invalid("checkpoint tail CAS does not bind its metadata"));
                    }
                    state_count = state_count
                        .checked_add(1)
                        .ok_or(DurableError::EncodingOverflow)?;
                    std::mem::take(&mut publication).publish(self, state, limits, cancel)
                } else {
                    publication.accept(self, &frame)
                }
            },
        )?;
        ensure_not_cancelled(cancel)?;
        cas.finish(state_count)?;
        if !publication.is_empty() {
            return Err(invalid(
                "checkpoint tail has an incomplete direct publication",
            ));
        }
        if self.active != tail.expected_active {
            return Err(invalid("checkpoint tail missed its captured authority"));
        }
        Ok(())
    }

    /// Read-only residual predicate for the final physical fence.
    ///
    /// Empty ranges are accepted only when the captured tip still matches.
    /// A single `StateCas` is accepted only when the ordinary updater would not
    /// choose a dense rebuild. Wider residuals return `Ok(false)` without
    /// mutating the destination.
    pub(in crate::engine::durable) fn checkpoint_tail_is_nonbulk(
        &self,
        source_metadata: &mut DurableFile,
        source_journal: &mut DurableFile,
        tail: &CheckpointTail,
        limits: RecoveryLimits,
        cancel: &impl CheckpointCancellation,
    ) -> Result<bool, DurableError> {
        ensure_not_cancelled(cancel)?;
        if tail_is_empty(tail) {
            return if self.active == tail.expected_active {
                Ok(true)
            } else {
                Err(invalid(
                    "empty checkpoint tail missed its captured authority",
                ))
            };
        }

        // Under the physical fence, inspect at most two journal CAS frames.
        // Wider residuals return before any metadata decode/work.
        let mut cas = SourceJournalCas::open(source_journal, tail.journal, limits);
        ensure_not_cancelled(cancel)?;
        let Some((expected, _replacement)) = cas.next_cas(tail.source_generation)? else {
            return Err(invalid(
                "checkpoint metadata exceeds its committed journal suffix",
            ));
        };
        if expected != Some(self.active) {
            return Err(invalid("checkpoint tail CAS does not bind its metadata"));
        }
        ensure_not_cancelled(cancel)?;
        if cas.next_cas(tail.source_generation)?.is_some() {
            return Ok(false);
        }
        if cas.cursor() != cas.range_end() {
            return Err(invalid(
                "checkpoint tail has an incomplete direct publication",
            ));
        }

        let mut publication = DirectPublication::default();
        let mut additions = 0_usize;
        let mut saw_state = false;
        scan_frames_range_with_source(
            source_metadata,
            format::METADATA_FILE,
            METADATA_MAGIC,
            limits,
            tail.metadata,
            |_, payload, _source| {
                ensure_not_cancelled(cancel)?;
                let frame = MetadataFrame::decode(payload)?;
                frame.verify(&Blake3PhysicalIdentity)?;
                if frame.kind == MetadataKind::State {
                    if saw_state || !publication.has_authority() {
                        return Err(invalid(
                            "checkpoint tail has an incomplete direct publication",
                        ));
                    }
                    saw_state = true;
                    additions = publication.count_new_direct(self)?;
                    publication.clear_records();
                    Ok(())
                } else {
                    publication.accept(self, &frame)
                }
            },
        )?;
        ensure_not_cancelled(cancel)?;
        if !saw_state || !publication.is_empty() {
            return Err(invalid(
                "checkpoint tail has an incomplete direct publication",
            ));
        }
        if additions == 0 {
            return Err(invalid(
                "checkpoint tail CAS does not add a direct representation",
            ));
        }
        self.direct_update_is_nonbulk(additions)
    }
}

fn tail_is_empty(tail: &CheckpointTail) -> bool {
    tail.metadata.start() == tail.metadata.end() && tail.journal.start() == tail.journal.end()
}

/// Stream one source `StateCas` at a time from an exact committed journal range.
///
/// The cursor advances one framed CAS per call. Preflight therefore stops after
/// a second CAS without retaining a location vector or decoding metadata.
struct SourceJournalCas<'a> {
    journal: &'a mut DurableFile,
    limits: RecoveryLimits,
    range: DurableFrameRange,
    cursor: DurablePrefixEnd,
    reads: usize,
}

impl<'a> SourceJournalCas<'a> {
    fn open(
        journal: &'a mut DurableFile,
        range: DurableFrameRange,
        limits: RecoveryLimits,
    ) -> Self {
        Self {
            journal,
            limits,
            range,
            cursor: range.start(),
            reads: 0,
        }
    }

    const fn cursor(&self) -> DurablePrefixEnd {
        self.cursor
    }

    const fn range_end(&self) -> DurablePrefixEnd {
        self.range.end()
    }

    fn next_cas(
        &mut self,
        source_generation: u64,
    ) -> Result<Option<(Option<RepresentationStateId>, RepresentationStateId)>, DurableError> {
        let Some((location, payload)) = read_frame_in_range(
            self.journal,
            format::JOURNAL_FILE,
            JOURNAL_MAGIC,
            self.limits,
            self.range,
            self.cursor,
        )?
        else {
            return Ok(None);
        };
        self.cursor = location.end()?;
        self.reads = self
            .reads
            .checked_add(1)
            .ok_or(DurableError::EncodingOverflow)?;
        let JournalEntry::StateCas {
            journal_generation,
            expected,
            replacement,
        } = JournalEntry::decode(&payload)?
        else {
            return Err(invalid("checkpoint tail contains another checkpoint"));
        };
        if journal_generation != source_generation {
            return Err(invalid("checkpoint tail changed source generation"));
        }
        Ok(Some((expected, replacement)))
    }

    fn next(
        &mut self,
        source_generation: u64,
    ) -> Result<(Option<RepresentationStateId>, RepresentationStateId), DurableError> {
        self.next_cas(source_generation)?
            .ok_or_else(|| invalid("checkpoint metadata exceeds its committed journal suffix"))
    }

    fn finish(self, expected_reads: usize) -> Result<(), DurableError> {
        if self.cursor != self.range.end() || self.reads != expected_reads {
            return Err(invalid(
                "checkpoint tail has an incomplete direct publication",
            ));
        }
        Ok(())
    }
}

fn verify_checkpoint_journal_tail(
    journal: &mut DurableFile,
    range: DurableFrameRange,
    journal_generation: u64,
    expected_prior: RepresentationStateId,
    expected_replacement: RepresentationStateId,
    limits: RecoveryLimits,
    cancel: &impl CheckpointCancellation,
) -> Result<(), DurableError> {
    ensure_not_cancelled(cancel)?;
    let Some((location, payload)) = read_frame_in_range(
        journal,
        format::JOURNAL_FILE,
        JOURNAL_MAGIC,
        limits,
        range,
        range.start(),
    )?
    else {
        return Err(invalid(
            "checkpoint tail destination journal range is empty",
        ));
    };
    ensure_not_cancelled(cancel)?;
    let JournalEntry::StateCas {
        journal_generation: actual_generation,
        expected,
        replacement,
    } = JournalEntry::decode(&payload)?
    else {
        return Err(invalid(
            "checkpoint tail destination journal is not a state CAS",
        ));
    };
    if actual_generation != journal_generation
        || expected != Some(expected_prior)
        || replacement != expected_replacement
    {
        return Err(invalid(
            "checkpoint tail destination journal CAS disagrees with the rebased tip",
        ));
    }
    if location.end()? != range.end() {
        return Err(invalid(
            "checkpoint tail destination journal range is not a single CAS",
        ));
    }
    Ok(())
}

impl DirectPublication {
    fn is_empty(&self) -> bool {
        self.records.is_empty()
            && self.placements.is_empty()
            && self.catalogue.is_none()
            && self.placement_set.is_none()
    }

    fn has_authority(&self) -> bool {
        self.catalogue.is_some() && self.placement_set.is_some()
    }

    fn clear_records(&mut self) {
        self.records.clear();
        self.placements.clear();
        self.catalogue = None;
        self.placement_set = None;
    }

    fn count_new_direct(&self, store: &RepresentationStore) -> Result<usize, DurableError> {
        let mut additions = 0_usize;
        let mut placements = self.placements.clone();
        for record in self.records.values() {
            let Recipe::DirectCanonical { blob } = record.recipe() else {
                return Err(invalid("checkpoint tail adds a non-direct representation"));
            };
            let Coverage::Exact {
                object,
                canonical_record_bytes,
            } = record.coverage();
            let placement = placements.remove(blob).ok_or_else(|| {
                invalid("checkpoint tail direct representation has no new placement")
            })?;
            if record.profile() != store.direct_profile
                || placement.profile() != store.direct_profile
                || placement.encoded_length() != *canonical_record_bytes
            {
                return Err(invalid(
                    "checkpoint tail direct profile or length disagrees",
                ));
            }
            if !store.contains_direct(*object) {
                additions = additions
                    .checked_add(1)
                    .ok_or(DurableError::EncodingOverflow)?;
            }
        }
        if !placements.is_empty() {
            return Err(invalid("checkpoint tail contains unassociated placements"));
        }
        Ok(additions)
    }

    fn accept(
        &mut self,
        store: &RepresentationStore,
        frame: &MetadataFrame<&[u8]>,
    ) -> Result<(), DurableError> {
        match frame.kind {
            MetadataKind::MapNode => {
                let (node, id) =
                    PhysicalMapNode::decode_and_identify(frame.value, &Blake3PhysicalIdentity)?;
                if id.as_bytes() != &frame.identity {
                    return Err(invalid("metadata identity does not match canonical value"));
                }
                match &node {
                    PhysicalMapNode::Leaf { domain, key, value } => {
                        self.accept_entry(store, *domain, *key, value)?;
                    },
                    PhysicalMapNode::Page { domain, entries } => {
                        for (key, value) in entries {
                            self.accept_entry(store, *domain, *key, value)?;
                        }
                    },
                    PhysicalMapNode::Branch { .. } | PhysicalMapNode::Radix { .. } => {},
                }
            },
            MetadataKind::Catalogue => {
                if self
                    .catalogue
                    .replace(RepresentationCatalogueRoot::decode(frame.value)?)
                    .is_some()
                {
                    return Err(invalid("checkpoint tail repeats its catalogue"));
                }
            },
            MetadataKind::Placement => {
                if self
                    .placement_set
                    .replace(PlacementSet::decode(frame.value)?)
                    .is_some()
                {
                    return Err(invalid("checkpoint tail repeats its placement authority"));
                }
            },
            MetadataKind::Profile | MetadataKind::Representation | MetadataKind::State => {
                return Err(invalid(
                    "checkpoint tail is not an ordinary direct publication",
                ));
            },
        }
        Ok(())
    }

    fn accept_entry(
        &mut self,
        store: &RepresentationStore,
        domain: PhysicalMapDomain,
        key: PhysicalMapKey,
        value: &[u8],
    ) -> Result<(), DurableError> {
        let existing = match domain {
            PhysicalMapDomain::Profile => store.profiles.get(key),
            PhysicalMapDomain::Representation => store.representations.get(key),
            PhysicalMapDomain::Placement => store.placement_entries.get(key),
        };
        if let Some(existing) = existing {
            if existing != value {
                return Err(invalid(
                    "checkpoint tail replaces an existing physical entry",
                ));
            }
            return Ok(());
        }
        match domain {
            PhysicalMapDomain::Profile => Err(invalid("checkpoint tail adds a new profile")),
            PhysicalMapDomain::Representation => {
                let record = RepresentationRecord::decode(value)?;
                let id = record.identify(&Blake3PhysicalIdentity)?;
                if key != PhysicalMapKey::from(id) {
                    return Err(invalid("checkpoint tail representation key disagrees"));
                }
                if let Some(previous) = self.records.insert(id, record.clone())
                    && previous != record
                {
                    return Err(invalid("checkpoint tail repeats unequal representations"));
                }
                Ok(())
            },
            PhysicalMapDomain::Placement => {
                let entry = PlacementEntry::decode(value)?;
                if key != PhysicalMapKey::from(entry.blob()) {
                    return Err(invalid("checkpoint tail placement key disagrees"));
                }
                if let Some(previous) = self.placements.insert(entry.blob(), entry.clone())
                    && previous != entry
                {
                    return Err(invalid("checkpoint tail repeats unequal placements"));
                }
                Ok(())
            },
        }
    }

    fn publish(
        self,
        store: &mut RepresentationStore,
        state: RepresentationState,
        limits: RecoveryLimits,
        cancel: &impl CheckpointCancellation,
    ) -> Result<(), DurableError> {
        let mut objects = Vec::with_capacity(self.records.len());
        let mut placements = self.placements;
        for record in self.records.into_values() {
            let Recipe::DirectCanonical { blob } = record.recipe() else {
                return Err(invalid("checkpoint tail adds a non-direct representation"));
            };
            let Coverage::Exact {
                object,
                canonical_record_bytes,
            } = record.coverage();
            let placement = placements.remove(blob).ok_or_else(|| {
                invalid("checkpoint tail direct representation has no new placement")
            })?;
            if record.profile() != store.direct_profile
                || placement.profile() != store.direct_profile
                || placement.encoded_length() != *canonical_record_bytes
            {
                return Err(invalid(
                    "checkpoint tail direct profile or length disagrees",
                ));
            }
            let [replica] = placement.replicas() else {
                return Err(invalid("checkpoint tail has noncanonical direct replicas"));
            };
            if replica.storage_node() != LOCAL_STORAGE_NODE {
                return Err(invalid("checkpoint tail direct replica is not local"));
            }
            let ReplicaLocator::ArenaFrame {
                arena_generation: 0,
                offset,
                payload_length,
                frame_checksum,
            } = replica.locator()
            else {
                return Err(invalid(
                    "checkpoint tail changed the direct arena generation",
                ));
            };
            objects.push(DirectArenaObject {
                object: *object,
                blob: *blob,
                canonical_length: *canonical_record_bytes,
                location: ArenaLocation {
                    offset,
                    payload_len: payload_length,
                    checksum: frame_checksum,
                },
            });
        }
        if !placements.is_empty() {
            return Err(invalid("checkpoint tail contains unassociated placements"));
        }

        let prior_active = store.active;
        let journal_generation = store.journal_generation;
        let (update, evidence) = store
            .append_direct_update_observed(&objects)?
            .ok_or_else(|| invalid("checkpoint tail CAS does not add a direct representation"))?;
        if update.state != state
            || Some(update.catalogue) != self.catalogue
            || Some(update.placements) != self.placement_set
        {
            return Err(invalid(
                "checkpoint tail roots disagree with checked direct replay",
            ));
        }
        if evidence.appended_map_nodes.is_empty()
            || evidence.metadata.start() == evidence.metadata.end()
        {
            return Err(invalid(
                "checkpoint tail destination emitted no physical map evidence",
            ));
        }
        let metadata_range = evidence.metadata;
        let expected_nodes = evidence.appended_map_nodes;
        let expected_replacement = update.state_id;
        ensure_not_cancelled(cancel)?;
        // flushMetadata -> appendCAS -> flushJournal happens inside publish.
        let journal_range = store.publish_direct_update_observed(update)?;
        if journal_range.start() == journal_range.end() {
            return Err(invalid(
                "checkpoint tail destination journal range is empty",
            ));
        }
        // Fresh destination proofs run only after both durability flushes.
        store.verify_checkpoint_metadata_tail(metadata_range, &expected_nodes, limits, cancel)?;
        verify_checkpoint_journal_tail(
            &mut store.journal,
            journal_range,
            journal_generation,
            prior_active,
            expected_replacement,
            limits,
            cancel,
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
