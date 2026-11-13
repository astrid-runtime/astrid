//! Automatic checkpoint adoption: prove sealed media equals the live tip, then
//! adopt handles after CURRENT publication without rebuilding owned maps.
//!
//! Compaction keeps reconstructing via `checkpoint_into` /
//! `prepare_checkpoint_volume` / `checkpoint_native`. Only automatic maintenance
//! (`checkpoint_volume`, `maybe_checkpoint_native`) uses this path.

use crate::storage_model::{
    CanonicalPhysicalMap, PhysicalMapDomain, PhysicalMapNode, PhysicalMapNodeId, PlacementSet,
    RepresentationCatalogueRoot, RepresentationState,
};
use std::collections::BTreeSet;

use super::super::super::scan_frames;
use super::super::activation::visit_new_reachable_map_nodes;
use super::super::recovery::{
    MetadataIndex, read_current_file, recover_metadata, recover_metadata_inspecting,
    validate_profiles, validate_representations,
};
use super::super::residency::MapResidency;
use super::super::{
    Blake3PhysicalIdentity, CurrentPointer, DurableError, DurableFile, FramedAppendStream,
    JOURNAL_MAGIC, JournalEntry, METADATA_MAGIC, MetadataFrame, MetadataKind, RecoveryLimits,
    RepresentationStore, append_frame, digest_journal_file, format, increment, io_error,
};

/// Emitted tip generation before media/journal correspondence proofs.
pub(super) struct SealedGenerationEmit {
    generation: u64,
    pub(super) current: CurrentPointer,
    appended: BTreeSet<PhysicalMapNodeId>,
    expected_metadata_len: u64,
    expected_journal_len: u64,
    prior_journal_digest: [u8; 32],
}

/// Private proof that sealed media matches the live tip and may adopt handles.
#[derive(Debug)]
pub(super) struct VerifiedSealedAdoption {
    generation: u64,
    verified_reachable: BTreeSet<PhysicalMapNodeId>,
    // Keep the protocol-width conversion checked before CURRENT publication.
    map_frame_count: u64,
}

impl RepresentationStore {
    /// Shared tip emit used by reconstructing and adopting consumers.
    pub(super) fn emit_sealed_generation(
        &mut self,
        metadata: &mut DurableFile,
        journal: &mut DurableFile,
    ) -> Result<SealedGenerationEmit, DurableError> {
        self.flush()?;
        let generation = increment(self.journal_generation)?;
        let mut appended = BTreeSet::new();
        let mut complete = BTreeSet::new();
        let mut durable = BTreeSet::new();
        {
            let mut stream = FramedAppendStream::begin(metadata, METADATA_MAGIC)?;
            for map in [
                &self.profiles,
                &self.representations,
                &self.placement_entries,
            ] {
                visit_new_reachable_map_nodes(
                    map,
                    &mut durable,
                    &mut appended,
                    &mut complete,
                    |node| {
                        let frame = MetadataFrame::map_node(&Blake3PhysicalIdentity, node)?;
                        stream.append_payload(&frame.encode()?)
                    },
                )?;
            }
            for frame in [
                MetadataFrame::catalogue(&Blake3PhysicalIdentity, self.catalogue),
                MetadataFrame::placement(&Blake3PhysicalIdentity, self.placements),
                MetadataFrame::state(&Blake3PhysicalIdentity, self.state),
            ] {
                stream.append_payload(&frame.encode()?)?;
            }
            stream.finish()?;
        }
        metadata
            .sync_data()
            .map_err(|source| io_error("flush checkpoint metadata", source))?;
        let prior = digest_journal_file(&mut self.journal, "digest prior representation journal")?;
        let checkpoint = JournalEntry::Checkpoint {
            journal_generation: generation,
            active: Some(self.active),
            state_generation: self.state.generation(),
            prior_journal_digest: Some(prior),
        };
        append_frame(journal, JOURNAL_MAGIC, &checkpoint.encode())?;
        journal
            .sync_data()
            .map_err(|source| io_error("flush checkpoint journal", source))?;
        let current = CurrentPointer {
            journal_generation: generation,
            checkpoint_digest: digest_journal_file(journal, "digest checkpoint journal")?,
            max_tail_frames: u32::MAX,
            max_tail_bytes: u64::MAX,
        };
        Ok(SealedGenerationEmit {
            generation,
            current,
            appended,
            expected_metadata_len: durable_len(metadata, "measure sealed checkpoint metadata")?,
            expected_journal_len: durable_len(journal, "measure sealed checkpoint journal")?,
            prior_journal_digest: prior,
        })
    }

    /// Reconstructing consumer used by prepare/compaction and `checkpoint_into`.
    pub(super) fn materialize_sealed_generation(
        &self,
        mut metadata: DurableFile,
        mut journal: DurableFile,
        emit: SealedGenerationEmit,
        limits: RecoveryLimits,
    ) -> Result<(Self, CurrentPointer), DurableError> {
        let SealedGenerationEmit {
            generation,
            current,
            appended,
            ..
        } = emit;
        // The independent consumer authenticates media itself. Release the
        // emission memo before allocating its recovered maps.
        drop(appended);
        let index = recover_metadata(&mut metadata, limits)?;
        let (active, state) =
            super::super::recovery::recover_journal(&mut journal, current, &index, limits)?;
        let (recovered, _) = Self::from_recovered::<false>(
            metadata, journal, generation, active, state, index, limits,
        )?;
        if recovered.active != self.active || recovered.reverse != self.reverse {
            return Err(DurableError::InvalidRepresentationState(
                "checkpoint changed physical authority",
            ));
        }
        Ok((recovered, current))
    }

    pub(super) fn verify_sealed_generation_for_adoption(
        &self,
        metadata: &mut DurableFile,
        journal: &mut DurableFile,
        emit: SealedGenerationEmit,
        limits: RecoveryLimits,
    ) -> Result<VerifiedSealedAdoption, DurableError> {
        require_exact_len(metadata, emit.expected_metadata_len, "checkpoint metadata")?;
        require_exact_len(journal, emit.expected_journal_len, "checkpoint journal")?;
        let index = self.scan_sealed_metadata_against_live(metadata, &emit, limits)?;
        require_exact_len(metadata, emit.expected_metadata_len, "checkpoint metadata")?;
        self.ensure_live_authority_binds_sealed_tip(&index)?;
        self.ensure_live_maps_still_canonical()?;
        self.ensure_live_semantic_agreement()?;
        self.verify_exact_fresh_checkpoint_journal(journal, &emit, limits)?;
        require_exact_len(journal, emit.expected_journal_len, "checkpoint journal")?;
        let map_frame_count =
            u64::try_from(emit.appended.len()).map_err(|_| DurableError::EncodingOverflow)?;
        if index.map_frame_count != map_frame_count {
            return Err(DurableError::InvalidRepresentationState(
                "checkpoint metadata frame count disagrees with the sealed tip",
            ));
        }
        Ok(VerifiedSealedAdoption {
            generation: emit.generation,
            verified_reachable: emit.appended,
            map_frame_count,
        })
    }

    fn scan_sealed_metadata_against_live(
        &self,
        metadata: &mut DurableFile,
        emit: &SealedGenerationEmit,
        limits: RecoveryLimits,
    ) -> Result<MetadataIndex, DurableError> {
        let mut saw_catalogue = false;
        let mut saw_placement = false;
        let mut saw_state = false;
        let index =
            recover_metadata_inspecting(metadata, limits, |_location, frame| match frame.kind {
                MetadataKind::Profile | MetadataKind::Representation => {
                    Err(DurableError::InvalidRepresentationState(
                        "fresh checkpoint metadata contains legacy authority frames",
                    ))
                },
                MetadataKind::MapNode => inspect_map_node_frame(self, emit, frame),
                MetadataKind::Catalogue => inspect_catalogue_frame(self, &mut saw_catalogue, frame),
                MetadataKind::Placement => inspect_placement_frame(self, &mut saw_placement, frame),
                MetadataKind::State => inspect_state_frame(self, &mut saw_state, frame),
            })?;
        if !saw_catalogue || !saw_placement || !saw_state {
            return Err(DurableError::InvalidRepresentationState(
                "checkpoint metadata contents disagree with the sealed tip",
            ));
        }
        // Unique indexed nodes + independent map_frame_count + tip closure prove
        // exact-once set equality with emit.appended (subset checked per frame).
        index.ensure_exact_tip_closure(
            [
                self.catalogue.profiles_root(),
                self.catalogue.representations_root(),
                self.placements.entries_root(),
            ],
            emit.appended.len(),
        )?;
        Ok(index)
    }

    fn verify_exact_fresh_checkpoint_journal(
        &self,
        journal: &mut DurableFile,
        emit: &SealedGenerationEmit,
        limits: RecoveryLimits,
    ) -> Result<(), DurableError> {
        let expected = JournalEntry::Checkpoint {
            journal_generation: emit.generation,
            active: Some(self.active),
            state_generation: self.state.generation(),
            prior_journal_digest: Some(emit.prior_journal_digest),
        };
        let mut saw_checkpoint = false;
        scan_frames(
            journal,
            format::JOURNAL_FILE,
            JOURNAL_MAGIC,
            limits,
            |_offset, payload| {
                if saw_checkpoint {
                    return Err(DurableError::InvalidRepresentationState(
                        "fresh checkpoint journal must contain exactly one frame",
                    ));
                }
                saw_checkpoint = true;
                let entry = JournalEntry::decode(payload)?;
                if entry != expected {
                    return Err(DurableError::InvalidRepresentationState(
                        "fresh checkpoint journal entry disagrees with the sealed tip",
                    ));
                }
                Ok(())
            },
        )?;
        if !saw_checkpoint {
            return Err(DurableError::InvalidRepresentationState(
                "fresh checkpoint journal must contain exactly one frame",
            ));
        }
        let digest = digest_journal_file(journal, "redigest sealed checkpoint journal")?;
        if digest != emit.current.checkpoint_digest {
            return Err(DurableError::InvalidRepresentationState(
                "checkpoint journal digest disagrees with the sealed pointer",
            ));
        }
        Ok(())
    }

    fn ensure_live_authority_binds_sealed_tip(
        &self,
        index: &MetadataIndex,
    ) -> Result<(), DurableError> {
        let catalogue = RepresentationCatalogueRoot::decode(
            index.value(MetadataKind::Catalogue, self.state.catalogue().as_bytes())?,
        )?;
        let placements = PlacementSet::decode(
            index.value(MetadataKind::Placement, self.state.placements().as_bytes())?,
        )?;
        let state =
            RepresentationState::decode(index.value(MetadataKind::State, self.active.as_bytes())?)?;
        if catalogue != self.catalogue
            || placements != self.placements
            || state != self.state
            || catalogue.profiles_root() != self.profiles.root()
            || catalogue.profile_count() != self.profiles.entry_count()
            || catalogue.representations_root() != self.representations.root()
            || catalogue.representation_count() != self.representations.entry_count()
            || placements.entries_root() != self.placement_entries.root()
            || placements.blob_count() != self.placement_entries.entry_count()
        {
            return Err(DurableError::InvalidRepresentationState(
                "sealed authority roots disagree with the live tip",
            ));
        }
        Ok(())
    }

    fn ensure_live_maps_still_canonical(&self) -> Result<(), DurableError> {
        for (map, domain) in [
            (&self.profiles, PhysicalMapDomain::Profile),
            (&self.representations, PhysicalMapDomain::Representation),
            (&self.placement_entries, PhysicalMapDomain::Placement),
        ] {
            let count = CanonicalPhysicalMap::validate_root(
                &Blake3PhysicalIdentity,
                domain,
                map.root(),
                map.nodes(),
            )?;
            if count != map.entry_count() {
                return Err(DurableError::InvalidRepresentationState(
                    "live physical map count disagrees with canonical validation",
                ));
            }
        }
        Ok(())
    }

    fn ensure_live_semantic_agreement(&self) -> Result<(), DurableError> {
        let direct_profile = validate_profiles(&self.profiles)?;
        if direct_profile != self.direct_profile {
            return Err(DurableError::InvalidRepresentationState(
                "live direct profile disagrees with catalogue validation",
            ));
        }
        let validated = validate_representations::<false>(
            &self.profiles,
            &self.representations,
            &self.placement_entries,
            direct_profile,
        )?;
        if validated.reverse != self.reverse
            || validated.extent_count != self.placements.replica_extent_count()
        {
            return Err(DurableError::InvalidRepresentationState(
                "live reverse index disagrees with representation validation",
            ));
        }
        Ok(())
    }

    /// After CURRENT publication, install new handles/generation and tip memos.
    pub(super) fn adopt_sealed_generation(
        &mut self,
        metadata: DurableFile,
        journal: DurableFile,
        proof: VerifiedSealedAdoption,
    ) -> Result<(), DurableError> {
        self.metadata = metadata;
        self.journal = journal;
        self.journal_generation = proof.generation;
        // Generation-bound memos must not survive a published handle transition
        // when a later prune fails. Clear/replace them before any fallible prune.
        self.complete_map_subtrees.clear();
        self.persisted_map_nodes = proof.verified_reachable;
        self.map_frame_count = proof.map_frame_count;
        for map in [
            &mut self.profiles,
            &mut self.representations,
            &mut self.placement_entries,
        ] {
            map.reclaim_unreachable_nodes()?;
        }
        self.residency = MapResidency::new(
            &self.profiles,
            &self.representations,
            &self.placement_entries,
        );
        // Exact media closure verification authenticated every retained node's
        // descendants. Carry that fresh proof just as cold recovery does, so
        // the first following write need not traverse the whole unchanged tip.
        self.complete_map_subtrees = std::mem::take(&mut self.persisted_map_nodes);
        Ok(())
    }
}

fn inspect_map_node_frame(
    store: &RepresentationStore,
    emit: &SealedGenerationEmit,
    frame: &MetadataFrame<&[u8]>,
) -> Result<(), DurableError> {
    let id = PhysicalMapNodeId::new(frame.identity);
    if !emit.appended.contains(&id) {
        return Err(DurableError::InvalidRepresentationState(
            "checkpoint metadata contains an unsealed map node",
        ));
    }
    // insert_at authenticates identity/codec; compare the decoded body to live.
    // Exact-once follows from subset checks plus unique/frame counts and tip closure.
    let decoded = PhysicalMapNode::decode(frame.value)?;
    let mut matched = false;
    for map in [
        &store.profiles,
        &store.representations,
        &store.placement_entries,
    ] {
        if let Some(live) = map.nodes().get(&id) {
            matched = true;
            if &decoded != live {
                return Err(DurableError::InvalidRepresentationState(
                    "checkpoint metadata map node body disagrees with the live tip",
                ));
            }
        }
    }
    if !matched {
        return Err(DurableError::InvalidRepresentationState(
            "checkpoint metadata map node is missing from the live tip",
        ));
    }
    Ok(())
}

fn inspect_catalogue_frame(
    store: &RepresentationStore,
    saw_catalogue: &mut bool,
    frame: &MetadataFrame<&[u8]>,
) -> Result<(), DurableError> {
    if *saw_catalogue {
        return Err(DurableError::InvalidRepresentationState(
            "checkpoint metadata repeats its catalogue frame",
        ));
    }
    *saw_catalogue = true;
    let decoded = RepresentationCatalogueRoot::decode(frame.value)?;
    if decoded != store.catalogue || frame.identity != *store.state.catalogue().as_bytes() {
        return Err(DurableError::InvalidRepresentationState(
            "checkpoint catalogue disagrees with the live tip",
        ));
    }
    Ok(())
}

fn inspect_placement_frame(
    store: &RepresentationStore,
    saw_placement: &mut bool,
    frame: &MetadataFrame<&[u8]>,
) -> Result<(), DurableError> {
    if *saw_placement {
        return Err(DurableError::InvalidRepresentationState(
            "checkpoint metadata repeats its placement frame",
        ));
    }
    *saw_placement = true;
    let decoded = PlacementSet::decode(frame.value)?;
    if decoded != store.placements || frame.identity != *store.state.placements().as_bytes() {
        return Err(DurableError::InvalidRepresentationState(
            "checkpoint placement set disagrees with the live tip",
        ));
    }
    Ok(())
}

fn inspect_state_frame(
    store: &RepresentationStore,
    saw_state: &mut bool,
    frame: &MetadataFrame<&[u8]>,
) -> Result<(), DurableError> {
    if *saw_state {
        return Err(DurableError::InvalidRepresentationState(
            "checkpoint metadata repeats its state frame",
        ));
    }
    *saw_state = true;
    let decoded = RepresentationState::decode(frame.value)?;
    if decoded != store.state || frame.identity != *store.active.as_bytes() {
        return Err(DurableError::InvalidRepresentationState(
            "checkpoint state disagrees with the live tip",
        ));
    }
    Ok(())
}

fn durable_len(file: &DurableFile, what: &'static str) -> Result<u64, DurableError> {
    file.metadata()
        .map(|metadata| metadata.len())
        .map_err(|source| io_error(what, source))
}

fn require_exact_len(
    file: &DurableFile,
    expected: u64,
    label: &'static str,
) -> Result<(), DurableError> {
    let actual = durable_len(file, "measure checkpoint media length")?;
    if actual != expected {
        return Err(DurableError::InvalidRepresentationState(match label {
            "checkpoint metadata" => "checkpoint metadata length disagrees with the sealed tip",
            _ => "checkpoint journal length disagrees with the sealed tip",
        }));
    }
    Ok(())
}

pub(super) fn write_verified_current_tmp(
    mut pointer: DurableFile,
    current: CurrentPointer,
    limits: RecoveryLimits,
) -> Result<(), DurableError> {
    append_frame(&mut pointer, format::CURRENT_MAGIC, &current.encode())?;
    pointer
        .sync_data()
        .map_err(|source| io_error("flush checkpoint pointer", source))?;
    if read_current_file(pointer, limits)? != current {
        return Err(DurableError::InvalidRepresentationState(
            "checkpoint pointer verification failed",
        ));
    }
    Ok(())
}

#[cfg(test)]
impl SealedGenerationEmit {
    /// Test-only: retarget sealed length expectations after a same-path media rewrite.
    pub(super) fn retarget_expected_lengths(&mut self, metadata_len: u64, journal_len: u64) {
        self.expected_metadata_len = metadata_len;
        self.expected_journal_len = journal_len;
    }

    pub(super) fn prior_journal_digest(&self) -> [u8; 32] {
        self.prior_journal_digest
    }

    pub(super) fn generation(&self) -> u64 {
        self.generation
    }
}
