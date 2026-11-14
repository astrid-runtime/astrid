//! Automatic checkpoint adoption: prove sealed media equals the live tip, then
//! adopt handles after CURRENT publication without rebuilding owned maps.
//!
//! Compaction keeps reconstructing via `checkpoint_into` /
//! `prepare_checkpoint_volume` / `checkpoint_native`. Only automatic maintenance
//! (`checkpoint_volume`, `maybe_checkpoint_native`) uses this path.

use crate::storage_model::physical::CanonicalRootProof;
use crate::storage_model::physical::{PlacementMap, ProfileMap, RepresentationMap};
use crate::storage_model::{
    ObjectId, PhysicalMapNodeId, PlacementSet, RepresentationCatalogueRoot,
    RepresentationProfileId, RepresentationRecordId, RepresentationState, RepresentationStateId,
};
use std::collections::{BTreeMap, BTreeSet};

use super::super::super::scan_frames;
use super::super::activation::visit_new_reachable_map_nodes;
use super::super::recovery::{
    read_current_file, recover_metadata, validate_profile_entries, validate_representation_entries,
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

/// Field-split borrows freeze the complete tip while the disjoint journal is
/// digested. No proof crosses a mutation or survives this checkpoint operation.
struct LiveTipRefs<'a> {
    profiles: &'a ProfileMap,
    representations: &'a RepresentationMap,
    placement_entries: &'a PlacementMap,
    reverse: &'a BTreeMap<ObjectId, Vec<RepresentationRecordId>>,
    catalogue: RepresentationCatalogueRoot,
    placements: PlacementSet,
    state: RepresentationState,
    active: RepresentationStateId,
    direct_profile: RepresentationProfileId,
}

struct CanonicalTip<'a> {
    roots: [CanonicalRootProof<'a>; 3],
    reachable: BTreeSet<PhysicalMapNodeId>,
}

#[cfg(test)]
impl<'a> LiveTipRefs<'a> {
    fn prove(&self) -> Result<CanonicalTip<'a>, DurableError> {
        self.ensure_live_authority_binds_sealed_tip()?;
        let roots = [
            self.profiles.prove_root()?,
            self.representations.prove_root()?,
            self.placement_entries.prove_root()?,
        ];
        let reachable = roots
            .iter()
            .flat_map(|proof| proof.visited().iter().copied())
            .collect();
        Ok(CanonicalTip { roots, reachable })
    }
}

impl RepresentationStore {
    /// Shared codec/write path; cold consumers retain their independent walk.
    pub(super) fn emit_sealed_generation(
        &mut self,
        metadata: &mut DurableFile,
        journal: &mut DurableFile,
    ) -> Result<SealedGenerationEmit, DurableError> {
        self.flush()?;
        let generation = increment(self.journal_generation)?;
        let tip = LiveTipRefs {
            profiles: &self.profiles,
            representations: &self.representations,
            placement_entries: &self.placement_entries,
            reverse: &self.reverse,
            catalogue: self.catalogue,
            placements: self.placements,
            state: self.state,
            active: self.active,
            direct_profile: self.direct_profile,
        };
        tip.emit(metadata, journal, &mut self.journal, generation)
    }

    pub(super) fn prepare_sealed_adoption(
        &mut self,
        metadata: &mut DurableFile,
        journal: &mut DurableFile,
        limits: RecoveryLimits,
    ) -> Result<(CurrentPointer, VerifiedSealedAdoption), DurableError> {
        self.flush()?;
        let generation = increment(self.journal_generation)?;
        let tip = LiveTipRefs {
            profiles: &self.profiles,
            representations: &self.representations,
            placement_entries: &self.placement_entries,
            reverse: &self.reverse,
            catalogue: self.catalogue,
            placements: self.placements,
            state: self.state,
            active: self.active,
            direct_profile: self.direct_profile,
        };
        let (canonical, emit) =
            tip.emit_proven(metadata, journal, &mut self.journal, generation)?;
        let current = emit.current;
        let proof = tip.verify(metadata, journal, &emit, limits, canonical)?;
        Ok((current, proof))
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

    #[cfg(test)]
    pub(super) fn verify_sealed_generation_for_adoption(
        &self,
        metadata: &mut DurableFile,
        journal: &mut DurableFile,
        emit: &SealedGenerationEmit,
        limits: RecoveryLimits,
    ) -> Result<VerifiedSealedAdoption, DurableError> {
        let tip = LiveTipRefs {
            profiles: &self.profiles,
            representations: &self.representations,
            placement_entries: &self.placement_entries,
            reverse: &self.reverse,
            catalogue: self.catalogue,
            placements: self.placements,
            state: self.state,
            active: self.active,
            direct_profile: self.direct_profile,
        };
        let canonical = tip.prove()?;
        tip.verify(metadata, journal, emit, limits, canonical)
    }
}

impl<'a> LiveTipRefs<'a> {
    fn emit_proven(
        &self,
        metadata: &mut DurableFile,
        journal: &mut DurableFile,
        prior_journal: &mut DurableFile,
        generation: u64,
    ) -> Result<(CanonicalTip<'a>, SealedGenerationEmit), DurableError> {
        self.ensure_live_authority_binds_sealed_tip()?;
        let mut stream = FramedAppendStream::begin(metadata, METADATA_MAGIC)?;
        // Domain-separated node IDs make cross-map collision impossible. Emit each
        // map's already-authenticated live bodies without a rebuild/identify storm;
        // fresh media verification still compares against every matching live arena.
        let mut append = |id: PhysicalMapNodeId, bytes: &[u8]| {
            let frame = MetadataFrame {
                kind: MetadataKind::MapNode,
                identity: *id.as_bytes(),
                value: bytes,
            };
            stream.append_payload(&frame.encode()?)?;
            Ok::<_, DurableError>(())
        };
        let roots = [
            self.profiles.encode_live_into(&mut append)?,
            self.representations.encode_live_into(&mut append)?,
            self.placement_entries.encode_live_into(&mut append)?,
        ];
        let reachable = roots
            .iter()
            .flat_map(|proof| proof.visited().iter().copied())
            .collect();
        let canonical = CanonicalTip { roots, reachable };
        // Incomplete private frames confer no authority. Do not finish/sync the
        // stream, append authority or journal frames, or publish CURRENT until
        // every root and independently walked set has passed its full proof.
        self.finish_metadata(stream)?;
        let emit = self.seal_generation(
            metadata,
            journal,
            prior_journal,
            generation,
            BTreeSet::new(),
        )?;
        Ok((canonical, emit))
    }
}

impl LiveTipRefs<'_> {
    fn emit(
        &self,
        metadata: &mut DurableFile,
        journal: &mut DurableFile,
        prior_journal: &mut DurableFile,
        generation: u64,
    ) -> Result<SealedGenerationEmit, DurableError> {
        let mut appended = BTreeSet::new();
        let mut complete = BTreeSet::new();
        let mut durable = BTreeSet::new();
        {
            let mut stream = FramedAppendStream::begin(metadata, METADATA_MAGIC)?;
            for map in [
                self.profiles.as_canonical(),
                self.representations.as_canonical(),
                self.placement_entries.as_canonical(),
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
            self.finish_metadata(stream)?;
        }
        self.seal_generation(metadata, journal, prior_journal, generation, appended)
    }

    fn finish_metadata(
        &self,
        mut stream: FramedAppendStream<'_, DurableFile>,
    ) -> Result<(), DurableError> {
        for frame in [
            MetadataFrame::catalogue(&Blake3PhysicalIdentity, self.catalogue),
            MetadataFrame::placement(&Blake3PhysicalIdentity, self.placements),
            MetadataFrame::state(&Blake3PhysicalIdentity, self.state),
        ] {
            stream.append_payload(&frame.encode()?)?;
        }
        stream.finish()
    }

    fn seal_generation(
        &self,
        metadata: &mut DurableFile,
        journal: &mut DurableFile,
        prior_journal: &mut DurableFile,
        generation: u64,
        appended: BTreeSet<PhysicalMapNodeId>,
    ) -> Result<SealedGenerationEmit, DurableError> {
        metadata
            .sync_data()
            .map_err(|source| io_error("flush checkpoint metadata", source))?;
        let prior = digest_journal_file(prior_journal, "digest prior representation journal")?;
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

    fn verify(
        &self,
        metadata: &mut DurableFile,
        journal: &mut DurableFile,
        emit: &SealedGenerationEmit,
        limits: RecoveryLimits,
        canonical: CanonicalTip<'_>,
    ) -> Result<VerifiedSealedAdoption, DurableError> {
        require_exact_len(metadata, emit.expected_metadata_len, "checkpoint metadata")?;
        require_exact_len(journal, emit.expected_journal_len, "checkpoint journal")?;
        self.scan_sealed_metadata_against_live(metadata, &canonical, limits)?;
        require_exact_len(metadata, emit.expected_metadata_len, "checkpoint metadata")?;
        self.ensure_live_semantic_agreement(&canonical)?;
        self.verify_exact_fresh_checkpoint_journal(journal, emit, limits)?;
        require_exact_len(journal, emit.expected_journal_len, "checkpoint journal")?;
        let map_frame_count =
            u64::try_from(canonical.reachable.len()).map_err(|_| DurableError::EncodingOverflow)?;
        Ok(VerifiedSealedAdoption {
            generation: emit.generation,
            verified_reachable: canonical.reachable,
            map_frame_count,
        })
    }

    fn scan_sealed_metadata_against_live(
        &self,
        metadata: &mut DurableFile,
        canonical: &CanonicalTip<'_>,
        limits: RecoveryLimits,
    ) -> Result<(), DurableError> {
        let mut saw_catalogue = false;
        let mut saw_placement = false;
        let mut saw_state = false;
        let mut observed = BTreeSet::new();
        scan_frames(
            metadata,
            format::METADATA_FILE,
            METADATA_MAGIC,
            limits,
            |_offset, payload| {
                let frame = MetadataFrame::decode(payload)?;
                match frame.kind {
                    MetadataKind::Profile | MetadataKind::Representation => {
                        Err(DurableError::InvalidRepresentationState(
                            "fresh checkpoint metadata contains legacy authority frames",
                        ))
                    },
                    MetadataKind::MapNode => {
                        inspect_map_node_frame(self, canonical, &frame)?;
                        if !observed.insert(PhysicalMapNodeId::new(frame.identity)) {
                            return Err(DurableError::InvalidRepresentationState(
                                "checkpoint metadata frame count disagrees with unique node set",
                            ));
                        }
                        Ok(())
                    },
                    MetadataKind::Catalogue => {
                        frame.verify(&Blake3PhysicalIdentity)?;
                        inspect_catalogue_frame(self, &mut saw_catalogue, &frame)
                    },
                    MetadataKind::Placement => {
                        frame.verify(&Blake3PhysicalIdentity)?;
                        inspect_placement_frame(self, &mut saw_placement, &frame)
                    },
                    MetadataKind::State => {
                        frame.verify(&Blake3PhysicalIdentity)?;
                        inspect_state_frame(self, &mut saw_state, &frame)
                    },
                }
            },
        )?;
        if !saw_catalogue || !saw_placement || !saw_state || observed != canonical.reachable {
            return Err(DurableError::InvalidRepresentationState(
                "checkpoint metadata contents disagree with the sealed tip",
            ));
        }
        Ok(())
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

    fn ensure_live_authority_binds_sealed_tip(&self) -> Result<(), DurableError> {
        if self.catalogue.identify(&Blake3PhysicalIdentity) != self.state.catalogue()
            || self.placements.identify(&Blake3PhysicalIdentity) != self.state.placements()
            || self.state.identify(&Blake3PhysicalIdentity) != self.active
            || self.catalogue.profiles_root() != self.profiles.root()
            || self.catalogue.profile_count() != self.profiles.entry_count()
            || self.catalogue.representations_root() != self.representations.root()
            || self.catalogue.representation_count() != self.representations.entry_count()
            || self.placements.entries_root() != self.placement_entries.root()
            || self.placements.blob_count() != self.placement_entries.entry_count()
        {
            return Err(DurableError::InvalidRepresentationState(
                "sealed authority roots disagree with the live tip",
            ));
        }
        Ok(())
    }

    fn ensure_live_semantic_agreement(
        &self,
        canonical: &CanonicalTip<'_>,
    ) -> Result<(), DurableError> {
        let direct_profile =
            validate_profile_entries(canonical.roots[0].entries().iter().copied())?;
        if direct_profile != self.direct_profile {
            return Err(DurableError::InvalidRepresentationState(
                "live direct profile disagrees with catalogue validation",
            ));
        }
        let validated = validate_representation_entries::<false, _>(
            self.profiles.as_canonical(),
            || Ok(canonical.roots[1].entries().iter().copied()),
            canonical.roots[2].entries().iter().copied(),
            direct_profile,
        )?;
        if validated.reverse != *self.reverse
            || validated.extent_count != self.placements.replica_extent_count()
        {
            return Err(DurableError::InvalidRepresentationState(
                "live reverse index disagrees with representation validation",
            ));
        }
        Ok(())
    }
}

impl RepresentationStore {
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
        self.profiles.reclaim_unreachable_nodes()?;
        self.representations.reclaim_unreachable_nodes()?;
        self.placement_entries.reclaim_unreachable_nodes()?;
        self.residency = MapResidency::new(
            self.profiles.as_canonical(),
            self.representations.as_canonical(),
            self.placement_entries.as_canonical(),
        );
        // Exact media closure verification authenticated every retained node's
        // descendants. Carry that fresh proof just as cold recovery does, so
        // the first following write need not traverse the whole unchanged tip.
        self.complete_map_subtrees = std::mem::take(&mut self.persisted_map_nodes);
        Ok(())
    }
}

fn inspect_map_node_frame(
    store: &LiveTipRefs<'_>,
    canonical: &CanonicalTip<'_>,
    frame: &MetadataFrame<&[u8]>,
) -> Result<(), DurableError> {
    let id = PhysicalMapNodeId::new(frame.identity);
    if !canonical.reachable.contains(&id) {
        return Err(DurableError::InvalidRepresentationState(
            "checkpoint metadata contains an unsealed map node",
        ));
    }
    // Typed birth/recovery already authenticated each live body's grammar and
    // identity under its domain map. Exact comparison below still binds fresh
    // media bytes to every matching live arena entry (including unreachable
    // adversarial aliases); decoding and hashing again would not add an
    // independent check beyond frame checksums and complete-closure scans.
    let mut matched = false;
    for map in [
        store.profiles.as_canonical(),
        store.representations.as_canonical(),
        store.placement_entries.as_canonical(),
    ] {
        if let Some(live) = map.nodes().get(&id) {
            matched = true;
            live.matches_encoded(frame.value).map_err(|_| {
                DurableError::InvalidRepresentationState(
                    "checkpoint metadata map node body disagrees with the live tip",
                )
            })?;
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
    store: &LiveTipRefs<'_>,
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
    store: &LiveTipRefs<'_>,
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
    store: &LiveTipRefs<'_>,
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

    pub(super) fn include_emitter_node(&mut self, id: PhysicalMapNodeId) {
        self.appended.insert(id);
    }

    pub(super) fn prior_journal_digest(&self) -> [u8; 32] {
        self.prior_journal_digest
    }

    pub(super) fn generation(&self) -> u64 {
        self.generation
    }
}
