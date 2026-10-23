//! Authoritative physical representation catalogue and placement state.

use std::collections::{BTreeMap, BTreeSet};
use std::io::SeekFrom;
use std::path::Path;

use crate::storage_model::{
    CanonicalPhysicalMap, Coverage, Dependency, ObjectId, PhysicalMapDomain, PhysicalMapKey,
    PlacementEntry, PlacementSet, ProfileDependency, Recipe, Replica, ReplicaLocator,
    RepresentationCatalogueRoot, RepresentationProfile, RepresentationProfileId,
    RepresentationRecord, RepresentationRecordId, RepresentationState, RepresentationStateId,
    StorageNodeId,
};

use super::File as DurableFile;
#[cfg(test)]
use super::open_rw;
use super::{
    ArenaLocation, DurableError, DurableIo, FRAME_HEADER_LEN, LocationIndexMemoryBudget,
    PersistentObjectIdentity, RecoveryLimits, append_frame, append_frames, canonical_record_bytes,
    io_error, read_indexed_object_with_payload,
};
use format::{
    Blake3PhysicalIdentity, CurrentPointer, JOURNAL_MAGIC, JournalEntry, METADATA_MAGIC,
    MetadataFrame, MetadataKind, journal_digest,
};

mod activation;
mod authority;
mod checkpoint;
mod format;
mod recovered_direct;
mod recovery;
mod residency;
mod reverse_index;

use reverse_index::ReverseIndex;

use activation::{append_new_reachable_map_nodes, build_initial_state, generation_name};
use recovery::{
    MetadataIndex, read_current_file, recover_journal, recover_metadata, validate_profiles,
    validate_representations,
};

mod batch;
mod cold;
mod contiguous;
mod node_view;
use cold::memoized_closure_handles;
use cold::{ColdNodes, ColdPhysicalMap};
mod direct;
mod volume;
use authority::{create_file as create_cap_file, open_file as open_cap_file, quarantine_entry};
pub(super) use contiguous::open_store_root;
use contiguous::{open_component, sync_directory};

pub(super) use direct::{DirectArenaObject, PreparedDirectArenaObject};

const DIRECTORY: &str = "representations";
const GENERATIONS_DIRECTORY: &str = "generations";
const METADATA_PATH: &str = "metadata.arena";
const JOURNAL_PATH: &str = "state.journal";
const CURRENT_PATH: &str = "CURRENT";
const CURRENT_TEMP_PATH: &str = "CURRENT.tmp";
const FIRST_JOURNAL_GENERATION: u64 = 1;
const LOCAL_STORAGE_NODE: StorageNodeId = StorageNodeId::new(0);

#[cfg(test)]
pub(super) fn profile_frame_count(
    path: &Path,
    limits: RecoveryLimits,
) -> Result<usize, DurableError> {
    let mut metadata = open_rw(path)?;
    let mut count = 0_usize;
    super::scan_frames(
        &mut metadata,
        format::METADATA_FILE,
        METADATA_MAGIC,
        limits,
        |_offset, payload| {
            let frame = MetadataFrame::decode(payload)?;
            count = count
                .checked_add(usize::from(frame.kind == MetadataKind::Profile))
                .ok_or(DurableError::EncodingOverflow)?;
            Ok(())
        },
    )?;
    Ok(count)
}

#[cfg(test)]
pub(super) fn append_legacy_profile_frame(
    path: &Path,
    frozen_specification: ObjectId,
) -> Result<(), DurableError> {
    let (profile, _) = activation::direct_profile(frozen_specification)?;
    let frame = MetadataFrame::profile(&Blake3PhysicalIdentity, &profile)?;
    let mut metadata = open_rw(path)?;
    append_frame(&mut metadata, METADATA_MAGIC, &frame.encode()?)?;
    metadata
        .sync_data()
        .map_err(|source| io_error("flush legacy profile frame", source))
}

#[derive(Debug)]
pub(super) struct RepresentationStore {
    metadata: DurableFile,
    journal: DurableFile,
    journal_generation: u64,
    active: RepresentationStateId,
    state: RepresentationState,
    catalogue: RepresentationCatalogueRoot,
    placements: PlacementSet,
    profiles: ColdPhysicalMap,
    representations: ColdPhysicalMap,
    placement_entries: ColdPhysicalMap,
    persisted_map_nodes: ColdNodes,
    residency: residency::MapResidency,
    direct_profile: RepresentationProfileId,
    reverse: ReverseIndex,
    recovered_direct: Option<(RepresentationStateId, recovered_direct::RecoveredDirect)>,
}

#[derive(Clone, Copy)]
struct RecoveredPhysicalAuthority {
    journal_generation: u64,
    active: RepresentationStateId,
    state: RepresentationState,
}

pub(super) struct PendingRepresentationUpdate {
    state: RepresentationState,
    state_id: RepresentationStateId,
    catalogue: RepresentationCatalogueRoot,
    placements: PlacementSet,
    reverse_additions: Vec<(ObjectId, RepresentationRecordId)>,
    replacement_reverse: Option<ReverseIndex>,
}

struct DirectMapEntry {
    object: ObjectId,
    representation: (PhysicalMapKey, Vec<u8>),
    representation_id: RepresentationRecordId,
    placement: (PhysicalMapKey, Vec<u8>),
}

impl RepresentationStore {
    pub(in crate::engine::durable) fn set_location_index_memory(
        &mut self,
        budget: LocationIndexMemoryBudget,
    ) -> Result<(), DurableError> {
        self.persisted_map_nodes.set_memory(budget)?;
        self.reverse.set_memory(budget)
    }

    pub(in crate::engine::durable) fn accelerator_failed(&self) -> bool {
        self.persisted_map_nodes.failed() || self.reverse.failed()
    }

    #[cfg(test)]
    pub(in crate::engine::durable) fn damage_reverse_run_after_inserts(&mut self, count: usize) {
        self.reverse.damage_run_after_inserts(count);
    }

    #[cfg(test)]
    pub(in crate::engine::durable) fn truncate_reverse_test_run(&self) {
        self.reverse.truncate_test_run();
    }

    pub(super) fn open(
        store_root: &cap_std::fs::Dir,
        limits: RecoveryLimits,
        index_memory: LocationIndexMemoryBudget,
    ) -> Result<Option<Self>, DurableError> {
        let root_directory = match contiguous::open_representation_root(store_root) {
            Ok(root) => root,
            Err(DurableError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                return Ok(None);
            },
            Err(error) => return Err(error),
        };
        let current_file = match open_cap_file(&root_directory, Path::new(CURRENT_PATH)) {
            Ok(file) => file,
            Err(DurableError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                return Ok(None);
            },
            Err(error) => return Err(error),
        };
        let current = read_current_file(current_file, limits)?;
        quarantine_entry(
            &root_directory,
            CURRENT_TEMP_PATH,
            &format!("{CURRENT_TEMP_PATH}.incomplete"),
        )?;
        let generations = open_component(&root_directory, Path::new(GENERATIONS_DIRECTORY), false)?;
        let generation_name = generation_name(current.journal_generation);
        let generation = open_component(&generations, Path::new(&generation_name), false)?;
        let mut metadata =
            DurableFile::native(open_cap_file(&generation, Path::new(METADATA_PATH))?);
        let mut journal = DurableFile::native(open_cap_file(&generation, Path::new(JOURNAL_PATH))?);
        let mut index = recover_metadata(&mut metadata, limits, index_memory)?;
        let (active, state) = recover_journal(&mut journal, current, &mut index, limits)?;
        let recovered = Self::from_recovered(
            metadata,
            journal,
            RecoveredPhysicalAuthority {
                journal_generation: current.journal_generation,
                active,
                state,
            },
            index,
            index_memory,
        )?;
        Ok(Some(recovered))
    }

    pub(super) fn activate(
        store_root: &cap_std::fs::Dir,
        limits: RecoveryLimits,
        frozen_specification: ObjectId,
        objects: impl IntoIterator<Item = Result<DirectArenaObject, DurableError>>,
        index_memory: LocationIndexMemoryBudget,
    ) -> Result<Self, DurableError> {
        if let Some(existing) = Self::open(store_root, limits, index_memory)? {
            return Ok(existing);
        }
        quarantine_entry(store_root, DIRECTORY, &format!("{DIRECTORY}.incomplete"))?;
        let root_directory = open_component(store_root, Path::new(DIRECTORY), true)?;
        let generations = open_component(&root_directory, Path::new(GENERATIONS_DIRECTORY), true)?;
        let generation_name = generation_name(FIRST_JOURNAL_GENERATION);
        let generation = open_component(&generations, Path::new(&generation_name), true)?;

        let mut metadata = create_cap_file(&generation, Path::new(METADATA_PATH))?;
        let mut journal = create_cap_file(&generation, Path::new(JOURNAL_PATH))?;
        let built = build_initial_state(frozen_specification, objects)?;
        let payloads = built
            .metadata
            .iter()
            .map(MetadataFrame::encode)
            .collect::<Result<Vec<_>, _>>()?;
        append_frames(&mut metadata, METADATA_MAGIC, &payloads)?;
        metadata
            .sync_data()
            .map_err(|source| io_error("flush representation metadata", source))?;

        let checkpoint = JournalEntry::Checkpoint {
            journal_generation: FIRST_JOURNAL_GENERATION,
            active: None,
            state_generation: 0,
            prior_journal_digest: None,
        }
        .encode();
        append_frame(&mut journal, JOURNAL_MAGIC, &checkpoint)?;
        journal
            .sync_data()
            .map_err(|source| io_error("flush representation checkpoint", source))?;
        let checkpoint_bytes = read_all(&mut journal, "read representation checkpoint")?;
        let checkpoint_digest = journal_digest(&checkpoint_bytes);
        let state_cas = JournalEntry::StateCas {
            journal_generation: FIRST_JOURNAL_GENERATION,
            expected: None,
            replacement: built.active,
        }
        .encode();
        append_frame(&mut journal, JOURNAL_MAGIC, &state_cas)?;
        journal
            .sync_data()
            .map_err(|source| io_error("flush initial representation state", source))?;
        sync_directory(&generation)
            .map_err(|source| io_error("flush representation generation", source))?;

        let current = CurrentPointer {
            journal_generation: FIRST_JOURNAL_GENERATION,
            checkpoint_digest,
            max_tail_frames: u32::MAX,
            max_tail_bytes: u64::MAX,
        };
        let mut current_file = create_cap_file(&root_directory, Path::new(CURRENT_TEMP_PATH))?;
        append_frame(&mut current_file, format::CURRENT_MAGIC, &current.encode())?;
        current_file
            .sync_data()
            .map_err(|source| io_error("flush representation current pointer", source))?;
        drop(current_file);
        let recovered = read_current_file(
            open_cap_file(&root_directory, Path::new(CURRENT_TEMP_PATH))?,
            RecoveryLimits::process_addressable(),
        )?;
        if recovered != current {
            return Err(DurableError::InvalidRepresentationState(
                "representation current pointer failed verification",
            ));
        }
        root_directory
            .rename(
                Path::new(CURRENT_TEMP_PATH),
                &root_directory,
                Path::new(CURRENT_PATH),
            )
            .map_err(|source| io_error("publish representation current pointer", source))?;
        sync_directory(&root_directory)
            .map_err(|source| io_error("flush representation root", source))?;
        drop(metadata);
        drop(journal);
        Self::open(store_root, limits, index_memory)?.ok_or(
            DurableError::InvalidRepresentationState(
                "published representation state did not reopen",
            ),
        )
    }

    pub(super) fn direct_profile_for(
        frozen_specification: ObjectId,
    ) -> Result<RepresentationProfileId, DurableError> {
        Ok(activation::direct_profile(frozen_specification)?.1)
    }

    pub(super) fn rebase_compacted_arena<I: PersistentObjectIdentity, F: super::DurableIo>(
        &mut self,
        arena: &F,
        index: &BTreeMap<ObjectId, ArenaLocation>,
        identity: &I,
        limits: RecoveryLimits,
    ) -> Result<(), DurableError> {
        // Objects deliberately excluded when physical authority was activated
        // (the in-band specification and other bootstrap records) remain
        // recoverable through store.meta. Compaction must not silently pull
        // those independent roots into the representation catalogue.
        let mut direct = Vec::new();
        for (id, location) in index {
            if self.reverse.contains(*id)? {
                let (_, payload) =
                    read_indexed_object_with_payload(arena, *id, *location, identity, limits)?;
                direct.push(self.describe_direct(
                    *id,
                    canonical_record_bytes(&payload, identity.scheme())?,
                    *location,
                )?);
            }
        }
        self.rebase_all_direct(&direct)
    }

    pub(super) fn logical_liveness_roots(&self) -> Result<BTreeSet<ObjectId>, DurableError> {
        let mut roots = BTreeSet::new();
        for entry in recovery::active_entries(&self.profiles) {
            let (_, bytes) = entry?;
            let profile = RepresentationProfile::decode(&bytes)?;
            roots.extend(
                profile
                    .immutable_dependencies()
                    .iter()
                    .filter_map(|dependency| match dependency {
                        ProfileDependency::LogicalObject(object) => Some(*object),
                        ProfileDependency::PhysicalBlob(_) => None,
                    }),
            );
        }
        for entry in recovery::active_entries(&self.representations) {
            let (_, bytes) = entry?;
            let record = RepresentationRecord::decode(&bytes)?;
            roots.extend(
                record
                    .dependencies()
                    .iter()
                    .filter_map(|dependency| match dependency {
                        Dependency::LogicalObject(object) | Dependency::Evidence(object) => {
                            Some(*object)
                        },
                        Dependency::Invocation(invocation) => Some(invocation.object_id()),
                        Dependency::PhysicalBlob(_)
                        | Dependency::Representation(_)
                        | Dependency::Profile(_) => None,
                    }),
            );
        }
        Ok(roots)
    }

    pub(super) fn describe_direct(
        &self,
        object: ObjectId,
        canonical_record: &[u8],
        location: ArenaLocation,
    ) -> Result<DirectArenaObject, DurableError> {
        DirectArenaObject::identify(self.direct_profile, object, canonical_record, location)
    }

    pub(super) const fn direct_profile(&self) -> RepresentationProfileId {
        self.direct_profile
    }

    pub(super) const fn active(&self) -> RepresentationStateId {
        self.active
    }

    pub(super) fn frozen_specification(&self) -> Result<ObjectId, DurableError> {
        let bytes = self
            .profiles
            .try_get(
                &Blake3PhysicalIdentity,
                PhysicalMapKey::from(self.direct_profile),
            )?
            .ok_or(DurableError::InvalidRepresentationState(
                "direct representation profile disappeared",
            ))?;
        Ok(RepresentationProfile::decode(&bytes)?.frozen_specification())
    }

    pub(super) fn contains_direct(&self, object: ObjectId) -> Result<bool, DurableError> {
        Ok(self.direct_record(object)?.is_some_and(|record| {
            matches!(record.coverage(), Coverage::Exact { object: covered, .. } if *covered == object)
                && matches!(record.recipe(), Recipe::DirectCanonical { .. })
        }))
    }

    fn direct_record(
        &self,
        object: ObjectId,
    ) -> Result<Option<RepresentationRecord>, DurableError> {
        let Some(id) = self.reverse.first(object)? else {
            return Ok(None);
        };
        // Recovery admits only validated Exact+DirectCanonical records into
        // this index, and the catalogue admits exactly one direct profile.
        // The authenticated earliest ID therefore preserves admission order
        // without scanning every later retained representation on each read.
        let bytes = self
            .representations
            .try_get(&Blake3PhysicalIdentity, PhysicalMapKey::from(id))?
            .ok_or(DurableError::InvalidRepresentationState(
                "reverse index references a missing representation",
            ))?;
        let record = RepresentationRecord::decode(&bytes)?;
        if record.profile() != self.direct_profile
            || !matches!(record.coverage(), Coverage::Exact { object: covered, .. } if *covered == object)
            || !matches!(record.recipe(), Recipe::DirectCanonical { .. })
        {
            return Err(DurableError::InvalidRepresentationState(
                "direct profile has incompatible coverage or recipe",
            ));
        }
        Ok(Some(record))
    }

    /// On any error the engine must poison this store and recover it before
    /// another operation: staged nodes and tentative map roots are not authority.
    pub(super) fn append_direct_update(
        &mut self,
        objects: &[DirectArenaObject],
    ) -> Result<Option<PendingRepresentationUpdate>, DurableError> {
        let mut metadata = Vec::new();
        let profile = RepresentationProfile::decode(
            &self
                .profiles
                .try_get(
                    &Blake3PhysicalIdentity,
                    PhysicalMapKey::from(self.direct_profile),
                )?
                .ok_or(DurableError::InvalidRepresentationState(
                    "direct representation profile disappeared",
                ))?,
        )?;
        let mut entries = Vec::new();
        for object in objects {
            if !self.contains_direct(object.object)? {
                entries.push(self.prepare_direct_entry(object, &profile)?);
            }
        }
        if entries.is_empty() {
            return Ok(None);
        }
        self.representations.insert_entries(
            &Blake3PhysicalIdentity,
            entries
                .iter()
                .map(|entry| entry.representation.clone())
                .collect(),
        )?;
        self.placement_entries.insert_entries(
            &Blake3PhysicalIdentity,
            entries
                .iter()
                .map(|entry| entry.placement.clone())
                .collect(),
        )?;
        let reverse_additions = entries
            .into_iter()
            .map(|entry| (entry.object, entry.representation_id))
            .collect();
        let mut appended_map_nodes = BTreeSet::new();
        {
            let (presence, mut complete) = memoized_closure_handles(&self.persisted_map_nodes);
            append_new_reachable_map_nodes(
                &mut metadata,
                &self.representations,
                &presence,
                &mut appended_map_nodes,
                &mut complete,
            )?;
        }
        {
            let (presence, mut complete) = memoized_closure_handles(&self.persisted_map_nodes);
            append_new_reachable_map_nodes(
                &mut metadata,
                &self.placement_entries,
                &presence,
                &mut appended_map_nodes,
                &mut complete,
            )?;
        }
        let (catalogue, placements, state) = self.next_authority()?;
        let state_id = state.identify(&Blake3PhysicalIdentity);
        metadata.push(MetadataFrame::catalogue(&Blake3PhysicalIdentity, catalogue));
        metadata.push(MetadataFrame::placement(
            &Blake3PhysicalIdentity,
            placements,
        ));
        metadata.push(MetadataFrame::state(&Blake3PhysicalIdentity, state));
        self.append_metadata_frames(&metadata)?;
        for id in appended_map_nodes {
            if !self.persisted_map_nodes.contains(&id)? {
                return Err(DurableError::InvalidRepresentationState(
                    "new physical node lacks a locator",
                ));
            }
        }
        Ok(Some(PendingRepresentationUpdate {
            state,
            state_id,
            catalogue,
            placements,
            reverse_additions,
            replacement_reverse: None,
        }))
    }

    /// Replace every active physical representation with the supplied direct
    /// arena placement after compaction has materialized all live objects.
    /// An error requires engine poisoning before reuse, as for direct updates.
    pub(super) fn rebase_all_direct(
        &mut self,
        objects: &[DirectArenaObject],
    ) -> Result<(), DurableError> {
        if self.direct_authority_matches(objects)? {
            return Ok(());
        }
        let profile = RepresentationProfile::decode(
            &self
                .profiles
                .try_get(
                    &Blake3PhysicalIdentity,
                    PhysicalMapKey::from(self.direct_profile),
                )?
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
        let replacement_representations = CanonicalPhysicalMap::build_dense(
            &Blake3PhysicalIdentity,
            PhysicalMapDomain::Representation,
            representation_entries,
        )?;
        let replacement_placements = CanonicalPhysicalMap::build_dense(
            &Blake3PhysicalIdentity,
            PhysicalMapDomain::Placement,
            placement_entries,
        )?;
        self.persisted_map_nodes
            .install_materialized(&replacement_representations)?;
        self.persisted_map_nodes
            .install_materialized(&replacement_placements)?;
        self.representations =
            replacement_representations.with_node_provider(self.persisted_map_nodes.clone());
        self.placement_entries =
            replacement_placements.with_node_provider(self.persisted_map_nodes.clone());
        self.residency = residency::MapResidency::new(
            &self.profiles,
            &self.representations,
            &self.placement_entries,
            self.persisted_map_nodes.len(),
        )?;
        let mut replacement_reverse = ReverseIndex::new(self.persisted_map_nodes.budget())?;
        for entry in entries {
            replacement_reverse.insert(entry.object, entry.representation_id)?;
        }

        let mut metadata = Vec::new();
        let mut appended_map_nodes = BTreeSet::new();
        for map in [&self.representations, &self.placement_entries] {
            {
                let (presence, mut complete) = memoized_closure_handles(&self.persisted_map_nodes);
                append_new_reachable_map_nodes(
                    &mut metadata,
                    map,
                    &presence,
                    &mut appended_map_nodes,
                    &mut complete,
                )?;
            }
        }
        let (catalogue, placements, state) = self.next_authority()?;
        let state_id = state.identify(&Blake3PhysicalIdentity);
        metadata.extend([
            MetadataFrame::catalogue(&Blake3PhysicalIdentity, catalogue),
            MetadataFrame::placement(&Blake3PhysicalIdentity, placements),
            MetadataFrame::state(&Blake3PhysicalIdentity, state),
        ]);
        self.append_metadata_frames(&metadata)?;
        for id in appended_map_nodes {
            if !self.persisted_map_nodes.contains(&id)? {
                return Err(DurableError::InvalidRepresentationState(
                    "new physical node lacks a locator",
                ));
            }
        }
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
            .map(|object| (object.object, &object.location))
            .collect::<BTreeMap<_, _>>();
        if expected.len() != objects.len()
            || self.representations.entry_count()
                != u64::try_from(objects.len()).map_err(|_| DurableError::EncodingOverflow)?
            || self.placement_entries.entry_count()
                != u64::try_from(objects.len()).map_err(|_| DurableError::EncodingOverflow)?
        {
            return Ok(false);
        }
        let mut count = 0_usize;
        let mut matched = true;
        for object in self.reverse.keys() {
            let object = object?;
            let placement = self.direct_placement(object)?;
            let last = recovered_direct::arena_locations(&placement).last();
            matched &= expected.get(&object).copied() == last.as_ref();
            count = count.checked_add(1).ok_or(DurableError::EncodingOverflow)?;
        }
        Ok(matched && count == expected.len())
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

    // Partial promotion or append errors require engine poisoning and reopen.
    // Scratch is released on success, or with this store during recovery.
    fn append_metadata_frames(&mut self, frames: &[MetadataFrame]) -> Result<(), DurableError> {
        let mut batch = batch::MetadataBatch::new(self.persisted_map_nodes.limits())?;
        for frame in frames {
            batch.push(frame)?;
        }
        let base = batch.append_to(&mut self.metadata)?;
        batch.promote_nodes(
            &self.persisted_map_nodes,
            base,
            self.persisted_map_nodes.limits(),
        )?;
        // Both current maps' complete closures have been emitted. No scratch
        // node is needed by the pending authority or any prior durable root.
        self.persisted_map_nodes.finish_staging();
        Ok(())
    }

    pub(super) fn publish_direct_update(
        &mut self,
        update: PendingRepresentationUpdate,
    ) -> Result<(), DurableError> {
        self.flush_metadata()?;
        let cas = JournalEntry::StateCas {
            journal_generation: self.journal_generation,
            expected: Some(self.active),
            replacement: update.state_id,
        }
        .encode();
        append_frame(&mut self.journal, JOURNAL_MAGIC, &cas)?;
        self.flush_journal()?;
        self.active = update.state_id;
        self.recovered_direct = None;
        self.state = update.state;
        self.catalogue = update.catalogue;
        self.placements = update.placements;
        if let Some(replacement) = update.replacement_reverse {
            self.reverse = replacement;
        } else {
            for (object, representation) in update.reverse_additions {
                self.reverse.insert(object, representation)?;
            }
        }
        // These maps came from canonical recovery or checked model mutations.
        // Reclaim cannot fail on a valid trie. Propagate an invariant failure
        // rather than hiding corruption, even though authority is now durable.
        self.reclaim_map_history()?;
        Ok(())
    }

    pub(super) fn flush(&mut self) -> Result<(), DurableError> {
        self.flush_metadata()?;
        self.flush_journal()
    }

    fn flush_metadata(&mut self) -> Result<(), DurableError> {
        self.metadata
            .sync_data()
            .map_err(|source| io_error("flush representation metadata", source))
    }

    fn flush_journal(&mut self) -> Result<(), DurableError> {
        self.journal
            .sync_data()
            .map_err(|source| io_error("flush representation state journal", source))
    }

    /// Return the arena prefix proven durable by published physical state.
    ///
    /// A malformed frame below this boundary is corruption, not a repairable
    /// uncommitted tail. Recovery consults this value before it may truncate
    /// the logical arena.
    pub(super) fn generation_zero_protected_len(&self) -> Result<u64, DurableError> {
        let (active, direct) =
            self.recovered_direct
                .as_ref()
                .ok_or(DurableError::InvalidRepresentationState(
                    "mount replica proof has been consumed",
                ))?;
        if *active != self.active {
            return Err(DurableError::InvalidRepresentationState(
                "mount replica proof names a different physical state",
            ));
        }
        Ok(direct.protected_len())
    }

    /// Consume mount-time replica evidence before exposing the recovered engine.
    /// Object reads still authenticate canonical frames and logical identities.
    pub(super) fn validate_generation_zero_index(
        &mut self,
        index: &BTreeMap<ObjectId, ArenaLocation>,
    ) -> Result<(), DurableError> {
        let (active, direct) =
            self.recovered_direct
                .take()
                .ok_or(DurableError::InvalidRepresentationState(
                    "mount replica proof has been consumed",
                ))?;
        if active != self.active {
            return Err(DurableError::InvalidRepresentationState(
                "mount replica proof names a different physical state",
            ));
        }
        direct.validate(index)
    }

    fn direct_placement(&self, object: ObjectId) -> Result<PlacementEntry, DurableError> {
        let record =
            self.direct_record(object)?
                .ok_or(DurableError::InvalidRepresentationState(
                    "reverse index has no direct representation",
                ))?;
        let Recipe::DirectCanonical { blob } = record.recipe() else {
            return Err(DurableError::InvalidRepresentationState(
                "direct profile uses a non-direct recipe",
            ));
        };
        let placement = self
            .placement_entries
            .try_get(&Blake3PhysicalIdentity, PhysicalMapKey::from(*blob))?
            .ok_or(DurableError::InvalidRepresentationState(
                "direct representation placement disappeared",
            ))?;
        let placement = PlacementEntry::decode(&placement)?;
        if recovered_direct::arena_locations(&placement)
            .next()
            .is_none()
        {
            return Err(DurableError::InvalidRepresentationState(
                "direct representation has no generation-zero arena placement",
            ));
        }
        Ok(placement)
    }

    #[cfg(test)]
    fn direct_arena_locations(&self) -> Result<Vec<(ObjectId, ArenaLocation)>, DurableError> {
        let mut direct = Vec::new();
        for object in self.reverse.keys() {
            let object = object?;
            let placement = self.direct_placement(object)?;
            direct.extend(
                recovered_direct::arena_locations(&placement).map(|location| (object, location)),
            );
        }
        Ok(direct)
    }

    fn from_recovered(
        metadata: DurableFile,
        journal: DurableFile,
        authority: RecoveredPhysicalAuthority,
        index: MetadataIndex,
        index_memory: LocationIndexMemoryBudget,
    ) -> Result<Self, DurableError> {
        let RecoveredPhysicalAuthority {
            journal_generation,
            active,
            state,
        } = authority;
        let catalogue = RepresentationCatalogueRoot::decode(
            index.value(MetadataKind::Catalogue, state.catalogue().as_bytes())?,
        )?;
        let placements = PlacementSet::decode(
            index.value(MetadataKind::Placement, state.placements().as_bytes())?,
        )?;
        let mut nodes = index.into_nodes();
        // Journal proof writes fragment the locator again after admission.
        // Canonical map walks need the locations, but none of those proofs.
        nodes.reset_proofs()?;
        let profiles = residency::recover_active_map(
            PhysicalMapDomain::Profile,
            catalogue.profiles_root(),
            &nodes,
        )?;
        let representations = residency::recover_active_map(
            PhysicalMapDomain::Representation,
            catalogue.representations_root(),
            &nodes,
        )?;
        let placement_entries = residency::recover_active_map(
            PhysicalMapDomain::Placement,
            placements.entries_root(),
            &nodes,
        )?;
        if profiles.entry_count() != catalogue.profile_count()
            || representations.entry_count() != catalogue.representation_count()
            || placement_entries.entry_count() != placements.blob_count()
        {
            return Err(DurableError::InvalidRepresentationState(
                "physical map count disagrees with its authority root",
            ));
        }
        let direct_profile = validate_profiles(&profiles)?;
        let (reverse, extent_count, recovered_direct) = validate_representations(
            &profiles,
            &representations,
            &placement_entries,
            index_memory,
        )?;
        if extent_count != placements.replica_extent_count() {
            return Err(DurableError::InvalidRepresentationState(
                "placement extent count disagrees with map entries",
            ));
        }
        let persisted_map_nodes =
            nodes.into_cold(&[&profiles, &representations, &placement_entries])?;
        let residency = residency::MapResidency::new(
            &profiles,
            &representations,
            &placement_entries,
            persisted_map_nodes.len(),
        )?;
        let profiles = profiles.with_node_provider(persisted_map_nodes.clone());
        let representations = representations.with_node_provider(persisted_map_nodes.clone());
        let placement_entries = placement_entries.with_node_provider(persisted_map_nodes.clone());
        Ok(Self {
            metadata,
            journal,
            journal_generation,
            active,
            state,
            catalogue,
            placements,
            residency,
            profiles,
            representations,
            placement_entries,
            persisted_map_nodes,
            direct_profile,
            reverse,
            recovered_direct: Some((active, recovered_direct)),
        })
    }
}

fn read_all<F: DurableIo>(file: &mut F, operation: &'static str) -> Result<Vec<u8>, DurableError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|source| io_error(operation, source))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|source| io_error(operation, source))?;
    file.seek(SeekFrom::End(0))
        .map_err(|source| io_error(operation, source))?;
    Ok(bytes)
}

fn increment(value: u64) -> Result<u64, DurableError> {
    value.checked_add(1).ok_or(DurableError::EncodingOverflow)
}
