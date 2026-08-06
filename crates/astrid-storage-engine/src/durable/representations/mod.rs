//! Authoritative physical representation catalogue and placement state.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use astrid_storage_model::{
    CanonicalPhysicalMap, Coverage, Dependency, ObjectId, PhysicalMapDomain, PhysicalMapKey,
    PlacementEntry, PlacementSet, ProfileDependency, Recipe, Replica, ReplicaLocator,
    RepresentationCatalogueRoot, RepresentationProfile, RepresentationProfileId,
    RepresentationRecord, RepresentationRecordId, RepresentationState, RepresentationStateId,
    StorageNodeId,
};

#[cfg(test)]
use super::open_rw;
use super::{
    ArenaLocation, DurableError, FRAME_HEADER_LEN, PersistentObjectIdentity, RecoveryLimits,
    append_frame, append_frames, canonical_record_bytes, io_error,
    read_indexed_object_with_payload,
};
pub(in crate::durable) use format::Blake3PhysicalIdentity as PhysicalIdentityV1;
use format::{
    Blake3PhysicalIdentity, CurrentPointer, JOURNAL_MAGIC, JournalEntry, METADATA_MAGIC,
    MetadataFrame, MetadataKind, journal_digest,
};

mod activation;
mod authority;
mod format;
mod recovery;

use activation::{append_new_reachable_map_nodes, build_initial_state, generation_name};
use recovery::{
    MetadataIndex, read_current_file, recover_journal, recover_metadata, validate_profiles,
    validate_representations,
};

mod contiguous;
mod direct;
use authority::{create_file as create_cap_file, open_file as open_cap_file, quarantine_entry};
pub(super) use contiguous::{
    install_loose_blob_copy, install_loose_blob_from_file, open_regular_read, open_store_root,
    read_contiguous_object,
};
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
    root: std::path::PathBuf,
    root_directory: cap_std::fs::Dir,
    metadata: File,
    journal: File,
    journal_generation: u64,
    active: RepresentationStateId,
    state: RepresentationState,
    catalogue: RepresentationCatalogueRoot,
    placements: PlacementSet,
    profiles: CanonicalPhysicalMap,
    representations: CanonicalPhysicalMap,
    placement_entries: CanonicalPhysicalMap,
    persisted_map_nodes: BTreeSet<astrid_storage_model::PhysicalMapNodeId>,
    direct_profile: RepresentationProfileId,
    reverse: BTreeMap<ObjectId, Vec<RepresentationRecordId>>,
    contiguous: BTreeMap<ObjectId, ContiguousLocation>,
}

#[derive(Debug)]
struct PinnedRepresentationRoot {
    path: std::path::PathBuf,
    directory: cap_std::fs::Dir,
}

pub(super) struct PendingRepresentationUpdate {
    state: RepresentationState,
    state_id: RepresentationStateId,
    catalogue: RepresentationCatalogueRoot,
    placements: PlacementSet,
    reverse_additions: Vec<(ObjectId, RepresentationRecordId)>,
    contiguous_additions: Vec<(ObjectId, ContiguousLocation)>,
    replacement_reverse: Option<BTreeMap<ObjectId, Vec<RepresentationRecordId>>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ContiguousLocation {
    pub(super) blob: astrid_storage_model::BlobId,
    pub(super) namespace_generation: u64,
    pub(super) offset: u64,
    pub(super) length: u64,
}

struct DirectMapEntry {
    object: ObjectId,
    representation: (PhysicalMapKey, Vec<u8>),
    representation_id: RepresentationRecordId,
    placement: (PhysicalMapKey, Vec<u8>),
}

impl RepresentationStore {
    pub(super) fn open(
        store: &Path,
        store_root: &cap_std::fs::Dir,
        limits: RecoveryLimits,
    ) -> Result<Option<Self>, DurableError> {
        let root = store.join(DIRECTORY);
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
        let mut metadata = open_cap_file(&generation, Path::new(METADATA_PATH))?;
        let mut journal = open_cap_file(&generation, Path::new(JOURNAL_PATH))?;
        let index = recover_metadata(&mut metadata, limits)?;
        let (active, state) = recover_journal(&mut journal, current, &index, limits)?;
        let recovered = Self::from_recovered(
            PinnedRepresentationRoot {
                path: root,
                directory: root_directory,
            },
            metadata,
            journal,
            current.journal_generation,
            active,
            state,
            &index,
        )?;
        Ok(Some(recovered))
    }

    pub(super) fn activate(
        store: &Path,
        store_root: &cap_std::fs::Dir,
        limits: RecoveryLimits,
        frozen_specification: ObjectId,
        objects: impl IntoIterator<Item = Result<DirectArenaObject, DurableError>>,
    ) -> Result<Self, DurableError> {
        if let Some(existing) = Self::open(store, store_root, limits)? {
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
        Self::open(store, store_root, limits)?.ok_or(DurableError::InvalidRepresentationState(
            "published representation state did not reopen",
        ))
    }

    pub(super) fn direct_profile_for(
        frozen_specification: ObjectId,
    ) -> Result<RepresentationProfileId, DurableError> {
        Ok(activation::direct_profile(frozen_specification)?.1)
    }

    pub(super) fn rebase_compacted_arena<I: PersistentObjectIdentity>(
        &mut self,
        arena: &File,
        index: &BTreeMap<ObjectId, ArenaLocation>,
        identity: &I,
        limits: RecoveryLimits,
    ) -> Result<(), DurableError> {
        // Objects deliberately excluded when physical authority was activated
        // (the in-band specification and other bootstrap records) remain
        // recoverable through store.meta. Compaction must not silently pull
        // those independent roots into the representation catalogue.
        let previously_authoritative = self
            .reverse
            .keys()
            .chain(self.contiguous.keys())
            .copied()
            .collect::<BTreeSet<_>>();
        let direct = index
            .iter()
            .filter(|(id, _)| previously_authoritative.contains(id))
            .map(|(id, location)| {
                let (_, payload) =
                    read_indexed_object_with_payload(arena, *id, *location, identity, limits)?;
                self.describe_direct(
                    *id,
                    canonical_record_bytes(&payload, identity.scheme())?,
                    *location,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.rebase_all_direct(&direct)
    }

    pub(super) fn logical_liveness_roots(&self) -> Result<BTreeSet<ObjectId>, DurableError> {
        let mut roots = BTreeSet::new();
        for (_, bytes) in recovery::active_entries(&self.profiles)? {
            let profile = RepresentationProfile::decode(bytes)?;
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
        for (_, bytes) in recovery::active_entries(&self.representations)? {
            let record = RepresentationRecord::decode(bytes)?;
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

    fn profile(&self, id: RepresentationProfileId) -> Result<RepresentationProfile, DurableError> {
        self.profiles
            .get(PhysicalMapKey::from(id))
            .ok_or(DurableError::InvalidRepresentationState(
                "representation profile disappeared",
            ))
            .and_then(|bytes| RepresentationProfile::decode(bytes).map_err(Into::into))
    }

    pub(super) const fn active(&self) -> RepresentationStateId {
        self.active
    }

    pub(super) fn frozen_specification(&self) -> Result<ObjectId, DurableError> {
        let bytes = self
            .profiles
            .get(PhysicalMapKey::from(self.direct_profile))
            .ok_or(DurableError::InvalidRepresentationState(
                "direct representation profile disappeared",
            ))?;
        Ok(RepresentationProfile::decode(bytes)?.frozen_specification())
    }

    pub(super) fn contains_direct(&self, object: ObjectId) -> bool {
        self.reverse.get(&object).is_some_and(|records| {
            records.iter().any(|record| {
                self.representations
                    .get(PhysicalMapKey::from(*record))
                    .and_then(|bytes| RepresentationRecord::decode(bytes).ok())
                    .is_some_and(|value| {
                        value.profile() == self.direct_profile
                            && matches!(value.coverage(), Coverage::Exact { object: covered, .. } if *covered == object)
                            && matches!(value.recipe(), Recipe::DirectCanonical { .. })
                    })
            })
        })
    }

    pub(super) fn append_direct_update(
        &mut self,
        objects: &[DirectArenaObject],
    ) -> Result<Option<PendingRepresentationUpdate>, DurableError> {
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
                .rebuild_with_entries(&Blake3PhysicalIdentity, representation_entries)?;
        } else {
            for (key, value) in representation_entries {
                self.representations
                    .insert(&Blake3PhysicalIdentity, key, value)?;
            }
        }
        if rebuild_placements {
            self.placement_entries
                .rebuild_with_entries(&Blake3PhysicalIdentity, placement_entries)?;
        } else {
            for (key, value) in placement_entries {
                self.placement_entries
                    .insert(&Blake3PhysicalIdentity, key, value)?;
            }
        }
        let reverse_additions = entries
            .into_iter()
            .map(|entry| (entry.object, entry.representation_id))
            .collect();
        let mut appended_map_nodes = BTreeSet::new();
        append_new_reachable_map_nodes(
            &mut metadata,
            &self.representations,
            &self.persisted_map_nodes,
            &mut appended_map_nodes,
        )?;
        append_new_reachable_map_nodes(
            &mut metadata,
            &self.placement_entries,
            &self.persisted_map_nodes,
            &mut appended_map_nodes,
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
        append_frames(&mut self.metadata, METADATA_MAGIC, &payloads)?;
        self.persisted_map_nodes.extend(appended_map_nodes);
        Ok(Some(PendingRepresentationUpdate {
            state,
            state_id,
            catalogue,
            placements,
            reverse_additions,
            contiguous_additions: Vec::new(),
            replacement_reverse: None,
        }))
    }

    /// Replace every active physical representation with the supplied direct
    /// arena placement. This is the compaction handoff: all represented live
    /// objects have already been materialized into the replacement arena, so
    /// no retired loose blob remains authoritative after this state CAS.
    pub(super) fn rebase_all_direct(
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
        self.representations = CanonicalPhysicalMap::build_dense(
            &Blake3PhysicalIdentity,
            PhysicalMapDomain::Representation,
            representation_entries,
        )?;
        self.placement_entries = CanonicalPhysicalMap::build_dense(
            &Blake3PhysicalIdentity,
            PhysicalMapDomain::Placement,
            placement_entries,
        )?;
        let replacement_reverse = entries
            .into_iter()
            .map(|entry| (entry.object, vec![entry.representation_id]))
            .collect();

        let mut metadata = Vec::new();
        let mut appended_map_nodes = BTreeSet::new();
        for map in [&self.representations, &self.placement_entries] {
            append_new_reachable_map_nodes(
                &mut metadata,
                map,
                &self.persisted_map_nodes,
                &mut appended_map_nodes,
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
        append_frames(&mut self.metadata, METADATA_MAGIC, &payloads)?;
        self.persisted_map_nodes.extend(appended_map_nodes);
        let update = PendingRepresentationUpdate {
            state,
            state_id,
            catalogue,
            placements,
            reverse_additions: Vec::new(),
            contiguous_additions: Vec::new(),
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

    pub(super) fn publish_direct_update(
        &mut self,
        update: PendingRepresentationUpdate,
    ) -> Result<(), DurableError> {
        let cas = JournalEntry::StateCas {
            journal_generation: self.journal_generation,
            expected: Some(self.active),
            replacement: update.state_id,
        }
        .encode();
        append_frame(&mut self.journal, JOURNAL_MAGIC, &cas)?;
        self.active = update.state_id;
        self.state = update.state;
        self.catalogue = update.catalogue;
        self.placements = update.placements;
        if let Some(replacement) = update.replacement_reverse {
            self.reverse = replacement;
            self.contiguous.clear();
        } else {
            for (object, representation) in update.reverse_additions {
                self.reverse.entry(object).or_default().push(representation);
            }
            self.contiguous.extend(update.contiguous_additions);
        }
        Ok(())
    }

    pub(super) fn flush(&mut self) -> Result<(), DurableError> {
        self.metadata
            .sync_data()
            .map_err(|source| io_error("flush representation metadata", source))?;
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
        self.direct_arena_locations()?
            .into_iter()
            .try_fold(0_u64, |protected, (_, location)| {
                let end = location
                    .offset
                    .checked_add(FRAME_HEADER_LEN)
                    .and_then(|value| value.checked_add(location.payload_len))
                    .ok_or(DurableError::EncodingOverflow)?;
                Ok(protected.max(end))
            })
    }

    /// Validate that generation-zero placements name the recovered arena
    /// index exactly.
    ///
    /// This is mount-time topology validation, not an implicit full-store
    /// scrub. Authoritative object reads verify the named frame checksum,
    /// canonical encoding, and logical identity before returning bytes. A
    /// scheduled refinery pass owns proactive full-corpus re-attestation.
    pub(super) fn validate_generation_zero_index(
        &self,
        index: &BTreeMap<ObjectId, ArenaLocation>,
    ) -> Result<(), DurableError> {
        let direct = self.direct_arena_locations()?;
        for object in self.reverse.keys() {
            let location =
                index
                    .get(object)
                    .copied()
                    .ok_or(DurableError::InvalidRepresentationState(
                        "direct representation names a missing logical object",
                    ))?;
            if !direct
                .iter()
                .any(|(covered, candidate)| *covered == *object && *candidate == location)
            {
                return Err(DurableError::InvalidRepresentationState(
                    "generation-zero placement disagrees with the arena index",
                ));
            }
        }
        Ok(())
    }

    fn direct_arena_locations(&self) -> Result<Vec<(ObjectId, ArenaLocation)>, DurableError> {
        let mut direct = Vec::new();
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
            let placement = self
                .placement_entries
                .get(PhysicalMapKey::from(*blob))
                .ok_or(DurableError::InvalidRepresentationState(
                    "direct representation placement disappeared",
                ))?;
            let placement = PlacementEntry::decode(placement)?;
            let before = direct.len();
            for replica in placement.replicas() {
                if let ReplicaLocator::ArenaFrame {
                    arena_generation: 0,
                    offset,
                    payload_length,
                    frame_checksum,
                } = replica.locator()
                {
                    direct.push((
                        *object,
                        ArenaLocation {
                            offset,
                            payload_len: payload_length,
                            checksum: frame_checksum,
                        },
                    ));
                }
            }
            if direct.len() == before {
                return Err(DurableError::InvalidRepresentationState(
                    "direct representation has no generation-zero arena placement",
                ));
            }
        }
        Ok(direct)
    }

    fn from_recovered(
        root: PinnedRepresentationRoot,
        metadata: File,
        journal: File,
        journal_generation: u64,
        active: RepresentationStateId,
        state: RepresentationState,
        index: &MetadataIndex,
    ) -> Result<Self, DurableError> {
        let catalogue = RepresentationCatalogueRoot::decode(
            index.value(MetadataKind::Catalogue, state.catalogue().as_bytes())?,
        )?;
        let placements = PlacementSet::decode(
            index.value(MetadataKind::Placement, state.placements().as_bytes())?,
        )?;
        let profiles = CanonicalPhysicalMap::recover(
            &Blake3PhysicalIdentity,
            PhysicalMapDomain::Profile,
            catalogue.profiles_root(),
            index.nodes.clone(),
        )?;
        let representations = CanonicalPhysicalMap::recover(
            &Blake3PhysicalIdentity,
            PhysicalMapDomain::Representation,
            catalogue.representations_root(),
            index.nodes.clone(),
        )?;
        let placement_entries = CanonicalPhysicalMap::recover(
            &Blake3PhysicalIdentity,
            PhysicalMapDomain::Placement,
            placements.entries_root(),
            index.nodes.clone(),
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
        let (reverse, extent_count) =
            validate_representations(&profiles, &representations, &placement_entries)?;
        if extent_count != placements.replica_extent_count() {
            return Err(DurableError::InvalidRepresentationState(
                "placement extent count disagrees with map entries",
            ));
        }
        Ok(Self {
            root: root.path,
            root_directory: root.directory,
            metadata,
            journal,
            journal_generation,
            active,
            state,
            catalogue,
            placements,
            profiles,
            representations,
            placement_entries,
            persisted_map_nodes: index.nodes.keys().copied().collect(),
            direct_profile,
            reverse,
            contiguous: BTreeMap::new(),
        })
    }
}

fn bulk_rebuild_is_cheaper(existing: u64, additions: usize) -> Result<bool, DurableError> {
    let additions = u64::try_from(additions).map_err(|_| DurableError::EncodingOverflow)?;
    let total = existing
        .checked_add(additions)
        .ok_or(DurableError::EncodingOverflow)?;
    let estimated_path_nodes = additions
        .checked_mul(u64::from(total.max(2).ilog2()).saturating_add(2))
        .ok_or(DurableError::EncodingOverflow)?;
    let final_tree_nodes = total
        .checked_mul(2)
        .and_then(|nodes| nodes.checked_sub(1))
        .ok_or(DurableError::EncodingOverflow)?;
    Ok(estimated_path_nodes > final_tree_nodes)
}

fn read_all(file: &mut File, operation: &'static str) -> Result<Vec<u8>, DurableError> {
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
