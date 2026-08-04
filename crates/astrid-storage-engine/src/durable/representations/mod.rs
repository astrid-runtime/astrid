//! Authoritative physical representation catalogue and placement state.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use astrid_storage_model::{
    BlobId, CanonicalPhysicalMap, Coverage, ObjectId, PhysicalMapDomain, PhysicalMapKey,
    PlacementEntry, PlacementSet, Recipe, Replica, ReplicaLocator, RepresentationCatalogueRoot,
    RepresentationProfile, RepresentationProfileId, RepresentationRecord, RepresentationRecordId,
    RepresentationState, RepresentationStateId, StorageNodeId,
};

use super::{
    ArenaLocation, DurableError, PersistentObjectIdentity, RecoveryLimits, append_frame,
    append_frames, canonical_record_bytes, encode_object_frame, io_error, open_rw,
    read_indexed_object, sync_store_directory,
};
use format::{
    Blake3PhysicalIdentity, CurrentPointer, JOURNAL_MAGIC, JournalEntry, METADATA_MAGIC,
    MetadataFrame, MetadataKind, journal_digest,
};

mod activation;
mod format;
mod recovery;

use activation::{
    append_map_nodes, build_initial_state, create_new, generation_name, publish_current,
    quarantine_incomplete_root, quarantine_temporary_current,
};
use recovery::{
    MetadataIndex, read_current, recover_journal, recover_metadata, validate_profiles,
    validate_representations,
};

const DIRECTORY: &str = "representations";
const GENERATIONS_DIRECTORY: &str = "generations";
const METADATA_PATH: &str = "metadata.arena";
const JOURNAL_PATH: &str = "state.journal";
const CURRENT_PATH: &str = "CURRENT";
const CURRENT_TEMP_PATH: &str = "CURRENT.tmp";
const FIRST_JOURNAL_GENERATION: u64 = 1;
const LOCAL_STORAGE_NODE: StorageNodeId = StorageNodeId::new(0);

#[derive(Clone, Debug)]
pub(super) struct DirectArenaObject {
    pub(super) object: ObjectId,
    pub(super) blob: BlobId,
    pub(super) canonical_length: u64,
    pub(super) location: ArenaLocation,
}

impl DirectArenaObject {
    pub(super) fn identify(
        profile: RepresentationProfileId,
        object: ObjectId,
        canonical_record: &[u8],
        location: ArenaLocation,
    ) -> Result<Self, DurableError> {
        Ok(Self {
            object,
            blob: BlobId::identify(&Blake3PhysicalIdentity, profile, canonical_record)?,
            canonical_length: u64::try_from(canonical_record.len())
                .map_err(|_| DurableError::EncodingOverflow)?,
            location,
        })
    }
}

#[derive(Debug)]
pub(super) struct RepresentationStore {
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
    direct_profile: RepresentationProfileId,
    reverse: BTreeMap<ObjectId, Vec<RepresentationRecordId>>,
}

pub(super) struct PendingDirectUpdate {
    state: RepresentationState,
    state_id: RepresentationStateId,
    catalogue: RepresentationCatalogueRoot,
    placements: PlacementSet,
    reverse_additions: Vec<(ObjectId, RepresentationRecordId)>,
}

impl RepresentationStore {
    pub(super) fn open(store: &Path, limits: RecoveryLimits) -> Result<Option<Self>, DurableError> {
        let root = store.join(DIRECTORY);
        let current_path = root.join(CURRENT_PATH);
        if !current_path.exists() {
            return Ok(None);
        }
        let current = read_current(&current_path, limits)?;
        quarantine_temporary_current(&root)?;
        let generation_path = root
            .join(GENERATIONS_DIRECTORY)
            .join(generation_name(current.journal_generation));
        let mut metadata = open_rw(&generation_path.join(METADATA_PATH))?;
        let mut journal = open_rw(&generation_path.join(JOURNAL_PATH))?;
        let index = recover_metadata(&mut metadata, limits)?;
        let (active, state) = recover_journal(&mut journal, current, &index, limits)?;
        let recovered = Self::from_recovered(
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
        limits: RecoveryLimits,
        frozen_specification: ObjectId,
        objects: impl IntoIterator<Item = Result<DirectArenaObject, DurableError>>,
    ) -> Result<Self, DurableError> {
        if let Some(existing) = Self::open(store, limits)? {
            return Ok(existing);
        }
        let root = store.join(DIRECTORY);
        quarantine_incomplete_root(store, &root)?;
        let generations = root.join(GENERATIONS_DIRECTORY);
        let generation_path = generations.join(generation_name(FIRST_JOURNAL_GENERATION));
        fs::create_dir_all(&generation_path)
            .map_err(|source| io_error("create representation generation", source))?;
        sync_store_directory(store)?;
        sync_store_directory(&root)?;
        sync_store_directory(&generations)?;

        let mut metadata = create_new(&generation_path.join(METADATA_PATH))?;
        let mut journal = create_new(&generation_path.join(JOURNAL_PATH))?;
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
        sync_store_directory(&generation_path)?;

        let current = CurrentPointer {
            journal_generation: FIRST_JOURNAL_GENERATION,
            checkpoint_digest,
            max_tail_frames: u32::MAX,
            max_tail_bytes: u64::MAX,
        };
        publish_current(&root, current)?;
        drop(metadata);
        drop(journal);
        Self::open(store, limits)?.ok_or(DurableError::InvalidRepresentationState(
            "published representation state did not reopen",
        ))
    }

    pub(super) fn direct_profile_for(
        frozen_specification: ObjectId,
    ) -> Result<RepresentationProfileId, DurableError> {
        Ok(activation::direct_profile(frozen_specification)?.1)
    }

    pub(super) fn describe_direct(
        &self,
        object: ObjectId,
        canonical_record: &[u8],
        location: ArenaLocation,
    ) -> Result<DirectArenaObject, DurableError> {
        DirectArenaObject::identify(self.direct_profile, object, canonical_record, location)
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
    ) -> Result<Option<PendingDirectUpdate>, DurableError> {
        let mut metadata = Vec::new();
        let mut reverse_additions = Vec::new();
        for object in objects {
            if let Some(addition) = self.append_direct_object(object, &mut metadata)? {
                reverse_additions.push(addition);
            }
        }
        if reverse_additions.is_empty() {
            return Ok(None);
        }
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
        Ok(Some(PendingDirectUpdate {
            state,
            state_id,
            catalogue,
            placements,
            reverse_additions,
        }))
    }

    fn append_direct_object(
        &mut self,
        object: &DirectArenaObject,
        metadata: &mut Vec<MetadataFrame>,
    ) -> Result<Option<(ObjectId, RepresentationRecordId)>, DurableError> {
        if self.contains_direct(object.object) {
            return Ok(None);
        }
        let record = RepresentationRecord::new(
            self.direct_profile,
            Coverage::exact(object.object, object.canonical_length)?,
            Recipe::DirectCanonical { blob: object.blob },
            object.canonical_length,
            object.canonical_length,
            None,
        )?;
        let profile = RepresentationProfile::decode(
            self.profiles
                .get(PhysicalMapKey::from(self.direct_profile))
                .ok_or(DurableError::InvalidRepresentationState(
                    "direct representation profile disappeared",
                ))?,
        )?;
        record.validate_against_profile(&Blake3PhysicalIdentity, &profile)?;
        let record_id = record.identify(&Blake3PhysicalIdentity)?;
        metadata.push(MetadataFrame::representation(
            &Blake3PhysicalIdentity,
            &record,
        )?);
        let update = self.representations.insert_with_delta(
            &Blake3PhysicalIdentity,
            PhysicalMapKey::from(record_id),
            record.encode()?,
        )?;
        append_map_nodes(metadata, update.new_nodes())?;
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
        let update = self.placement_entries.insert_with_delta(
            &Blake3PhysicalIdentity,
            PhysicalMapKey::from(object.blob),
            placement.encode()?,
        )?;
        append_map_nodes(metadata, update.new_nodes())?;
        Ok(Some((object.object, record_id)))
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
        update: PendingDirectUpdate,
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
        for (object, representation) in update.reverse_additions {
            self.reverse.entry(object).or_default().push(representation);
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

    pub(super) fn validate_generation_zero_arena<I: PersistentObjectIdentity>(
        &self,
        arena: &File,
        index: &BTreeMap<ObjectId, ArenaLocation>,
        identity: &I,
        limits: RecoveryLimits,
    ) -> Result<(), DurableError> {
        for (object, records) in &self.reverse {
            let location =
                index
                    .get(object)
                    .copied()
                    .ok_or(DurableError::InvalidRepresentationState(
                        "direct representation names a missing logical object",
                    ))?;
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
            if !placement.replicas().iter().any(|replica| {
                matches!(
                    replica.locator(),
                    ReplicaLocator::ArenaFrame {
                        arena_generation: 0,
                        offset,
                        payload_length,
                        frame_checksum,
                    } if offset == location.offset
                        && payload_length == location.payload_len
                        && frame_checksum == location.checksum
                )
            }) {
                return Err(DurableError::InvalidRepresentationState(
                    "generation-zero placement disagrees with the arena index",
                ));
            }
            let logical = read_indexed_object(arena, *object, location, identity, limits)?;
            let payload = encode_object_frame(identity.scheme(), *object, &logical)?;
            let canonical = canonical_record_bytes(&payload, identity.scheme())?;
            if BlobId::identify(&Blake3PhysicalIdentity, self.direct_profile, canonical)? != *blob {
                return Err(DurableError::InvalidRepresentationState(
                    "generation-zero blob identity does not match logical bytes",
                ));
            }
        }
        Ok(())
    }

    fn from_recovered(
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
            direct_profile,
            reverse,
        })
    }
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
