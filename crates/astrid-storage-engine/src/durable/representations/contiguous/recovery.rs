//! Recovery of virtual chunk objects from authoritative contiguous blobs.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use astrid_storage_content::{ChunkingProfile, ContentObjectSink, build_content_streaming};
use astrid_storage_model::{
    Coverage, ObjectId, ObjectKind, ObjectRecord, PhysicalMapKey, PlacementEntry, Recipe,
    ReplicaLocator, RepresentationAdmissionEvidence, RepresentationOutputObservation,
    RepresentationProfile, RepresentationRecord,
};

use super::{
    Blake3PhysicalIdentity, ContiguousIndexes, DurableError, RepresentationStore, chunk_record,
    contiguous_index_additions, verify_published_blob,
};
use crate::durable::contiguous::ContiguousSlice;
use crate::durable::{
    ArenaLocation, PersistentObjectIdentity, RecoveryLimits, io_error, read_indexed_object,
};

pub(super) fn active_contiguous_records(
    store: &RepresentationStore,
) -> Result<
    Vec<(
        astrid_storage_model::RepresentationRecordId,
        RepresentationRecord,
        u64,
    )>,
    DurableError,
> {
    let mut records = Vec::new();
    for (key, bytes) in active_entries(&store.representations)? {
        let record = RepresentationRecord::decode(bytes)?;
        if !matches!(record.recipe(), Recipe::ContiguousFile { .. }) {
            continue;
        }
        let id = record.identify(&Blake3PhysicalIdentity)?;
        if PhysicalMapKey::from(id) != key {
            return Err(DurableError::InvalidRepresentationState(
                "contiguous representation key mismatch",
            ));
        }
        let profile = RepresentationProfile::decode(
            store
                .profiles
                .get(PhysicalMapKey::from(record.profile()))
                .ok_or(DurableError::InvalidRepresentationState(
                    "contiguous profile is missing",
                ))?,
        )?;
        record.validate_against_profile(&Blake3PhysicalIdentity, &profile)?;
        let blob = match record.recipe() {
            Recipe::ContiguousFile { blob } => *blob,
            _ => continue,
        };
        let placement = PlacementEntry::decode(
            store
                .placement_entries
                .get(PhysicalMapKey::from(blob))
                .ok_or(DurableError::InvalidRepresentationState(
                    "contiguous placement is missing",
                ))?,
        )?;
        if placement.blob() != blob
            || placement.profile() != record.profile()
            || placement.encoded_length()
                != match record.coverage() {
                    Coverage::CanonicalFileChunks { logical_bytes, .. } => *logical_bytes,
                    Coverage::Exact { .. } => continue,
                }
        {
            return Err(DurableError::InvalidRepresentationState(
                "contiguous placement disagrees with its representation",
            ));
        }
        let namespace_generation = placement
            .replicas()
            .iter()
            .find_map(|replica| {
                (replica.storage_node() == super::super::LOCAL_STORAGE_NODE).then(|| {
                    if let ReplicaLocator::LooseBlob {
                        namespace_generation,
                    } = replica.locator()
                    {
                        Some(namespace_generation)
                    } else {
                        None
                    }
                })?
            })
            .ok_or(DurableError::InvalidRepresentationState(
                "contiguous placement has no local loose blob",
            ))?;
        records.push((id, record, namespace_generation));
    }
    Ok(records)
}

pub(super) struct RecoveryStore<'a, I> {
    arena: &'a mut File,
    index: &'a BTreeMap<ObjectId, ArenaLocation>,
    identity: &'a I,
    limits: RecoveryLimits,
}

impl<'a, I: PersistentObjectIdentity> RecoveryStore<'a, I> {
    pub(super) const fn new(
        arena: &'a mut File,
        index: &'a BTreeMap<ObjectId, ArenaLocation>,
        identity: &'a I,
        limits: RecoveryLimits,
    ) -> Self {
        Self {
            arena,
            index,
            identity,
            limits,
        }
    }

    pub(super) fn recover_contiguous_record(
        &mut self,
        representation_directory: &cap_std::fs::Dir,
        representation_root: &Path,
        record_id: astrid_storage_model::RepresentationRecordId,
        record: &RepresentationRecord,
        profile: &RepresentationProfile,
        namespace_generation: u64,
    ) -> Result<ContiguousIndexes, DurableError> {
        recover_contiguous_record_with_store(
            representation_directory,
            representation_root,
            record_id,
            record,
            profile,
            namespace_generation,
            self,
        )
    }
}

fn recover_contiguous_record_with_store<I: PersistentObjectIdentity>(
    representation_directory: &cap_std::fs::Dir,
    representation_root: &Path,
    record_id: astrid_storage_model::RepresentationRecordId,
    record: &RepresentationRecord,
    profile: &RepresentationProfile,
    namespace_generation: u64,
    store: &mut RecoveryStore<'_, I>,
) -> Result<ContiguousIndexes, DurableError> {
    let Coverage::CanonicalFileChunks {
        file,
        content_root,
        logical_bytes,
        chunk_count,
        chunking_profile,
    } = record.coverage()
    else {
        return Err(DurableError::InvalidRepresentationState(
            "contiguous representation has non-file coverage",
        ));
    };
    let Recipe::ContiguousFile { blob } = record.recipe() else {
        return Err(DurableError::InvalidRepresentationState(
            "contiguous representation has a different recipe",
        ));
    };
    let blob_file = verify_published_blob(
        representation_directory,
        representation_root,
        namespace_generation,
        *blob,
        record.profile(),
        *logical_bytes,
    )?;
    let sink_file = blob_file
        .try_clone()
        .map_err(|source| io_error("clone contiguous loose blob", source))?;
    let logical_profile = ChunkingProfile::fastcdc_v2020(
        chunking_profile.minimum_bytes(),
        chunking_profile.average_bytes(),
        chunking_profile.maximum_bytes(),
        chunking_profile.gear_seed(),
    )?;
    let mut sink = RecoverySink {
        arena: store.arena,
        index: store.index,
        identity: store.identity,
        limits: store.limits,
        blob: sink_file,
        offset: 0,
        slices: BTreeMap::new(),
        observations: Vec::new(),
        canonical_output_bytes: 0,
    };
    let streamed =
        build_content_streaming(logical_profile, blob_file.take(*logical_bytes), &mut sink)
            .map_err(map_recovery_stream_error)?;
    let descriptor = streamed.descriptor();
    if descriptor.file() != *file
        || streamed.verified_content().opened_content().content_root() != *content_root
        || descriptor.logical_bytes() != *logical_bytes
        || descriptor.chunk_count() != *chunk_count
        || descriptor.profile() != logical_profile
        || sink.canonical_output_bytes != record.canonical_output_bytes()
    {
        return Err(DurableError::InvalidRepresentationState(
            "contiguous representation disagrees with reconstructed file DAG",
        ));
    }
    let observations = std::mem::take(&mut sink.observations);
    let slices = std::mem::take(&mut sink.slices);
    drop(sink);
    verify_admission_evidence(store, profile, record, *blob, *logical_bytes, &observations)?;
    Ok(contiguous_index_additions(
        record_id,
        *blob,
        namespace_generation,
        &slices,
    ))
}

fn verify_admission_evidence<I: PersistentObjectIdentity>(
    store: &mut RecoveryStore<'_, I>,
    profile: &RepresentationProfile,
    record: &RepresentationRecord,
    blob: astrid_storage_model::BlobId,
    logical_bytes: u64,
    observations: &[RepresentationOutputObservation],
) -> Result<(), DurableError> {
    let expected = RepresentationAdmissionEvidence::new(
        &Blake3PhysicalIdentity,
        profile,
        record,
        blob,
        logical_bytes,
        observations,
    )?
    .object_record()?;
    let evidence_id = store.identity.identify(&expected);
    if record.verification_evidence() != Some(evidence_id) {
        return Err(DurableError::InvalidRepresentationState(
            "contiguous representation names different admission evidence",
        ));
    }
    let location =
        store
            .index
            .get(&evidence_id)
            .copied()
            .ok_or(DurableError::InvalidRepresentationState(
                "contiguous admission evidence is missing from the arena",
            ))?;
    if read_indexed_object(
        store.arena,
        evidence_id,
        location,
        store.identity,
        store.limits,
    )? != expected
    {
        return Err(DurableError::InvalidRepresentationState(
            "contiguous admission evidence bytes disagree",
        ));
    }
    Ok(())
}

fn active_entries(
    map: &astrid_storage_model::CanonicalPhysicalMap,
) -> Result<Vec<(PhysicalMapKey, &[u8])>, DurableError> {
    let Some(root) = map.root() else {
        return Ok(Vec::new());
    };
    let mut entries = Vec::new();
    let mut pending = vec![root];
    let mut visited = BTreeSet::new();
    while let Some(id) = pending.pop() {
        if !visited.insert(id) {
            return Err(DurableError::InvalidRepresentationState(
                "contiguous map traversal revisited a node",
            ));
        }
        match map
            .nodes()
            .get(&id)
            .ok_or(DurableError::InvalidRepresentationState(
                "contiguous map traversal found a missing node",
            ))? {
            astrid_storage_model::PhysicalMapNode::Leaf { key, value, .. } => {
                entries.push((*key, value.as_slice()));
            },
            astrid_storage_model::PhysicalMapNode::Branch { zero, one, .. } => {
                pending.extend([*one, *zero]);
            },
            astrid_storage_model::PhysicalMapNode::Page { entries: page, .. } => {
                entries.extend(page.iter().map(|(key, value)| (*key, value.as_slice())));
            },
            astrid_storage_model::PhysicalMapNode::Radix { children, .. } => {
                pending.extend(children.iter().rev().copied());
            },
        }
    }
    Ok(entries)
}

struct RecoverySink<'a, I> {
    arena: &'a mut File,
    index: &'a BTreeMap<ObjectId, ArenaLocation>,
    identity: &'a I,
    limits: RecoveryLimits,
    blob: File,
    offset: u64,
    slices: BTreeMap<ObjectId, ContiguousSlice>,
    observations: Vec<RepresentationOutputObservation>,
    canonical_output_bytes: u64,
}

impl<I: PersistentObjectIdentity> ContentObjectSink for RecoverySink<'_, I> {
    type Error = DurableError;

    fn stage_content_object(&mut self, record: ObjectRecord) -> Result<ObjectId, Self::Error> {
        let id = self.identity.identify(&record);
        if record.kind() == ObjectKind::Chunk {
            let length = u64::try_from(record.canonical_bytes().len())
                .map_err(|_| DurableError::EncodingOverflow)?;
            if let Some(previous) = self.slices.get(&id).copied() {
                let prior =
                    read_contiguous_object_from_file(&self.blob, previous, id, self.identity)?;
                if prior != record {
                    return Err(astrid_storage_model::ModelError::ObjectCollision(id).into());
                }
            } else {
                let canonical = record.retained_bytes()?;
                self.canonical_output_bytes = self
                    .canonical_output_bytes
                    .checked_add(canonical)
                    .ok_or(DurableError::EncodingOverflow)?;
                self.observations
                    .push(RepresentationOutputObservation::new(id, canonical));
                self.slices.insert(
                    id,
                    ContiguousSlice {
                        offset: self.offset,
                        length,
                    },
                );
            }
            self.offset = self
                .offset
                .checked_add(length)
                .ok_or(DurableError::EncodingOverflow)?;
            return Ok(id);
        }
        let location = self
            .index
            .get(&id)
            .copied()
            .ok_or(astrid_storage_model::ModelError::MissingObject(id))?;
        if read_indexed_object(self.arena, id, location, self.identity, self.limits)? != record {
            return Err(astrid_storage_model::ModelError::ObjectCollision(id).into());
        }
        Ok(id)
    }
}

fn read_contiguous_object_from_file<I: PersistentObjectIdentity>(
    file: &File,
    location: ContiguousSlice,
    expected: ObjectId,
    identity: &I,
) -> Result<ObjectRecord, DurableError> {
    let mut file = file
        .try_clone()
        .map_err(|source| io_error("clone contiguous chunk reader", source))?;
    file.seek(SeekFrom::Start(location.offset))
        .map_err(|source| io_error("seek repeated contiguous chunk", source))?;
    let length = usize::try_from(location.length).map_err(|_| DurableError::EncodingOverflow)?;
    let mut bytes = vec![0; length];
    file.read_exact(&mut bytes)
        .map_err(|source| io_error("read repeated contiguous chunk", source))?;
    let record = chunk_record(bytes)?;
    if identity.identify(&record) != expected {
        return Err(DurableError::InvalidRepresentationState(
            "repeated contiguous chunk identity mismatch",
        ));
    }
    Ok(record)
}

fn map_recovery_stream_error(
    error: astrid_storage_content::ContentStreamError<DurableError>,
) -> DurableError {
    match error {
        astrid_storage_content::ContentStreamError::Content(error) => error.into(),
        astrid_storage_content::ContentStreamError::Source(source) => {
            io_error("read contiguous blob during recovery", source)
        },
        astrid_storage_content::ContentStreamError::Sink(error) => error,
    }
}
