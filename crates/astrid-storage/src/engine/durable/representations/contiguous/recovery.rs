//! Recovery of virtual chunk objects from authoritative contiguous blobs.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Read;
#[cfg(not(any(unix, windows)))]
use std::io::{Seek, SeekFrom};
use std::path::Path;

use crate::content_dag::{ChunkingProfile, ContentObjectSink, build_content_streaming};
use crate::storage_model::{
    Coverage, ObjectId, ObjectKind, ObjectRecord, PhysicalMapKey, PlacementEntry, Recipe,
    ReplicaLocator, RepresentationAdmissionEvidence, RepresentationOutputObservation,
    RepresentationProfile, RepresentationRecord,
};

use super::{
    Blake3PhysicalIdentity, ContiguousIndexes, DurableError, RepresentationStore, chunk_record,
    contiguous_index_additions, verify_published_blob,
};
use crate::engine::durable::contiguous::ContiguousSlice;
use crate::engine::durable::{
    ArenaLocation, PersistentObjectIdentity, RecoveryLimits, io_error, read_indexed_object,
};

pub(super) fn active_contiguous_records(
    store: &RepresentationStore,
) -> Result<
    Vec<(
        crate::storage_model::RepresentationRecordId,
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

pub(super) struct RecoveryStore<'a, I, F: super::super::super::DurableIo> {
    arena: &'a mut F,
    index: &'a BTreeMap<ObjectId, ArenaLocation>,
    identity: &'a I,
    limits: RecoveryLimits,
}

impl<'a, I: PersistentObjectIdentity, F: super::super::super::DurableIo> RecoveryStore<'a, I, F> {
    pub(super) const fn new(
        arena: &'a mut F,
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
        record_id: crate::storage_model::RepresentationRecordId,
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

fn recover_contiguous_record_with_store<
    I: PersistentObjectIdentity,
    F: super::super::super::DurableIo,
>(
    representation_directory: &cap_std::fs::Dir,
    representation_root: &Path,
    record_id: crate::storage_model::RepresentationRecordId,
    record: &RepresentationRecord,
    profile: &RepresentationProfile,
    namespace_generation: u64,
    store: &mut RecoveryStore<'_, I, F>,
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

fn verify_admission_evidence<I: PersistentObjectIdentity, F: super::super::super::DurableIo>(
    store: &mut RecoveryStore<'_, I, F>,
    profile: &RepresentationProfile,
    record: &RepresentationRecord,
    blob: crate::storage_model::BlobId,
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
    map: &crate::storage_model::CanonicalPhysicalMap,
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
            crate::storage_model::PhysicalMapNode::Leaf { key, value, .. } => {
                entries.push((*key, value.as_slice()));
            },
            crate::storage_model::PhysicalMapNode::Branch { zero, one, .. } => {
                pending.extend([*one, *zero]);
            },
            crate::storage_model::PhysicalMapNode::Page { entries: page, .. } => {
                entries.extend(page.iter().map(|(key, value)| (*key, value.as_slice())));
            },
            crate::storage_model::PhysicalMapNode::Radix { children, .. } => {
                pending.extend(children.iter().rev().copied());
            },
        }
    }
    Ok(entries)
}

struct RecoverySink<'a, I, F: super::super::super::DurableIo> {
    arena: &'a mut F,
    index: &'a BTreeMap<ObjectId, ArenaLocation>,
    identity: &'a I,
    limits: RecoveryLimits,
    blob: File,
    offset: u64,
    slices: BTreeMap<ObjectId, ContiguousSlice>,
    observations: Vec<RepresentationOutputObservation>,
    canonical_output_bytes: u64,
}

impl<I: PersistentObjectIdentity, F: super::super::super::DurableIo> ContentObjectSink
    for RecoverySink<'_, I, F>
{
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
                    return Err(crate::storage_model::ModelError::ObjectCollision(id).into());
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
            .ok_or(crate::storage_model::ModelError::MissingObject(id))?;
        if read_indexed_object(self.arena, id, location, self.identity, self.limits)? != record {
            return Err(crate::storage_model::ModelError::ObjectCollision(id).into());
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
    let length = usize::try_from(location.length).map_err(|_| DurableError::EncodingOverflow)?;
    let mut bytes = vec![0; length];
    read_exact_at(file, &mut bytes, location.offset)
        .map_err(|source| io_error("read repeated contiguous chunk", source))?;
    let record = chunk_record(bytes)?;
    if identity.identify(&record) != expected {
        return Err(DurableError::InvalidRepresentationState(
            "repeated contiguous chunk identity mismatch",
        ));
    }
    Ok(record)
}

#[cfg(unix)]
fn read_exact_at(file: &File, bytes: &mut [u8], offset: u64) -> std::io::Result<()> {
    use std::os::unix::fs::FileExt as _;

    file.read_exact_at(bytes, offset)
}

#[cfg(windows)]
fn read_exact_at(file: &File, mut bytes: &mut [u8], mut offset: u64) -> std::io::Result<()> {
    use std::os::windows::fs::FileExt as _;

    while !bytes.is_empty() {
        let read = file.seek_read(bytes, offset)?;
        if read == 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
        }
        offset = offset
            .checked_add(u64::try_from(read).map_err(std::io::Error::other)?)
            .ok_or_else(|| std::io::Error::other("positional read offset overflow"))?;
        bytes = &mut bytes[read..];
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn read_exact_at(file: &File, bytes: &mut [u8], offset: u64) -> std::io::Result<()> {
    let mut cursor = file.try_clone()?;
    let original = cursor.stream_position()?;
    let result = cursor
        .seek(SeekFrom::Start(offset))
        .and_then(|_| cursor.read_exact(bytes));
    let restore = cursor.seek(SeekFrom::Start(original)).map(drop);
    result.and(restore)
}

fn map_recovery_stream_error(
    error: crate::content_dag::ContentStreamError<DurableError>,
) -> DurableError {
    match error {
        crate::content_dag::ContentStreamError::Content(error) => error.into(),
        crate::content_dag::ContentStreamError::Source(source) => {
            io_error("read contiguous blob during recovery", source)
        },
        crate::content_dag::ContentStreamError::Sink(error) => error,
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read as _, Seek as _, SeekFrom, Write as _};

    #[test]
    fn repeated_chunk_read_does_not_move_streaming_cursor() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("contiguous-reader");
        let mut writer = std::fs::File::create(&path).unwrap();
        writer.write_all(b"first-second-third").unwrap();
        writer.sync_all().unwrap();
        drop(writer);

        let mut stream = std::fs::File::open(path).unwrap();
        stream.seek(SeekFrom::Start(12)).unwrap();
        let duplicate_reader = stream.try_clone().unwrap();
        let mut duplicate = [0_u8; 5];
        super::read_exact_at(&duplicate_reader, &mut duplicate, 0).unwrap();
        assert_eq!(&duplicate, b"first");

        let mut remaining = Vec::new();
        stream.read_to_end(&mut remaining).unwrap();
        assert_eq!(remaining, b"-third");
    }
}
