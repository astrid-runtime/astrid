//! Contiguous-file catalogue entries and disposable chunk-slice locations.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use astrid_storage_model::{
    Coverage, ObjectClass, ObjectFormatVersion, ObjectId, ObjectKind, ObjectRecord, PhysicalMapKey,
    PlacementEntry, Recipe, Replica, ReplicaLocator, RepresentationProfile, RepresentationRecord,
};

use super::activation::append_new_reachable_map_nodes;
use super::format::{Blake3PhysicalIdentity, MetadataFrame};
use super::{
    ContiguousLocation, DurableError, METADATA_MAGIC, PendingRepresentationUpdate,
    RepresentationStore, append_frames,
};
use crate::durable::contiguous::ContiguousSlice;
use crate::durable::{
    ArenaLocation, PersistentObjectIdentity, RecoveryLimits, io_error, sync_store_directory,
};

mod platform;
mod recovery;
use platform::{clone_file_no_replace, clone_is_unsupported, open_regular_read};

pub(super) const LOOSE_NAMESPACE_GENERATION: u64 = 1;
const LOOSE_META_MAGIC: [u8; 8] = *b"ASTBLM1\0";
const LOOSE_META_VERSION: u16 = 1;
static COPY_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

impl RepresentationStore {
    pub(in crate::durable) fn append_contiguous_update(
        &mut self,
        profile: &RepresentationProfile,
        representation: &RepresentationRecord,
        slices: &BTreeMap<astrid_storage_model::ObjectId, ContiguousSlice>,
    ) -> Result<Option<PendingRepresentationUpdate>, DurableError> {
        let profile_id = profile.identify(&Blake3PhysicalIdentity)?;
        if profile_id != representation.profile() {
            return Err(DurableError::InvalidRepresentationState(
                "contiguous representation names a different profile",
            ));
        }
        representation.validate_against_profile(&Blake3PhysicalIdentity, profile)?;
        let (blob, logical_bytes) = match (representation.recipe(), representation.coverage()) {
            (
                Recipe::ContiguousFile { blob },
                Coverage::CanonicalFileChunks { logical_bytes, .. },
            ) => (*blob, *logical_bytes),
            _ => {
                return Err(DurableError::InvalidRepresentationState(
                    "contiguous update has incompatible coverage or recipe",
                ));
            },
        };
        let representation_id = representation.identify(&Blake3PhysicalIdentity)?;
        let placement = PlacementEntry::new(
            blob,
            profile_id,
            logical_bytes,
            vec![Replica::new(
                super::LOCAL_STORAGE_NODE,
                ReplicaLocator::LooseBlob {
                    namespace_generation: LOOSE_NAMESPACE_GENERATION,
                },
            )?],
        )?;

        let mut changed = false;
        changed |= self.profiles.insert(
            &Blake3PhysicalIdentity,
            PhysicalMapKey::from(profile_id),
            profile.encode()?,
        )?;
        changed |= self.representations.insert(
            &Blake3PhysicalIdentity,
            PhysicalMapKey::from(representation_id),
            representation.encode()?,
        )?;
        changed |= self.placement_entries.insert(
            &Blake3PhysicalIdentity,
            PhysicalMapKey::from(blob),
            placement.encode()?,
        )?;

        let (reverse_additions, contiguous_additions) =
            contiguous_index_additions(representation_id, blob, LOOSE_NAMESPACE_GENERATION, slices);
        if !changed {
            self.install_contiguous_indexes(&reverse_additions, &contiguous_additions);
            return Ok(None);
        }

        self.append_contiguous_authority(reverse_additions, contiguous_additions)
    }

    pub(in crate::durable) fn contiguous_read(
        &self,
        object: ObjectId,
    ) -> Option<(PathBuf, ContiguousLocation)> {
        let location = self.contiguous.get(&object).copied()?;
        Some((
            self.loose_blob_path(location.blob, location.namespace_generation),
            location,
        ))
    }

    pub(in crate::durable) fn contains_contiguous(&self, object: ObjectId) -> bool {
        self.contiguous.contains_key(&object)
    }

    pub(in crate::durable) fn contiguous_count_excluding(
        &self,
        arena: &BTreeMap<ObjectId, ArenaLocation>,
    ) -> usize {
        self.contiguous
            .keys()
            .filter(|object| !arena.contains_key(object))
            .count()
    }

    pub(in crate::durable) fn rebuild_contiguous_index<I: PersistentObjectIdentity>(
        &mut self,
        arena: &mut File,
        index: &BTreeMap<ObjectId, ArenaLocation>,
        identity: &I,
        limits: RecoveryLimits,
    ) -> Result<(), DurableError> {
        self.contiguous.clear();
        let active = recovery::active_contiguous_records(self)?;
        let mut recovery = recovery::RecoveryStore::new(arena, index, identity, limits);
        for (record_id, record, namespace_generation) in active {
            let (reverse, locations) = recovery.recover_contiguous_record(
                &self.root,
                record_id,
                &record,
                namespace_generation,
            )?;
            self.install_contiguous_indexes(&reverse, &locations);
        }
        Ok(())
    }

    pub(in crate::durable) fn loose_blob_path(
        &self,
        blob: astrid_storage_model::BlobId,
        namespace_generation: u64,
    ) -> PathBuf {
        loose_blob_path_from_representation_root(&self.root, blob, namespace_generation)
    }

    fn install_contiguous_indexes(
        &mut self,
        reverse: &[(
            astrid_storage_model::ObjectId,
            astrid_storage_model::RepresentationRecordId,
        )],
        locations: &[(astrid_storage_model::ObjectId, ContiguousLocation)],
    ) {
        for (object, representation) in reverse {
            let records = self.reverse.entry(*object).or_default();
            if !records.contains(representation) {
                records.push(*representation);
            }
        }
        self.contiguous.extend(locations.iter().copied());
    }

    fn append_contiguous_authority(
        &mut self,
        reverse_additions: Vec<(ObjectId, astrid_storage_model::RepresentationRecordId)>,
        contiguous_additions: Vec<(ObjectId, ContiguousLocation)>,
    ) -> Result<Option<PendingRepresentationUpdate>, DurableError> {
        let mut metadata = Vec::new();
        let mut appended_map_nodes = BTreeSet::new();
        for map in [
            &self.profiles,
            &self.representations,
            &self.placement_entries,
        ] {
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
        Ok(Some(PendingRepresentationUpdate {
            state,
            state_id,
            catalogue,
            placements,
            reverse_additions,
            contiguous_additions,
        }))
    }
}

type ContiguousIndexes = (
    Vec<(ObjectId, astrid_storage_model::RepresentationRecordId)>,
    Vec<(ObjectId, ContiguousLocation)>,
);

fn contiguous_index_additions(
    representation: astrid_storage_model::RepresentationRecordId,
    blob: astrid_storage_model::BlobId,
    namespace_generation: u64,
    slices: &BTreeMap<ObjectId, ContiguousSlice>,
) -> ContiguousIndexes {
    let reverse = slices
        .keys()
        .copied()
        .map(|object| (object, representation))
        .collect();
    let locations = slices
        .iter()
        .map(|(object, slice)| {
            (
                *object,
                ContiguousLocation {
                    blob,
                    namespace_generation,
                    offset: slice.offset,
                    length: slice.length,
                },
            )
        })
        .collect();
    (reverse, locations)
}

pub(in crate::durable) fn install_loose_blob_copy(
    store: &Path,
    blob: astrid_storage_model::BlobId,
    profile: astrid_storage_model::RepresentationProfileId,
    logical_bytes: u64,
    source: impl Read,
) -> Result<PathBuf, DurableError> {
    let path = loose_blob_path_from_representation_root(
        &store.join(super::DIRECTORY),
        blob,
        LOOSE_NAMESPACE_GENERATION,
    );
    let directory = path
        .parent()
        .ok_or(DurableError::InvalidRepresentationState(
            "loose blob path has no parent",
        ))?;
    ensure_loose_blob_directory(store, LOOSE_NAMESPACE_GENERATION)?;
    ensure_loose_metadata(&path, profile, blob, logical_bytes)?;
    let sequence = COPY_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary =
        path.with_extension(format!("blob.copy.{}.{}.tmp", std::process::id(), sequence));
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut output = options
        .open(&temporary)
        .map_err(|source| io_error("create loose blob temporary", source))?;
    let copied = std::io::copy(&mut source.take(logical_bytes), &mut output)
        .map_err(|source| io_error("copy loose blob bytes", source))?;
    if copied != logical_bytes {
        let _ = std::fs::remove_file(&temporary);
        return Err(DurableError::InvalidRepresentationState(
            "loose blob source ended before its declared length",
        ));
    }
    output
        .flush()
        .and_then(|()| output.sync_all())
        .map_err(|source| io_error("flush loose blob temporary", source))?;
    drop(output);
    publish_loose_blob_temporary(&temporary, &path, profile, blob, logical_bytes)?;
    sync_store_directory(directory)?;
    Ok(path)
}

pub(in crate::durable) fn install_loose_blob_from_path(
    store: &Path,
    blob: astrid_storage_model::BlobId,
    profile: astrid_storage_model::RepresentationProfileId,
    logical_bytes: u64,
    source: &Path,
) -> Result<PathBuf, DurableError> {
    let mut source = open_regular_read(source)
        .map_err(|source| io_error("open loose blob adoption source no-follow", source))?;
    if source
        .metadata()
        .map_err(|source| io_error("inspect loose blob adoption source", source))?
        .len()
        < logical_bytes
    {
        return Err(DurableError::InvalidRepresentationState(
            "loose blob adoption source is truncated",
        ));
    }
    let path = loose_blob_path_from_representation_root(
        &store.join(super::DIRECTORY),
        blob,
        LOOSE_NAMESPACE_GENERATION,
    );
    let directory = path
        .parent()
        .ok_or(DurableError::InvalidRepresentationState(
            "loose blob path has no parent",
        ))?;
    ensure_loose_blob_directory(store, LOOSE_NAMESPACE_GENERATION)?;
    ensure_loose_metadata(&path, profile, blob, logical_bytes)?;
    let sequence = COPY_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = path.with_extension(format!(
        "blob.adopt.{}.{}.tmp",
        std::process::id(),
        sequence
    ));
    match clone_file_no_replace(&source, &temporary) {
        Ok(()) => {
            let file = OpenOptions::new()
                .write(true)
                .open(&temporary)
                .map_err(|source| io_error("open cloned loose blob temporary", source))?;
            file.set_len(logical_bytes)
                .and_then(|()| file.sync_all())
                .map_err(|source| io_error("truncate and flush cloned loose blob", source))?;
        },
        Err(error) if clone_is_unsupported(&error) => {
            let _ = std::fs::remove_file(&temporary);
            source
                .seek(SeekFrom::Start(0))
                .map_err(|source| io_error("rewind loose blob adoption source", source))?;
            return install_loose_blob_copy(store, blob, profile, logical_bytes, source);
        },
        Err(source) => return Err(io_error("clone loose blob adoption source", source)),
    }
    publish_loose_blob_temporary(&temporary, &path, profile, blob, logical_bytes)?;
    sync_store_directory(directory)?;
    Ok(path)
}

fn publish_loose_blob_temporary(
    temporary: &Path,
    path: &Path,
    profile: astrid_storage_model::RepresentationProfileId,
    blob: astrid_storage_model::BlobId,
    logical_bytes: u64,
) -> Result<(), DurableError> {
    verify_blob_bytes(temporary, profile, blob, logical_bytes)?;
    match std::fs::hard_link(temporary, path) {
        Ok(()) => {
            std::fs::remove_file(temporary)
                .map_err(|source| io_error("remove published loose blob temporary", source))?;
        },
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            verify_blob_bytes(path, profile, blob, logical_bytes)?;
            compare_files(temporary, path, logical_bytes)?;
            std::fs::remove_file(temporary)
                .map_err(|source| io_error("remove duplicate loose blob temporary", source))?;
        },
        Err(source) => return Err(io_error("publish loose blob", source)),
    }
    Ok(())
}

fn ensure_loose_blob_directory(
    store: &Path,
    namespace_generation: u64,
) -> Result<(), DurableError> {
    let representation_root = store.join(super::DIRECTORY);
    let blobs = representation_root.join("blobs");
    let loose = blobs.join("loose");
    let generation = loose.join(format!("{namespace_generation:016x}"));
    for (parent, directory) in [
        (representation_root.as_path(), blobs.as_path()),
        (blobs.as_path(), loose.as_path()),
        (loose.as_path(), generation.as_path()),
    ] {
        match std::fs::create_dir(directory) {
            Ok(()) => sync_store_directory(parent)?,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let metadata = std::fs::symlink_metadata(directory)
                    .map_err(|source| io_error("inspect loose blob directory", source))?;
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(DurableError::InvalidRepresentationState(
                        "loose blob namespace component is redirected or not a directory",
                    ));
                }
            },
            Err(source) => return Err(io_error("create loose blob directory", source)),
        }
    }
    Ok(())
}

fn ensure_loose_metadata(
    blob_path: &Path,
    profile: astrid_storage_model::RepresentationProfileId,
    blob: astrid_storage_model::BlobId,
    logical_bytes: u64,
) -> Result<(), DurableError> {
    let metadata_path = blob_path.with_extension("meta");
    let sequence = COPY_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary =
        blob_path.with_extension(format!("meta.{}.{}.tmp", std::process::id(), sequence));
    let expected = encode_loose_metadata(profile, blob, logical_bytes)?;
    match std::fs::symlink_metadata(&metadata_path) {
        Ok(_) => {
            verify_exact_regular_file(&metadata_path, &expected, "loose blob metadata")?;
            return Ok(());
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
        Err(source) => return Err(io_error("inspect loose blob metadata", source)),
    }
    create_exact_file(&temporary, &expected, "loose blob metadata temporary")?;
    match std::fs::hard_link(&temporary, &metadata_path) {
        Ok(()) => {},
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            verify_exact_regular_file(&metadata_path, &expected, "loose blob metadata")?;
        },
        Err(source) => return Err(io_error("publish loose blob metadata", source)),
    }
    std::fs::remove_file(&temporary)
        .map_err(|source| io_error("remove loose blob metadata temporary", source))?;
    let directory = metadata_path
        .parent()
        .ok_or(DurableError::InvalidRepresentationState(
            "loose metadata path has no parent",
        ))?;
    sync_store_directory(directory)
}

fn create_exact_file(
    path: &Path,
    bytes: &[u8],
    operation: &'static str,
) -> Result<(), DurableError> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|source| io_error(operation, source))?;
    file.write_all(bytes)
        .and_then(|()| file.flush())
        .and_then(|()| file.sync_all())
        .map_err(|source| io_error(operation, source))
}

fn encode_loose_metadata(
    profile: astrid_storage_model::RepresentationProfileId,
    blob: astrid_storage_model::BlobId,
    logical_bytes: u64,
) -> Result<Vec<u8>, DurableError> {
    let mut payload = Vec::with_capacity(90);
    payload.extend_from_slice(&LOOSE_META_VERSION.to_le_bytes());
    append_tagged_identity(&mut payload, blob.as_bytes());
    append_tagged_identity(&mut payload, profile.as_bytes());
    payload.extend_from_slice(&logical_bytes.to_le_bytes());
    let payload_len = u64::try_from(payload.len()).map_err(|_| DurableError::EncodingOverflow)?;
    let checksum = crate::durable::format::frame_checksum(LOOSE_META_MAGIC, payload_len, &payload);
    let capacity = crate::durable::FRAME_HEADER_LEN_USIZE
        .checked_add(payload.len())
        .ok_or(DurableError::EncodingOverflow)?;
    let mut encoded = Vec::with_capacity(capacity);
    encoded.extend_from_slice(&LOOSE_META_MAGIC);
    encoded.extend_from_slice(&crate::durable::FRAME_VERSION.to_le_bytes());
    encoded.extend_from_slice(&[0; 2]);
    encoded.extend_from_slice(&payload_len.to_le_bytes());
    encoded.extend_from_slice(&checksum);
    encoded.extend_from_slice(&payload);
    Ok(encoded)
}

fn append_tagged_identity(output: &mut Vec<u8>, digest: &[u8; 32]) {
    output.extend_from_slice(&1_u16.to_le_bytes());
    output.extend_from_slice(&2_u16.to_le_bytes());
    output.extend_from_slice(&32_u32.to_le_bytes());
    output.extend_from_slice(digest);
}

fn verify_exact_regular_file(
    path: &Path,
    expected: &[u8],
    description: &'static str,
) -> Result<(), DurableError> {
    let mut file = open_authoritative_regular(path, description)?;
    if file
        .metadata()
        .map_err(|source| io_error("inspect loose representation file", source))?
        .len()
        != u64::try_from(expected.len()).map_err(|_| DurableError::EncodingOverflow)?
    {
        return Err(DurableError::InvalidRepresentationState(description));
    }
    let mut actual = Vec::new();
    file.read_to_end(&mut actual)
        .map_err(|source| io_error("read loose representation file", source))?;
    if actual != expected {
        return Err(DurableError::InvalidRepresentationState(description));
    }
    Ok(())
}

fn compare_files(left: &Path, right: &Path, logical_bytes: u64) -> Result<(), DurableError> {
    let mut left = open_regular_read(left)
        .map_err(|source| io_error("open candidate loose blob no-follow", source))?;
    let mut right = open_authoritative_regular(
        right,
        "occupied loose blob is redirected or not a regular file",
    )?;
    let mut left_buffer = vec![0; 1024 * 1024];
    let mut right_buffer = vec![0; 1024 * 1024];
    let mut remaining = logical_bytes;
    while remaining != 0 {
        let target = usize::try_from(remaining.min(left_buffer.len() as u64))
            .map_err(|_| DurableError::EncodingOverflow)?;
        left.read_exact(&mut left_buffer[..target])
            .map_err(|source| io_error("read candidate loose blob", source))?;
        right
            .read_exact(&mut right_buffer[..target])
            .map_err(|source| io_error("read occupied loose blob", source))?;
        if left_buffer[..target] != right_buffer[..target] {
            return Err(DurableError::InvalidRepresentationState(
                "occupied loose blob has a different complete preimage",
            ));
        }
        remaining = remaining
            .checked_sub(u64::try_from(target).map_err(|_| DurableError::EncodingOverflow)?)
            .ok_or(DurableError::EncodingOverflow)?;
    }
    Ok(())
}

fn loose_blob_path_from_representation_root(
    root: &Path,
    blob: astrid_storage_model::BlobId,
    namespace_generation: u64,
) -> PathBuf {
    root.join("blobs")
        .join("loose")
        .join(format!("{namespace_generation:016x}"))
        .join(format!("{}.blob", tagged_blob_hex(blob)))
}

pub(in crate::durable) fn read_contiguous_object<I: PersistentObjectIdentity>(
    path: &Path,
    location: ContiguousLocation,
    expected: ObjectId,
    identity: &I,
) -> Result<ObjectRecord, DurableError> {
    let mut file = open_authoritative_regular(
        path,
        "contiguous blob is missing, redirected, or not a regular file",
    )?;
    file.seek(SeekFrom::Start(location.offset))
        .map_err(|source| io_error("seek contiguous chunk", source))?;
    let length = usize::try_from(location.length).map_err(|_| DurableError::EncodingOverflow)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| DurableError::EncodingOverflow)?;
    bytes.resize(length, 0);
    file.read_exact(&mut bytes)
        .map_err(|source| io_error("read contiguous chunk", source))?;
    let record = chunk_record(bytes)?;
    if identity.identify(&record) != expected {
        return Err(DurableError::InvalidRepresentationState(
            "contiguous chunk identity mismatch",
        ));
    }
    Ok(record)
}

fn chunk_record(bytes: Vec<u8>) -> Result<ObjectRecord, DurableError> {
    Ok(ObjectRecord::new(
        ObjectKind::Chunk,
        ObjectFormatVersion::V1,
        bytes,
        Vec::new(),
        0,
        ObjectClass::Data,
    )?)
}

fn verify_published_blob(
    path: &Path,
    profile: astrid_storage_model::RepresentationProfileId,
    expected: astrid_storage_model::BlobId,
    logical_bytes: u64,
) -> Result<(), DurableError> {
    let metadata = encode_loose_metadata(profile, expected, logical_bytes)?;
    verify_exact_regular_file(
        &path.with_extension("meta"),
        &metadata,
        "loose blob metadata mismatch",
    )?;
    verify_blob_bytes(path, profile, expected, logical_bytes)
}

fn verify_blob_bytes(
    path: &Path,
    profile: astrid_storage_model::RepresentationProfileId,
    expected: astrid_storage_model::BlobId,
    logical_bytes: u64,
) -> Result<(), DurableError> {
    let mut file = open_authoritative_regular(
        path,
        "loose blob is missing, redirected, or not a regular file",
    )?;
    if file
        .metadata()
        .map_err(|source| io_error("inspect loose blob", source))?
        .len()
        != logical_bytes
    {
        return Err(DurableError::InvalidRepresentationState(
            "loose blob is redirected, not regular, or has the wrong length",
        ));
    }
    let mut hasher = blob_hasher(profile, logical_bytes);
    let mut buffer = vec![0; 1024 * 1024];
    let mut remaining = logical_bytes;
    while remaining != 0 {
        let target = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| DurableError::EncodingOverflow)?;
        file.read_exact(&mut buffer[..target])
            .map_err(|source| io_error("read loose blob", source))?;
        hasher.update(&buffer[..target]);
        remaining = remaining
            .checked_sub(u64::try_from(target).map_err(|_| DurableError::EncodingOverflow)?)
            .ok_or(DurableError::EncodingOverflow)?;
    }
    if astrid_storage_model::BlobId::new(*hasher.finalize().as_bytes()) != expected {
        return Err(DurableError::InvalidRepresentationState(
            "loose blob identity mismatch",
        ));
    }
    Ok(())
}

fn open_authoritative_regular(
    path: &Path,
    description: &'static str,
) -> Result<File, DurableError> {
    match open_regular_read(path) {
        Ok(file) => Ok(file),
        Err(error)
            if error.kind() == std::io::ErrorKind::NotFound
                || error.kind() == std::io::ErrorKind::InvalidData
                || std::fs::symlink_metadata(path)
                    .is_ok_and(|metadata| metadata.file_type().is_symlink()) =>
        {
            Err(DurableError::InvalidRepresentationState(description))
        },
        Err(source) => Err(io_error("open authoritative loose representation", source)),
    }
}

fn blob_hasher(
    profile: astrid_storage_model::RepresentationProfileId,
    logical_bytes: u64,
) -> blake3::Hasher {
    let mut hasher = blake3::Hasher::new_derive_key("astrid-blob-identity-v1\0");
    hasher.update(&1_u16.to_le_bytes());
    hasher.update(&2_u16.to_le_bytes());
    hasher.update(&32_u32.to_le_bytes());
    hasher.update(profile.as_bytes());
    hasher.update(&logical_bytes.to_le_bytes());
    hasher
}

fn tagged_blob_hex(blob: astrid_storage_model::BlobId) -> String {
    let mut bytes = Vec::with_capacity(40);
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.extend_from_slice(&2_u16.to_le_bytes());
    bytes.extend_from_slice(&32_u32.to_le_bytes());
    bytes.extend_from_slice(blob.as_bytes());
    let mut encoded = String::with_capacity(80);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}
