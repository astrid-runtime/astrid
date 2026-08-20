//! Contiguous-file catalogue entries and disposable chunk-slice locations.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::storage_model::{
    Coverage, ObjectClass, ObjectFormatVersion, ObjectId, ObjectKind, ObjectRecord, PhysicalMapKey,
    PlacementEntry, Recipe, Replica, ReplicaLocator, RepresentationProfile, RepresentationRecord,
};

use super::activation::append_new_reachable_map_nodes;
use super::format::{Blake3PhysicalIdentity, MetadataFrame};
use super::{
    ContiguousLocation, DurableError, METADATA_MAGIC, PendingRepresentationUpdate,
    RepresentationStore, append_frames,
};
use crate::engine::durable::contiguous::ContiguousSlice;
use crate::engine::durable::{ArenaLocation, PersistentObjectIdentity, RecoveryLimits, io_error};

mod namespace;
mod platform;
mod recovery;
use namespace::{LooseBlobDirectory, retire_loose_blob_tree};
pub(in crate::engine::durable::representations) use namespace::{
    configure_no_follow, open_component, sync_directory, validate_opened_regular,
};
pub(in crate::engine::durable) use namespace::{open_representation_root, open_store_root};
pub(in crate::engine::durable) use platform::open_regular_read;
use platform::{clone_file_no_replace, clone_is_unsupported};

pub(super) const LOOSE_NAMESPACE_GENERATION: u64 = 1;
const LOOSE_META_MAGIC: [u8; 8] = *b"ASTBLM1\0";
const LOOSE_META_VERSION: u16 = 1;
const RETIRED_BLOBS_DIRECTORY: &str = "blobs.retired";
static COPY_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

impl RepresentationStore {
    pub(in crate::engine::durable) fn append_contiguous_update(
        &mut self,
        profile: &RepresentationProfile,
        representation: &RepresentationRecord,
        slices: &BTreeMap<crate::storage_model::ObjectId, ContiguousSlice>,
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

    pub(in crate::engine::durable) fn open_contiguous_read(
        &self,
        object: ObjectId,
    ) -> Result<Option<(super::super::File, ContiguousLocation)>, DurableError> {
        let Some(location) = self.contiguous.get(&object).copied() else {
            return Ok(None);
        };
        if let Some(volume) = self.volume_media() {
            let file = super::volume::open_volume_blob(
                volume,
                location.blob,
                location.namespace_generation,
            )?;
            return Ok(Some((file, location)));
        }
        let (root, root_directory) = self.directory_media()?;
        let directory =
            LooseBlobDirectory::open(root_directory, root, location.namespace_generation, false)?;
        let file = open_authoritative_regular(
            &directory,
            &loose_blob_name(location.blob),
            "contiguous blob is missing, redirected, or not a regular file",
        )?;
        Ok(Some((super::super::File::native(file), location)))
    }

    pub(in crate::engine::durable) fn open_loose_blob(
        &self,
        blob: crate::storage_model::BlobId,
        namespace_generation: u64,
    ) -> Result<super::super::File, DurableError> {
        if let Some(volume) = self.volume_media() {
            return super::volume::open_volume_blob(volume, blob, namespace_generation);
        }
        let directory = LooseBlobDirectory::open(
            self.directory_media()?.1,
            self.directory_media()?.0,
            namespace_generation,
            false,
        )?;
        Ok(super::super::File::native(open_authoritative_regular(
            &directory,
            &loose_blob_name(blob),
            "contiguous blob is missing, redirected, or not a regular file",
        )?))
    }

    pub(in crate::engine::durable) fn contains_contiguous(&self, object: ObjectId) -> bool {
        self.contiguous.contains_key(&object)
    }

    pub(in crate::engine::durable) fn contiguous_count_excluding(
        &self,
        arena: &BTreeMap<ObjectId, ArenaLocation>,
    ) -> usize {
        self.contiguous
            .keys()
            .filter(|object| !arena.contains_key(object))
            .count()
    }

    pub(in crate::engine::durable) fn contiguous_object_ids(
        &self,
    ) -> impl Iterator<Item = ObjectId> + '_ {
        self.contiguous.keys().copied()
    }

    /// Retire loose payloads only after active authority contains direct arena
    /// placements for the complete live object set.
    pub(in crate::engine::durable) fn retire_loose_blobs(&self) -> Result<(), DurableError> {
        retire_loose_blob_tree(self.directory_media()?.1)
    }

    pub(in crate::engine::durable) fn rebuild_contiguous_index<
        I: PersistentObjectIdentity,
        F: super::super::DurableIo,
    >(
        &mut self,
        arena: &mut F,
        index: &BTreeMap<ObjectId, ArenaLocation>,
        identity: &I,
        limits: RecoveryLimits,
    ) -> Result<(), DurableError> {
        self.contiguous.clear();
        let active = recovery::active_contiguous_records(self)?;
        let mut recovery = recovery::RecoveryStore::new(arena, index, identity, limits);
        if let Some(volume) = self.volume_media().cloned() {
            for (record_id, record, namespace_generation) in active {
                let profile = self.profile(record.profile())?;
                let crate::storage_model::Coverage::CanonicalFileChunks {
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
                let crate::storage_model::Recipe::ContiguousFile { blob } = record.recipe() else {
                    return Err(DurableError::InvalidRepresentationState(
                        "contiguous representation has a different recipe",
                    ));
                };
                let blob_file =
                    super::volume::open_volume_blob(&volume, *blob, namespace_generation)?;
                let (reverse, locations) = recovery::recover_contiguous_opened_blob(
                    blob_file,
                    record_id,
                    &record,
                    &profile,
                    namespace_generation,
                    &mut recovery,
                    *file,
                    *content_root,
                    *logical_bytes,
                    *chunk_count,
                    chunking_profile,
                    *blob,
                )?;
                self.install_contiguous_indexes(&reverse, &locations);
            }
            return Ok(());
        }
        for (record_id, record, namespace_generation) in active {
            let profile = self.profile(record.profile())?;
            let (reverse, locations) = recovery.recover_contiguous_record(
                self.directory_media()?.1,
                self.directory_media()?.0,
                record_id,
                &record,
                &profile,
                namespace_generation,
            )?;
            self.install_contiguous_indexes(&reverse, &locations);
        }
        Ok(())
    }

    #[cfg(test)]
    pub(in crate::engine::durable) fn loose_blob_path(
        &self,
        blob: crate::storage_model::BlobId,
        namespace_generation: u64,
    ) -> PathBuf {
        loose_blob_path_from_representation_root(
            self.directory_media().expect("directory media").0,
            blob,
            namespace_generation,
        )
    }

    fn install_contiguous_indexes(
        &mut self,
        reverse: &[(
            crate::storage_model::ObjectId,
            crate::storage_model::RepresentationRecordId,
        )],
        locations: &[(crate::storage_model::ObjectId, ContiguousLocation)],
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
        reverse_additions: Vec<(ObjectId, crate::storage_model::RepresentationRecordId)>,
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
            replacement_reverse: None,
        }))
    }
}

type ContiguousIndexes = (
    Vec<(ObjectId, crate::storage_model::RepresentationRecordId)>,
    Vec<(ObjectId, ContiguousLocation)>,
);

fn contiguous_index_additions(
    representation: crate::storage_model::RepresentationRecordId,
    blob: crate::storage_model::BlobId,
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

pub(in crate::engine::durable) fn install_loose_blob_copy(
    store_root: &cap_std::fs::Dir,
    store_path: &Path,
    blob: crate::storage_model::BlobId,
    profile: crate::storage_model::RepresentationProfileId,
    logical_bytes: u64,
    source: impl Read,
) -> Result<PathBuf, DurableError> {
    let representation_root_path = store_path.join(super::DIRECTORY);
    let representation_root = open_representation_root(store_root)?;
    let directory = LooseBlobDirectory::open(
        &representation_root,
        &representation_root_path,
        LOOSE_NAMESPACE_GENERATION,
        true,
    )?;
    let name = loose_blob_name(blob);
    ensure_loose_metadata(&directory, &name, profile, blob, logical_bytes)?;
    let sequence = COPY_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = PathBuf::from(format!(
        "{}.copy.{}.{}.tmp",
        name.to_string_lossy(),
        std::process::id(),
        sequence
    ));
    let result = (|| {
        let mut output = directory
            .create_new(&temporary)
            .map_err(|source| io_error("create loose blob temporary", source))?;
        let copied = std::io::copy(&mut source.take(logical_bytes), &mut output)
            .map_err(|source| io_error("copy loose blob bytes", source))?;
        if copied != logical_bytes {
            return Err(DurableError::InvalidRepresentationState(
                "loose blob source ended before its declared length",
            ));
        }
        output
            .flush()
            .and_then(|()| output.sync_all())
            .map_err(|source| io_error("flush loose blob temporary", source))?;
        drop(output);
        publish_loose_blob_temporary(&directory, &temporary, &name, profile, blob, logical_bytes)?;
        directory
            .sync()
            .map_err(|source| io_error("flush loose blob directory capability", source))?;
        Ok(directory.ambient_path().join(&name))
    })();
    if result.is_err() {
        let _ = directory.remove_file(&temporary);
    }
    result
}

pub(in crate::engine::durable) fn install_loose_blob_from_file(
    store_root: &cap_std::fs::Dir,
    store_path: &Path,
    blob: crate::storage_model::BlobId,
    profile: crate::storage_model::RepresentationProfileId,
    logical_bytes: u64,
    source: &File,
) -> Result<PathBuf, DurableError> {
    let mut source = source
        .try_clone()
        .map_err(|source| io_error("clone loose blob adoption source handle", source))?;
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
    let representation_root_path = store_path.join(super::DIRECTORY);
    let representation_root = open_representation_root(store_root)?;
    let directory = LooseBlobDirectory::open(
        &representation_root,
        &representation_root_path,
        LOOSE_NAMESPACE_GENERATION,
        true,
    )?;
    let name = loose_blob_name(blob);
    ensure_loose_metadata(&directory, &name, profile, blob, logical_bytes)?;
    let sequence = COPY_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = PathBuf::from(format!(
        "{}.adopt.{}.{}.tmp",
        name.to_string_lossy(),
        std::process::id(),
        sequence
    ));
    match clone_file_no_replace(&source, directory.capability(), &temporary) {
        Ok(()) => {
            let prepared = (|| {
                let mut options = cap_std::fs::OpenOptions::new();
                options.write(true);
                configure_no_follow(&mut options);
                let file = directory
                    .capability()
                    .open_with(&temporary, &options)
                    .map(cap_std::fs::File::into_std)
                    .map_err(|source| io_error("open cloned loose blob temporary", source))?;
                validate_opened_regular(&file)
                    .map_err(|source| io_error("validate cloned loose blob temporary", source))?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt as _;
                    file.set_permissions(std::fs::Permissions::from_mode(0o600))
                        .map_err(|source| {
                            io_error("set cloned loose blob private permissions", source)
                        })?;
                }
                file.set_len(logical_bytes)
                    .and_then(|()| file.sync_all())
                    .map_err(|source| io_error("truncate and flush cloned loose blob", source))
            })();
            if let Err(error) = prepared {
                let _ = directory.remove_file(&temporary);
                return Err(error);
            }
        },
        Err(error) if clone_is_unsupported(&error) => {
            let _ = directory.remove_file(&temporary);
            source
                .seek(SeekFrom::Start(0))
                .map_err(|source| io_error("rewind loose blob adoption source", source))?;
            return install_loose_blob_copy(
                store_root,
                store_path,
                blob,
                profile,
                logical_bytes,
                source,
            );
        },
        Err(source) => {
            let _ = directory.remove_file(&temporary);
            return Err(io_error("clone loose blob adoption source", source));
        },
    }
    let result = (|| {
        publish_loose_blob_temporary(&directory, &temporary, &name, profile, blob, logical_bytes)?;
        directory
            .sync()
            .map_err(|source| io_error("flush loose blob directory capability", source))?;
        Ok(directory.ambient_path().join(&name))
    })();
    if result.is_err() {
        let _ = directory.remove_file(&temporary);
    }
    result
}

fn publish_loose_blob_temporary(
    directory: &LooseBlobDirectory,
    temporary: &Path,
    name: &Path,
    profile: crate::storage_model::RepresentationProfileId,
    blob: crate::storage_model::BlobId,
    logical_bytes: u64,
) -> Result<(), DurableError> {
    let result = (|| {
        let temporary_file = verify_blob_file(directory, temporary, profile, blob, logical_bytes)?;
        match directory.hard_link(temporary, name) {
            Ok(()) => {
                if let Err(error) = verify_linked_identity(
                    directory,
                    name,
                    &temporary_file,
                    logical_bytes,
                    "published loose blob does not name the verified temporary",
                ) {
                    let _ = directory.remove_file(name);
                    return Err(error);
                }
            },
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                verify_blob_bytes(directory, name, profile, blob, logical_bytes)?;
                compare_files(directory, temporary, name, logical_bytes)?;
            },
            Err(source) => return Err(io_error("publish loose blob", source)),
        }
        directory
            .remove_file(temporary)
            .map_err(|source| io_error("remove loose blob temporary", source))
    })();
    if result.is_err() {
        let _ = directory.remove_file(temporary);
    }
    result
}

fn ensure_loose_metadata(
    directory: &LooseBlobDirectory,
    blob_name: &Path,
    profile: crate::storage_model::RepresentationProfileId,
    blob: crate::storage_model::BlobId,
    logical_bytes: u64,
) -> Result<(), DurableError> {
    let metadata_path = blob_name.with_extension("meta");
    let sequence = COPY_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary =
        blob_name.with_extension(format!("meta.{}.{}.tmp", std::process::id(), sequence));
    let expected = encode_loose_metadata(profile, blob, logical_bytes)?;
    match directory.capability().symlink_metadata(&metadata_path) {
        Ok(_) => {
            verify_exact_regular_file(directory, &metadata_path, &expected, "loose blob metadata")?;
            return Ok(());
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
        Err(source) => return Err(io_error("inspect loose blob metadata", source)),
    }
    let result = (|| {
        let temporary_file = create_exact_file(
            directory,
            &temporary,
            &expected,
            "loose blob metadata temporary",
        )?;
        match directory.hard_link(&temporary, &metadata_path) {
            Ok(()) => {
                if let Err(error) = verify_linked_identity(
                    directory,
                    &metadata_path,
                    &temporary_file,
                    u64::try_from(expected.len()).map_err(|_| DurableError::EncodingOverflow)?,
                    "published loose metadata does not name the verified temporary",
                ) {
                    let _ = directory.remove_file(&metadata_path);
                    return Err(error);
                }
            },
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                verify_exact_regular_file(
                    directory,
                    &metadata_path,
                    &expected,
                    "loose blob metadata",
                )?;
            },
            Err(source) => return Err(io_error("publish loose blob metadata", source)),
        }
        directory
            .remove_file(&temporary)
            .map_err(|source| io_error("remove loose blob metadata temporary", source))?;
        directory
            .sync()
            .map_err(|source| io_error("flush loose blob metadata directory", source))
    })();
    if result.is_err() {
        let _ = directory.remove_file(&temporary);
    }
    result
}

fn create_exact_file(
    directory: &LooseBlobDirectory,
    path: &Path,
    bytes: &[u8],
    operation: &'static str,
) -> Result<File, DurableError> {
    let mut file = directory
        .create_new(path)
        .map_err(|source| io_error(operation, source))?;
    file.write_all(bytes)
        .and_then(|()| file.flush())
        .and_then(|()| file.sync_all())
        .map_err(|source| io_error(operation, source))?;
    Ok(file)
}

fn verify_linked_identity(
    directory: &LooseBlobDirectory,
    installed: &Path,
    verified: &File,
    expected_bytes: u64,
    description: &'static str,
) -> Result<(), DurableError> {
    let installed = directory
        .open_regular(installed)
        .map_err(|source| io_error("open newly linked loose representation file", source))?;
    let installed_metadata = installed
        .metadata()
        .map_err(|source| io_error("inspect newly linked loose representation file", source))?;
    if installed_metadata.len() != expected_bytes
        || namespace::opened_file_identity(&installed)
            .map_err(|source| io_error("identify newly linked loose representation file", source))?
            != namespace::opened_file_identity(verified)
                .map_err(|source| io_error("identify verified loose temporary", source))?
    {
        return Err(DurableError::InvalidRepresentationState(description));
    }
    Ok(())
}

pub(super) fn encode_loose_metadata(
    profile: crate::storage_model::RepresentationProfileId,
    blob: crate::storage_model::BlobId,
    logical_bytes: u64,
) -> Result<Vec<u8>, DurableError> {
    let mut payload = Vec::with_capacity(90);
    payload.extend_from_slice(&LOOSE_META_VERSION.to_le_bytes());
    append_tagged_identity(&mut payload, blob.as_bytes());
    append_tagged_identity(&mut payload, profile.as_bytes());
    payload.extend_from_slice(&logical_bytes.to_le_bytes());
    let payload_len = u64::try_from(payload.len()).map_err(|_| DurableError::EncodingOverflow)?;
    let checksum =
        crate::engine::durable::format::frame_checksum(LOOSE_META_MAGIC, payload_len, &payload);
    let capacity = crate::engine::durable::FRAME_HEADER_LEN_USIZE
        .checked_add(payload.len())
        .ok_or(DurableError::EncodingOverflow)?;
    let mut encoded = Vec::with_capacity(capacity);
    encoded.extend_from_slice(&LOOSE_META_MAGIC);
    encoded.extend_from_slice(&crate::engine::durable::FRAME_VERSION.to_le_bytes());
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
    directory: &LooseBlobDirectory,
    path: &Path,
    expected: &[u8],
    description: &'static str,
) -> Result<(), DurableError> {
    let mut file = open_authoritative_regular(directory, path, description)?;
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

fn compare_files(
    directory: &LooseBlobDirectory,
    left: &Path,
    right: &Path,
    logical_bytes: u64,
) -> Result<(), DurableError> {
    let mut left = directory
        .open_regular(left)
        .map_err(|source| io_error("open candidate loose blob no-follow", source))?;
    let mut right = open_authoritative_regular(
        directory,
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

#[cfg(test)]
fn loose_blob_path_from_representation_root(
    root: &Path,
    blob: crate::storage_model::BlobId,
    namespace_generation: u64,
) -> PathBuf {
    root.join("blobs")
        .join("loose")
        .join(format!("{namespace_generation:016x}"))
        .join(loose_blob_name(blob))
}

pub(super) fn loose_blob_name(blob: crate::storage_model::BlobId) -> PathBuf {
    PathBuf::from(format!("{}.blob", tagged_blob_hex(blob)))
}

pub(in crate::engine::durable) fn read_contiguous_object<I, F>(
    mut file: F,
    location: ContiguousLocation,
    expected: ObjectId,
    identity: &I,
) -> Result<ObjectRecord, DurableError>
where
    I: PersistentObjectIdentity,
    F: Read + Seek,
{
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
    representation_directory: &cap_std::fs::Dir,
    representation_root: &Path,
    namespace_generation: u64,
    blob: crate::storage_model::BlobId,
    profile: crate::storage_model::RepresentationProfileId,
    logical_bytes: u64,
) -> Result<File, DurableError> {
    let directory = LooseBlobDirectory::open(
        representation_directory,
        representation_root,
        namespace_generation,
        false,
    )?;
    let name = loose_blob_name(blob);
    let metadata = encode_loose_metadata(profile, blob, logical_bytes)?;
    verify_exact_regular_file(
        &directory,
        &name.with_extension("meta"),
        &metadata,
        "loose blob metadata mismatch",
    )?;
    verify_blob_file(&directory, &name, profile, blob, logical_bytes)
}

fn verify_blob_bytes(
    directory: &LooseBlobDirectory,
    path: &Path,
    profile: crate::storage_model::RepresentationProfileId,
    expected: crate::storage_model::BlobId,
    logical_bytes: u64,
) -> Result<(), DurableError> {
    verify_blob_file(directory, path, profile, expected, logical_bytes).map(drop)
}

fn verify_blob_file(
    directory: &LooseBlobDirectory,
    path: &Path,
    profile: crate::storage_model::RepresentationProfileId,
    expected: crate::storage_model::BlobId,
    logical_bytes: u64,
) -> Result<File, DurableError> {
    let mut file = open_authoritative_regular(
        directory,
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
    if crate::storage_model::BlobId::new(*hasher.finalize().as_bytes()) != expected {
        return Err(DurableError::InvalidRepresentationState(
            "loose blob identity mismatch",
        ));
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|source| io_error("rewind verified loose blob", source))?;
    Ok(file)
}

fn open_authoritative_regular(
    directory: &LooseBlobDirectory,
    path: &Path,
    description: &'static str,
) -> Result<File, DurableError> {
    match directory.open_regular(path) {
        Ok(file) => Ok(file),
        Err(error)
            if error.kind() == std::io::ErrorKind::NotFound
                || error.kind() == std::io::ErrorKind::InvalidData
                || directory
                    .capability()
                    .symlink_metadata(path)
                    .is_ok_and(|metadata| metadata.file_type().is_symlink()) =>
        {
            Err(DurableError::InvalidRepresentationState(description))
        },
        Err(source) => Err(io_error("open authoritative loose representation", source)),
    }
}

pub(super) fn blob_hasher(
    profile: crate::storage_model::RepresentationProfileId,
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

fn tagged_blob_hex(blob: crate::storage_model::BlobId) -> String {
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

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::path::Path;

    use cap_std::ambient_authority;

    #[test]
    fn publication_rejects_a_link_to_an_unverified_inode() {
        let root = tempfile::tempdir().unwrap();
        let root_directory =
            cap_std::fs::Dir::open_ambient_dir(root.path(), ambient_authority()).unwrap();
        let directory =
            super::LooseBlobDirectory::open(&root_directory, root.path(), 1, true).unwrap();
        let mut verified = directory.create_new(Path::new("verified.tmp")).unwrap();
        verified.write_all(b"same-length").unwrap();
        verified.sync_all().unwrap();
        let mut substituted = directory.create_new(Path::new("installed.blob")).unwrap();
        substituted.write_all(b"other-byte!").unwrap();
        substituted.sync_all().unwrap();

        assert!(matches!(
            super::verify_linked_identity(
                &directory,
                Path::new("installed.blob"),
                &verified,
                11,
                "substituted publication",
            ),
            Err(super::DurableError::InvalidRepresentationState(
                "substituted publication"
            ))
        ));
    }
}
