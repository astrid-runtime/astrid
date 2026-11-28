//! Disposable persistent object index for the host-file engine.
//!
//! The arena and root journal remain the only authoritative files. This cache
//! may lag, tear, corrupt, or disappear; those cases fall back to an
//! authoritative arena scan and checkpoint replacement. Once a new
//! checkpoint is required, its publication is part of the durable operation:
//! an I/O failure is returned instead of allowing a successful root with a
//! missing or stale index. Principal roots and validated closures are
//! deliberately absent: recovery always derives them from the root journal
//! and identity-checked arena objects.

use std::borrow::Borrow;
use std::collections::BTreeMap;
use std::io::{Seek, SeekFrom};
use std::path::Path;

use crate::storage_model::ObjectId;

use super::{
    ARENA_FILE, ArenaLocation, DurableEngine, DurableError, DurableInner, FRAME_HEADER_LEN,
    FRAME_HEADER_LEN_USIZE, FaultInjector, File, INDEX_FILE, INDEX_MAGIC, IdentityScheme,
    PersistentObjectIdentity, PrincipalCodec, RecoveryLimits, append_frame,
    create_private_file_capability, live_files_mut, open_rw_capability, scan_frames,
    sync_store_directory_capability, verify_indexed_location, verify_indexed_tail,
};
use crate::volume::AstridVolume;
use std::sync::Arc;

use super::{format::encode_identity, root_wire};

use super::{IndexState, checkpoint_admission as admission};
mod key;
use super::arena_index;
use key as checkpoint_key;
mod snapshot;
#[cfg(test)]
mod tests;
mod validation;
mod wire;

use snapshot::Snapshot;

use validation::validate_state;

use key::ROW_LEN as LOCATION_BYTES;
use wire::{DELTA_RECORD, SNAPSHOT_RECORD};

/// One successfully persisted object-arena change cached after publication.
pub(super) struct IndexDelta<'a> {
    pub(super) previous_arena_len: u64,
    pub(super) arena_len: u64,
    pub(super) arena_tail: ArenaLocation,
    pub(super) objects: &'a [(ObjectId, ArenaLocation)],
}

#[derive(Clone, Copy)]
enum IndexCacheKind {
    Missing,
    Empty,
    Snapshot,
    Invalid,
}

struct IndexFrontier<'a> {
    previous_arena_len: u64,
    arena_len: u64,
    arena_tail: Option<ArenaLocation>,
    locations: &'a [(ObjectId, ArenaLocation)],
}

impl<P, I, C> DurableEngine<P, I, C>
where
    P: Clone + Ord,
    I: PersistentObjectIdentity,
    C: PrincipalCodec<P>,
{
    /// Publish every arena location appended since the cached durable frontier.
    pub(super) fn advance_index_frontier(
        &self,
        inner: &mut DurableInner<P>,
        arena_len: u64,
    ) -> Result<(), DurableError> {
        let (previous_arena_len, previous_arena_tail) = {
            let files = live_files_mut(&mut inner.files)?;
            (files.arena_len, files.arena_tail)
        };
        if arena_len < previous_arena_len {
            return Err(DurableError::Corrupt {
                file: ARENA_FILE,
                offset: arena_len,
                detail: "object arena moved behind the cached durable frontier",
            });
        }

        let locations = std::mem::take(&mut inner.pending_index_locations);
        inner.pending_direct_objects.clear();
        let arena_tail = locations
            .last()
            .map(|(_, location)| *location)
            .or(previous_arena_tail);
        let arena_tail = match (arena_len > previous_arena_len, arena_tail) {
            (true, Some(arena_tail)) => Some(arena_tail),
            (true, None) => {
                return Err(DurableError::Corrupt {
                    file: ARENA_FILE,
                    offset: previous_arena_len,
                    detail: "object arena advanced without indexed locations",
                });
            },
            (false, arena_tail) => arena_tail,
        };
        let cache_kind = {
            let files = live_files_mut(&mut inner.files)?;
            match files.index_cache.as_ref() {
                None => IndexCacheKind::Missing,
                Some(cache) if index_cache_is_empty(cache) => IndexCacheKind::Empty,
                Some(cache) if index_cache_starts_with_snapshot(cache) => IndexCacheKind::Snapshot,
                Some(_) => IndexCacheKind::Invalid,
            }
        };
        let frontier = IndexFrontier {
            previous_arena_len,
            arena_len,
            arena_tail,
            locations: &locations,
        };
        self.publish_index_cache(inner, cache_kind, &frontier)?;
        let files = live_files_mut(&mut inner.files)?;
        files.arena_len = arena_len;
        files.arena_tail = arena_tail;
        Ok(())
    }

    fn publish_index_cache(
        &self,
        inner: &mut DurableInner<P>,
        cache_kind: IndexCacheKind,
        frontier: &IndexFrontier<'_>,
    ) -> Result<(), DurableError> {
        let files = live_files_mut(&mut inner.files)?;
        match cache_kind {
            IndexCacheKind::Snapshot => {
                let Some(mut cache) = files.index_cache.take() else {
                    return Err(DurableError::Closed);
                };
                if frontier.locations.is_empty() {
                    files.index_cache = Some(cache);
                } else {
                    self.fail_if(super::FaultPoint::BeforeIndexCachePublication)?;
                    let delta = IndexDelta {
                        previous_arena_len: frontier.previous_arena_len,
                        arena_len: frontier.arena_len,
                        arena_tail: frontier.arena_tail.ok_or(DurableError::Corrupt {
                            file: ARENA_FILE,
                            offset: frontier.previous_arena_len,
                            detail: "object arena advanced without indexed locations",
                        })?,
                        objects: frontier.locations,
                    };
                    append_index_delta(&mut cache, &delta, self.identity.scheme())?;
                    cache.sync_data().map_err(|source| {
                        super::io_error("flush durable object-index delta", source)
                    })?;
                    files.index_cache = Some(cache);
                }
            },
            IndexCacheKind::Empty => {
                let Some(mut cache) = files.index_cache.take() else {
                    return Err(DurableError::Closed);
                };
                self.fail_if(super::FaultPoint::BeforeIndexCachePublication)?;
                let current_state = IndexState {
                    arena_len: frontier.arena_len,
                    arena_tail: frontier.arena_tail,
                    objects: &inner.index,
                };
                Snapshot::new(&current_state, self.identity.scheme())?.append(&mut cache)?;
                cache.sync_data().map_err(|source| {
                    super::io_error("flush rebuilt durable object index", source)
                })?;
                files.index_cache = Some(cache);
            },
            IndexCacheKind::Invalid | IndexCacheKind::Missing => {
                let current_state = IndexState {
                    arena_len: frontier.arena_len,
                    arena_tail: frontier.arena_tail,
                    objects: &inner.index,
                };
                drop(files.index_cache.take());
                files.index_cache = Some(self.replace_index_cache(&current_state)?);
            },
        }
        Ok(())
    }

    pub(super) fn replace_index_cache<M: Borrow<BTreeMap<ObjectId, ArenaLocation>>>(
        &self,
        state: &IndexState<M>,
    ) -> Result<File, DurableError> {
        let volume = self.volume.read();
        match (self.directory_capability.as_deref(), volume.as_ref()) {
            (Some(directory), None) => replace_index(
                directory,
                state,
                self.identity.scheme(),
                self.faults.as_ref(),
            ),
            (None, Some(volume)) => replace_volume_index(
                std::sync::Arc::clone(volume),
                state,
                self.identity.scheme(),
                self.faults.as_ref(),
            ),
            _ => Err(DurableError::InvalidRepresentationState(
                "durable index media configuration is inconsistent",
            )),
        }
    }
}

/// Attempt to restore an exact object-arena prefix from the cache.
///
/// A cache failure is represented as `None`: the caller must scan the
/// authoritative arena and replace the checkpoint. Publication errors from
/// that replacement are returned by the caller and fail recovery closed.
pub(super) fn recover_index(
    file: &mut File,
    arena: &mut File,
    scheme: IdentityScheme,
    limits: RecoveryLimits,
    authoritative_arena_len: u64,
) -> Option<IndexState> {
    let mut state = None;
    let recovered = scan_frames(
        file,
        INDEX_FILE,
        INDEX_MAGIC,
        RecoveryLimits::process_addressable(),
        |offset, payload| {
            state = Some(decode_record(state.take(), payload, scheme, offset)?);
            Ok(())
        },
    );
    let mut reader = CandidateArena {
        arena,
        scheme,
        limits,
    };
    IndexState::validated(
        state,
        recovered.is_ok(),
        authoritative_arena_len,
        &mut reader,
    )
}

struct CandidateArena<'a> {
    arena: &'a mut File,
    scheme: IdentityScheme,
    limits: RecoveryLimits,
}

impl admission::Arena for CandidateArena<'_> {
    fn gap(&mut self, map: &BTreeMap<ObjectId, ArenaLocation>, at: u64, end: u64) -> bool {
        super::format::duplicate_range(self.arena, map, self.scheme, self.limits, at, end)
    }

    fn entry(&mut self, id: ObjectId, location: ArenaLocation) -> bool {
        verify_indexed_location(self.arena, id, location, self.scheme, self.limits).is_ok()
    }

    fn tail(&mut self, location: ArenaLocation) -> bool {
        verify_indexed_tail(self.arena, location, self.limits).is_ok()
    }
}

fn decode_record(
    state: Option<IndexState>,
    payload: &[u8],
    scheme: IdentityScheme,
    offset: u64,
) -> Result<IndexState, DurableError> {
    wire::record(payload, state, scheme.into(), |state| {
        validate_state(state, offset)
    })
    .map_err(|error| match error {
        wire::RecordError::Invalid(error) => error,
        wire::RecordError::Discontinuous => corrupt(
            offset,
            "index delta does not continue the cached arena prefix",
        ),
        wire::RecordError::Backwards => corrupt(offset, "index delta arena length moves backwards"),
        wire::RecordError::Remap => corrupt(offset, "index delta remaps an object identity"),
        wire::RecordError::Wire(wire::Error::Field(error)) => corrupt(offset, key_error(error)),
        wire::RecordError::Wire(wire::Error::TailTag) => {
            corrupt(offset, "invalid optional arena-tail tag")
        },
        wire::RecordError::Wire(wire::Error::Count) => {
            corrupt(offset, "index length is not process-addressable")
        },
        wire::RecordError::MissingSnapshot => corrupt(offset, "index delta precedes snapshot"),
        wire::RecordError::RepeatedSnapshot => {
            corrupt(offset, "index contains more than one snapshot")
        },
        wire::RecordError::Unknown => corrupt(offset, "unknown index record kind"),
        wire::RecordError::Trailing => corrupt(offset, "trailing index-record bytes"),
    })
}

/// Replace the disposable index with one complete, flushed checkpoint.
pub(super) fn replace_index<M: Borrow<BTreeMap<ObjectId, ArenaLocation>>>(
    directory: &cap_std::fs::Dir,
    state: &IndexState<M>,
    scheme: IdentityScheme,
    faults: &dyn FaultInjector,
) -> Result<File, DurableError> {
    if faults.should_fail(super::FaultPoint::BeforeIndexCachePublication) {
        return Err(DurableError::FaultInjected(
            super::FaultPoint::BeforeIndexCachePublication,
        ));
    }
    let snapshot = Snapshot::new(state, scheme)?;
    let temporary = format!("{INDEX_FILE}.tmp");
    remove_checkpoint_if_present(directory, &temporary)
        .map_err(|source| super::io_error("remove temporary durable object index", source))?;
    let mut file = create_private_file_capability(directory, Path::new(&temporary))
        .map_err(|error| index_error("create temporary durable object index", error))?;
    snapshot.append(&mut file)?;
    file.sync_data()
        .map_err(|source| super::io_error("flush durable object-index snapshot", source))?;
    drop(file);
    replace_checkpoint(directory, &temporary, INDEX_FILE)
        .map_err(|source| super::io_error("publish durable object-index snapshot", source))?;
    sync_store_directory_capability(directory)?;
    let mut reopened = open_rw_capability(directory, Path::new(INDEX_FILE), false)
        .map_err(|error| index_error("reopen durable object index", error))?;
    reopened
        .seek(SeekFrom::End(0))
        .map_err(|source| super::io_error("seek durable object index", source))?;
    Ok(reopened)
}

pub(super) fn replace_volume_index<M: Borrow<BTreeMap<ObjectId, ArenaLocation>>>(
    volume: Arc<dyn AstridVolume>,
    state: &IndexState<M>,
    scheme: IdentityScheme,
    faults: &dyn FaultInjector,
) -> Result<File, DurableError> {
    if faults.should_fail(super::FaultPoint::BeforeIndexCachePublication) {
        return Err(DurableError::FaultInjected(
            super::FaultPoint::BeforeIndexCachePublication,
        ));
    }
    let snapshot = Snapshot::new(state, scheme)?;
    let mut file = File::volume(volume, INDEX_FILE, true)
        .map_err(|error| index_error("open durable volume object index", error))?;
    file.set_len(0)
        .map_err(|source| super::io_error("truncate durable volume object index", source))?;
    file.seek(SeekFrom::Start(0))
        .map_err(|source| super::io_error("seek durable volume object index", source))?;
    snapshot.append(&mut file)?;
    file.sync_data()
        .map_err(|source| super::io_error("flush durable volume object-index snapshot", source))?;
    file.seek(SeekFrom::End(0))
        .map_err(|source| super::io_error("seek durable volume object index", source))?;
    Ok(file)
}

fn index_error(operation: &'static str, error: DurableError) -> DurableError {
    match error {
        DurableError::Io { source, .. } => super::io_error(operation, source),
        error => error,
    }
}

#[cfg(not(windows))]
fn replace_checkpoint(
    directory: &cap_std::fs::Dir,
    temporary: &str,
    destination: &str,
) -> std::io::Result<()> {
    directory.rename(temporary, directory, destination)
}

#[cfg(windows)]
fn replace_checkpoint(
    directory: &cap_std::fs::Dir,
    temporary: &str,
    destination: &str,
) -> std::io::Result<()> {
    if directory.symlink_metadata(destination).is_err() {
        return directory.rename(temporary, directory, destination);
    }
    let backup = "objects.index.previous";
    remove_checkpoint_if_present(directory, backup)?;
    directory.rename(destination, directory, backup)?;
    match directory.rename(temporary, directory, destination) {
        Ok(()) => {
            let _ = directory.remove_file(backup);
            Ok(())
        },
        Err(error) => {
            let _ = directory.rename(backup, directory, destination);
            Err(error)
        },
    }
}

fn remove_checkpoint_if_present(directory: &cap_std::fs::Dir, name: &str) -> std::io::Result<()> {
    match directory.remove_file(name) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

/// Append one non-authoritative cache delta after authoritative publication.
pub(super) fn append_index_delta(
    file: &mut File,
    delta: &IndexDelta<'_>,
    scheme: IdentityScheme,
) -> Result<(), DurableError> {
    let payload = encode_delta(delta, scheme)?;
    append_frame(file, INDEX_MAGIC, &payload)
        .map_err(|error| index_error("append durable object-index delta", error))?;
    Ok(())
}

pub(super) fn index_cache_starts_with_snapshot(file: &File) -> bool {
    let Ok(length) = file.metadata().map(|metadata| metadata.len()) else {
        return false;
    };
    if length < FRAME_HEADER_LEN {
        return false;
    }
    let mut header = [0_u8; FRAME_HEADER_LEN_USIZE];
    if !matches!(file.read_at(&mut header, 0), Ok(read) if read == FRAME_HEADER_LEN_USIZE) {
        return false;
    }
    if header[..8] != INDEX_MAGIC {
        return false;
    }
    let payload_len = u64::from_le_bytes(header[12..20].try_into().unwrap_or([0; 8]));
    let Some(frame_end) = FRAME_HEADER_LEN.checked_add(payload_len) else {
        return false;
    };
    if frame_end > length {
        return false;
    }
    let mut record = [0_u8; 1];
    matches!(file.read_at(&mut record, FRAME_HEADER_LEN), Ok(read) if read == 1)
        && record[0] == SNAPSHOT_RECORD
}

fn index_cache_is_empty(file: &File) -> bool {
    file.metadata().is_ok_and(|metadata| metadata.len() == 0)
}

#[cfg(test)]
fn encode_snapshot<M: Borrow<BTreeMap<ObjectId, ArenaLocation>>>(
    state: &IndexState<M>,
    scheme: IdentityScheme,
) -> Result<Vec<u8>, DurableError> {
    let mut bytes = Vec::new();
    bytes.push(SNAPSHOT_RECORD);
    encode_scheme(&mut bytes, scheme);
    bytes.extend_from_slice(&state.arena_len.to_le_bytes());
    encode_optional_location(&mut bytes, state.arena_tail);
    let objects = state.objects.borrow();
    encode_len(&mut bytes, objects.len())?;
    // A BTreeMap is already unique and ordered by the canonical ObjectId.
    // Borrow its entries directly instead of allocating another full vector.
    for (id, location) in objects {
        encode_identity(&mut bytes, scheme, *id);
        location.encode(&mut bytes);
    }
    Ok(bytes)
}

fn encode_delta(delta: &IndexDelta<'_>, scheme: IdentityScheme) -> Result<Vec<u8>, DurableError> {
    let mut bytes = Vec::new();
    bytes.push(DELTA_RECORD);
    encode_scheme(&mut bytes, scheme);
    bytes.extend_from_slice(&delta.previous_arena_len.to_le_bytes());
    bytes.extend_from_slice(&delta.arena_len.to_le_bytes());
    delta.arena_tail.encode(&mut bytes);
    encode_locations(&mut bytes, scheme, delta.objects.iter().copied())?;
    Ok(bytes)
}

fn encode_locations(
    bytes: &mut Vec<u8>,
    scheme: IdentityScheme,
    locations: impl IntoIterator<Item = (ObjectId, ArenaLocation)>,
) -> Result<(), DurableError> {
    let mut locations = locations.into_iter().collect::<Vec<_>>();
    locations.sort_by_key(|(id, _)| *id);
    if locations.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(corrupt(0, "index encoder received duplicate object"));
    }
    encode_len(bytes, locations.len())?;
    for (id, location) in locations {
        encode_identity(bytes, scheme, id);
        location.encode(bytes);
    }
    Ok(())
}

fn encode_optional_location(bytes: &mut Vec<u8>, location: Option<ArenaLocation>) {
    match location {
        None => bytes.push(0),
        Some(location) => {
            bytes.push(1);
            location.encode(bytes);
        },
    }
}

fn encode_len(bytes: &mut Vec<u8>, len: usize) -> Result<(), DurableError> {
    bytes.extend_from_slice(
        &u64::try_from(len)
            .map_err(|_| DurableError::EncodingOverflow)?
            .to_le_bytes(),
    );
    Ok(())
}

fn encode_scheme(bytes: &mut Vec<u8>, scheme: IdentityScheme) {
    bytes.extend_from_slice(&scheme.algorithm().to_le_bytes());
    bytes.extend_from_slice(&scheme.construction().to_le_bytes());
}

fn corrupt(offset: u64, detail: &'static str) -> DurableError {
    DurableError::Corrupt {
        file: INDEX_FILE,
        offset,
        detail,
    }
}

fn key_error(error: key::Error) -> &'static str {
    match error {
        key::Error::Read(root_wire::ReadError::Overflow(_)) => "index length overflow",
        key::Error::Read(root_wire::ReadError::Truncated) => "truncated index record",
        key::Error::ZeroScheme => "index identity scheme fields must be non-zero",
        key::Error::WrongScheme => "index identity scheme does not match the store",
        key::Error::LengthOverflow => "index digest length overflow",
        key::Error::ZeroLength => "index digest length must be non-zero",
        key::Error::Capacity => "index location count exceeds frame capacity",
        key::Error::Order => "index identities are not canonically ordered",
        key::Error::WrongLength => "index digest length does not match the active scheme",
    }
}
