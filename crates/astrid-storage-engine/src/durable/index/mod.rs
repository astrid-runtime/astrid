//! Disposable persistent object index for the host-file engine.
//!
//! The arena and root journal remain the only authoritative files. This cache
//! may lag, tear, corrupt, or disappear; every such case falls back to an
//! authoritative arena scan and checkpoint replacement. Principal roots and
//! validated closures are deliberately absent: recovery always derives them
//! from the root journal and identity-checked arena objects.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Seek, SeekFrom};
use std::path::Path;

use astrid_storage_model::ObjectId;

use super::{
    ARENA_FILE, ArenaLocation, DurableEngine, DurableError, DurableInner, FRAME_HEADER_LEN,
    INDEX_FILE, INDEX_MAGIC, IdentityScheme, PersistentObjectIdentity, PrincipalCodec,
    RecoveryLimits, append_frame, create_private_file_capability, live_files_mut,
    open_rw_capability, scan_frames, sync_store_directory_capability, verify_indexed_location,
    verify_indexed_tail,
};

const SNAPSHOT_RECORD: u8 = 1;
const DELTA_RECORD: u8 = 2;
const CURRENT_DIGEST_BYTES: u32 = 32;
const TAGGED_IDENTITY_BYTES: usize = 40;
const LOCATION_BYTES: usize = TAGGED_IDENTITY_BYTES + 8 + 8 + 32;

/// Recovered disposable object-location state.
pub(super) struct IndexState {
    pub(super) arena_len: u64,
    pub(super) arena_tail: Option<ArenaLocation>,
    pub(super) objects: BTreeMap<ObjectId, ArenaLocation>,
}

/// One successfully persisted object-arena change cached after publication.
pub(super) struct IndexDelta<'a> {
    pub(super) previous_arena_len: u64,
    pub(super) arena_len: u64,
    pub(super) arena_tail: ArenaLocation,
    pub(super) objects: &'a [(ObjectId, ArenaLocation)],
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
        let previous_arena_len = live_files_mut(&mut inner.files)?.arena_len;
        if arena_len < previous_arena_len {
            return Err(DurableError::Corrupt {
                file: ARENA_FILE,
                offset: arena_len,
                detail: "object arena moved behind the cached durable frontier",
            });
        }
        if arena_len == previous_arena_len {
            debug_assert!(inner.pending_index_locations.is_empty());
            debug_assert!(inner.pending_direct_objects.is_empty());
            return Ok(());
        }

        let locations = std::mem::take(&mut inner.pending_index_locations);
        inner.pending_direct_objects.clear();
        let Some(arena_tail) = locations.last().map(|(_, location)| *location) else {
            return Err(DurableError::Corrupt {
                file: ARENA_FILE,
                offset: previous_arena_len,
                detail: "object arena advanced without indexed locations",
            });
        };
        let files = live_files_mut(&mut inner.files)?;
        if let Some(mut cache) = files.index_cache.take() {
            let delta = IndexDelta {
                previous_arena_len,
                arena_len,
                arena_tail,
                objects: &locations,
            };
            if append_index_delta(&mut cache, &delta, self.identity.scheme()).is_ok() {
                files.index_cache = Some(cache);
            }
        }
        files.arena_len = arena_len;
        files.arena_tail = Some(arena_tail);
        Ok(())
    }
}

/// Attempt to restore an exact object-arena prefix from the cache.
///
/// Every cache failure is represented as `None`: the caller must scan the
/// authoritative arena and replace the checkpoint. The cache can improve
/// availability only, never reduce it.
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
            let mut reader = WireReader::new(payload);
            let record = reader.u8().map_err(|detail| corrupt(offset, detail))?;
            let decoded = match record {
                SNAPSHOT_RECORD if state.is_none() => decode_snapshot(&mut reader, scheme, offset)?,
                DELTA_RECORD => {
                    let current = state
                        .take()
                        .ok_or_else(|| corrupt(offset, "index delta precedes snapshot"))?;
                    apply_delta(current, &mut reader, scheme, offset)?
                },
                SNAPSHOT_RECORD => {
                    return Err(corrupt(offset, "index contains more than one snapshot"));
                },
                _ => return Err(corrupt(offset, "unknown index record kind")),
            };
            if reader.remaining() != 0 {
                return Err(corrupt(offset, "trailing index-record bytes"));
            }
            validate_state(&decoded, offset)?;
            state = Some(decoded);
            Ok(())
        },
    );
    if recovered.is_err() {
        return None;
    }
    let state = state?;
    if state.arena_len != authoritative_arena_len {
        return None;
    }
    let mut ordered = state
        .objects
        .iter()
        .map(|(id, location)| (*id, *location))
        .collect::<Vec<_>>();
    ordered.sort_by_key(|(_, location)| location.offset);
    for (id, location) in ordered {
        if verify_indexed_location(arena, id, location, scheme, limits).is_err() {
            return None;
        }
    }
    match state.arena_tail {
        Some(location) if verify_indexed_tail(arena, location, limits).is_err() => return None,
        None if state.arena_len != 0 => return None,
        _ => {},
    }
    Some(state)
}

/// Replace the disposable index with one complete, flushed checkpoint.
pub(super) fn replace_index(
    directory: &cap_std::fs::Dir,
    state: &IndexState,
    scheme: IdentityScheme,
) -> Option<File> {
    let payload = encode_snapshot(state, scheme).ok()?;
    let temporary = format!("{INDEX_FILE}.tmp");
    remove_checkpoint_if_present(directory, &temporary).ok()?;
    let mut file = create_private_file_capability(directory, Path::new(&temporary)).ok()?;
    append_frame(&mut file, INDEX_MAGIC, &payload).ok()?;
    file.sync_data().ok()?;
    drop(file);
    replace_checkpoint(directory, &temporary, INDEX_FILE).ok()?;
    sync_store_directory_capability(directory).ok()?;
    let mut reopened = open_rw_capability(directory, Path::new(INDEX_FILE), false).ok()?;
    reopened.seek(SeekFrom::End(0)).ok()?;
    Some(reopened)
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
    append_frame(file, INDEX_MAGIC, &payload)?;
    Ok(())
}

fn encode_snapshot(state: &IndexState, scheme: IdentityScheme) -> Result<Vec<u8>, DurableError> {
    let mut bytes = Vec::new();
    bytes.push(SNAPSHOT_RECORD);
    encode_scheme(&mut bytes, scheme);
    bytes.extend_from_slice(&state.arena_len.to_le_bytes());
    encode_optional_location(&mut bytes, state.arena_tail);
    encode_locations(
        &mut bytes,
        scheme,
        state.objects.iter().map(|(id, location)| (*id, *location)),
    )?;
    Ok(bytes)
}

fn encode_delta(delta: &IndexDelta<'_>, scheme: IdentityScheme) -> Result<Vec<u8>, DurableError> {
    let mut bytes = Vec::new();
    bytes.push(DELTA_RECORD);
    encode_scheme(&mut bytes, scheme);
    bytes.extend_from_slice(&delta.previous_arena_len.to_le_bytes());
    bytes.extend_from_slice(&delta.arena_len.to_le_bytes());
    encode_location(&mut bytes, delta.arena_tail);
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
        bytes.extend_from_slice(&location.offset.to_le_bytes());
        bytes.extend_from_slice(&location.payload_len.to_le_bytes());
        bytes.extend_from_slice(&location.checksum);
    }
    Ok(())
}

fn decode_snapshot(
    reader: &mut WireReader<'_>,
    scheme: IdentityScheme,
    offset: u64,
) -> Result<IndexState, DurableError> {
    reader
        .scheme(scheme)
        .map_err(|detail| corrupt(offset, detail))?;
    let arena_len = reader.u64().map_err(|detail| corrupt(offset, detail))?;
    let arena_tail = decode_optional_location(reader, offset)?;
    let objects = decode_locations(reader, scheme, offset)?;
    Ok(IndexState {
        arena_len,
        arena_tail,
        objects,
    })
}

fn apply_delta(
    mut state: IndexState,
    reader: &mut WireReader<'_>,
    scheme: IdentityScheme,
    offset: u64,
) -> Result<IndexState, DurableError> {
    reader
        .scheme(scheme)
        .map_err(|detail| corrupt(offset, detail))?;
    let previous_arena_len = reader.u64().map_err(|detail| corrupt(offset, detail))?;
    let arena_len = reader.u64().map_err(|detail| corrupt(offset, detail))?;
    if previous_arena_len != state.arena_len {
        return Err(corrupt(
            offset,
            "index delta does not continue the cached arena prefix",
        ));
    }
    if arena_len < previous_arena_len {
        return Err(corrupt(offset, "index delta arena length moves backwards"));
    }
    let arena_tail = decode_location(reader, offset)?;
    let additions = decode_locations(reader, scheme, offset)?;
    for (id, location) in additions {
        match state.objects.get(&id) {
            Some(existing) if same_location(*existing, location) => {},
            Some(_) => return Err(corrupt(offset, "index delta remaps an object identity")),
            None => {
                state.objects.insert(id, location);
            },
        }
    }
    state.arena_len = arena_len;
    state.arena_tail = Some(arena_tail);
    Ok(state)
}

fn encode_optional_location(bytes: &mut Vec<u8>, location: Option<ArenaLocation>) {
    match location {
        None => bytes.push(0),
        Some(location) => {
            bytes.push(1);
            encode_location(bytes, location);
        },
    }
}

fn encode_location(bytes: &mut Vec<u8>, location: ArenaLocation) {
    bytes.extend_from_slice(&location.offset.to_le_bytes());
    bytes.extend_from_slice(&location.payload_len.to_le_bytes());
    bytes.extend_from_slice(&location.checksum);
}

fn decode_optional_location(
    reader: &mut WireReader<'_>,
    offset: u64,
) -> Result<Option<ArenaLocation>, DurableError> {
    match reader.u8().map_err(|detail| corrupt(offset, detail))? {
        0 => Ok(None),
        1 => decode_location(reader, offset).map(Some),
        _ => Err(corrupt(offset, "invalid optional arena-tail tag")),
    }
}

fn decode_location(
    reader: &mut WireReader<'_>,
    offset: u64,
) -> Result<ArenaLocation, DurableError> {
    Ok(ArenaLocation {
        offset: reader.u64().map_err(|detail| corrupt(offset, detail))?,
        payload_len: reader.u64().map_err(|detail| corrupt(offset, detail))?,
        checksum: reader
            .take(32)
            .and_then(|bytes| bytes.try_into().map_err(|_| "truncated checksum"))
            .map_err(|detail| corrupt(offset, detail))?,
    })
}

fn decode_locations(
    reader: &mut WireReader<'_>,
    scheme: IdentityScheme,
    offset: u64,
) -> Result<BTreeMap<ObjectId, ArenaLocation>, DurableError> {
    let count = reader
        .usize_len()
        .map_err(|detail| corrupt(offset, detail))?;
    if count > reader.remaining() / LOCATION_BYTES {
        return Err(corrupt(
            offset,
            "index location count exceeds frame capacity",
        ));
    }
    let mut locations = BTreeMap::new();
    let mut previous = None;
    for _ in 0..count {
        let id = reader
            .identity(scheme)
            .map_err(|detail| corrupt(offset, detail))?;
        if previous.is_some_and(|value| value >= id) {
            return Err(corrupt(
                offset,
                "index identities are not canonically ordered",
            ));
        }
        let location = ArenaLocation {
            offset: reader.u64().map_err(|detail| corrupt(offset, detail))?,
            payload_len: reader.u64().map_err(|detail| corrupt(offset, detail))?,
            checksum: reader
                .take(32)
                .and_then(|bytes| bytes.try_into().map_err(|_| "truncated checksum"))
                .map_err(|detail| corrupt(offset, detail))?,
        };
        locations.insert(id, location);
        previous = Some(id);
    }
    Ok(locations)
}

fn validate_state(state: &IndexState, offset: u64) -> Result<(), DurableError> {
    for location in state.objects.values() {
        let end = location
            .offset
            .checked_add(FRAME_HEADER_LEN)
            .and_then(|value| value.checked_add(location.payload_len))
            .ok_or(DurableError::EncodingOverflow)?;
        if end > state.arena_len {
            return Err(corrupt(
                offset,
                "indexed object extends beyond covered arena",
            ));
        }
    }
    match state.arena_tail {
        Some(location) => {
            let end = location
                .offset
                .checked_add(FRAME_HEADER_LEN)
                .and_then(|value| value.checked_add(location.payload_len))
                .ok_or(DurableError::EncodingOverflow)?;
            if end != state.arena_len {
                return Err(corrupt(
                    offset,
                    "indexed arena tail does not end at covered length",
                ));
            }
        },
        None if state.arena_len != 0 => {
            return Err(corrupt(offset, "non-empty arena has no indexed tail"));
        },
        None => {},
    }
    Ok(())
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

fn encode_identity(bytes: &mut Vec<u8>, scheme: IdentityScheme, id: ObjectId) {
    encode_scheme(bytes, scheme);
    bytes.extend_from_slice(&CURRENT_DIGEST_BYTES.to_le_bytes());
    bytes.extend_from_slice(id.as_bytes());
}

fn same_location(left: ArenaLocation, right: ArenaLocation) -> bool {
    left.offset == right.offset
        && left.payload_len == right.payload_len
        && left.checksum == right.checksum
}

fn corrupt(offset: u64, detail: &'static str) -> DurableError {
    DurableError::Corrupt {
        file: INDEX_FILE,
        offset,
        detail,
    }
}

struct WireReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> WireReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], &'static str> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or("index length overflow")?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or("truncated index record")?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, &'static str> {
        self.take(1)?.first().copied().ok_or("truncated u8")
    }

    fn u16(&mut self) -> Result<u16, &'static str> {
        Ok(u16::from_le_bytes(
            self.take(2)?.try_into().map_err(|_| "truncated u16")?,
        ))
    }

    fn u32(&mut self) -> Result<u32, &'static str> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().map_err(|_| "truncated u32")?,
        ))
    }

    fn u64(&mut self) -> Result<u64, &'static str> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().map_err(|_| "truncated u64")?,
        ))
    }

    fn usize_len(&mut self) -> Result<usize, &'static str> {
        usize::try_from(self.u64()?).map_err(|_| "index length is not process-addressable")
    }

    fn scheme(&mut self, expected: IdentityScheme) -> Result<(), &'static str> {
        let algorithm = self.u16()?;
        let construction = self.u16()?;
        if algorithm == 0 || construction == 0 {
            return Err("index identity scheme fields must be non-zero");
        }
        if algorithm != expected.algorithm() || construction != expected.construction() {
            return Err("index identity scheme does not match the store");
        }
        Ok(())
    }

    fn identity(&mut self, scheme: IdentityScheme) -> Result<ObjectId, &'static str> {
        self.scheme(scheme)?;
        let digest_len =
            usize::try_from(self.u32()?).map_err(|_| "index digest length overflow")?;
        if digest_len == 0 {
            return Err("index digest length must be non-zero");
        }
        self.take(digest_len)?
            .try_into()
            .map(ObjectId::new)
            .map_err(|_| "index digest length does not match the active scheme")
    }
}
