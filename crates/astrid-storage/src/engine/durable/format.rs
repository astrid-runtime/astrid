//! Native arena and root-journal framing, parsing, and recovery.

use super::{
    ARENA_FILE, ARENA_MAGIC, ArenaLocation, BTreeMap, CHECKSUM_START, DurableError,
    FRAME_HEADER_LEN, FRAME_HEADER_LEN_USIZE, FRAME_VERSION, File, IdentityScheme, ModelError,
    ObjectClass, ObjectFormatVersion, ObjectId, ObjectKind, ObjectRecord, ObjectReference,
    PersistentObjectIdentity, Read, RecoveryLimits, ReferenceKind, ReferenceLabel, Seek, SeekFrom,
    Write, io,
};
#[cfg(test)]
use std::fs::OpenOptions;
#[cfg(test)]
use std::path::Path;

const IDENTITY_PREFIX_BYTES: usize = 8;
const CURRENT_DIGEST_BYTES: u32 = 32;
const CURRENT_DIGEST_BYTES_USIZE: usize = 32;
const MIN_REFERENCE_WIRE_BYTES: usize =
    std::mem::size_of::<u64>() + IDENTITY_PREFIX_BYTES + CURRENT_DIGEST_BYTES_USIZE + 1;

#[path = "format/indexed.rs"]
mod indexed;
#[path = "format/prepared.rs"]
mod prepared;
#[path = "format/reader.rs"]
mod reader;

#[cfg(test)]
pub(super) use indexed::last_batch_spans;
pub(super) use indexed::{
    read_indexed_object, read_indexed_object_with_payload, read_indexed_objects,
    visit_indexed_objects,
};
pub(super) use prepared::{PreparedFrame, append_prepared_frames};
use reader::SliceReader;

pub(super) fn verify_indexed_location(
    arena: &mut File,
    expected_id: ObjectId,
    location: ArenaLocation,
    scheme: IdentityScheme,
    limits: RecoveryLimits,
) -> Result<(), DurableError> {
    let file_len = arena
        .metadata()
        .map_err(|source| io_error("read indexed arena metadata", source))?
        .len();
    let frame_end = location
        .offset
        .checked_add(FRAME_HEADER_LEN)
        .and_then(|value| value.checked_add(location.payload_len))
        .ok_or(DurableError::EncodingOverflow)?;
    if frame_end > file_len {
        return Err(corrupt(
            ARENA_FILE,
            location.offset,
            "indexed frame extends beyond the arena",
        ));
    }
    arena
        .seek(SeekFrom::Start(location.offset))
        .map_err(|source| io_error("seek indexed arena header", source))?;
    let mut header = [0_u8; FRAME_HEADER_LEN_USIZE];
    arena
        .read_exact(&mut header)
        .map_err(|source| io_error("read indexed arena header", source))?;
    if header[..8] != ARENA_MAGIC
        || u16::from_le_bytes([header[8], header[9]]) != FRAME_VERSION
        || header[10..12] != [0, 0]
    {
        return Err(corrupt(
            ARENA_FILE,
            location.offset,
            "indexed frame header is invalid",
        ));
    }
    let payload_len = u64::from_le_bytes(
        header[12..20]
            .try_into()
            .map_err(|_| DurableError::EncodingOverflow)?,
    );
    if payload_len > limits.max_frame_bytes {
        return Err(DurableError::FrameTooLarge {
            file: ARENA_FILE,
            offset: location.offset,
            declared: payload_len,
            limit: limits.max_frame_bytes,
        });
    }
    let checksum: [u8; 32] = header[CHECKSUM_START..]
        .try_into()
        .map_err(|_| DurableError::EncodingOverflow)?;
    if payload_len != location.payload_len || checksum != location.checksum {
        return Err(corrupt(
            ARENA_FILE,
            location.offset,
            "indexed frame header does not match the cache",
        ));
    }
    let mut identity_bytes = [0_u8; IDENTITY_PREFIX_BYTES + CURRENT_DIGEST_BYTES_USIZE];
    arena
        .read_exact(&mut identity_bytes)
        .map_err(|source| io_error("read indexed object identity", source))?;
    let mut reader = SliceReader::new(&identity_bytes);
    let actual = reader
        .identity(scheme)
        .map_err(|detail| corrupt(ARENA_FILE, location.offset, detail))?;
    if actual != expected_id {
        return Err(corrupt(
            ARENA_FILE,
            location.offset,
            "indexed object identity mismatch",
        ));
    }
    Ok(())
}

pub(super) fn verify_indexed_tail(
    arena: &mut File,
    location: ArenaLocation,
    limits: RecoveryLimits,
) -> Result<(), DurableError> {
    let payload = read_frame_at(arena, ARENA_FILE, ARENA_MAGIC, location.offset, limits)?;
    let payload_len = u64::try_from(payload.len()).map_err(|_| DurableError::EncodingOverflow)?;
    if payload_len != location.payload_len
        || frame_checksum(ARENA_MAGIC, payload_len, &payload) != location.checksum
    {
        return Err(corrupt(
            ARENA_FILE,
            location.offset,
            "indexed arena tail no longer matches the cache",
        ));
    }
    Ok(())
}

fn read_frame_at(
    file: &File,
    file_name: &'static str,
    magic: [u8; 8],
    offset: u64,
    limits: RecoveryLimits,
) -> Result<Vec<u8>, DurableError> {
    let mut header = [0_u8; FRAME_HEADER_LEN_USIZE];
    read_exact_at(file, &mut header, offset)
        .map_err(|source| io_error("read indexed durable frame header", source))?;
    if header[..8] != magic {
        return Err(corrupt(file_name, offset, "frame magic mismatch"));
    }
    let version = u16::from_le_bytes([header[8], header[9]]);
    if version != FRAME_VERSION {
        return Err(corrupt(file_name, offset, "unsupported frame version"));
    }
    if header[10..12] != [0, 0] {
        return Err(corrupt(
            file_name,
            offset,
            "reserved header bytes are non-zero",
        ));
    }
    let payload_len = u64::from_le_bytes(
        header[12..20]
            .try_into()
            .map_err(|_| DurableError::EncodingOverflow)?,
    );
    if payload_len > limits.max_frame_bytes {
        return Err(DurableError::FrameTooLarge {
            file: file_name,
            offset,
            declared: payload_len,
            limit: limits.max_frame_bytes,
        });
    }
    let payload_usize = usize::try_from(payload_len).map_err(|_| DurableError::EncodingOverflow)?;
    let mut payload = Vec::new();
    payload
        .try_reserve_exact(payload_usize)
        .map_err(|_| DurableError::EncodingOverflow)?;
    payload.resize(payload_usize, 0);
    let payload_offset = offset
        .checked_add(FRAME_HEADER_LEN)
        .ok_or(DurableError::EncodingOverflow)?;
    read_exact_at(file, &mut payload, payload_offset)
        .map_err(|source| io_error("read indexed durable frame payload", source))?;
    let checksum: [u8; 32] = header[CHECKSUM_START..]
        .try_into()
        .map_err(|_| DurableError::EncodingOverflow)?;
    if frame_checksum(magic, payload_len, &payload) != checksum {
        return Err(corrupt(file_name, offset, "frame checksum mismatch"));
    }
    Ok(payload)
}

fn read_exact_at(file: &File, buffer: &mut [u8], offset: u64) -> io::Result<()> {
    let mut filled = 0_usize;
    while filled != buffer.len() {
        let relative = u64::try_from(filled)
            .map_err(|_| io::Error::other("positional read offset overflow"))?;
        let position = offset
            .checked_add(relative)
            .ok_or_else(|| io::Error::other("positional read offset overflow"))?;
        let read = positioned_read(file, &mut buffer[filled..], position)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "positional read reached end of file",
            ));
        }
        filled = filled
            .checked_add(read)
            .ok_or_else(|| io::Error::other("positional read length overflow"))?;
    }
    Ok(())
}

#[cfg(unix)]
fn positioned_read(file: &File, buffer: &mut [u8], offset: u64) -> io::Result<usize> {
    std::os::unix::fs::FileExt::read_at(file, buffer, offset)
}

#[cfg(windows)]
fn positioned_read(file: &File, buffer: &mut [u8], offset: u64) -> io::Result<usize> {
    std::os::windows::fs::FileExt::seek_read(file, buffer, offset)
}

#[cfg(not(any(unix, windows)))]
fn positioned_read(file: &File, buffer: &mut [u8], offset: u64) -> io::Result<usize> {
    let mut reader = file.try_clone()?;
    reader.seek(SeekFrom::Start(offset))?;
    reader.read(buffer)
}

#[cfg(test)]
pub(super) fn open_rw(path: &Path) -> Result<File, DurableError> {
    let mut options = OpenOptions::new();
    options.create(true).truncate(false).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .map_err(|source| io_error("open principal-store file", source))
}

pub(super) fn io_error(operation: &'static str, source: io::Error) -> DurableError {
    DurableError::Io { operation, source }
}

pub(super) fn recover_arena<I: PersistentObjectIdentity>(
    arena: &mut File,
    identity: &I,
    limits: RecoveryLimits,
    protected_len: u64,
) -> Result<(BTreeMap<ObjectId, ArenaLocation>, Option<ArenaLocation>), DurableError> {
    let scheme = identity.scheme();
    let mut index = BTreeMap::<ObjectId, ArenaLocation>::new();
    let mut tail = None;
    scan_frames_with_protected_prefix(
        arena,
        ARENA_FILE,
        ARENA_MAGIC,
        limits,
        protected_len,
        |offset, payload| {
            let (id, record) = decode_object_frame(payload, scheme)
                .map_err(|detail| corrupt(ARENA_FILE, offset, detail))?;
            let computed = identity.identify(&record);
            if computed != id {
                return Err(corrupt(ARENA_FILE, offset, "object identity mismatch"));
            }
            if encode_object_frame(scheme, id, &record)? != payload {
                return Err(corrupt(ARENA_FILE, offset, "object frame is not canonical"));
            }
            let payload_len =
                u64::try_from(payload.len()).map_err(|_| DurableError::EncodingOverflow)?;
            let checksum = frame_checksum(ARENA_MAGIC, payload_len, payload);
            let location = ArenaLocation {
                offset,
                payload_len,
                checksum,
            };
            match index.get(&id) {
                Some(existing)
                    if existing.payload_len == payload_len && existing.checksum == checksum => {},
                Some(_) => {
                    return Err(DurableError::RecoveryModel {
                        file: ARENA_FILE,
                        offset,
                        source: ModelError::ObjectCollision(id),
                    });
                },
                None => {
                    index.insert(id, location);
                },
            }
            tail = Some(location);
            Ok(())
        },
    )?;
    Ok((index, tail))
}

pub(super) fn scan_frames(
    file: &mut File,
    file_name: &'static str,
    magic: [u8; 8],
    limits: RecoveryLimits,
    accept: impl FnMut(u64, &[u8]) -> Result<(), DurableError>,
) -> Result<(), DurableError> {
    scan_frames_with_protected_prefix(file, file_name, magic, limits, 0, accept)
}

fn scan_frames_with_protected_prefix(
    file: &mut File,
    file_name: &'static str,
    magic: [u8; 8],
    limits: RecoveryLimits,
    protected_len: u64,
    mut accept: impl FnMut(u64, &[u8]) -> Result<(), DurableError>,
) -> Result<(), DurableError> {
    let file_len = validated_file_len(file, file_name, protected_len)?;
    let policy = FrameScanPolicy {
        magic,
        limits,
        protected_len,
        file_len,
    };
    let mut offset = 0_u64;
    while offset < file_len {
        let remaining = file_len
            .checked_sub(offset)
            .ok_or(DurableError::EncodingOverflow)?;
        if remaining < FRAME_HEADER_LEN {
            if offset < protected_len {
                return Err(corrupt(
                    file_name,
                    offset,
                    "published frame header is truncated",
                ));
            }
            truncate_tail(file, offset)?;
            break;
        }
        file.seek(SeekFrom::Start(offset))
            .map_err(|source| io_error("seek durable frame", source))?;
        let mut header = [0_u8; FRAME_HEADER_LEN_USIZE];
        file.read_exact(&mut header)
            .map_err(|source| io_error("read durable frame header", source))?;
        if header[..8] != magic {
            truncate_unpublished_tail_or_fail(
                file,
                policy,
                offset,
                false,
                corrupt(file_name, offset, "frame magic mismatch"),
            )?;
            break;
        }
        let decoded = decode_frame_header(file_name, offset, &header)?;
        let payload_len = decoded.payload_len;
        if payload_len > limits.max_frame_bytes {
            let error = DurableError::FrameTooLarge {
                file: file_name,
                offset,
                declared: payload_len,
                limit: limits.max_frame_bytes,
            };
            if offset < protected_len {
                return Err(error);
            }
            let claimed_end = FRAME_HEADER_LEN
                .checked_add(payload_len)
                .and_then(|frame_len| offset.checked_add(frame_len));
            truncate_unpublished_tail_or_fail(
                file,
                policy,
                offset,
                claimed_end.is_some_and(|end| end <= file_len),
                error,
            )?;
            break;
        }
        let frame_len = FRAME_HEADER_LEN
            .checked_add(payload_len)
            .ok_or(DurableError::EncodingOverflow)?;
        let frame_end = offset
            .checked_add(frame_len)
            .ok_or(DurableError::EncodingOverflow)?;
        if frame_end > file_len {
            if offset < protected_len {
                return Err(corrupt(
                    file_name,
                    offset,
                    "published frame payload is truncated",
                ));
            }
            truncate_tail(file, offset)?;
            break;
        }
        let payload = read_frame_payload(file, payload_len)?;
        if frame_checksum(magic, payload_len, &payload) != decoded.checksum {
            truncate_unpublished_tail_or_fail(
                file,
                policy,
                offset,
                false,
                corrupt(file_name, offset, "frame checksum mismatch"),
            )?;
            break;
        }
        accept(offset, &payload)?;
        offset = frame_end;
    }
    file.seek(SeekFrom::End(0))
        .map_err(|source| io_error("seek durable file tail", source))?;
    Ok(())
}

fn validated_file_len(
    file: &File,
    file_name: &'static str,
    protected_len: u64,
) -> Result<u64, DurableError> {
    let file_len = file
        .metadata()
        .map_err(|source| io_error("read principal-store metadata", source))?
        .len();
    if file_len < protected_len {
        return Err(corrupt(
            file_name,
            file_len,
            "published durable prefix is truncated",
        ));
    }
    Ok(file_len)
}

#[derive(Clone, Copy)]
struct DecodedFrameHeader {
    payload_len: u64,
    checksum: [u8; 32],
}

#[derive(Clone, Copy)]
struct FrameScanPolicy {
    magic: [u8; 8],
    limits: RecoveryLimits,
    protected_len: u64,
    file_len: u64,
}

fn decode_frame_header(
    file_name: &'static str,
    offset: u64,
    header: &[u8; FRAME_HEADER_LEN_USIZE],
) -> Result<DecodedFrameHeader, DurableError> {
    let version = u16::from_le_bytes([header[8], header[9]]);
    if version != FRAME_VERSION {
        return Err(corrupt(file_name, offset, "unsupported frame version"));
    }
    if header[10..12] != [0, 0] {
        return Err(corrupt(
            file_name,
            offset,
            "reserved header bytes are non-zero",
        ));
    }
    Ok(DecodedFrameHeader {
        payload_len: u64::from_le_bytes(
            header[12..20]
                .try_into()
                .map_err(|_| DurableError::EncodingOverflow)?,
        ),
        checksum: header[CHECKSUM_START..]
            .try_into()
            .map_err(|_| DurableError::EncodingOverflow)?,
    })
}

fn read_frame_payload(file: &mut File, payload_len: u64) -> Result<Vec<u8>, DurableError> {
    let payload_usize = usize::try_from(payload_len).map_err(|_| DurableError::EncodingOverflow)?;
    let mut payload = Vec::new();
    payload
        .try_reserve_exact(payload_usize)
        .map_err(|_| DurableError::EncodingOverflow)?;
    payload.resize(payload_usize, 0);
    file.read_exact(&mut payload)
        .map_err(|source| io_error("read durable frame payload", source))?;
    Ok(payload)
}

fn truncate_unpublished_tail_or_fail(
    file: &mut File,
    policy: FrameScanPolicy,
    offset: u64,
    known_interior: bool,
    error: DurableError,
) -> Result<(), DurableError> {
    if offset < policy.protected_len
        || known_interior
        || valid_frame_follows(file, policy.magic, offset, policy.file_len, policy.limits)?
    {
        return Err(error);
    }
    truncate_tail(file, offset)
}

fn valid_frame_follows(
    file: &mut File,
    magic: [u8; 8],
    invalid_offset: u64,
    file_len: u64,
    limits: RecoveryLimits,
) -> Result<bool, DurableError> {
    let Some(mut search_offset) = invalid_offset.checked_add(1) else {
        return Ok(false);
    };
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(65_543)
        .map_err(|_| DurableError::EncodingOverflow)?;
    buffer.resize(65_543, 0);
    while search_offset < file_len {
        file.seek(SeekFrom::Start(search_offset))
            .map_err(|source| io_error("seek durable tail recovery scan", source))?;
        let remaining = file_len
            .checked_sub(search_offset)
            .ok_or(DurableError::EncodingOverflow)?;
        let wanted = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| DurableError::EncodingOverflow)?;
        let read = file
            .read(&mut buffer[..wanted])
            .map_err(|source| io_error("read durable tail recovery scan", source))?;
        if read < magic.len() {
            return Ok(false);
        }
        for relative in 0..=read.saturating_sub(magic.len()) {
            let candidate_end = relative
                .checked_add(magic.len())
                .ok_or(DurableError::EncodingOverflow)?;
            if buffer.get(relative..candidate_end) != Some(magic.as_slice()) {
                continue;
            }
            let candidate = search_offset
                .checked_add(u64::try_from(relative).map_err(|_| DurableError::EncodingOverflow)?)
                .ok_or(DurableError::EncodingOverflow)?;
            if physical_frame_is_valid(file, magic, candidate, file_len, limits)? {
                return Ok(true);
            }
        }
        if read < wanted {
            return Ok(false);
        }
        let overlap = magic.len().saturating_sub(1);
        search_offset = search_offset
            .checked_add(
                u64::try_from(read.saturating_sub(overlap))
                    .map_err(|_| DurableError::EncodingOverflow)?,
            )
            .ok_or(DurableError::EncodingOverflow)?;
    }
    Ok(false)
}

fn physical_frame_is_valid(
    file: &mut File,
    magic: [u8; 8],
    offset: u64,
    file_len: u64,
    limits: RecoveryLimits,
) -> Result<bool, DurableError> {
    let remaining = file_len
        .checked_sub(offset)
        .ok_or(DurableError::EncodingOverflow)?;
    if remaining < FRAME_HEADER_LEN {
        return Ok(false);
    }
    file.seek(SeekFrom::Start(offset))
        .map_err(|source| io_error("seek durable recovery candidate", source))?;
    let mut header = [0_u8; FRAME_HEADER_LEN_USIZE];
    file.read_exact(&mut header)
        .map_err(|source| io_error("read durable recovery candidate", source))?;
    if header[..8] != magic
        || u16::from_le_bytes([header[8], header[9]]) != FRAME_VERSION
        || header[10..12] != [0, 0]
    {
        return Ok(false);
    }
    let payload_len = u64::from_le_bytes(
        header[12..20]
            .try_into()
            .map_err(|_| DurableError::EncodingOverflow)?,
    );
    let frame_len = FRAME_HEADER_LEN
        .checked_add(payload_len)
        .ok_or(DurableError::EncodingOverflow)?;
    if frame_len > remaining {
        return Ok(false);
    }
    if payload_len > limits.max_frame_bytes {
        return Ok(true);
    }
    let expected: [u8; 32] = header[CHECKSUM_START..]
        .try_into()
        .map_err(|_| DurableError::EncodingOverflow)?;
    let mut hasher = blake3::Hasher::new_derive_key("astrid durable physical frame checksum v1");
    hasher.update(&magic);
    hasher.update(&FRAME_VERSION.to_le_bytes());
    hasher.update(&payload_len.to_le_bytes());
    let mut unread = payload_len;
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(65_536)
        .map_err(|_| DurableError::EncodingOverflow)?;
    buffer.resize(65_536, 0);
    while unread != 0 {
        let chunk = usize::try_from(unread.min(buffer.len() as u64))
            .map_err(|_| DurableError::EncodingOverflow)?;
        file.read_exact(&mut buffer[..chunk])
            .map_err(|source| io_error("read durable recovery candidate payload", source))?;
        hasher.update(&buffer[..chunk]);
        unread = unread
            .checked_sub(u64::try_from(chunk).map_err(|_| DurableError::EncodingOverflow)?)
            .ok_or(DurableError::EncodingOverflow)?;
    }
    Ok(hasher.finalize().as_bytes() == &expected)
}

fn truncate_tail(file: &mut File, valid_len: u64) -> Result<(), DurableError> {
    file.set_len(valid_len)
        .map_err(|source| io_error("truncate incomplete durable tail", source))?;
    file.sync_data()
        .map_err(|source| io_error("flush durable tail truncation", source))
}

pub(super) fn append_frame(
    file: &mut File,
    magic: [u8; 8],
    payload: &[u8],
) -> Result<ArenaLocation, DurableError> {
    let payload_len = u64::try_from(payload.len()).map_err(|_| DurableError::EncodingOverflow)?;
    let checksum = frame_checksum(magic, payload_len, payload);
    let offset = file
        .seek(SeekFrom::End(0))
        .map_err(|source| io_error("seek durable append", source))?;
    let mut header = [0_u8; FRAME_HEADER_LEN_USIZE];
    header[..8].copy_from_slice(&magic);
    header[8..10].copy_from_slice(&FRAME_VERSION.to_le_bytes());
    header[12..20].copy_from_slice(&payload_len.to_le_bytes());
    header[CHECKSUM_START..].copy_from_slice(&checksum);
    file.write_all(&header)
        .map_err(|source| io_error("append durable frame header", source))?;
    file.write_all(payload)
        .map_err(|source| io_error("append durable frame payload", source))?;
    Ok(ArenaLocation {
        offset,
        payload_len,
        checksum,
    })
}

pub(super) fn append_frames<T: AsRef<[u8]>>(
    file: &mut File,
    magic: [u8; 8],
    payloads: &[T],
) -> Result<Vec<ArenaLocation>, DurableError> {
    let capacity = payloads.iter().try_fold(0_usize, |total, payload| {
        let payload = payload.as_ref();
        total
            .checked_add(FRAME_HEADER_LEN_USIZE)
            .and_then(|value| value.checked_add(payload.len()))
            .ok_or(DurableError::EncodingOverflow)
    })?;
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(capacity)
        .map_err(|_| DurableError::EncodingOverflow)?;
    let mut locations = Vec::new();
    locations
        .try_reserve_exact(payloads.len())
        .map_err(|_| DurableError::EncodingOverflow)?;
    let base = file
        .seek(SeekFrom::End(0))
        .map_err(|source| io_error("seek durable batch append", source))?;
    for payload in payloads {
        let payload = payload.as_ref();
        let payload_len =
            u64::try_from(payload.len()).map_err(|_| DurableError::EncodingOverflow)?;
        let checksum = frame_checksum(magic, payload_len, payload);
        let relative = u64::try_from(encoded.len()).map_err(|_| DurableError::EncodingOverflow)?;
        let offset = base
            .checked_add(relative)
            .ok_or(DurableError::EncodingOverflow)?;
        let mut header = [0_u8; FRAME_HEADER_LEN_USIZE];
        header[..8].copy_from_slice(&magic);
        header[8..10].copy_from_slice(&FRAME_VERSION.to_le_bytes());
        header[12..20].copy_from_slice(&payload_len.to_le_bytes());
        header[CHECKSUM_START..].copy_from_slice(&checksum);
        encoded.extend_from_slice(&header);
        encoded.extend_from_slice(payload);
        locations.push(ArenaLocation {
            offset,
            payload_len,
            checksum,
        });
    }
    file.write_all(&encoded)
        .map_err(|source| io_error("append durable frame batch", source))?;
    Ok(locations)
}

pub(super) fn frame_checksum(magic: [u8; 8], payload_len: u64, payload: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("astrid durable physical frame checksum v1");
    hasher.update(&magic);
    hasher.update(&FRAME_VERSION.to_le_bytes());
    hasher.update(&payload_len.to_le_bytes());
    hasher.update(payload);
    *hasher.finalize().as_bytes()
}

pub(super) fn corrupt(file: &'static str, offset: u64, detail: &'static str) -> DurableError {
    DurableError::Corrupt {
        file,
        offset,
        detail,
    }
}

pub(super) fn ensure_payload_limit(
    file: &'static str,
    offset: u64,
    payload_len: usize,
    limits: RecoveryLimits,
) -> Result<(), DurableError> {
    let declared = u64::try_from(payload_len).map_err(|_| DurableError::EncodingOverflow)?;
    if declared > limits.max_frame_bytes {
        return Err(DurableError::FrameTooLarge {
            file,
            offset,
            declared,
            limit: limits.max_frame_bytes,
        });
    }
    Ok(())
}

fn encode_identity(bytes: &mut Vec<u8>, scheme: IdentityScheme, id: ObjectId) {
    bytes.extend_from_slice(&scheme.algorithm().to_le_bytes());
    bytes.extend_from_slice(&scheme.construction().to_le_bytes());
    bytes.extend_from_slice(&CURRENT_DIGEST_BYTES.to_le_bytes());
    bytes.extend_from_slice(id.as_bytes());
}

pub(super) fn encode_object_frame(
    scheme: IdentityScheme,
    id: ObjectId,
    record: &ObjectRecord,
) -> Result<Vec<u8>, DurableError> {
    let canonical_len = u64::try_from(record.canonical_bytes().len())
        .map_err(|_| DurableError::EncodingOverflow)?;
    let reference_count =
        u64::try_from(record.references().len()).map_err(|_| DurableError::EncodingOverflow)?;
    let mut bytes = Vec::new();
    encode_identity(&mut bytes, scheme, id);
    bytes.extend_from_slice(&record.kind().code().to_le_bytes());
    bytes.extend_from_slice(&record.format_version().get().to_le_bytes());
    bytes.push(record.class().code());
    bytes.extend_from_slice(&record.logical_bytes().to_le_bytes());
    bytes.extend_from_slice(&canonical_len.to_le_bytes());
    bytes.extend_from_slice(&reference_count.to_le_bytes());
    bytes.extend_from_slice(record.canonical_bytes());
    for reference in record.references() {
        let label_len = u64::try_from(reference.label().as_bytes().len())
            .map_err(|_| DurableError::EncodingOverflow)?;
        bytes.extend_from_slice(&label_len.to_le_bytes());
        bytes.extend_from_slice(reference.label().as_bytes());
        encode_identity(&mut bytes, scheme, reference.target());
        bytes.push(reference.kind().code());
    }
    Ok(bytes)
}

pub(super) fn canonical_record_bytes(
    frame_payload: &[u8],
    scheme: IdentityScheme,
) -> Result<&[u8], DurableError> {
    let mut reader = SliceReader::new(frame_payload);
    reader
        .identity(scheme)
        .map_err(|detail| corrupt(ARENA_FILE, 0, detail))?;
    frame_payload
        .get(reader.offset..)
        .ok_or(DurableError::EncodingOverflow)
}

pub(super) fn decode_object_frame(
    bytes: &[u8],
    scheme: IdentityScheme,
) -> Result<(ObjectId, ObjectRecord), &'static str> {
    let mut reader = SliceReader::new(bytes);
    let id = reader.identity(scheme)?;
    let kind = ObjectKind::from_code(reader.u16()?).ok_or("unknown object-kind code")?;
    let version =
        ObjectFormatVersion::new(reader.u16()?).ok_or("object-format version must be non-zero")?;
    let class = ObjectClass::from_code(reader.u8()?).ok_or("unknown object-class code")?;
    let logical_bytes = reader.u64()?;
    let canonical_len = reader.usize_len()?;
    let reference_count = reader.usize_len()?;
    let canonical_bytes = reader.take(canonical_len)?.to_vec();
    if reference_count > reader.remaining() / MIN_REFERENCE_WIRE_BYTES {
        return Err("reference count exceeds frame capacity");
    }
    let mut references = Vec::new();
    references
        .try_reserve(reference_count)
        .map_err(|_| "reference allocation failed")?;
    for _ in 0..reference_count {
        let label_len = reader.usize_len()?;
        let label = reader.take(label_len)?.to_vec();
        let target = reader.identity(scheme)?;
        let reference_kind =
            ReferenceKind::from_code(reader.u8()?).ok_or("unknown reference-kind code")?;
        references.push(ObjectReference::new(
            ReferenceLabel::new(label),
            target,
            reference_kind,
        ));
    }
    if reader.remaining() != 0 {
        return Err("trailing object-frame bytes");
    }
    let record = ObjectRecord::new(
        kind,
        version,
        canonical_bytes,
        references,
        logical_bytes,
        class,
    )
    .map_err(|_| "non-canonical object references")?;
    Ok((id, record))
}
