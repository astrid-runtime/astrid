//! Native arena and root-journal framing, parsing, and recovery.

use super::{
    ARENA_FILE, ARENA_MAGIC, ArenaLocation, BTreeMap, CHECKSUM_START, DurableError,
    FRAME_HEADER_LEN, FRAME_HEADER_LEN_USIZE, FRAME_VERSION, File, IdentityScheme, ModelError,
    ObjectClass, ObjectFormatVersion, ObjectId, ObjectKind, ObjectRecord, ObjectReference,
    OpenOptions, Path, PersistentObjectIdentity, Read, RecoveryLimits, ReferenceKind,
    ReferenceLabel, Seek, SeekFrom, Write, io,
};

const IDENTITY_PREFIX_BYTES: usize = 8;
const CURRENT_DIGEST_BYTES: u32 = 32;
const CURRENT_DIGEST_BYTES_USIZE: usize = 32;
const MIN_REFERENCE_WIRE_BYTES: usize =
    std::mem::size_of::<u64>() + IDENTITY_PREFIX_BYTES + CURRENT_DIGEST_BYTES_USIZE + 1;

pub(super) fn read_indexed_object<I: PersistentObjectIdentity>(
    arena: &mut File,
    expected_id: ObjectId,
    location: ArenaLocation,
    identity: &I,
    limits: RecoveryLimits,
) -> Result<ObjectRecord, DurableError> {
    let scheme = identity.scheme();
    let payload = read_frame_at(arena, ARENA_FILE, ARENA_MAGIC, location.offset, limits)?;
    let payload_len = u64::try_from(payload.len()).map_err(|_| DurableError::EncodingOverflow)?;
    if payload_len != location.payload_len
        || frame_checksum(ARENA_MAGIC, payload_len, &payload) != location.checksum
    {
        return Err(corrupt(
            ARENA_FILE,
            location.offset,
            "indexed frame location no longer matches the arena",
        ));
    }
    let (id, record) = decode_object_frame(&payload, scheme)
        .map_err(|detail| corrupt(ARENA_FILE, location.offset, detail))?;
    if id != expected_id {
        return Err(corrupt(
            ARENA_FILE,
            location.offset,
            "indexed object identifier mismatch",
        ));
    }
    if identity.identify(&record) != expected_id {
        return Err(corrupt(
            ARENA_FILE,
            location.offset,
            "indexed object identity does not match its canonical record",
        ));
    }
    Ok(record)
}

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
    file: &mut File,
    file_name: &'static str,
    magic: [u8; 8],
    offset: u64,
    limits: RecoveryLimits,
) -> Result<Vec<u8>, DurableError> {
    file.seek(SeekFrom::Start(offset))
        .map_err(|source| io_error("seek indexed durable frame", source))?;
    let mut header = [0_u8; FRAME_HEADER_LEN_USIZE];
    file.read_exact(&mut header)
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
    file.read_exact(&mut payload)
        .map_err(|source| io_error("read indexed durable frame payload", source))?;
    let checksum: [u8; 32] = header[CHECKSUM_START..]
        .try_into()
        .map_err(|_| DurableError::EncodingOverflow)?;
    if frame_checksum(magic, payload_len, &payload) != checksum {
        return Err(corrupt(file_name, offset, "frame checksum mismatch"));
    }
    Ok(payload)
}

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

#[cfg(unix)]
pub(super) fn sync_store_directory(path: &Path) -> Result<(), DurableError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| io_error("flush principal-store directory", source))
}

#[cfg(not(unix))]
pub(super) fn sync_store_directory(_path: &Path) -> Result<(), DurableError> {
    Ok(())
}

pub(super) fn io_error(operation: &'static str, source: io::Error) -> DurableError {
    DurableError::Io { operation, source }
}

pub(super) fn recover_arena<I: PersistentObjectIdentity>(
    arena: &mut File,
    identity: &I,
    limits: RecoveryLimits,
) -> Result<(BTreeMap<ObjectId, ArenaLocation>, Option<ArenaLocation>), DurableError> {
    let scheme = identity.scheme();
    let mut index = BTreeMap::<ObjectId, ArenaLocation>::new();
    let mut tail = None;
    scan_frames(arena, ARENA_FILE, ARENA_MAGIC, limits, |offset, payload| {
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
    })?;
    Ok((index, tail))
}

pub(super) fn scan_frames(
    file: &mut File,
    file_name: &'static str,
    magic: [u8; 8],
    limits: RecoveryLimits,
    mut accept: impl FnMut(u64, &[u8]) -> Result<(), DurableError>,
) -> Result<(), DurableError> {
    let file_len = file
        .metadata()
        .map_err(|source| io_error("read principal-store metadata", source))?
        .len();
    let mut offset = 0_u64;
    while offset < file_len {
        let remaining = file_len
            .checked_sub(offset)
            .ok_or(DurableError::EncodingOverflow)?;
        if remaining < FRAME_HEADER_LEN {
            truncate_tail(file, offset)?;
            break;
        }
        file.seek(SeekFrom::Start(offset))
            .map_err(|source| io_error("seek durable frame", source))?;
        let mut header = [0_u8; FRAME_HEADER_LEN_USIZE];
        file.read_exact(&mut header)
            .map_err(|source| io_error("read durable frame header", source))?;
        if header[..8] != magic {
            let error = corrupt(file_name, offset, "frame magic mismatch");
            if valid_frame_follows(file, magic, offset, file_len, limits)? {
                return Err(error);
            }
            truncate_tail(file, offset)?;
            break;
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
        let frame_len = FRAME_HEADER_LEN
            .checked_add(payload_len)
            .ok_or(DurableError::EncodingOverflow)?;
        let frame_end = offset
            .checked_add(frame_len)
            .ok_or(DurableError::EncodingOverflow)?;
        if frame_end > file_len {
            truncate_tail(file, offset)?;
            break;
        }
        let payload_usize =
            usize::try_from(payload_len).map_err(|_| DurableError::EncodingOverflow)?;
        let mut payload = Vec::new();
        payload
            .try_reserve_exact(payload_usize)
            .map_err(|_| DurableError::EncodingOverflow)?;
        payload.resize(payload_usize, 0);
        file.read_exact(&mut payload)
            .map_err(|source| io_error("read durable frame payload", source))?;
        let checksum: [u8; 32] = header[CHECKSUM_START..]
            .try_into()
            .map_err(|_| DurableError::EncodingOverflow)?;
        if frame_checksum(magic, payload_len, &payload) != checksum {
            let error = corrupt(file_name, offset, "frame checksum mismatch");
            if valid_frame_follows(file, magic, offset, file_len, limits)? {
                return Err(error);
            }
            truncate_tail(file, offset)?;
            break;
        }
        accept(offset, &payload)?;
        offset = frame_end;
    }
    file.seek(SeekFrom::End(0))
        .map_err(|source| io_error("seek durable file tail", source))?;
    Ok(())
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
    if payload_len > limits.max_frame_bytes {
        return Ok(false);
    }
    let frame_len = FRAME_HEADER_LEN
        .checked_add(payload_len)
        .ok_or(DurableError::EncodingOverflow)?;
    if frame_len > remaining {
        return Ok(false);
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

pub(super) fn append_frames(
    file: &mut File,
    magic: [u8; 8],
    payloads: &[Vec<u8>],
) -> Result<Vec<ArenaLocation>, DurableError> {
    let capacity = payloads.iter().try_fold(0_usize, |total, payload| {
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

struct SliceReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> SliceReader<'a> {
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
            .ok_or("frame length overflow")?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or("truncated frame payload")?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, &'static str> {
        self.take(1)?.first().copied().ok_or("truncated u8 field")
    }

    fn u16(&mut self) -> Result<u16, &'static str> {
        Ok(u16::from_le_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| "truncated u16 field")?,
        ))
    }

    fn u32(&mut self) -> Result<u32, &'static str> {
        Ok(u32::from_le_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| "truncated u32 field")?,
        ))
    }

    fn u64(&mut self) -> Result<u64, &'static str> {
        Ok(u64::from_le_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| "truncated u64 field")?,
        ))
    }

    fn usize_len(&mut self) -> Result<usize, &'static str> {
        usize::try_from(self.u64()?).map_err(|_| "length is not process-addressable")
    }

    fn identity(&mut self, scheme: IdentityScheme) -> Result<ObjectId, &'static str> {
        let algorithm = self.u16()?;
        let construction = self.u16()?;
        let digest_len =
            usize::try_from(self.u32()?).map_err(|_| "identity digest length overflow")?;
        if algorithm == 0 || construction == 0 || digest_len == 0 {
            return Err("identity tag fields must be non-zero");
        }
        let digest = self.take(digest_len)?;
        if algorithm != scheme.algorithm() || construction != scheme.construction() {
            return Err("unsupported identity algorithm or construction version");
        }
        digest
            .try_into()
            .map(ObjectId::new)
            .map_err(|_| "identity digest length does not match the supported scheme")
    }
}
