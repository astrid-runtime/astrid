//! Native arena and root-journal framing, parsing, and recovery.

#[cfg(test)]
use super::File;
use super::{
    ARENA_FILE, ARENA_MAGIC, ArenaLocation, BTreeMap, CHECKSUM_START, DurableError, DurableIo,
    FRAME_HEADER_LEN, FRAME_HEADER_LEN_USIZE, FRAME_VERSION, IdentityScheme, ModelError,
    ObjectClass, ObjectFormatVersion, ObjectId, ObjectKind, ObjectRecord, ObjectReference,
    PersistentObjectIdentity, RecoveryLimits, ReferenceKind, ReferenceLabel, SeekFrom, io,
    root_wire,
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

#[cfg(test)]
thread_local! {
    pub(super) static FRAME_CHECKSUM_PASSES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static RECOVERY_ARENA_SCANS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

mod framed_append;
mod indexed;
mod location;
mod positioned;
#[cfg(test)]
mod positioned_tests;
mod prepared;
mod reader;
mod scan;
#[cfg(test)]
mod scan_tests;
#[cfg(test)]
mod tests;
mod verified_record;

pub(super) use framed_append::{FramedAppendStream, TRANSFER_BUFFER_BYTES};
#[cfg(test)]
pub(super) use indexed::{last_batch_spans, reset_last_batch_spans};
pub(super) use indexed::{
    read_indexed_object, read_indexed_object_with_payload, read_indexed_objects,
    visit_indexed_objects,
};
#[cfg(test)]
pub(super) use location::scan_frames_prefix_with_source;
pub(super) use location::{
    DurableFrameRange, DurablePrefixEnd, FrameLocation, read_frame_in_range,
    scan_frames_range_with_source, scan_frames_with_source,
};
pub(super) use positioned::read_frame_at;
pub(super) use prepared::{PreparedFrame, append_prepared_frames};
use reader::SliceReader;
#[cfg(test)]
pub(super) use scan::scan_frames_prefix;
use scan::{FrameScanBound, read_frame_preserving_cursor_within, scan_frames_with_bound};
pub(super) use scan::{scan_frames, scan_frames_range, scan_frames_with_protected_prefix};

pub(super) fn verify_indexed_location<F: DurableIo>(
    arena: &mut F,
    expected_id: ObjectId,
    location: ArenaLocation,
    scheme: IdentityScheme,
    limits: RecoveryLimits,
) -> Result<(), DurableError> {
    let file_len = arena
        .durable_metadata()
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

pub(super) fn verify_indexed_tail<F: DurableIo>(
    arena: &mut F,
    location: ArenaLocation,
    limits: RecoveryLimits,
) -> Result<(), DurableError> {
    let frame = read_frame_at(arena, ARENA_FILE, ARENA_MAGIC, location.offset, limits)?;
    let payload_len =
        u64::try_from(frame.payload().len()).map_err(|_| DurableError::EncodingOverflow)?;
    if payload_len != location.payload_len || frame.checksum() != location.checksum {
        return Err(corrupt(
            ARENA_FILE,
            location.offset,
            "indexed arena tail no longer matches the cache",
        ));
    }
    Ok(())
}

fn validate_positioned_header(
    file_name: &'static str,
    magic: [u8; 8],
    offset: u64,
    header: &[u8; FRAME_HEADER_LEN_USIZE],
    limits: RecoveryLimits,
) -> Result<DecodedFrameHeader, DurableError> {
    if header[..8] != magic {
        return Err(corrupt(file_name, offset, "frame magic mismatch"));
    }
    let decoded = decode_frame_header(file_name, offset, header)?;
    check_frame_payload_limit(file_name, offset, decoded.payload_len, limits)?;
    Ok(decoded)
}

fn check_frame_payload_limit(
    file: &'static str,
    offset: u64,
    declared: u64,
    limits: RecoveryLimits,
) -> Result<(), DurableError> {
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

fn validate_positioned_payload(
    file_name: &'static str,
    magic: [u8; 8],
    offset: u64,
    decoded: DecodedFrameHeader,
    payload: &[u8],
) -> Result<[u8; 32], DurableError> {
    if u64::try_from(payload.len()).map_err(|_| DurableError::EncodingOverflow)?
        != decoded.payload_len
    {
        return Err(corrupt(file_name, offset, "frame payload length mismatch"));
    }
    let actual = frame_checksum(magic, decoded.payload_len, payload);
    if actual != decoded.checksum {
        return Err(corrupt(file_name, offset, "frame checksum mismatch"));
    }
    Ok(actual)
}

fn read_exact_at<F: DurableIo>(file: &F, buffer: &mut [u8], offset: u64) -> io::Result<()> {
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

fn positioned_read<F: DurableIo>(file: &F, buffer: &mut [u8], offset: u64) -> io::Result<usize> {
    file.durable_read_at(buffer, offset)
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
        .map(File::native)
        .map_err(|source| io_error("open principal-store file", source))
}

pub(super) fn io_error(operation: &'static str, source: io::Error) -> DurableError {
    DurableError::Io { operation, source }
}

pub(super) fn recover_arena<I: PersistentObjectIdentity, F: DurableIo>(
    arena: &mut F,
    identity: &I,
    limits: RecoveryLimits,
    protected_len: u64,
) -> Result<(BTreeMap<ObjectId, ArenaLocation>, Option<ArenaLocation>), DurableError> {
    #[cfg(test)]
    RECOVERY_ARENA_SCANS.with(|scans| scans.set(scans.get().saturating_add(1)));
    let scheme = identity.scheme();
    let mut index = BTreeMap::<ObjectId, ArenaLocation>::new();
    let mut tail = None;
    scan_frames_with_protected_prefix(
        arena,
        ARENA_FILE,
        ARENA_MAGIC,
        limits,
        protected_len,
        |offset, payload, _source| {
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

#[cfg(test)]
pub(in crate::engine::durable) fn reset_recovery_arena_scans() {
    RECOVERY_ARENA_SCANS.with(|scans| scans.set(0));
}

#[cfg(test)]
pub(in crate::engine::durable) fn recovery_arena_scans() -> usize {
    RECOVERY_ARENA_SCANS.with(std::cell::Cell::get)
}

#[derive(Clone, Copy)]
struct DecodedFrameHeader {
    payload_len: u64,
    checksum: [u8; 32],
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

pub(super) fn append_frame<F: DurableIo>(
    file: &mut F,
    magic: [u8; 8],
    payload: &[u8],
) -> Result<ArenaLocation, DurableError> {
    let payload_len = u64::try_from(payload.len()).map_err(|_| DurableError::EncodingOverflow)?;
    let checksum = frame_checksum(magic, payload_len, payload);
    let offset = file
        .seek(SeekFrom::End(0))
        .map_err(|source| io_error("seek durable append", source))?;
    let header = frame_header(magic, payload_len, checksum);
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

pub(super) fn append_frames<T: AsRef<[u8]>, F: DurableIo>(
    file: &mut F,
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
        let header = frame_header(magic, payload_len, checksum);
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
    #[cfg(test)]
    FRAME_CHECKSUM_PASSES.with(|passes| passes.set(passes.get().strict_add(1)));
    let mut hasher = frame_checksum_hasher(magic, payload_len);
    hasher.update(payload);
    *hasher.finalize().as_bytes()
}

pub(super) fn frame_checksum_hasher(magic: [u8; 8], payload_len: u64) -> blake3::Hasher {
    // Only the immutable domain-derived initial state is shared. Every frame
    // still hashes its own complete header fields and payload independently.
    static INITIAL: std::sync::LazyLock<blake3::Hasher> = std::sync::LazyLock::new(|| {
        blake3::Hasher::new_derive_key("astrid durable physical frame checksum v1")
    });
    let mut hasher = INITIAL.clone();
    hasher.update(&magic);
    hasher.update(&FRAME_VERSION.to_le_bytes());
    hasher.update(&payload_len.to_le_bytes());
    hasher
}

pub(super) fn frame_header(
    magic: [u8; 8],
    payload_len: u64,
    checksum: [u8; 32],
) -> [u8; FRAME_HEADER_LEN_USIZE] {
    let mut header = [0_u8; FRAME_HEADER_LEN_USIZE];
    header[..8].copy_from_slice(&magic);
    header[8..10].copy_from_slice(&FRAME_VERSION.to_le_bytes());
    header[12..20].copy_from_slice(&payload_len.to_le_bytes());
    header[CHECKSUM_START..].copy_from_slice(&checksum);
    header
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
    verified_record::append_identity(bytes, scheme.into(), *id.as_bytes());
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
        verified_record::append_reference(
            &mut bytes,
            reference.label().as_bytes(),
            scheme.into(),
            *reference.target().as_bytes(),
            reference.kind(),
        )
        .map_err(|()| DurableError::EncodingOverflow)?;
    }
    Ok(bytes)
}

/// Check the fixed identity prefix of a canonical object frame without
/// decoding or allocating its record body.
pub(super) fn object_frame_declares_identity(
    frame_payload: &[u8],
    scheme: IdentityScheme,
    id: ObjectId,
) -> bool {
    const IDENTITY_BYTES: usize = IDENTITY_PREFIX_BYTES + CURRENT_DIGEST_BYTES_USIZE;
    frame_payload.len() >= IDENTITY_BYTES
        && frame_payload[..2] == scheme.algorithm().to_le_bytes()
        && frame_payload[2..4] == scheme.construction().to_le_bytes()
        && frame_payload[4..8] == CURRENT_DIGEST_BYTES.to_le_bytes()
        && frame_payload[8..IDENTITY_BYTES] == *id.as_bytes()
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
    verified_record::decode(bytes, scheme.into(), |input, start| {
        decode_record_body(input, start, scheme)
    })
    .map(|(id, record)| (ObjectId::new(id), record))
    .map_err(decode_error_detail)
}

fn decode_error_detail(error: verified_record::DecodeError<&'static str>) -> &'static str {
    match error {
        verified_record::DecodeError::Tag(e) => e.detail(),
        verified_record::DecodeError::Record(detail) => detail,
    }
}

fn decode_record_body(
    bytes: &[u8],
    start: usize,
    scheme: IdentityScheme,
) -> Result<ObjectRecord, &'static str> {
    let mut reader = SliceReader::new(bytes);
    reader.offset = start;
    let kind = ObjectKind::from_code(reader.u16()?).ok_or("unknown object-kind code")?;
    let version =
        ObjectFormatVersion::new(reader.u16()?).ok_or("object-format version must be non-zero")?;
    let class = ObjectClass::from_code(reader.u8()?).ok_or("unknown object-class code")?;
    let logical_bytes = reader.u64()?;
    let canonical_len = reader.usize_len()?;
    let reference_count = reader.usize_len()?;
    let canonical_bytes = reader.take(canonical_len)?.to_vec();
    // Empty records have no reference bytes to decode. Avoid an out-of-line
    // decoder call while keeping the trailing-byte and record checks below.
    let references = if reference_count == 0 {
        Vec::new()
    } else {
        decode_references(&mut reader, scheme, reference_count)?
    };
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
    Ok(record)
}

fn decode_references(
    reader: &mut SliceReader<'_>,
    scheme: IdentityScheme,
    count: usize,
) -> Result<Vec<ObjectReference>, &'static str> {
    if count > reader.remaining() / MIN_REFERENCE_WIRE_BYTES {
        return Err("reference count exceeds frame capacity");
    }
    let mut references = Vec::new();
    // The complete count is known: growth slack would live as long as the
    // immutable decoded record, including while retained in the object cache.
    references
        .try_reserve_exact(count)
        .map_err(|_| "reference allocation failed")?;
    reader.references(scheme, count, references)
}
