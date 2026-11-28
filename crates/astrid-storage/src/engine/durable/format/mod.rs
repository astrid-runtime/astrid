//! Native arena and root-journal framing, parsing, and recovery.

use super::{
    ARENA_FILE, ARENA_MAGIC, ArenaLocation, BTreeMap, DurableError, DurableIo, FRAME_HEADER_LEN,
    FRAME_HEADER_LEN_USIZE, FRAME_VERSION, IdentityScheme, ModelError, ObjectClass,
    ObjectFormatVersion, ObjectId, ObjectKind, ObjectRecord, ObjectReference,
    PersistentObjectIdentity, RecoveryLimits, ReferenceKind, ReferenceLabel, SeekFrom, io,
    root_wire,
};
#[cfg(test)]
use super::{CHECKSUM_START, File};
#[cfg(test)]
use std::fs::OpenOptions;
#[cfg(test)]
use std::path::Path;

const IDENTITY_PREFIX_BYTES: usize = 8;
const CURRENT_DIGEST_BYTES: u32 = 32;
const CURRENT_DIGEST_BYTES_USIZE: usize = 32;

#[cfg(test)]
thread_local! {
    pub(super) static FRAME_CHECKSUM_PASSES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static RECOVERY_ARENA_SCANS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

mod arena_span;
mod checkpoint_reader;
mod duplicates;
const _: () = assert!(arena_span::HEADER_BYTES == FRAME_HEADER_LEN_USIZE);

mod framed_append;
mod indexed;
mod location;
mod positional_read;
mod positioned;
#[cfg(test)]
mod positioned_tests;
mod prepared;
mod reader;
mod recovered_record;
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
pub(super) use prepared::append_prepared_frames;
#[cfg(test)]
use reader::SliceReader;
#[cfg(test)]
pub(super) use scan::scan_frames_prefix;
use scan::{FrameScanBound, read_frame_preserving_cursor_within, scan_frames_with_bound};
pub(super) use scan::{scan_frames, scan_frames_range, scan_frames_with_protected_prefix};

struct CopyReader<'a, F>(&'a mut F, RecoveryLimits);

impl<F: DurableIo> duplicates::Media for CopyReader<'_, F> {
    fn bounded(&mut self, at: u64, end: u64) -> Option<Vec<u8>> {
        read_frame_preserving_cursor_within(self.0, ARENA_FILE, ARENA_MAGIC, at, self.1, end).ok()
    }
}

pub(in crate::engine::durable) fn duplicate_range(
    arena: &mut impl DurableIo,
    map: &BTreeMap<ObjectId, ArenaLocation>,
    scheme: IdentityScheme,
    limits: RecoveryLimits,
    at: u64,
    end: u64,
) -> bool {
    duplicates::check(&mut CopyReader(arena, limits), map, scheme.into(), at, end)
}

struct CheckpointInput<'a, F>(&'a mut F);

impl<F: DurableIo> checkpoint_reader::Input for CheckpointInput<'_, F> {
    type Error = io::Error;

    fn length(&self) -> io::Result<u64> {
        self.0.durable_metadata().map(|metadata| metadata.len())
    }

    fn seek(&mut self, at: u64) -> io::Result<()> {
        self.0.seek(SeekFrom::Start(at)).map(|_| ())
    }

    fn read<const N: usize>(&mut self) -> io::Result<[u8; N]> {
        let mut field = [0; N];
        self.0.read_exact(&mut field)?;
        Ok(field)
    }
}

pub(super) fn verify_indexed_location<F: DurableIo>(
    arena: &mut F,
    expected_id: ObjectId,
    location: ArenaLocation,
    scheme: IdentityScheme,
    limits: RecoveryLimits,
) -> Result<(), DurableError> {
    use checkpoint_reader::Error;
    checkpoint_reader::check(
        &mut CheckpointInput(arena),
        ARENA_MAGIC,
        FRAME_VERSION,
        location,
        scheme.into(),
        expected_id,
        limits.max_frame_bytes,
    )
    .map_err(|error| match error {
        Error::Length(e) => io_error("read indexed arena metadata", e),
        Error::Seek(e) => io_error("seek indexed arena header", e),
        Error::HeaderRead(e) => io_error("read indexed arena header", e),
        Error::IdentityRead(e) => io_error("read indexed object identity", e),
        Error::Overflow => DurableError::EncodingOverflow,
        Error::Extent => corrupt(
            ARENA_FILE,
            location.offset,
            "indexed frame extends beyond the arena",
        ),
        Error::Header => corrupt(
            ARENA_FILE,
            location.offset,
            "indexed frame header is invalid",
        ),
        Error::Limit(declared) => DurableError::FrameTooLarge {
            file: ARENA_FILE,
            offset: location.offset,
            declared,
            limit: limits.max_frame_bytes,
        },
        Error::Placement => corrupt(
            ARENA_FILE,
            location.offset,
            "indexed frame header does not match the cache",
        ),
        Error::Short => corrupt(
            ARENA_FILE,
            location.offset,
            "indexed frame payload is shorter than its object identity",
        ),
        Error::Tag(e) => corrupt(ARENA_FILE, location.offset, e.detail()),
        Error::Name => corrupt(
            ARENA_FILE,
            location.offset,
            "indexed object identity mismatch",
        ),
    })
}

pub(super) fn verify_indexed_tail<F: DurableIo>(
    arena: &mut F,
    location: ArenaLocation,
    limits: RecoveryLimits,
) -> Result<(), DurableError> {
    arena_span::at_location(
        location.offset,
        location.payload_len,
        location.checksum,
        |at| {
            let frame = read_frame_at(arena, ARENA_FILE, ARENA_MAGIC, at, limits)?;
            let sum = frame.checksum();
            Ok((frame.into_payload(), sum))
        },
    )
    .map(|_| ())
    .map_err(|error| match error {
        arena_span::IndexedError::Read(error) => error,
        arena_span::IndexedError::Placement => corrupt(
            ARENA_FILE,
            location.offset,
            "indexed arena tail no longer matches the cache",
        ),
    })
}

fn validate_positioned_header(
    file_name: &'static str,
    magic: [u8; 8],
    offset: u64,
    header: &[u8; FRAME_HEADER_LEN_USIZE],
    limits: RecoveryLimits,
) -> Result<DecodedFrameHeader, DurableError> {
    if !arena_frame::magic_matches(header, magic) {
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
    arena_frame::check_payload(decoded, magic, payload, frame_checksum).map_err(|error| match error
    {
        arena_frame::PayloadError::Length => {
            corrupt(file_name, offset, "frame payload length mismatch")
        },
        arena_frame::PayloadError::Checksum => {
            corrupt(file_name, offset, "frame checksum mismatch")
        },
    })
}

impl<F: DurableIo> positional_read::Media for F {
    type Error = io::Error;

    fn read_at(&self, offset: u64, buffer: &mut [u8]) -> io::Result<usize> {
        self.durable_read_at(buffer, offset)
    }
}

fn read_exact_at<F: DurableIo>(file: &F, buffer: &mut [u8], offset: u64) -> io::Result<()> {
    positional_read::exact(file, offset, buffer).map_err(|error| match error {
        positional_read::Error::Offset => io::Error::other("positional read offset overflow"),
        positional_read::Error::Length => io::Error::other("positional read length overflow"),
        positional_read::Error::Short => io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "positional read reached end of file",
        ),
        positional_read::Error::Io(error) => error,
    })
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
            use recovered_record::{Error, IndexError};
            let location = recovered_record::index(
                &mut index,
                offset,
                payload,
                scheme.into(),
                |r| identity.identify(r),
                |length, bytes| frame_checksum(ARENA_MAGIC, length, bytes),
            )
            .map_err(|error| match error {
                IndexError::Record(Error::Decode(e)) => {
                    corrupt(ARENA_FILE, offset, body_error_detail(e))
                },
                IndexError::Record(Error::Identity) => {
                    corrupt(ARENA_FILE, offset, "object identity mismatch")
                },
                IndexError::Record(Error::Overflow) => DurableError::EncodingOverflow,
                IndexError::Record(Error::Canonical) => {
                    corrupt(ARENA_FILE, offset, "object frame is not canonical")
                },
                IndexError::Collision(id) => DurableError::RecoveryModel {
                    file: ARENA_FILE,
                    offset,
                    source: ModelError::ObjectCollision(id),
                },
            })?;
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

use super::arena_frame::{self, DecodedFrameHeader};

fn decode_frame_header(
    file_name: &'static str,
    offset: u64,
    header: &[u8; FRAME_HEADER_LEN_USIZE],
) -> Result<DecodedFrameHeader, DurableError> {
    arena_frame::decode_header(header, FRAME_VERSION).map_err(|error| match error {
        arena_frame::HeaderError::Version => {
            corrupt(file_name, offset, "unsupported frame version")
        },
        arena_frame::HeaderError::Reserved => {
            corrupt(file_name, offset, "reserved header bytes are non-zero")
        },
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
    super::arena_frame::header(magic, FRAME_VERSION, payload_len, checksum)
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

pub(super) fn encode_identity(bytes: &mut Vec<u8>, scheme: IdentityScheme, id: ObjectId) {
    verified_record::append_identity(bytes, scheme.into(), *id.as_bytes());
}

pub(super) fn encode_object_frame(
    scheme: IdentityScheme,
    id: ObjectId,
    record: &ObjectRecord,
) -> Result<Vec<u8>, DurableError> {
    verified_record::encode(scheme.into(), id, record).map_err(|()| DurableError::EncodingOverflow)
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
    verified_record::canonical_suffix(frame_payload, scheme.into())
        .map_err(|error| corrupt(ARENA_FILE, 0, error.detail()))
}

pub(super) fn decode_object_frame(
    bytes: &[u8],
    scheme: IdentityScheme,
) -> Result<(ObjectId, ObjectRecord), &'static str> {
    recovered_record::unpack(bytes, scheme.into()).map_err(body_error_detail)
}

/// Decode a published frame only if both its wire name and computed identity match the commit.
pub(super) fn published_record<I: PersistentObjectIdentity>(
    payload: &[u8],
    expected: ObjectId,
    identity: &I,
) -> Option<ObjectRecord> {
    verified_record::confirmed(payload, identity.scheme().into(), expected, |record| {
        *identity.identify(record).as_bytes()
    })
    .ok()
}

/// Confirm a prepared WAL frame before retaining its immutable payload and record.
pub(super) fn pending_object_frame<I: PersistentObjectIdentity>(
    frame: &std::sync::Arc<[u8]>,
    id: ObjectId,
    identity: &I,
) -> Result<verified_record::PendingFrame<ObjectRecord>, DurableError> {
    let scheme = identity.scheme();
    verified_record::pending(frame, scheme.into(), id, |record| {
        *identity.identify(record).as_bytes()
    })
    .map_err(|error| {
        corrupt(
            super::WAL_FILE,
            0,
            match error {
                verified_record::Error::Decode(error) => body_error_detail(error),
                verified_record::Error::Identifier | verified_record::Error::Identity => {
                    "WAL overlay object identity mismatch"
                },
            },
        )
    })
}

fn body_error_detail(
    error: verified_record::DecodeError<verified_record::BodyError>,
) -> &'static str {
    match error {
        verified_record::DecodeError::Tag(e) => e.detail(),
        verified_record::DecodeError::Record(e) => e.detail(),
    }
}

#[cfg(test)]
fn decode_references(
    reader: &mut SliceReader<'_>,
    scheme: IdentityScheme,
    count: usize,
) -> Result<Vec<ObjectReference>, &'static str> {
    reader.references(scheme, count)
}
