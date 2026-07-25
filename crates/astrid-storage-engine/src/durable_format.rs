//! Native arena and root-journal framing, parsing, and recovery.

use super::{
    ARENA_FILE, ARENA_MAGIC, ArenaLocation, BTreeMap, BTreeSet, CHECKSUM_START, DurableError,
    FRAME_HEADER_LEN, FRAME_HEADER_LEN_USIZE, FRAME_VERSION, File, ModelError, ObjectClass,
    ObjectFormatVersion, ObjectId, ObjectIdentity, ObjectKind, ObjectRecord, ObjectReference,
    OpenOptions, Path, PrincipalCodec, ROOT_FILE, ROOT_MAGIC, Read, RecoveryLimits, ReferenceKind,
    RootState, Seek, SeekFrom, Write, io, materialize_closure, recovery_closure_error,
    validate_commit_closure,
};
pub(super) fn read_indexed_object(
    arena: &mut File,
    expected_id: ObjectId,
    location: ArenaLocation,
    limits: RecoveryLimits,
) -> Result<ObjectRecord, DurableError> {
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
    let (id, record) = decode_object_frame(&payload)
        .map_err(|detail| corrupt(ARENA_FILE, location.offset, detail))?;
    if id != expected_id {
        return Err(corrupt(
            ARENA_FILE,
            location.offset,
            "indexed object identifier mismatch",
        ));
    }
    Ok(record)
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

pub(super) fn recover_arena<I: ObjectIdentity>(
    arena: &mut File,
    identity: &I,
    limits: RecoveryLimits,
) -> Result<BTreeMap<ObjectId, ArenaLocation>, DurableError> {
    let mut index = BTreeMap::<ObjectId, ArenaLocation>::new();
    scan_frames(arena, ARENA_FILE, ARENA_MAGIC, limits, |offset, payload| {
        let (id, record) =
            decode_object_frame(payload).map_err(|detail| corrupt(ARENA_FILE, offset, detail))?;
        let computed = identity.identify(&record);
        if computed != id {
            return Err(corrupt(ARENA_FILE, offset, "object identity mismatch"));
        }
        if encode_object_frame(id, &record)? != payload {
            return Err(corrupt(ARENA_FILE, offset, "object frame is not canonical"));
        }
        let payload_len =
            u64::try_from(payload.len()).map_err(|_| DurableError::EncodingOverflow)?;
        let checksum = frame_checksum(ARENA_MAGIC, payload_len, payload);
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
                index.insert(
                    id,
                    ArenaLocation {
                        offset,
                        payload_len,
                        checksum,
                    },
                );
            },
        }
        Ok(())
    })?;
    Ok(index)
}

pub(super) fn recover_roots<P, C>(
    roots: &mut File,
    arena: &mut File,
    index: &BTreeMap<ObjectId, ArenaLocation>,
    codec: &C,
    limits: RecoveryLimits,
) -> Result<(BTreeMap<P, RootState>, BTreeSet<ObjectId>), DurableError>
where
    P: Clone + Ord,
    C: PrincipalCodec<P>,
{
    let mut recovered = BTreeMap::<P, (RootState, u64)>::new();
    scan_frames(roots, ROOT_FILE, ROOT_MAGIC, limits, |offset, payload| {
        let record =
            decode_root_record(payload).map_err(|detail| corrupt(ROOT_FILE, offset, detail))?;
        let principal = codec
            .decode(record.principal)
            .ok_or(DurableError::InvalidPrincipal { offset })?;
        if codec.encode(&principal) != record.principal {
            return Err(DurableError::InvalidPrincipal { offset });
        }
        if encode_root_record(record.principal, record.expected, record.replacement)? != payload {
            return Err(corrupt(
                ROOT_FILE,
                offset,
                "root-journal frame is not canonical",
            ));
        }
        let actual = recovered.get(&principal).map(|(root, _)| *root);
        if actual != record.expected {
            return Err(DurableError::RecoveryModel {
                file: ROOT_FILE,
                offset,
                source: ModelError::RootConflict {
                    expected: record.expected,
                    actual,
                },
            });
        }
        let generation = match actual {
            Some(root) => root.generation.checked_add(1),
            None => Some(0),
        }
        .ok_or(DurableError::RecoveryModel {
            file: ROOT_FILE,
            offset,
            source: ModelError::ArithmeticOverflow,
        })?;
        if record.replacement.generation != generation {
            return Err(corrupt(
                ROOT_FILE,
                offset,
                "replacement generation does not match journal history",
            ));
        }
        recovered.insert(principal, (record.replacement, offset));
        Ok(())
    })?;

    let mut validated = BTreeSet::new();
    for (root, offset) in recovered.values().copied() {
        let records = materialize_closure(arena, index, &BTreeMap::new(), root.commit, limits)
            .map_err(|error| recovery_closure_error(error, offset))?;
        validate_commit_closure(&records, root.commit).map_err(|source| {
            DurableError::RecoveryModel {
                file: ROOT_FILE,
                offset,
                source,
            }
        })?;
        validated.extend(records.into_iter().map(|(id, _)| id));
    }
    Ok((
        recovered
            .into_iter()
            .map(|(principal, (root, _))| (principal, root))
            .collect(),
        validated,
    ))
}

fn scan_frames(
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
            return Err(corrupt(file_name, offset, "frame checksum mismatch"));
        }
        accept(offset, &payload)?;
        offset = frame_end;
    }
    file.seek(SeekFrom::End(0))
        .map_err(|source| io_error("seek durable file tail", source))?;
    Ok(())
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

pub(super) fn encode_object_frame(
    id: ObjectId,
    record: &ObjectRecord,
) -> Result<Vec<u8>, DurableError> {
    let canonical_len = u64::try_from(record.canonical_bytes().len())
        .map_err(|_| DurableError::EncodingOverflow)?;
    let reference_count =
        u64::try_from(record.references().len()).map_err(|_| DurableError::EncodingOverflow)?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(id.as_bytes());
    bytes.extend_from_slice(&record.kind().code().to_le_bytes());
    bytes.extend_from_slice(&record.format_version().get().to_le_bytes());
    bytes.push(record.class().code());
    bytes.extend_from_slice(&record.logical_bytes().to_le_bytes());
    bytes.extend_from_slice(&canonical_len.to_le_bytes());
    bytes.extend_from_slice(&reference_count.to_le_bytes());
    bytes.extend_from_slice(record.canonical_bytes());
    for reference in record.references() {
        let label_len =
            u64::try_from(reference.label().len()).map_err(|_| DurableError::EncodingOverflow)?;
        bytes.extend_from_slice(&label_len.to_le_bytes());
        bytes.extend_from_slice(reference.label());
        bytes.extend_from_slice(reference.target().as_bytes());
        bytes.push(reference.kind().code());
    }
    Ok(bytes)
}

pub(super) fn decode_object_frame(bytes: &[u8]) -> Result<(ObjectId, ObjectRecord), &'static str> {
    let mut reader = SliceReader::new(bytes);
    let id = ObjectId::new(reader.array_32()?);
    let kind = ObjectKind::from_code(reader.u16()?).ok_or("unknown object-kind code")?;
    let version = ObjectFormatVersion::new(reader.u16()?);
    let class = ObjectClass::from_code(reader.u8()?).ok_or("unknown object-class code")?;
    let logical_bytes = reader.u64()?;
    let canonical_len = reader.usize_len()?;
    let reference_count = reader.usize_len()?;
    let canonical_bytes = reader.take(canonical_len)?.to_vec();
    if reference_count > reader.remaining() / 41 {
        return Err("reference count exceeds frame capacity");
    }
    let mut references = Vec::new();
    references
        .try_reserve(reference_count)
        .map_err(|_| "reference allocation failed")?;
    for _ in 0..reference_count {
        let label_len = reader.usize_len()?;
        let label = reader.take(label_len)?.to_vec();
        let target = ObjectId::new(reader.array_32()?);
        let reference_kind =
            ReferenceKind::from_code(reader.u8()?).ok_or("unknown reference-kind code")?;
        references.push(ObjectReference::new(label, target, reference_kind));
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

pub(super) fn encode_root_record(
    principal: &[u8],
    expected: Option<RootState>,
    replacement: RootState,
) -> Result<Vec<u8>, DurableError> {
    let principal_len =
        u64::try_from(principal.len()).map_err(|_| DurableError::EncodingOverflow)?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&principal_len.to_le_bytes());
    bytes.extend_from_slice(principal);
    match expected {
        None => bytes.push(0),
        Some(root) => {
            bytes.push(1);
            encode_root_state(&mut bytes, root);
        },
    }
    encode_root_state(&mut bytes, replacement);
    Ok(bytes)
}

fn encode_root_state(bytes: &mut Vec<u8>, root: RootState) {
    bytes.extend_from_slice(&root.generation.to_le_bytes());
    bytes.extend_from_slice(root.commit.as_bytes());
}

struct DecodedRootRecord<'a> {
    principal: &'a [u8],
    expected: Option<RootState>,
    replacement: RootState,
}

fn decode_root_record(bytes: &[u8]) -> Result<DecodedRootRecord<'_>, &'static str> {
    let mut reader = SliceReader::new(bytes);
    let principal_len = reader.usize_len()?;
    let principal = reader.take(principal_len)?;
    let expected = match reader.u8()? {
        0 => None,
        1 => Some(reader.root_state()?),
        _ => return Err("invalid expected-root tag"),
    };
    let replacement = reader.root_state()?;
    if reader.remaining() != 0 {
        return Err("trailing root-journal bytes");
    }
    Ok(DecodedRootRecord {
        principal,
        expected,
        replacement,
    })
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

    fn array_32(&mut self) -> Result<[u8; 32], &'static str> {
        self.take(32)?
            .try_into()
            .map_err(|_| "truncated 32-byte field")
    }

    fn root_state(&mut self) -> Result<RootState, &'static str> {
        Ok(RootState {
            generation: self.u64()?,
            commit: ObjectId::new(self.array_32()?),
        })
    }
}
