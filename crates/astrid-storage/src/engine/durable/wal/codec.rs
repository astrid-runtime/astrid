use super::super::format::{decode_object_frame, encode_object_frame, frame_checksum};
use super::super::roots::encode_root_record;
use super::super::{IdentityScheme, PersistentObjectIdentity, PrincipalCodec};
use crate::storage_model::{ObjectId, ObjectRecord, RootGeneration, RootState};
use std::borrow::Cow;

use super::types::{
    WalBeginHints, WalCount, WalDigest, WalError, WalLength, WalLimits, WalOrdinal,
    WalPhysicalLimit, WalRecordKind, WalRootTransition, WalSequence,
};

/// ASTWAL2 physical magic.
pub(super) const WAL_MAGIC: [u8; 8] = *b"ASTWAL2\0";
/// Physical header width shared by every ASTWAL2 record.
pub(super) const PHYSICAL_HEADER_LEN: usize = 52;
/// Logical record header width inside each physical payload.
pub(super) const RECORD_HEADER_LEN: usize = 20;
const LEGACY_VERSION: u16 = 1;
const COMPRESSED_OBJECT_VERSION: u16 = 2;
const BEGIN_FIXED_LEN: usize = 8;
const COMMIT_BODY_LEN: usize = 8 + 8 + 8 + 8 + 8 + 32;
const DIGEST_DOMAIN: &str = "astrid durable transaction wal v2";
pub(super) const OBJECT_FLAG_LZ4: u8 = 1;
const COMPRESSED_OBJECT_LENGTH_LEN: usize = 8;

/// Derive the physical WAL payload bound from the canonical frame bound.
pub(super) fn wal_physical_limit(limits: WalLimits) -> WalPhysicalLimit {
    WalPhysicalLimit::from_canonical(limits.max_frame_bytes(), RECORD_HEADER_LEN)
}

/// Enforce the canonical arena/root bound after removing the WAL record
/// header.  This keeps decoded logical bodies within the same allocation
/// contract as native durable frames.
pub(super) fn validate_logical_body(
    body: &[u8],
    limits: WalLimits,
    offset: super::types::WalOffset,
) -> Result<WalLength, WalError> {
    let declared = WalLength::new(
        u64::try_from(body.len()).map_err(|_| WalError::Encoding("WAL body length overflow"))?,
    );
    let limit = WalLength::new(limits.max_frame_bytes());
    if declared > limit {
        return Err(WalError::FrameTooLarge {
            offset,
            declared,
            limit,
        });
    }
    Ok(declared)
}

/// Parsed physical header fields.
#[derive(Clone, Copy)]
pub(super) struct PhysicalHeader {
    pub(super) version: u16,
    pub(super) payload_len: WalLength,
    pub(super) checksum: [u8; 32],
}

/// Parsed logical record header fields.
#[derive(Clone, Copy)]
pub(super) struct RecordHeader {
    pub(super) kind: WalRecordKind,
    pub(super) flags: u8,
    pub(super) sequence: WalSequence,
    pub(super) ordinal: WalOrdinal,
}

/// Encode one bounded physical record. The caller supplies one record body,
/// so allocation is proportional to that record rather than its transaction.
pub(super) fn encode_physical_record(
    kind: WalRecordKind,
    sequence: WalSequence,
    ordinal: WalOrdinal,
    body: &[u8],
    limits: WalLimits,
) -> Result<Vec<u8>, WalError> {
    encode_physical_record_with_flags(kind, 0, sequence, ordinal, body, limits)
}

pub(super) fn encode_physical_record_with_flags(
    kind: WalRecordKind,
    flags: u8,
    sequence: WalSequence,
    ordinal: WalOrdinal,
    body: &[u8],
    limits: WalLimits,
) -> Result<Vec<u8>, WalError> {
    validate_logical_body(body, limits, super::types::WalOffset::new(0))?;
    let record_len = u64::try_from(RECORD_HEADER_LEN)
        .ok()
        .and_then(|header| header.checked_add(u64::try_from(body.len()).ok()?))
        .ok_or(WalError::Encoding("WAL record length overflow"))?;
    let payload_len = WalLength::new(record_len);
    let limit = wal_physical_limit(limits).length();
    if payload_len > limit {
        return Err(WalError::FrameTooLarge {
            offset: super::types::WalOffset::new(0),
            declared: payload_len,
            limit,
        });
    }
    let payload_len_usize = payload_len.as_usize()?;
    let total_len = PHYSICAL_HEADER_LEN
        .checked_add(payload_len_usize)
        .ok_or(WalError::Encoding("WAL physical length overflow"))?;
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(total_len)
        .map_err(|_| WalError::Encoding("WAL physical allocation failed"))?;
    encoded.extend_from_slice(&WAL_MAGIC);
    let version = if flags == 0 {
        LEGACY_VERSION
    } else {
        COMPRESSED_OBJECT_VERSION
    };
    encoded.extend_from_slice(&version.to_le_bytes());
    encoded.extend_from_slice(&0_u16.to_le_bytes());
    encoded.extend_from_slice(&payload_len.get().to_le_bytes());
    encoded.extend_from_slice(&[0_u8; 32]);
    let mut record_header = [0_u8; RECORD_HEADER_LEN];
    write_record_header(&mut record_header, kind, flags, sequence, ordinal);
    encoded.extend_from_slice(&record_header);
    encoded.extend_from_slice(body);
    let checksum = frame_checksum(
        WAL_MAGIC,
        payload_len.get(),
        &encoded[PHYSICAL_HEADER_LEN..],
    );
    encoded[20..PHYSICAL_HEADER_LEN].copy_from_slice(&checksum);
    Ok(encoded)
}

/// Parse and validate a physical header without allocating its payload.
pub(super) fn decode_physical_header(
    header: &[u8; PHYSICAL_HEADER_LEN],
    offset: super::types::WalOffset,
) -> Result<PhysicalHeader, WalError> {
    let version = u16::from_le_bytes([header[8], header[9]]);
    if header[..8] != WAL_MAGIC
        || !matches!(version, LEGACY_VERSION | COMPRESSED_OBJECT_VERSION)
        || header[10..12] != [0, 0]
    {
        return Err(WalError::Corrupt {
            offset,
            detail: "WAL physical header is invalid",
        });
    }
    let payload_len =
        u64::from_le_bytes(header[12..20].try_into().map_err(|_| WalError::Corrupt {
            offset,
            detail: "WAL physical length is truncated",
        })?);
    let checksum = header[20..].try_into().map_err(|_| WalError::Corrupt {
        offset,
        detail: "WAL checksum is truncated",
    })?;
    Ok(PhysicalHeader {
        version,
        payload_len: WalLength::new(payload_len),
        checksum,
    })
}

/// Ensure record features are paired with the physical version that defines
/// them. Version one remains byte-for-byte readable for flags-zero WALs;
/// compressed Object records are explicitly version two and are therefore a
/// forward-only transient WAL extension for older binaries.
pub(super) fn validate_record_version(
    physical: PhysicalHeader,
    record: RecordHeader,
    offset: super::types::WalOffset,
) -> Result<(), WalError> {
    let valid = match physical.version {
        LEGACY_VERSION => record.flags == 0,
        COMPRESSED_OBJECT_VERSION => {
            record.kind == WalRecordKind::Object && record.flags == OBJECT_FLAG_LZ4
        },
        _ => false,
    };
    if !valid {
        return Err(WalError::Corrupt {
            offset,
            detail: "WAL record features do not match its physical version",
        });
    }
    Ok(())
}

/// Verify a payload checksum.
pub(super) fn checksum_valid(header: PhysicalHeader, payload: &[u8]) -> bool {
    frame_checksum(WAL_MAGIC, header.payload_len.get(), payload) == header.checksum
}

/// Parse the logical record header.
pub(super) fn decode_record_header(
    payload: &[u8],
    offset: super::types::WalOffset,
) -> Result<RecordHeader, WalError> {
    if payload.len() < RECORD_HEADER_LEN {
        return Err(WalError::Corrupt {
            offset,
            detail: "WAL record header is truncated",
        });
    }
    let kind = WalRecordKind::from_tag(payload[0]).ok_or(WalError::Corrupt {
        offset,
        detail: "WAL record kind is unknown",
    })?;
    let flags = payload[1];
    if payload[2..4] != [0, 0]
        || (kind == WalRecordKind::Object && flags & !OBJECT_FLAG_LZ4 != 0)
        || (kind != WalRecordKind::Object && flags != 0)
    {
        return Err(WalError::Corrupt {
            offset,
            detail: "WAL record flags or reserved bytes are non-zero",
        });
    }
    let sequence = WalSequence::new(u64::from_le_bytes(payload[4..12].try_into().map_err(
        |_| WalError::Corrupt {
            offset,
            detail: "WAL record sequence is truncated",
        },
    )?))
    .ok_or(WalError::Corrupt {
        offset,
        detail: "WAL record sequence is zero",
    })?;
    let ordinal = WalOrdinal::new(u64::from_le_bytes(payload[12..20].try_into().map_err(
        |_| WalError::Corrupt {
            offset,
            detail: "WAL record ordinal is truncated",
        },
    )?));
    Ok(RecordHeader {
        kind,
        flags,
        sequence,
        ordinal,
    })
}

/// Return the body after a validated logical record header.
pub(super) fn record_body(
    payload: &[u8],
    offset: super::types::WalOffset,
) -> Result<&[u8], WalError> {
    payload.get(RECORD_HEADER_LEN..).ok_or(WalError::Corrupt {
        offset,
        detail: "WAL record body is truncated",
    })
}

/// Encode a Begin body with optional non-authoritative hints.
pub(super) fn encode_begin_body(
    scheme: IdentityScheme,
    hints: Option<WalBeginHints>,
) -> Result<Vec<u8>, WalError> {
    let mut bytes = Vec::new();
    let hint_bytes = if hints.is_some() { 24 } else { 0 };
    let capacity = BEGIN_FIXED_LEN
        .checked_add(hint_bytes)
        .ok_or(WalError::Encoding("WAL Begin length overflow"))?;
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| WalError::Encoding("WAL Begin allocation failed"))?;
    bytes.extend_from_slice(&scheme.algorithm().to_le_bytes());
    bytes.extend_from_slice(&scheme.construction().to_le_bytes());
    bytes.push(u8::from(hints.is_some()));
    bytes.extend_from_slice(&[0, 0, 0]);
    if let Some(hints) = hints {
        bytes.extend_from_slice(&hints.object_count().get().to_le_bytes());
        bytes.extend_from_slice(&hints.root_count().get().to_le_bytes());
        bytes.extend_from_slice(&hints.logical_bytes().get().to_le_bytes());
    }
    Ok(bytes)
}

/// Decode a Begin body; hint values are returned but never trusted.
pub(super) fn decode_begin_body(
    body: &[u8],
    offset: super::types::WalOffset,
) -> Result<(IdentityScheme, Option<WalBeginHints>), WalError> {
    if body.len() < BEGIN_FIXED_LEN || body[5..8] != [0, 0, 0] {
        return Err(WalError::Corrupt {
            offset,
            detail: "WAL Begin body is invalid",
        });
    }
    let scheme = IdentityScheme::new(
        u16::from_le_bytes([body[0], body[1]]),
        u16::from_le_bytes([body[2], body[3]]),
    )
    .ok_or(WalError::Corrupt {
        offset,
        detail: "WAL Begin identity scheme is invalid",
    })?;
    let hints = match body[4] {
        0 if body.len() == BEGIN_FIXED_LEN => None,
        1 if body.len() == BEGIN_FIXED_LEN + 24 => {
            let object_count = read_u64(&body[8..16], offset, "Begin object hint")?;
            let root_count = read_u64(&body[16..24], offset, "Begin root hint")?;
            let logical_bytes = read_u64(&body[24..32], offset, "Begin byte hint")?;
            Some(WalBeginHints::new(
                WalCount::new(object_count),
                WalCount::new(root_count),
                WalLength::new(logical_bytes),
            ))
        },
        _ => {
            return Err(WalError::Corrupt {
                offset,
                detail: "WAL Begin hint encoding is invalid",
            });
        },
    };
    Ok((scheme, hints))
}

/// Encode a Commit body.
pub(super) fn encode_commit_body(
    sequence: WalSequence,
    logical_count: WalCount,
    object_count: WalCount,
    root_count: WalCount,
    logical_bytes: WalLength,
    digest: WalDigest,
) -> [u8; COMMIT_BODY_LEN] {
    let mut body = [0_u8; COMMIT_BODY_LEN];
    body[..8].copy_from_slice(&sequence.get().to_le_bytes());
    body[8..16].copy_from_slice(&logical_count.get().to_le_bytes());
    body[16..24].copy_from_slice(&object_count.get().to_le_bytes());
    body[24..32].copy_from_slice(&root_count.get().to_le_bytes());
    body[32..40].copy_from_slice(&logical_bytes.get().to_le_bytes());
    body[40..].copy_from_slice(digest.as_bytes());
    body
}

/// Decode a Commit body.
pub(super) fn decode_commit_body(
    body: &[u8],
    offset: super::types::WalOffset,
) -> Result<
    (
        WalSequence,
        WalCount,
        WalCount,
        WalCount,
        WalLength,
        WalDigest,
    ),
    WalError,
> {
    if body.len() != COMMIT_BODY_LEN {
        return Err(WalError::Corrupt {
            offset,
            detail: "WAL Commit body length is invalid",
        });
    }
    let sequence = WalSequence::new(read_u64(&body[..8], offset, "Commit sequence")?).ok_or(
        WalError::Corrupt {
            offset,
            detail: "WAL Commit sequence is zero",
        },
    )?;
    let logical_count = WalCount::new(read_u64(&body[8..16], offset, "Commit logical count")?);
    let object_count = WalCount::new(read_u64(&body[16..24], offset, "Commit object count")?);
    let root_count = WalCount::new(read_u64(&body[24..32], offset, "Commit root count")?);
    let logical_bytes = WalLength::new(read_u64(&body[32..40], offset, "Commit byte count")?);
    let digest = body[40..]
        .try_into()
        .map(WalDigest::new)
        .map_err(|_| WalError::Corrupt {
            offset,
            detail: "WAL Commit digest is truncated",
        })?;
    Ok((
        sequence,
        logical_count,
        object_count,
        root_count,
        logical_bytes,
        digest,
    ))
}

/// Encode the caller-validated object frame.
pub(super) fn encode_object_body<I: PersistentObjectIdentity>(
    scheme: IdentityScheme,
    id: ObjectId,
    record: &ObjectRecord,
    identity: &I,
) -> Result<Vec<u8>, WalError> {
    if identity.scheme() != scheme || identity.identify(record) != id {
        return Err(WalError::ObjectIdentityMismatch { object: id });
    }
    encode_object_frame(scheme, id, record)
        .map_err(|_| WalError::Encoding("WAL object-frame encoding failed"))
}

/// Decode and structurally validate one object frame.
pub(super) fn decode_object_body<I: PersistentObjectIdentity>(
    body: &[u8],
    scheme: IdentityScheme,
    identity: &I,
    offset: super::types::WalOffset,
) -> Result<(ObjectId, WalLength), WalError> {
    if identity.scheme() != scheme {
        return Err(WalError::IdentitySchemeMismatch);
    }
    let (id, record) =
        decode_object_frame(body, scheme).map_err(|detail| WalError::Corrupt { offset, detail })?;
    let canonical = encode_object_frame(scheme, id, &record).map_err(|_| WalError::Corrupt {
        offset,
        detail: "WAL object canonical encoding failed",
    })?;
    if canonical.as_slice() != body {
        return Err(WalError::Corrupt {
            offset,
            detail: "WAL object frame is not canonical",
        });
    }
    if identity.identify(&record) != id {
        return Err(WalError::ObjectIdentityMismatch { object: id });
    }
    let length =
        u64::try_from(body.len()).map_err(|_| WalError::Encoding("WAL object length overflow"))?;
    Ok((id, WalLength::new(length)))
}

/// Select compression only when its explicit length prefix and compressed
/// bytes are strictly smaller than the canonical object frame.
pub(super) fn encode_object_storage_body(body: &[u8]) -> Result<(u8, Cow<'_, [u8]>), WalError> {
    let compressed = lz4_flex::block::compress(body);
    let stored_len = COMPRESSED_OBJECT_LENGTH_LEN
        .checked_add(compressed.len())
        .ok_or(WalError::Encoding("WAL compressed object length overflow"))?;
    if stored_len >= body.len() {
        return Ok((0, Cow::Borrowed(body)));
    }
    let mut stored = Vec::new();
    stored
        .try_reserve_exact(stored_len)
        .map_err(|_| WalError::Encoding("WAL compressed object allocation failed"))?;
    stored.extend_from_slice(
        &u64::try_from(body.len())
            .map_err(|_| WalError::Encoding("WAL object length overflow"))?
            .to_le_bytes(),
    );
    stored.extend_from_slice(&compressed);
    Ok((OBJECT_FLAG_LZ4, Cow::Owned(stored)))
}

/// Recover a canonical object frame with allocation bounded by the declared
/// uncompressed size and the engine recovery limit.
pub(super) fn decode_object_storage_body(
    body: &[u8],
    flags: u8,
    limits: WalLimits,
    offset: super::types::WalOffset,
) -> Result<Cow<'_, [u8]>, WalError> {
    if flags == 0 {
        validate_logical_body(body, limits, offset)?;
        return Ok(Cow::Borrowed(body));
    }
    if flags != OBJECT_FLAG_LZ4 || body.len() < COMPRESSED_OBJECT_LENGTH_LEN {
        return Err(WalError::Corrupt {
            offset,
            detail: "WAL compressed object body is invalid",
        });
    }
    let declared = WalLength::new(read_u64(
        &body[..COMPRESSED_OBJECT_LENGTH_LEN],
        offset,
        "WAL compressed object length is truncated",
    )?);
    let limit = WalLength::new(limits.max_frame_bytes());
    if declared > limit {
        return Err(WalError::FrameTooLarge {
            offset,
            declared,
            limit,
        });
    }
    let size = declared.as_usize()?;
    let mut decoded = Vec::new();
    decoded
        .try_reserve_exact(size)
        .map_err(|_| WalError::Encoding("WAL decompression allocation failed"))?;
    decoded.resize(size, 0);
    let written =
        lz4_flex::block::decompress_into(&body[COMPRESSED_OBJECT_LENGTH_LEN..], &mut decoded)
            .map_err(|_| WalError::Corrupt {
                offset,
                detail: "WAL compressed object payload is invalid",
            })?;
    if written != size {
        return Err(WalError::Corrupt {
            offset,
            detail: "WAL compressed object length does not match payload",
        });
    }
    Ok(Cow::Owned(decoded))
}

/// Encode a canonical root transition after codec round-trip validation.
pub(super) fn encode_root_body<P, C>(
    scheme: IdentityScheme,
    principal: &P,
    expected: Option<RootState>,
    replacement: RootState,
    codec: &C,
) -> Result<(Vec<u8>, Vec<u8>), WalError>
where
    C: PrincipalCodec<P>,
{
    validate_root_generation(expected, replacement)?;
    let bytes = codec.encode(principal);
    validate_principal(codec, &bytes)?;
    let payload = encode_root_record(scheme, &bytes, expected, replacement)
        .map_err(|_| WalError::Encoding("WAL root-record encoding failed"))?;
    Ok((bytes, payload))
}

/// Decode a canonical root transition and validate its principal codec.
pub(super) fn decode_root_body<P, C>(
    body: &[u8],
    scheme: IdentityScheme,
    codec: &C,
    offset: super::types::WalOffset,
) -> Result<(WalRootTransition, WalLength), WalError>
where
    C: PrincipalCodec<P>,
{
    let mut reader = BodyReader::new(body, offset);
    let principal_len = reader.u64()?;
    let principal_len = WalLength::new(principal_len).as_usize()?;
    let principal = reader.take(principal_len)?.to_vec();
    validate_principal(codec, &principal)?;
    let expected = match reader.u8()? {
        0 => None,
        1 => Some(reader.root_state(scheme)?),
        _ => {
            return Err(WalError::Corrupt {
                offset,
                detail: "WAL root expected tag is invalid",
            });
        },
    };
    let replacement = reader.root_state(scheme)?;
    if reader.remaining() != 0 {
        return Err(WalError::Corrupt {
            offset,
            detail: "WAL root record has trailing bytes",
        });
    }
    validate_root_generation(expected, replacement).map_err(|_| WalError::Corrupt {
        offset,
        detail: "WAL root generation transition is invalid",
    })?;
    let canonical =
        encode_root_record(scheme, &principal, expected, replacement).map_err(|_| {
            WalError::Corrupt {
                offset,
                detail: "WAL root canonical encoding failed",
            }
        })?;
    if canonical.as_slice() != body {
        return Err(WalError::Corrupt {
            offset,
            detail: "WAL root record is not canonical",
        });
    }
    let length =
        u64::try_from(body.len()).map_err(|_| WalError::Encoding("WAL root length overflow"))?;
    Ok((
        WalRootTransition::new(principal, expected, replacement),
        WalLength::new(length),
    ))
}

fn validate_root_generation(
    expected: Option<RootState>,
    replacement: RootState,
) -> Result<(), WalError> {
    match expected {
        None if replacement.generation == RootGeneration::INITIAL => Ok(()),
        Some(expected) if expected.generation.checked_next() == Some(replacement.generation) => {
            Ok(())
        },
        _ => Err(WalError::InvalidTransaction(
            "WAL root generation transition is invalid",
        )),
    }
}

fn validate_principal<P, C>(codec: &C, bytes: &[u8]) -> Result<(), WalError>
where
    C: PrincipalCodec<P>,
{
    let principal = codec.decode(bytes).ok_or(WalError::PrincipalMismatch)?;
    if codec.encode(&principal) != bytes {
        return Err(WalError::PrincipalMismatch);
    }
    Ok(())
}

/// Create the domain-separated logical-record digest state.
pub(super) fn new_digest() -> blake3::Hasher {
    blake3::Hasher::new_derive_key(DIGEST_DOMAIN)
}

/// Feed one canonical logical record into a digest.
pub(super) fn digest_record(
    hasher: &mut blake3::Hasher,
    kind: WalRecordKind,
    sequence: WalSequence,
    ordinal: WalOrdinal,
    body: &[u8],
) -> Result<(), WalError> {
    digest_record_with_flags(hasher, kind, 0, sequence, ordinal, body)
}

/// Feed a logical record with feature flags into a transaction digest.
///
/// Flags-zero records retain the original digest grammar exactly. A non-zero
/// flag uses an otherwise-invalid kind prefix so decoding semantics cannot be
/// changed without invalidating Commit.digest.
pub(super) fn digest_record_with_flags(
    hasher: &mut blake3::Hasher,
    kind: WalRecordKind,
    flags: u8,
    sequence: WalSequence,
    ordinal: WalOrdinal,
    body: &[u8],
) -> Result<(), WalError> {
    let body_len = u64::try_from(body.len())
        .map_err(|_| WalError::Encoding("WAL digest body length overflow"))?;
    if flags == 0 {
        hasher.update(&[kind.tag()]);
    } else {
        hasher.update(&[u8::MAX, kind.tag(), flags]);
    }
    hasher.update(&sequence.get().to_le_bytes());
    hasher.update(&ordinal.get().to_le_bytes());
    hasher.update(&body_len.to_le_bytes());
    hasher.update(body);
    Ok(())
}

/// Return the canonical logical record length used by Commit accounting.
pub(super) fn logical_record_length(body: &[u8]) -> Result<WalLength, WalError> {
    let body_length = WalLength::new(
        u64::try_from(body.len()).map_err(|_| WalError::Encoding("WAL logical length overflow"))?,
    );
    WalLength::new(
        u64::try_from(RECORD_HEADER_LEN)
            .map_err(|_| WalError::Encoding("WAL record header length overflow"))?,
    )
    .checked_add(body_length)
    .ok_or(WalError::CountOverflow {
        field: "logical bytes",
    })
}

/// Finalize a logical-record digest.
pub(super) fn finish_digest(hasher: &blake3::Hasher) -> WalDigest {
    WalDigest::new(*hasher.finalize().as_bytes())
}

fn write_record_header(
    destination: &mut [u8],
    kind: WalRecordKind,
    flags: u8,
    sequence: WalSequence,
    ordinal: WalOrdinal,
) {
    destination[0] = kind.tag();
    destination[1] = flags;
    destination[4..12].copy_from_slice(&sequence.get().to_le_bytes());
    destination[12..20].copy_from_slice(&ordinal.get().to_le_bytes());
}

fn read_u64(
    bytes: &[u8],
    offset: super::types::WalOffset,
    field: &'static str,
) -> Result<u64, WalError> {
    bytes
        .try_into()
        .map(u64::from_le_bytes)
        .map_err(|_| WalError::Corrupt {
            offset,
            detail: field,
        })
}

struct BodyReader<'a> {
    bytes: &'a [u8],
    offset: super::types::WalOffset,
    position: usize,
}

impl<'a> BodyReader<'a> {
    fn new(bytes: &'a [u8], offset: super::types::WalOffset) -> Self {
        Self {
            bytes,
            offset,
            position: 0,
        }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], WalError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(WalError::LengthOverflow {
                value: WalLength::new(length as u64),
            })?;
        let bytes = self
            .bytes
            .get(self.position..end)
            .ok_or(WalError::Corrupt {
                offset: self.offset,
                detail: "WAL root record is truncated",
            })?;
        self.position = end;
        Ok(bytes)
    }

    fn u8(&mut self) -> Result<u8, WalError> {
        self.take(1)?.first().copied().ok_or(WalError::Corrupt {
            offset: self.offset,
            detail: "WAL root byte is truncated",
        })
    }

    fn u64(&mut self) -> Result<u64, WalError> {
        self.take(8)?
            .try_into()
            .map(u64::from_le_bytes)
            .map_err(|_| WalError::Corrupt {
                offset: self.offset,
                detail: "WAL root integer is truncated",
            })
    }

    fn root_state(&mut self, scheme: IdentityScheme) -> Result<RootState, WalError> {
        Ok(RootState {
            generation: RootGeneration::new(self.u64()?),
            commit: self.identity(scheme)?,
        })
    }

    fn identity(&mut self, scheme: IdentityScheme) -> Result<ObjectId, WalError> {
        let algorithm = self.u16()?;
        let construction = self.u16()?;
        let digest_len = self.u32()?;
        if algorithm != scheme.algorithm()
            || construction != scheme.construction()
            || digest_len != 32
        {
            return Err(WalError::IdentitySchemeMismatch);
        }
        let digest = self.take(32)?.try_into().map_err(|_| WalError::Corrupt {
            offset: self.offset,
            detail: "WAL root identity is truncated",
        })?;
        Ok(ObjectId::new(digest))
    }

    fn u16(&mut self) -> Result<u16, WalError> {
        self.take(2)?
            .try_into()
            .map(u16::from_le_bytes)
            .map_err(|_| WalError::Corrupt {
                offset: self.offset,
                detail: "WAL root u16 is truncated",
            })
    }

    fn u32(&mut self) -> Result<u32, WalError> {
        self.take(4)?
            .try_into()
            .map(u32::from_le_bytes)
            .map_err(|_| WalError::Corrupt {
                offset: self.offset,
                detail: "WAL root u32 is truncated",
            })
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.position)
    }
}
