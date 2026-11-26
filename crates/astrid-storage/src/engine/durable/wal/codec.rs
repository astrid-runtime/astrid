use super::super::format::{decode_object_frame, encode_object_frame, frame_checksum};
use super::super::root_wire::{self, BindingError, OwnerError, RootError, TailError};
use super::super::roots::encode_root_record;
use super::super::{IdentityScheme, PersistentObjectIdentity, PrincipalCodec};
use crate::storage_model::{ObjectId, ObjectRecord, RootState};
use std::borrow::Cow;

use super::types::{
    WalBeginHints, WalCount, WalDigest, WalError, WalLength, WalLimits, WalOrdinal,
    WalPhysicalLimit, WalRecordKind, WalRootTransition, WalSequence,
};

pub(super) use super::physical_wire::{
    Envelope as PhysicalHeader, MAGIC as WAL_MAGIC, WIDTH as PHYSICAL_HEADER_LEN,
};
/// Logical record header width inside each physical payload.
pub(super) const RECORD_HEADER_LEN: usize = super::record_wire::HEADER_LEN;
const BEGIN_FIXED_LEN: usize = 8;
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
    encoded.resize(PHYSICAL_HEADER_LEN, 0);
    super::record_wire::Header {
        kind: kind.tag(),
        flags,
        reserved: [0; 2],
        sequence: sequence.get().to_le_bytes(),
        ordinal: ordinal.get().to_le_bytes(),
    }
    .append(&mut encoded, body);
    if !super::physical_wire::seal(&mut encoded, flags, frame_checksum) {
        return Err(WalError::Encoding("WAL physical header is truncated"));
    }
    Ok(encoded)
}

/// Parse and validate a physical header without allocating its payload.
pub(super) fn decode_physical_header(
    header: &[u8; PHYSICAL_HEADER_LEN],
    offset: super::types::WalOffset,
) -> Result<PhysicalHeader, WalError> {
    super::physical_wire::decode(header).ok_or(WalError::Corrupt {
        offset,
        detail: "WAL physical header is invalid",
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
    if !physical.accepts(record.kind, record.flags) {
        return Err(WalError::Corrupt {
            offset,
            detail: "WAL record features do not match its physical version",
        });
    }
    Ok(())
}

/// Verify a payload checksum.
pub(super) fn checksum_valid(header: PhysicalHeader, payload: &[u8]) -> bool {
    header.validates(payload, frame_checksum)
}

/// Parse the logical record header.
pub(super) fn decode_record(
    payload: &[u8],
    offset: super::types::WalOffset,
) -> Result<(RecordHeader, &[u8]), WalError> {
    let (header, body) = super::record_wire::split(payload).ok_or(WalError::Corrupt {
        offset,
        detail: "WAL record header is truncated",
    })?;
    let kind = WalRecordKind::from_tag(header.kind).ok_or(WalError::Corrupt {
        offset,
        detail: "WAL record kind is unknown",
    })?;
    let flags = header.flags;
    if header.reserved != [0, 0]
        || (kind == WalRecordKind::Object && flags & !OBJECT_FLAG_LZ4 != 0)
        || (kind != WalRecordKind::Object && flags != 0)
    {
        return Err(WalError::Corrupt {
            offset,
            detail: "WAL record flags or reserved bytes are non-zero",
        });
    }
    let sequence =
        WalSequence::new(u64::from_le_bytes(header.sequence)).ok_or(WalError::Corrupt {
            offset,
            detail: "WAL record sequence is zero",
        })?;
    let ordinal = WalOrdinal::new(u64::from_le_bytes(header.ordinal));
    Ok((
        RecordHeader {
            kind,
            flags,
            sequence,
            ordinal,
        },
        body,
    ))
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
) -> [u8; super::commit_wire::LENGTH] {
    super::commit_wire::Marker {
        counts: super::commit_wire::Counts {
            sequence: sequence.get(),
            logical: logical_count.get(),
            objects: object_count.get(),
            roots: root_count.get(),
            bytes: logical_bytes.get(),
        },
        digest: *digest.as_bytes(),
    }
    .encode()
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
    let (principal, expected, replacement) = root_fields(body, scheme, codec, offset)?;
    let expected = expected.map(Into::into);
    let replacement = replacement.into();
    validate_root_generation(expected, replacement).map_err(|_| WalError::Corrupt {
        offset,
        detail: "WAL root generation transition is invalid",
    })?;
    let canonical = encode_root_record(scheme, principal, expected, replacement).map_err(|_| {
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
        WalRootTransition::new(principal.to_vec(), expected, replacement),
        WalLength::new(length),
    ))
}

/// Validate the prepared bytes at the live writer boundary. Return the owner
/// used for WAL ordering only when both roots and the live owner codec agree.
pub(super) fn prepared_owner<P, C: PrincipalCodec<P>>(
    body: &[u8],
    owner: &P,
    expected: Option<RootState>,
    replacement: RootState,
    scheme: IdentityScheme,
    codec: &C,
) -> Result<Vec<u8>, WalError> {
    validate_root_generation(expected, replacement)?;
    let (saved, prior, next) = root_fields(body, scheme, codec, super::types::WalOffset::new(0))?;
    root_wire::bind_owner(
        codec.encode(owner),
        saved,
        expected.map(Into::into),
        prior,
        replacement.into(),
        next,
    )
    .map_err(|error| match error {
        BindingError::Owner => WalError::PrincipalMismatch,
        BindingError::Roots => {
            WalError::InvalidTransaction("prepared WAL root differs from its transaction")
        },
    })
}

fn root_fields<'a, P, C: PrincipalCodec<P>>(
    body: &'a [u8],
    scheme: IdentityScheme,
    codec: &C,
    offset: super::types::WalOffset,
) -> Result<(&'a [u8], Option<root_wire::Root>, root_wire::Root), WalError> {
    let (principal, mut cursor) = root_wire::read_owner(body).map_err(|error| match error {
        OwnerError::Read(error) => root_read_error(offset, error),
        OwnerError::Length(length) => WalError::LengthOverflow {
            value: WalLength::new(length),
        },
    })?;
    validate_principal(codec, principal)?;
    let (expected, replacement) =
        root_wire::read_tail(body, &mut cursor, scheme.into()).map_err(|error| match error {
            TailError::Read(e) | TailError::Root(RootError::Read(e)) => root_read_error(offset, e),
            TailError::Root(RootError::Scheme { .. }) => WalError::IdentitySchemeMismatch,
            TailError::ExpectedTag => WalError::Corrupt {
                offset,
                detail: "WAL root expected tag is invalid",
            },
            TailError::Trailing => WalError::Corrupt {
                offset,
                detail: "WAL root record has trailing bytes",
            },
        })?;
    Ok((principal, expected, replacement))
}

fn validate_root_generation(
    expected: Option<RootState>,
    replacement: RootState,
) -> Result<(), WalError> {
    if super::super::root_transition::valid_generation(
        expected.map(Into::into),
        replacement.generation.get(),
    ) {
        Ok(())
    } else {
        Err(WalError::InvalidTransaction(
            "WAL root generation transition is invalid",
        ))
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
) {
    digest_record_with_flags(hasher, kind, 0, sequence, ordinal, body);
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
) {
    super::measurement::digest_record(
        kind,
        flags,
        sequence.get(),
        ordinal.get(),
        body,
        |header, payload| {
            hasher.update(header);
            hasher.update(payload);
        },
    );
}

/// Return the canonical logical record length used by Commit accounting.
#[cfg(test)]
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

fn root_read_error(
    offset: super::types::WalOffset,
    error: super::super::root_wire::ReadError,
) -> WalError {
    match error {
        super::super::root_wire::ReadError::Overflow(length) => WalError::LengthOverflow {
            value: WalLength::new(length as u64),
        },
        super::super::root_wire::ReadError::Truncated => WalError::Corrupt {
            offset,
            detail: "WAL root record is truncated",
        },
    }
}
