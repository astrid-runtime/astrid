//! Position-independent reads through recovered arena locations.

use std::collections::BTreeMap;

use super::{
    ARENA_FILE, ARENA_MAGIC, ArenaLocation, CHECKSUM_START, DurableError, DurableIo,
    FRAME_HEADER_LEN, FRAME_HEADER_LEN_USIZE, FRAME_VERSION, ObjectId, ObjectRecord,
    PersistentObjectIdentity, RecoveryLimits, corrupt, decode_object_frame, frame_checksum,
    io_error, read_exact_at, read_frame_at,
};

#[cfg(test)]
thread_local! {
    static LAST_BATCH_SPANS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

pub(in crate::engine::durable) fn read_indexed_object<I: PersistentObjectIdentity, F: DurableIo>(
    arena: &F,
    expected_id: ObjectId,
    location: ArenaLocation,
    identity: &I,
    limits: RecoveryLimits,
) -> Result<ObjectRecord, DurableError> {
    read_indexed_object_with_payload(arena, expected_id, location, identity, limits)
        .map(|(record, _)| record)
}

/// Read and verify one object while retaining its canonical frame payload.
///
/// Physical consumers use the returned payload to derive representation
/// identity without serializing the decoded record a second time.
pub(in crate::engine::durable) fn read_indexed_object_with_payload<
    I: PersistentObjectIdentity,
    F: DurableIo,
>(
    arena: &F,
    expected_id: ObjectId,
    location: ArenaLocation,
    identity: &I,
    limits: RecoveryLimits,
) -> Result<(ObjectRecord, Vec<u8>), DurableError> {
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
    Ok((record, payload))
}

pub(in crate::engine::durable) fn read_indexed_objects<
    I: PersistentObjectIdentity,
    F: DurableIo,
>(
    arena: &F,
    requested: &[(ObjectId, ArenaLocation)],
    identity: &I,
    limits: RecoveryLimits,
) -> Result<BTreeMap<ObjectId, ObjectRecord>, DurableError> {
    let mut records = BTreeMap::new();
    visit_indexed_objects(
        arena,
        requested,
        FRAME_HEADER_LEN.saturating_add(limits.max_frame_bytes),
        identity,
        limits,
        |expected_id, _location, record, _payload| {
            records.insert(expected_id, record);
            Ok(())
        },
    )?;
    Ok(records)
}

pub(in crate::engine::durable) fn visit_indexed_objects<
    I: PersistentObjectIdentity,
    F: DurableIo,
>(
    arena: &F,
    requested: &[(ObjectId, ArenaLocation)],
    target_span_bytes: u64,
    identity: &I,
    limits: RecoveryLimits,
    mut accept: impl FnMut(ObjectId, ArenaLocation, ObjectRecord, &[u8]) -> Result<(), DurableError>,
) -> Result<(), DurableError> {
    let mut ordered = requested.to_vec();
    ordered.sort_unstable_by_key(|(_, location)| location.offset);
    let mut first = 0_usize;
    #[cfg(test)]
    let mut spans = 0_usize;
    while first < ordered.len() {
        let first_location = ordered[first].1;
        if first_location.payload_len > limits.max_frame_bytes {
            return Err(DurableError::FrameTooLarge {
                file: ARENA_FILE,
                offset: first_location.offset,
                declared: first_location.payload_len,
                limit: limits.max_frame_bytes,
            });
        }
        let max_span_bytes = target_span_bytes.max(frame_len(first_location)?);
        #[cfg(test)]
        {
            spans = spans.saturating_add(1);
        }
        let span_start = first_location.offset;
        let mut span_end = frame_end(first_location)?;
        let mut end = first.saturating_add(1);
        while let Some((_, location)) = ordered.get(end) {
            if location.offset != span_end {
                break;
            }
            let candidate_end = frame_end(*location)?;
            let candidate_len = candidate_end
                .checked_sub(span_start)
                .ok_or(DurableError::EncodingOverflow)?;
            if candidate_len > max_span_bytes {
                break;
            }
            span_end = candidate_end;
            end = end.saturating_add(1);
        }
        let span_len = span_end
            .checked_sub(span_start)
            .ok_or(DurableError::EncodingOverflow)?;
        let span_len = usize::try_from(span_len).map_err(|_| DurableError::EncodingOverflow)?;
        let mut span = Vec::new();
        span.try_reserve_exact(span_len)
            .map_err(|_| DurableError::EncodingOverflow)?;
        span.resize(span_len, 0);
        read_exact_at(arena, &mut span, span_start)
            .map_err(|source| io_error("read coalesced durable frames", source))?;

        for (expected_id, location) in &ordered[first..end] {
            let relative = location
                .offset
                .checked_sub(span_start)
                .ok_or(DurableError::EncodingOverflow)?;
            let relative = usize::try_from(relative).map_err(|_| DurableError::EncodingOverflow)?;
            let frame_len = usize::try_from(frame_len(*location)?)
                .map_err(|_| DurableError::EncodingOverflow)?;
            let relative_end = relative
                .checked_add(frame_len)
                .ok_or(DurableError::EncodingOverflow)?;
            let frame = span
                .get(relative..relative_end)
                .ok_or(DurableError::EncodingOverflow)?;
            let record = decode_indexed_frame(frame, *expected_id, *location, identity, limits)?;
            let payload = frame
                .get(FRAME_HEADER_LEN_USIZE..)
                .ok_or(DurableError::EncodingOverflow)?;
            accept(*expected_id, *location, record, payload)?;
        }
        first = end;
    }
    #[cfg(test)]
    LAST_BATCH_SPANS.set(spans);
    Ok(())
}

#[cfg(test)]
pub(in crate::engine::durable) fn last_batch_spans() -> usize {
    LAST_BATCH_SPANS.get()
}

fn decode_indexed_frame<I: PersistentObjectIdentity>(
    frame: &[u8],
    expected_id: ObjectId,
    location: ArenaLocation,
    identity: &I,
    limits: RecoveryLimits,
) -> Result<ObjectRecord, DurableError> {
    let header = frame
        .get(..FRAME_HEADER_LEN_USIZE)
        .ok_or_else(|| corrupt(ARENA_FILE, location.offset, "coalesced frame is truncated"))?;
    if header[..8] != ARENA_MAGIC {
        return Err(corrupt(ARENA_FILE, location.offset, "frame magic mismatch"));
    }
    if u16::from_le_bytes([header[8], header[9]]) != FRAME_VERSION {
        return Err(corrupt(
            ARENA_FILE,
            location.offset,
            "unsupported frame version",
        ));
    }
    if header[10..12] != [0, 0] {
        return Err(corrupt(
            ARENA_FILE,
            location.offset,
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
            file: ARENA_FILE,
            offset: location.offset,
            declared: payload_len,
            limit: limits.max_frame_bytes,
        });
    }
    if payload_len != location.payload_len {
        return Err(corrupt(
            ARENA_FILE,
            location.offset,
            "indexed frame length no longer matches the arena",
        ));
    }
    let payload = frame
        .get(FRAME_HEADER_LEN_USIZE..)
        .ok_or(DurableError::EncodingOverflow)?;
    if u64::try_from(payload.len()).map_err(|_| DurableError::EncodingOverflow)? != payload_len {
        return Err(corrupt(
            ARENA_FILE,
            location.offset,
            "coalesced frame payload is truncated",
        ));
    }
    let header_checksum: [u8; 32] = header[CHECKSUM_START..]
        .try_into()
        .map_err(|_| DurableError::EncodingOverflow)?;
    let actual_checksum = frame_checksum(ARENA_MAGIC, payload_len, payload);
    if actual_checksum != header_checksum || actual_checksum != location.checksum {
        return Err(corrupt(
            ARENA_FILE,
            location.offset,
            "indexed frame checksum no longer matches the arena",
        ));
    }
    let (id, record) = decode_object_frame(payload, identity.scheme())
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

fn frame_len(location: ArenaLocation) -> Result<u64, DurableError> {
    FRAME_HEADER_LEN
        .checked_add(location.payload_len)
        .ok_or(DurableError::EncodingOverflow)
}

fn frame_end(location: ArenaLocation) -> Result<u64, DurableError> {
    location
        .offset
        .checked_add(frame_len(location)?)
        .ok_or(DurableError::EncodingOverflow)
}
