//! Position-independent reads through recovered arena locations.

use std::collections::BTreeMap;

use super::{
    ARENA_FILE, ARENA_MAGIC, ArenaLocation, DurableError, DurableIo, FRAME_HEADER_LEN,
    FRAME_VERSION, ObjectId, ObjectRecord, PersistentObjectIdentity, RecoveryLimits, corrupt,
    frame_checksum, io_error, read_exact_at, read_frame_at,
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
    use super::arena_span::IndexedError;
    let scheme = identity.scheme();
    let payload = super::arena_span::at_location(
        location.offset,
        location.payload_len,
        location.checksum,
        |offset| {
            let frame = read_frame_at(arena, ARENA_FILE, ARENA_MAGIC, offset, limits)?;
            let checksum = frame.checksum();
            Ok((frame.into_payload(), checksum))
        },
    )
    .map_err(|error| match error {
        IndexedError::Read(error) => error,
        IndexedError::Placement => corrupt(
            ARENA_FILE,
            location.offset,
            "indexed frame location no longer matches the arena",
        ),
    })?;
    let record = verified_payload(&payload, expected_id, location.offset, scheme, identity)?;
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
    #[cfg(test)]
    let spans = std::cell::Cell::new(0_usize);
    super::indexed_frame::dispatch(
        &ordered,
        target_span_bytes,
        limits.max_frame_bytes,
        &mut accept,
        |visitor, rows, span_start, span_len| {
            #[cfg(test)]
            spans.set(spans.get().saturating_add(1));
            let span_len = usize::try_from(span_len).map_err(|_| DurableError::EncodingOverflow)?;
            let mut span = Vec::new();
            span.try_reserve_exact(span_len)
                .map_err(|_| DurableError::EncodingOverflow)?;
            span.resize(span_len, 0);
            read_exact_at(arena, &mut span, span_start)
                .map_err(|source| io_error("read coalesced durable frames", source))?;
            super::indexed_frame::deliver(
                rows,
                visitor,
                |id, location| {
                    decode_indexed_frame(&span, span_start, id, location, identity, limits)
                },
                |visitor, id, location, record, payload| {
                    visitor(id, location, record, payload)?;
                    Ok(visitor)
                },
            )
        },
    )
    .map_err(|error| match error {
        super::indexed_frame::DispatchError::Limit(loc) => DurableError::FrameTooLarge {
            file: ARENA_FILE,
            offset: loc.offset,
            declared: loc.payload_len,
            limit: limits.max_frame_bytes,
        },
        super::indexed_frame::DispatchError::Overflow => DurableError::EncodingOverflow,
        super::indexed_frame::DispatchError::Visit(e) => e,
    })?;
    #[cfg(test)]
    LAST_BATCH_SPANS.set(spans.get());
    Ok(())
}

#[cfg(test)]
pub(in crate::engine::durable) fn last_batch_spans() -> usize {
    LAST_BATCH_SPANS.get()
}

#[cfg(test)]
pub(in crate::engine::durable) fn reset_last_batch_spans() {
    LAST_BATCH_SPANS.set(0);
}

fn decode_indexed_frame<'a, I: PersistentObjectIdentity>(
    span: &'a [u8],
    start: u64,
    expected_id: ObjectId,
    location: ArenaLocation,
    identity: &I,
    limits: RecoveryLimits,
) -> Result<(ObjectRecord, &'a [u8]), DurableError> {
    use super::arena_span::Error;
    use super::indexed_frame;
    indexed_frame::read(
        span,
        start,
        location,
        expected_id,
        indexed_frame::Format {
            magic: ARENA_MAGIC,
            version: FRAME_VERSION,
            limit: limits.max_frame_bytes,
            scheme: identity.scheme().into(),
        },
        frame_checksum,
        |record| *identity.identify(record).as_bytes(),
    )
    .map_err(|error| match error {
        indexed_frame::Error::Bounds => DurableError::EncodingOverflow,
        indexed_frame::Error::Record(error) => record_error(location.offset, error),
        indexed_frame::Error::Envelope(error) => {
            let detail = match error {
                Error::Truncated => "coalesced frame is truncated",
                Error::Magic => "frame magic mismatch",
                Error::Version => "unsupported frame version",
                Error::Reserved => "reserved header bytes are non-zero",
                Error::Limit(declared) => {
                    return DurableError::FrameTooLarge {
                        file: ARENA_FILE,
                        offset: location.offset,
                        declared,
                        limit: limits.max_frame_bytes,
                    };
                },
                Error::Length => "indexed frame length no longer matches the arena",
                Error::Payload => "coalesced frame payload is truncated",
                Error::Checksum => "indexed frame checksum no longer matches the arena",
            };
            corrupt(ARENA_FILE, location.offset, detail)
        },
    })
}

fn verified_payload<I: PersistentObjectIdentity>(
    payload: &[u8],
    expected: ObjectId,
    offset: u64,
    scheme: super::IdentityScheme,
    identity: &I,
) -> Result<ObjectRecord, DurableError> {
    use super::verified_record;
    verified_record::confirmed(payload, scheme.into(), expected, |record| {
        *identity.identify(record).as_bytes()
    })
    .map_err(|error| record_error(offset, error))
}

fn record_error(
    offset: u64,
    error: super::verified_record::Error<super::verified_record::BodyError>,
) -> DurableError {
    use super::verified_record::Error;
    corrupt(
        ARENA_FILE,
        offset,
        match error {
            Error::Decode(e) => super::body_error_detail(e),
            Error::Identifier => "indexed object identifier mismatch",
            Error::Identity => "indexed object identity does not match its canonical record",
        },
    )
}
