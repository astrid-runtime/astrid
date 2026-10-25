//! Bounds invariants for a validated object-index prefix.

use super::{ArenaLocation, DurableError, FRAME_HEADER_LEN, IndexState, corrupt};

#[cfg(test)]
thread_local! {
    pub(super) static LOCATION_VISITS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

pub(super) fn validate_state(state: &IndexState, offset: u64) -> Result<(), DurableError> {
    validate_locations(state.objects.values(), state.arena_len, offset)?;
    validate_tail(state.arena_tail, state.arena_len, offset)
}

pub(super) fn validate_locations<'a>(
    locations: impl IntoIterator<Item = &'a ArenaLocation>,
    arena_len: u64,
    offset: u64,
) -> Result<(), DurableError> {
    for location in locations {
        #[cfg(test)]
        LOCATION_VISITS.with(|count| count.set(count.get().strict_add(1)));
        if location_end(location)? > arena_len {
            return Err(corrupt(
                offset,
                "indexed object extends beyond covered arena",
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_tail(
    tail: Option<ArenaLocation>,
    arena_len: u64,
    offset: u64,
) -> Result<(), DurableError> {
    match tail {
        Some(location) if location_end(&location)? != arena_len => Err(corrupt(
            offset,
            "indexed arena tail does not end at covered length",
        )),
        None if arena_len != 0 => Err(corrupt(offset, "non-empty arena has no indexed tail")),
        _ => Ok(()),
    }
}

fn location_end(location: &ArenaLocation) -> Result<u64, DurableError> {
    location
        .offset
        .checked_add(FRAME_HEADER_LEN)
        .and_then(|end| end.checked_add(location.payload_len))
        .ok_or(DurableError::EncodingOverflow)
}
