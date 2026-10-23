//! Borrowed complete locator for a validated arena prefix.

use super::super::FRAME_HEADER_LEN;
use super::{ArenaLocation, DurableError, LocationLookup, ObjectId};

pub(in crate::engine::durable) struct ArenaPrefix<'a> {
    source: &'a dyn LocationLookup,
    arena_len: u64,
    count: usize,
}

impl<'a> ArenaPrefix<'a> {
    pub(in crate::engine::durable) fn new(
        source: &'a dyn LocationLookup,
        arena_len: u64,
    ) -> Result<Self, DurableError> {
        let mut count = 0_usize;
        for entry in source.locations() {
            let (_, location) = entry?;
            if contains(location, arena_len)? {
                count = count.checked_add(1).ok_or(DurableError::EncodingOverflow)?;
            }
        }
        Ok(Self {
            source,
            arena_len,
            count,
        })
    }
}

fn contains(location: ArenaLocation, arena_len: u64) -> Result<bool, DurableError> {
    location
        .offset
        .checked_add(FRAME_HEADER_LEN)
        .and_then(|value| value.checked_add(location.payload_len))
        .map(|end| end <= arena_len)
        .ok_or(DurableError::EncodingOverflow)
}

impl LocationLookup for ArenaPrefix<'_> {
    fn location(&self, id: ObjectId) -> Result<Option<ArenaLocation>, DurableError> {
        match self.source.location(id)? {
            Some(location) if contains(location, self.arena_len)? => Ok(Some(location)),
            _ => Ok(None),
        }
    }

    fn location_count(&self) -> usize {
        self.count
    }

    fn locations(
        &self,
    ) -> Box<dyn Iterator<Item = Result<(ObjectId, ArenaLocation), DurableError>> + '_> {
        Box::new(self.source.locations().filter_map(|entry| match entry {
            Err(error) => Some(Err(error)),
            Ok((id, location)) => match contains(location, self.arena_len) {
                Ok(true) => Some(Ok((id, location))),
                Ok(false) => None,
                Err(error) => Some(Err(error)),
            },
        }))
    }
}
