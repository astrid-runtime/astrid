//! Fallible complete location lookup, independent of resident index layout.
//!
//! An I/O or authentication failure must never be translated into absence.
//! These locators accelerate the arena; they do not confer object authority.

use std::collections::BTreeMap;

use super::{ArenaLocation, DurableError, ObjectId};

pub(super) trait LocationLookup {
    fn location(&self, id: ObjectId) -> Result<Option<ArenaLocation>, DurableError>;
    fn location_count(&self) -> usize;
    /// Iterate every entry exactly once in strictly increasing object-ID order.
    fn locations(
        &self,
    ) -> Box<dyn Iterator<Item = Result<(ObjectId, ArenaLocation), DurableError>> + '_>;
}

impl LocationLookup for BTreeMap<ObjectId, ArenaLocation> {
    fn location(&self, id: ObjectId) -> Result<Option<ArenaLocation>, DurableError> {
        Ok(self.get(&id).copied())
    }

    fn location_count(&self) -> usize {
        self.len()
    }

    fn locations(
        &self,
    ) -> Box<dyn Iterator<Item = Result<(ObjectId, ArenaLocation), DurableError>> + '_> {
        Box::new(self.iter().map(|(id, location)| Ok((*id, *location))))
    }
}

impl<T: LocationLookup + ?Sized> LocationLookup for &T {
    fn location(&self, id: ObjectId) -> Result<Option<ArenaLocation>, DurableError> {
        (**self).location(id)
    }

    fn location_count(&self) -> usize {
        (**self).location_count()
    }

    fn locations(
        &self,
    ) -> Box<dyn Iterator<Item = Result<(ObjectId, ArenaLocation), DurableError>> + '_> {
        (**self).locations()
    }
}

#[cfg(test)]
pub(in crate::engine::durable) mod tests;

mod run;

mod paged;

pub(super) use paged::PagedLocations;

/// Resident workspace target for the complete historical object locator.
///
/// The sorted staging vector reserves at most this many entry bytes. Tree roots,
/// iterators and one page per merge level are additional bounded workspace; OS
/// file cache is outside this target. Durable history is never truncated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocationIndexMemoryBudget(std::num::NonZeroU64);

impl LocationIndexMemoryBudget {
    /// Default shared staging-vector target (one `MiB`).
    pub const DEFAULT: Self =
        Self(std::num::NonZeroU64::new(1_048_576).expect("one MiB is nonzero"));

    /// Smallest budget capable of holding one complete locator entry.
    pub const MIN_BYTES: u64 = std::mem::size_of::<(ObjectId, ArenaLocation)>() as u64;

    /// Admit a finite, addressable target capable of holding an entry.
    ///
    /// # Errors
    /// Rejects targets smaller than one entry or above addressable memory.
    pub fn new(bytes: std::num::NonZeroU64) -> Result<Self, &'static str> {
        if bytes.get() < Self::MIN_BYTES || bytes.get() > isize::MAX as u64 {
            return Err("location index budget must hold an entry and fit addressable memory");
        }
        Ok(Self(bytes))
    }

    /// Return the admitted target in bytes.
    #[must_use]
    pub const fn bytes(self) -> std::num::NonZeroU64 {
        self.0
    }

    pub(super) fn entries(self) -> std::num::NonZeroUsize {
        // Constructor bounds establish both conversion and nonzero division.
        std::num::NonZeroUsize::new((self.0.get() / Self::MIN_BYTES) as usize)
            .expect("validated locator budget holds an addressable entry")
    }
}

impl Default for LocationIndexMemoryBudget {
    fn default() -> Self {
        // One shared 1 MiB vector stages roughly 13k entries before a geometric
        // spill. This amortizes writes without reserving RAM per principal or
        // retaining an entire 10k-agent historical catalogue in memory.
        Self::DEFAULT
    }
}

mod prefix;
pub(super) use prefix::ArenaPrefix;

#[cfg(test)]
mod engine_tests;

type LocationEntry = Result<(ObjectId, ArenaLocation), DurableError>;
type LocationEntries<'a> = Box<dyn Iterator<Item = LocationEntry> + 'a>;
