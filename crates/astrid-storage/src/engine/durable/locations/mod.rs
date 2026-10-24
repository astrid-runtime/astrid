//! Fallible complete location lookup, independent of resident index layout.
//!
//! An I/O or authentication failure must never be translated into absence.
//! These locators accelerate the arena; they do not confer object authority.

use std::collections::BTreeMap;

use super::{ArenaLocation, DurableError, ObjectId};

/// Process-local evidence; never encoded in the durable index cache.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::engine::durable) enum ClosureProof {
    Unknown,
    Complete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::engine::durable) struct LocatorValue {
    location: ArenaLocation,
    proof: ClosureProof,
}

impl LocatorValue {
    #[cfg(test)]
    const fn unknown(location: ArenaLocation) -> Self {
        Self {
            location,
            proof: ClosureProof::Unknown,
        }
    }
}

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

pub(super) use paged::{AuthenticatedPageMemo, PagedLocations, RebuildLocations};

/// Shared resident staging target for complete durable locators.
///
/// The engine divides this target between the historical object locator,
/// physical-node locator, private path-copy locator, and reverse heads. During
/// recovery, a bounded positive reachability memo borrows the otherwise absent
/// private path-copy partition; it is released before cold mutation starts. All are shared across
/// principals. Their sorted staging vectors together reserve at most this many
/// entry bytes. Tree roots,
/// iterators, buffered page output and one page per merge level are additional bounded workspace; OS
/// file cache is outside this target. Durable history is never truncated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocationIndexMemoryBudget(std::num::NonZeroU64);

impl LocationIndexMemoryBudget {
    /// Default shared staging-vector target (one `MiB`).
    pub const DEFAULT: Self =
        Self(std::num::NonZeroU64::new(1_048_576).expect("one MiB is nonzero"));

    /// Historical admission floor, retained for configuration compatibility.
    /// Smaller-than-row partitions spill directly without reserving a row.
    pub const MIN_BYTES: u64 = std::mem::size_of::<(ObjectId, ArenaLocation)>() as u64;

    /// Admit a finite, addressable target at or above the historical floor.
    ///
    /// # Errors
    /// Rejects targets below the historical floor or above addressable memory.
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

    pub(super) fn durable_entries(self) -> std::num::NonZeroUsize {
        // Four live tables: logical, physical, private mutation, reverse heads.
        // A one-entry table spills directly without allocating a resident slot,
        // so targets below four entries still respect the shared ceiling.
        std::num::NonZeroUsize::new((self.entries().get() / 4).max(1))
            .expect("a direct-spill locator has a nonzero threshold")
    }

    pub(super) fn entries(self) -> std::num::NonZeroUsize {
        // The historical floor predates proof bits. Tiny targets use direct
        // spilling; they never reserve an over-budget resident row.
        let bytes =
            usize::try_from(self.0.get()).expect("validated budget fits addressable memory");
        let rows = bytes
            .checked_div(std::mem::size_of::<(ObjectId, LocatorValue)>())
            .expect("complete locator rows have nonzero size");
        std::num::NonZeroUsize::new(rows.max(1))
            .expect("validated locator budget holds an addressable entry")
    }
}

impl Default for LocationIndexMemoryBudget {
    fn default() -> Self {
        // Shared staging amortizes writes without reserving RAM per principal or
        // retaining an entire 10k-agent historical catalogue in memory.
        Self::DEFAULT
    }
}

mod prefix;
pub(super) use prefix::ArenaPrefix;

#[cfg(test)]
mod engine_tests;
