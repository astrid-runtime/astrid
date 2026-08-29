//! Canonical cursors and fixed-capacity delta records.

use super::types::{DELTA_RING_ENTRIES, RelationChange};

/// Canonical position from which a reader replay starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeltaCursor {
    pub(crate) reader_generation: u64,
    pub(crate) after_epoch: u64,
}

impl DeltaCursor {
    pub const fn new(reader_generation: u64, after_epoch: u64) -> Self {
        Self {
            reader_generation,
            after_epoch,
        }
    }

    pub(crate) const fn matches(self, reader_generation: u64, after_epoch: u64) -> bool {
        self.reader_generation == reader_generation && self.after_epoch == after_epoch
    }
}

/// Canonical page position. It is reader-generation checked by the projection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageCursor {
    pub(crate) reader_generation: u64,
    pub(crate) epoch: u64,
    pub(crate) page: u32,
}

impl PageCursor {
    pub const fn new(reader_generation: u64, epoch: u64, page: u32) -> Self {
        Self {
            reader_generation,
            epoch,
            page,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RelationDelta {
    epoch: u64,
    change: RelationChange,
}

impl RelationDelta {
    pub(crate) const fn new(epoch: u64, change: RelationChange) -> Self {
        Self { epoch, change }
    }

    pub(crate) const fn epoch(self) -> u64 {
        self.epoch
    }

    pub(crate) const fn change(self) -> RelationChange {
        self.change
    }
}

#[derive(Clone, Copy)]
pub(crate) struct DeltaRing {
    entries: [Option<RelationDelta>; DELTA_RING_ENTRIES],
    len: usize,
    overflowed: bool,
}

impl DeltaRing {
    pub(crate) const fn empty() -> Self {
        Self {
            entries: [None; DELTA_RING_ENTRIES],
            len: 0,
            overflowed: false,
        }
    }

    pub(crate) fn push(&mut self, delta: RelationDelta) {
        if self.overflowed {
            return;
        }
        if self.len == DELTA_RING_ENTRIES {
            self.overflowed = true;
            return;
        }
        self.entries[self.len] = Some(delta);
        self.len += 1;
    }

    pub(crate) const fn overflowed(&self) -> bool {
        self.overflowed
    }

    pub(crate) fn deltas(&self) -> [Option<RelationDelta>; DELTA_RING_ENTRIES] {
        self.entries
    }
}
