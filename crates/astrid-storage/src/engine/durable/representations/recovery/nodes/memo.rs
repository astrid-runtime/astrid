//! Bounded positive reachability reuse within one locator-run incarnation.

use super::{DurableError, LocationIndexMemoryBudget, PhysicalMapNodeId};

pub(super) struct CompleteMemo {
    slots: Box<[Option<PhysicalMapNodeId>]>,
    epoch: u64,
}

impl CompleteMemo {
    pub(super) fn new(budget: LocationIndexMemoryBudget) -> Result<Self, DurableError> {
        // Recovery has no private path-copy staging table. Borrow its existing
        // quarter of the shared target, and release it before constructing cold
        // mutation state. Full IDs avoid false positives from hash collisions.
        let bytes =
            usize::try_from(budget.bytes().get()).map_err(|_| DurableError::EncodingOverflow)? / 4;
        let count = bytes
            .checked_div(std::mem::size_of::<Option<PhysicalMapNodeId>>())
            .expect("a complete memo slot is nonempty");
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(count)
            .map_err(|_| DurableError::EncodingOverflow)?;
        slots.resize(count, None);
        Ok(Self {
            slots: slots.into_boxed_slice(),
            epoch: 0,
        })
    }

    pub(super) fn sync(&mut self, epoch: u64) {
        if self.epoch != epoch {
            self.clear();
            self.epoch = epoch;
        }
    }

    pub(super) fn clear(&mut self) {
        self.slots.fill(None);
    }

    pub(super) fn contains(&self, id: PhysicalMapNodeId) -> bool {
        self.slot(id)
            .is_some_and(|slot| self.slots[slot] == Some(id))
    }

    pub(super) fn insert(&mut self, id: PhysicalMapNodeId) {
        if let Some(slot) = self.slot(id) {
            self.slots[slot] = Some(id);
        }
    }

    fn slot(&self, id: PhysicalMapNodeId) -> Option<usize> {
        if self.slots.is_empty() {
            return None;
        }
        let prefix = usize::from_le_bytes(
            id.as_bytes()[..std::mem::size_of::<usize>()]
                .try_into()
                .expect("a physical ID contains a native word"),
        );
        prefix.checked_rem(self.slots.len())
    }

    #[cfg(test)]
    pub(super) fn capacity_bytes(&self) -> usize {
        std::mem::size_of_val(self.slots.as_ref())
    }
}
