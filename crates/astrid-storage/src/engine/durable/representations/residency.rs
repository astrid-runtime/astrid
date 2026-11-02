//! Keep active map residency independent of durable historical nodes.

use crate::storage_model::{CanonicalPhysicalMap, PhysicalMapNodeId};

use super::DurableError;
use super::RepresentationStore;

/// Last measured reachable closures; scheduling evidence confers no authority.
#[derive(Debug)]
pub(super) struct MapResidency {
    profiles: usize,
    representations: usize,
    placements: usize,
}

impl MapResidency {
    pub(super) fn new(
        profiles: &CanonicalPhysicalMap,
        representations: &CanonicalPhysicalMap,
        placements: &CanonicalPhysicalMap,
    ) -> Self {
        Self {
            profiles: profiles.nodes().len(),
            representations: representations.nodes().len(),
            placements: placements.nodes().len(),
        }
    }
}

impl RepresentationStore {
    pub(super) fn reclaim_map_history(&mut self) -> Result<(), DurableError> {
        // rebase_all_direct retains memos against the replacement occupancy.
        // Collection still drops unreachable path-copy debris after 2x growth.
        let mut reclaimed = false;
        let collection = (|| -> Result<(), DurableError> {
            for (map, baseline) in [
                (&mut self.profiles, &mut self.residency.profiles),
                (
                    &mut self.representations,
                    &mut self.residency.representations,
                ),
                (&mut self.placement_entries, &mut self.residency.placements),
            ] {
                // Dense pages can contain many entries per node. Measure reachable
                // nodes rather than treating the binary worst case as live memory.
                // A doubling amortizes each traversal over growth or path copies.
                if map.nodes().len() > baseline.saturating_mul(2) {
                    map.reclaim_unreachable_nodes()?;
                    *baseline = map.nodes().len();
                    reclaimed = true;
                }
            }
            Ok(())
        })();
        if reclaimed || collection.is_err() {
            // Also evict on error: an earlier map may already have reclaimed
            // nodes before a later map failed. Propagate that failure below.
            let profiles = self.profiles.nodes();
            let representations = self.representations.nodes();
            let placements = self.placement_entries.nodes();
            let resident = |id: &PhysicalMapNodeId| {
                profiles.contains_key(id)
                    || representations.contains_key(id)
                    || placements.contains_key(id)
            };
            if collection.is_err() {
                self.complete_map_subtrees.clear();
            } else {
                // Immutable resident nodes keep their complete durable closure:
                // successful collection retains every reachable descendant.
                self.complete_map_subtrees.retain(resident);
            }
            // Durable frames and historical roots remain unchanged;
            // reintroduced IDs are safely appended again.
            self.pending_unpersisted_map_nodes.retain(resident);
        }
        collection
    }
}

#[cfg(test)]
mod tests;
