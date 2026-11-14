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
        // rebase_all_direct replaces maps with build_dense, discarding old nodes
        // without crossing a collection threshold. Its disposable ID memos need
        // eviction after the newly built root has become durable.
        let resident = self
            .profiles
            .nodes()
            .len()
            .saturating_add(self.representations.nodes().len())
            .saturating_add(self.placement_entries.nodes().len());
        let mut reclaimed = self
            .persisted_map_nodes
            .len()
            .saturating_add(self.complete_map_subtrees.len())
            > resident;
        let collection = (|| -> Result<(), DurableError> {
            // Dense pages can contain many entries per node. Measure reachable
            // nodes rather than treating the binary worst case as live memory.
            // A doubling amortizes each traversal over growth or path copies.
            // Unrolled across typed maps: a shared loop cannot hold heterogeneous
            // &mut ProfileMap / RepresentationMap / PlacementMap.
            if self.profiles.nodes().len() > self.residency.profiles.saturating_mul(2) {
                self.profiles.reclaim_unreachable_nodes()?;
                self.residency.profiles = self.profiles.nodes().len();
                reclaimed = true;
            }
            if self.representations.nodes().len() > self.residency.representations.saturating_mul(2)
            {
                self.representations.reclaim_unreachable_nodes()?;
                self.residency.representations = self.representations.nodes().len();
                reclaimed = true;
            }
            if self.placement_entries.nodes().len() > self.residency.placements.saturating_mul(2) {
                self.placement_entries.reclaim_unreachable_nodes()?;
                self.residency.placements = self.placement_entries.nodes().len();
                reclaimed = true;
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
                // Retain knowledge of existing frames, but revoke their closure
                // proofs when a later map fails after partial collection.
                self.persisted_map_nodes
                    .append(&mut self.complete_map_subtrees);
            } else {
                // Immutable resident nodes keep their complete durable closure:
                // successful collection retains every reachable descendant.
                self.complete_map_subtrees.retain(resident);
            }
            // Durable frames and historical roots remain unchanged;
            // reintroduced IDs are safely appended again.
            self.persisted_map_nodes.retain(resident);
        }
        collection
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod recovery_tests;
