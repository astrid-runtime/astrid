//! Keep active map residency independent of durable historical nodes.

use std::collections::BTreeMap;

use crate::storage_model::{
    CanonicalPhysicalMap, PhysicalMapDomain, PhysicalMapNode, PhysicalMapNodeId,
};

use super::DurableError;
use super::RepresentationStore;
use super::format::Blake3PhysicalIdentity;

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
        let mut reclaimed = self.persisted_map_nodes.len() > resident;
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
            self.persisted_map_nodes.retain(resident);
        }
        collection
    }
}

#[tracing::instrument(target = "astrid_storage::recovery", level = "debug", skip_all, fields(domain = ?domain, input_nodes = arena.len(), active_nodes = tracing::field::Empty))]
pub(super) fn recover_active_map(
    domain: PhysicalMapDomain,
    root: Option<PhysicalMapNodeId>,
    arena: &mut BTreeMap<PhysicalMapNodeId, PhysicalMapNode>,
) -> Result<CanonicalPhysicalMap, DurableError> {
    let mut nodes = BTreeMap::new();
    let mut pending = root.into_iter().collect::<Vec<_>>();
    while let Some(id) = pending.pop() {
        if nodes.contains_key(&id) {
            continue;
        }
        let node = arena
            .remove(&id)
            .ok_or(DurableError::InvalidRepresentationState(
                "active physical map closure is incomplete",
            ))?;
        match &node {
            PhysicalMapNode::Branch { zero, one, .. } => pending.extend([*zero, *one]),
            PhysicalMapNode::Radix { children, .. } => pending.extend(children.iter().copied()),
            PhysicalMapNode::Leaf { .. } | PhysicalMapNode::Page { .. } => {},
        }
        nodes.insert(id, node);
    }
    if tracing::enabled!(target: "astrid_storage::recovery", tracing::Level::DEBUG) {
        tracing::Span::current().record("active_nodes", nodes.len());
    }
    // Durable metadata retains historical roots. An active view needs only its
    // own closure, and domain-bound identities prevent sharing between maps.
    // Keep canonical validation: reachability alone proves neither identity nor
    // shape, and the visited set must not turn cycles into accepted maps.
    Ok(CanonicalPhysicalMap::recover(
        &Blake3PhysicalIdentity,
        domain,
        root,
        nodes,
    )?)
}

#[cfg(test)]
mod tests;
