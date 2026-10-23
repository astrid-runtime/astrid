//! Keep active map residency independent of durable historical nodes.

use std::collections::BTreeMap;

use crate::storage_model::{
    CanonicalPhysicalMap, PhysicalMapDomain, PhysicalMapNode, PhysicalMapNodeId,
};

use super::DurableError;
use super::RepresentationStore;
use super::format::Blake3PhysicalIdentity;

/// Reachable-node counts measured after recovery, rebuild, or collection.
/// These disposable baselines schedule work; they confer no authority.
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

    fn total(&self) -> usize {
        self.profiles
            .saturating_add(self.representations)
            .saturating_add(self.placements)
    }
}

impl RepresentationStore {
    #[cfg(test)]
    pub(in crate::engine::durable) fn persisted_physical_node_count(&self) -> usize {
        self.persisted_map_nodes.len()
    }

    pub(in crate::engine::durable) fn checkpoint_required(&self) -> bool {
        self.persisted_map_nodes.len() > self.residency.total().saturating_mul(2)
    }

    pub(super) fn reclaim_map_history(&mut self) -> Result<(), DurableError> {
        let mut reclaimed = false;
        for (map, baseline) in [
            (&mut self.profiles, &mut self.residency.profiles),
            (
                &mut self.representations,
                &mut self.residency.representations,
            ),
            (&mut self.placement_entries, &mut self.residency.placements),
        ] {
            // Use the last measured reachable closure, not the 2n-1 binary
            // worst case: radix branches can combine more than two children.
            // Crossing twice this baseline amortizes a traversal over new
            // path copies or genuine growth; both establish a fresh baseline.
            if map.nodes().len() > baseline.saturating_mul(2) {
                map.reclaim_unreachable_nodes()?;
                *baseline = map.nodes().len();
                reclaimed = true;
            }
        }
        if reclaimed {
            self.complete_map_subtrees.clear();
        }
        Ok(())
    }
}

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
