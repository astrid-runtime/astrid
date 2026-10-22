//! Keep active map residency independent of durable historical nodes.

use std::collections::BTreeMap;

use crate::storage_model::{
    CanonicalPhysicalMap, PhysicalMapDomain, PhysicalMapNode, PhysicalMapNodeId,
};

use super::DurableError;
use super::RepresentationStore;
use super::format::Blake3PhysicalIdentity;

impl RepresentationStore {
    pub(super) fn reclaim_map_history(&mut self) -> Result<(), DurableError> {
        let mut reclaimed = false;
        for map in [
            &mut self.profiles,
            &mut self.representations,
            &mut self.placement_entries,
        ] {
            // Both canonical constructions have at least two children per
            // internal node, hence at most 2n-1 active nodes for n entries.
            // Collect at twice that bound: at least half the resident nodes
            // are then obsolete, amortizing traversal over path-copy writes.
            // This derives work from live cardinality, not an operator quota.
            let active_bound = map.entry_count().saturating_mul(2).saturating_sub(1);
            if u64::try_from(map.nodes().len()).unwrap_or(u64::MAX) > active_bound.saturating_mul(2)
            {
                map.reclaim_unreachable_nodes()?;
                reclaimed = true;
            }
        }
        if reclaimed {
            // These are disposable traversal proofs. Keeping old proofs after
            // collecting their nodes would retain the same history as IDs.
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
