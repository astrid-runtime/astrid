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
    measured_history: usize,
}

impl MapResidency {
    pub(super) fn new(
        profiles: &impl super::node_view::MapView,
        representations: &impl super::node_view::MapView,
        placements: &impl super::node_view::MapView,
        measured_history: usize,
    ) -> Result<Self, DurableError> {
        Ok(Self {
            profiles: super::node_view::node_count(profiles)?,
            representations: super::node_view::node_count(representations)?,
            placements: super::node_view::node_count(placements)?,
            measured_history,
        })
    }

    /// Recover exactly the active closures before using their retained lengths.
    /// Generic canonical maps may also contain unreachable historical nodes;
    /// only this constructor owns the reachability walk establishing these counts.
    pub(super) fn recover<N: crate::storage_model::PhysicalMapNodes>(
        roots: [Option<PhysicalMapNodeId>; 3],
        arena: &N,
        measured_history: usize,
    ) -> Result<(Self, [CanonicalPhysicalMap; 3]), DurableError>
    where
        N::Error: Into<DurableError>,
    {
        let [profile, representation, placement] = roots;
        let profiles = recover_active_map(PhysicalMapDomain::Profile, profile, arena)?;
        let representations =
            recover_active_map(PhysicalMapDomain::Representation, representation, arena)?;
        let placements = recover_active_map(PhysicalMapDomain::Placement, placement, arena)?;
        // Each successful recovery collected exactly its root closure and ran
        // the production canonical validator. Counting the retained nodes needs
        // no additional decoding, cloning, hashing or ordered-entry traversal.
        let residency = Self {
            profiles: profiles.nodes().len(),
            representations: representations.nodes().len(),
            placements: placements.nodes().len(),
            measured_history,
        };
        Ok((residency, [profiles, representations, placements]))
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
        // Cold views own no decoded historical nodes. Re-measure the active
        // closure only after geometric catalogue growth, preserving checkpoint
        // scheduling without keeping another resident membership set.
        if self
            .persisted_map_nodes
            .len()
            .saturating_sub(self.residency.measured_history)
            > self.residency.total()
        {
            // Scope page authentication to this immutable count, as in checkpoint
            // traversal. Node bodies are still fetched and verified on each read.
            let nodes = self.persisted_map_nodes.memoized_nodes();
            self.residency = MapResidency::new(
                &self.profiles.with_node_provider(&nodes),
                &self.representations.with_node_provider(&nodes),
                &self.placement_entries.with_node_provider(&nodes),
                self.persisted_map_nodes.len(),
            )?;
        }
        Ok(())
    }
}

pub(super) fn recover_active_map<N: crate::storage_model::PhysicalMapNodes>(
    domain: PhysicalMapDomain,
    root: Option<PhysicalMapNodeId>,
    arena: &N,
) -> Result<CanonicalPhysicalMap, DurableError>
where
    N::Error: Into<DurableError>,
{
    let mut nodes = BTreeMap::new();
    let mut pending = root.into_iter().collect::<Vec<_>>();
    while let Some(id) = pending.pop() {
        if nodes.contains_key(&id) {
            continue;
        }
        let node = arena
            .node(id)
            .map_err(Into::into)?
            .ok_or(DurableError::InvalidRepresentationState(
                "active physical map closure is incomplete",
            ))?
            .into_owned();
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
