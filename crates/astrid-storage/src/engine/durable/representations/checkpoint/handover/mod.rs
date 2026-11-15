//! Bind a worker-validated checkpoint to the still-fenced live writer tip.

use std::collections::BTreeSet;

use crate::storage_model::{CanonicalPhysicalMap, PhysicalMapNode};

use super::super::{DurableError, RepresentationStore};

impl RepresentationStore {
    /// The worker has already validated framing, canonical closures and full
    /// semantic associations, including all replayed direct transitions. This
    /// final fence binds that result to the actual live state without another
    /// decode/hash/rebuild of the complete catalogue in the writer.
    ///
    /// This remains linear in live nodes and reverse entries; it is not an
    /// O(delta) or constant-time publication claim. End-to-end matched latency
    /// must accept that comparison before this path can be released.
    pub(in crate::engine::durable) fn verify_checkpoint_tip(
        &self,
        prepared: &Self,
    ) -> Result<(), DurableError> {
        if self.active != prepared.active
            || self.state != prepared.state
            || self.catalogue != prepared.catalogue
            || self.placements != prepared.placements
            || self.direct_profile != prepared.direct_profile
            || self.reverse != prepared.reverse
        {
            return Err(disagreement());
        }
        let live_maps = [
            self.profiles.as_canonical(),
            self.representations.as_canonical(),
            self.placement_entries.as_canonical(),
        ];
        for (live, prepared) in live_maps.into_iter().zip([
            prepared.profiles.as_canonical(),
            prepared.representations.as_canonical(),
            prepared.placement_entries.as_canonical(),
        ]) {
            verify_map_bodies(live, prepared, live_maps)?;
        }
        Ok(())
    }
}

fn disagreement() -> DurableError {
    DurableError::InvalidRepresentationState(
        "prepared checkpoint disagrees with the live writer tip",
    )
}

fn verify_map_bodies(
    live: &CanonicalPhysicalMap,
    prepared: &CanonicalPhysicalMap,
    live_maps: [&CanonicalPhysicalMap; 3],
) -> Result<(), DurableError> {
    if live.domain() != prepared.domain()
        || live.root() != prepared.root()
        || live.entry_count() != prepared.entry_count()
    {
        return Err(disagreement());
    }
    let mut pending: Vec<_> = prepared.root().into_iter().collect();
    let mut visited = BTreeSet::new();
    while let Some(id) = pending.pop() {
        if !visited.insert(id) {
            continue;
        }
        let node = prepared.nodes().get(&id).ok_or_else(disagreement)?;
        if live.nodes().get(&id) != Some(node) {
            return Err(disagreement());
        }
        // A shadow body under the same identity in another arena must not be
        // hidden by selecting the first matching domain. This includes aliases
        // that are currently unreachable in the other map.
        for map in live_maps {
            if let Some(alias) = map.nodes().get(&id)
                && alias != node
            {
                return Err(disagreement());
            }
        }
        match node {
            PhysicalMapNode::Branch { zero, one, .. } => {
                pending.push(*one);
                pending.push(*zero);
            },
            PhysicalMapNode::Radix { children, .. } => {
                pending.extend(children.iter().copied());
            },
            PhysicalMapNode::Leaf { .. } | PhysicalMapNode::Page { .. } => {},
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
