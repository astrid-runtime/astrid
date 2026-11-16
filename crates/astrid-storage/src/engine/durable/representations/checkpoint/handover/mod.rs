//! Bind a worker-validated checkpoint to the still-fenced live writer tip.

use crate::storage_model::PhysicalMapNode;
use crate::storage_model::physical::SharedPhysicalMap;

use super::super::{DurableError, RepresentationStore};

#[cfg(test)]
std::thread_local! {
    static NODE_BODY_DEEP_COMPARISONS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

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

/// Node body equality for tip binding only.
///
/// Same immutable allocation is sufficient for equality here. This is not
/// authenticity, identity derivation, or a subtree proof. Callers must still
/// walk roots, enforce counts/domains/cycle bounds, and compare every matching
/// live-arena alias even when roots share an allocation.
fn map_nodes_equal(left: &PhysicalMapNode, right: &PhysicalMapNode) -> bool {
    if core::ptr::eq(left, right) {
        return true;
    }
    #[cfg(test)]
    NODE_BODY_DEEP_COMPARISONS.with(|count| count.set(count.get().strict_add(1)));
    left == right
}

fn verify_map_bodies(
    live: &SharedPhysicalMap,
    prepared: &SharedPhysicalMap,
    live_maps: [&SharedPhysicalMap; 3],
) -> Result<(), DurableError> {
    if live.domain() != prepared.domain()
        || live.root() != prepared.root()
        || live.entry_count() != prepared.entry_count()
    {
        return Err(disagreement());
    }
    let mut pending: Vec<_> = prepared.root().into_iter().collect();
    // Canonical reachable closures are trees: recovery and rebuild reject
    // repeated nodes. The arena can contain historical extras, so its size
    // bounds every valid traversal and also terminates a corrupted cycle.
    let mut remaining = prepared.nodes().len();
    while let Some(id) = pending.pop() {
        remaining = remaining.checked_sub(1).ok_or_else(disagreement)?;
        let node = prepared.nodes().get(&id).ok_or_else(disagreement)?.as_ref();
        match live.nodes().get(&id) {
            Some(live_node) if map_nodes_equal(live_node.as_ref(), node) => {},
            _ => return Err(disagreement()),
        }
        // A shadow body under the same identity in another arena must not be
        // hidden by selecting the first matching domain. This includes aliases
        // that are currently unreachable in the other map.
        for map in live_maps {
            if !std::ptr::eq(map, live)
                && let Some(alias) = map.nodes().get(&id)
                && !map_nodes_equal(alias.as_ref(), node)
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
fn node_body_deep_comparisons_for_test() -> usize {
    NODE_BODY_DEEP_COMPARISONS.with(core::cell::Cell::get)
}

#[cfg(test)]
mod tests;
