//! Residency of an active view is independent of durable historical roots.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use super::{CanonicalPhysicalMap, PhysicalMapNode, PhysicalModelError};

impl CanonicalPhysicalMap {
    /// Discard unreachable nodes from a runtime view after its new root is durable.
    /// Historical roots must be recovered from durable metadata rather than this
    /// view. Ordinary model insertions continue to retain their historical nodes.
    pub(crate) fn reclaim_unreachable_nodes(&mut self) -> Result<(), PhysicalModelError> {
        let mut retained = BTreeSet::new();
        let mut pending = self.root.into_iter().collect::<Vec<_>>();
        while let Some(id) = pending.pop() {
            if !retained.insert(id) {
                return Err(PhysicalModelError::InvalidMap(
                    "node is cyclic or shared by two parents",
                ));
            }
            let node = self
                .nodes
                .get(&id)
                .ok_or(PhysicalModelError::InvalidMap("missing active map node"))?;
            match node {
                PhysicalMapNode::Branch { zero, one, .. } => pending.extend([*zero, *one]),
                PhysicalMapNode::Radix { children, .. } => pending.extend(children.iter().copied()),
                PhysicalMapNode::Leaf { .. } | PhysicalMapNode::Page { .. } => {},
            }
        }
        self.nodes.retain(|id, _| retained.contains(id));
        Ok(())
    }
}

#[cfg(test)]
mod tests;
