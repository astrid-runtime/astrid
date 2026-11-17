//! Residency of an active view is independent of durable historical roots.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use core::borrow::Borrow;

use super::{CanonicalPhysicalMap, PhysicalMapNode, PhysicalMapNodeId, PhysicalModelError};

#[cfg(test)]
std::thread_local! {
    static RECLAIM_WALKS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

impl<N> CanonicalPhysicalMap<N>
where
    N: Borrow<PhysicalMapNode>,
{
    /// Discard unreachable nodes from a runtime view after its new root is durable.
    /// Historical roots must be recovered from durable metadata rather than this
    /// view. Ordinary model insertions continue to retain their historical nodes.
    pub(crate) fn reclaim_unreachable_nodes(&mut self) -> Result<(), PhysicalModelError> {
        #[cfg(test)]
        RECLAIM_WALKS.with(|count| count.set(count.get().strict_add(1)));
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
                .ok_or(PhysicalModelError::InvalidMap("missing active map node"))?
                .borrow();
            match node {
                PhysicalMapNode::Branch { zero, one, .. } => pending.extend([*zero, *one]),
                PhysicalMapNode::Radix { children, .. } => pending.extend(children.iter().copied()),
                PhysicalMapNode::Leaf { .. } | PhysicalMapNode::Page { .. } => {},
            }
        }
        // Successful closure validation proves every retained ID is in nodes.
        // Both iterators ascend, so each match consumes the next reachable ID.
        let mut retained = retained.into_iter().peekable();
        self.nodes
            .retain(|id, _| retained.next_if(|reachable| reachable == id).is_some());
        Ok(())
    }

    /// Keep a proposed closed subset without reconstructing another visited set.
    ///
    /// This preserves an already-authenticated map, rather than authenticating
    /// supplied IDs. Check the actual root and every retained edge before any
    /// mutation, so even an invented subset cannot remove reachable nodes.
    /// Domain filtering excludes foreign aliases in a union of typed closures.
    pub(super) fn retain_closed_nodes(
        &mut self,
        retained: &BTreeSet<PhysicalMapNodeId>,
    ) -> Result<(), PhysicalModelError> {
        let Some(root) = self.root else {
            self.nodes.clear();
            return Ok(());
        };
        let domain = self.domain;
        let keeps = |id: &PhysicalMapNodeId| {
            retained.contains(id)
                && self
                    .nodes
                    .get(id)
                    .is_some_and(|node| node.borrow().domain() == domain)
        };
        if !keeps(&root) {
            return Err(PhysicalModelError::InvalidMap(
                "closed map subset omits current root",
            ));
        }
        let mut selected = retained.iter().peekable();
        for (id, body) in &self.nodes {
            let node = body.borrow();
            if !take_matching_id(&mut selected, id) || node.domain() != domain {
                continue;
            }
            let closed = match node {
                PhysicalMapNode::Branch { zero, one, .. } => keeps(zero) && keeps(one),
                PhysicalMapNode::Radix { children, .. } => children.iter().all(&keeps),
                PhysicalMapNode::Leaf { .. } | PhysicalMapNode::Page { .. } => true,
            };
            if !closed {
                return Err(PhysicalModelError::InvalidMap(
                    "closed map subset omits an active child",
                ));
            }
        }
        let mut selected = retained.iter().peekable();
        self.nodes.retain(|id, node| {
            take_matching_id(&mut selected, id)
                && <N as Borrow<PhysicalMapNode>>::borrow(node).domain() == domain
        });
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn reclaim_walks_for_test() -> usize {
        RECLAIM_WALKS.with(core::cell::Cell::get)
    }

    #[cfg(test)]
    pub(crate) fn corrupt_root_for_reclaim_fault(&mut self, root: super::PhysicalMapNodeId) {
        self.root = Some(root);
    }
}

// Both the arena and the supplied union ascend. Skip union IDs belonging to
// other maps without allocating a per-map set or searching once per arena node.
fn take_matching_id(
    selected: &mut core::iter::Peekable<alloc::collections::btree_set::Iter<'_, PhysicalMapNodeId>>,
    id: &PhysicalMapNodeId,
) -> bool {
    while selected.peek().is_some_and(|candidate| *candidate < id) {
        selected.next();
    }
    selected.next_if(|candidate| *candidate == id).is_some()
}

#[cfg(test)]
mod tests;
