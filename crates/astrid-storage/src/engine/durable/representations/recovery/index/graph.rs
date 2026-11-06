//! Interned historical closure links, scoped to one immutable metadata replay.

use std::collections::HashMap;
use std::ops::Range;

use super::{DurableError, MetadataFrameOffset, PhysicalMapNodeId};

#[cfg(test)]
mod tests;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NodeIndex(usize);

#[derive(Debug)]
pub(in crate::engine::durable::representations::recovery) struct RecoveredMapNode {
    pub(in crate::engine::durable::representations::recovery) offset: MetadataFrameOffset,
    children: Range<usize>,
}

#[derive(Clone, Copy, Default)]
enum NodeBody {
    #[default]
    Unresolved,
    Available(MetadataFrameOffset),
    Consumed,
}

#[derive(Default)]
struct NodeDescriptor {
    body: NodeBody,
    children: Range<usize>,
}

/// Each ID is retained once; forward references occupy unresolved slots.
/// `HashMap` deliberately keeps its default randomized, keyed hasher because
/// metadata identities originate from untrusted durable input.
#[derive(Default)]
pub(in crate::engine::durable::representations::recovery) struct HistoricalMapGraph {
    indices: HashMap<PhysicalMapNodeId, NodeIndex>,
    nodes: Vec<NodeDescriptor>,
    edges: Vec<NodeIndex>,
    resolved: usize,
}

impl HistoricalMapGraph {
    pub(in crate::engine::durable::representations::recovery) const fn len(&self) -> usize {
        self.resolved
    }

    pub(in crate::engine::durable::representations::recovery) fn offset(
        &self,
        id: &PhysicalMapNodeId,
    ) -> Option<MetadataFrameOffset> {
        self.indices.get(id).and_then(|index| {
            if let NodeBody::Available(offset) = self.nodes[index.0].body {
                Some(offset)
            } else {
                None
            }
        })
    }

    /// Resolve a unique authenticated body after the caller checks duplicates
    /// against their exact original frame bytes. Existing bodies cannot change.
    pub(in crate::engine::durable::representations::recovery) fn insert(
        &mut self,
        id: PhysicalMapNodeId,
        offset: MetadataFrameOffset,
        children: &[PhysicalMapNodeId],
    ) -> Result<(), DurableError> {
        if self
            .indices
            .get(&id)
            .is_some_and(|index| !matches!(self.nodes[index.0].body, NodeBody::Unresolved))
        {
            return Err(DurableError::InvalidRepresentationState(
                "historical map node is already resolved",
            ));
        }
        let additional = children
            .len()
            .checked_add(1)
            .ok_or(DurableError::EncodingOverflow)?;
        // Reserve before interning so a capacity error cannot publish a partial
        // node. Native usize indices cover every addressable entry and edge.
        self.indices
            .try_reserve(additional)
            .map_err(|_| DurableError::EncodingOverflow)?;
        self.nodes
            .try_reserve(additional)
            .map_err(|_| DurableError::EncodingOverflow)?;
        self.edges
            .try_reserve(children.len())
            .map_err(|_| DurableError::EncodingOverflow)?;
        let index = self.intern(id);
        let start = self.edges.len();
        for child in children {
            let child = self.intern(*child);
            self.edges.push(child);
        }
        let end = self.edges.len();
        self.nodes[index.0] = NodeDescriptor {
            body: NodeBody::Available(offset),
            children: start..end,
        };
        self.resolved = self.resolved.strict_add(1);
        Ok(())
    }

    fn intern(&mut self, id: PhysicalMapNodeId) -> NodeIndex {
        *self.indices.entry(id).or_insert_with(|| {
            let index = NodeIndex(self.nodes.len());
            self.nodes.push(NodeDescriptor::default());
            index
        })
    }

    /// Consume a body location during active-map recovery. Slots and links
    /// remain stable, but this body is no longer available for another take.
    pub(in crate::engine::durable::representations::recovery) fn take(
        &mut self,
        id: &PhysicalMapNodeId,
    ) -> Option<RecoveredMapNode> {
        let index = self.indices.get(id)?;
        let descriptor = &mut self.nodes[index.0];
        let NodeBody::Available(offset) = descriptor.body else {
            return None;
        };
        descriptor.body = NodeBody::Consumed;
        self.resolved = self.resolved.strict_sub(1);
        Some(RecoveredMapNode {
            offset,
            children: descriptor.children.clone(),
        })
    }

    /// Compare the ordered authenticated inventory with the freshly decoded
    /// active body without keeping a second reverse array of 32-byte IDs.
    pub(in crate::engine::durable::representations::recovery) fn matches_children(
        &self,
        node: &RecoveredMapNode,
        children: &[PhysicalMapNodeId],
    ) -> bool {
        self.edges.get(node.children.clone()).is_some_and(|edges| {
            edges.len() == children.len()
                && edges
                    .iter()
                    .zip(children)
                    .all(|(index, id)| self.indices.get(id) == Some(index))
        })
    }

    pub(in crate::engine::durable::representations::recovery) fn closure_checker(
        &self,
    ) -> HistoricalMapClosure<'_> {
        HistoricalMapClosure {
            graph: self,
            status: vec![ClosureStatus::Unknown; self.nodes.len()],
            pending: Vec::new(),
            touched: Vec::new(),
            complete: 0,
            #[cfg(test)]
            visits: 0,
        }
    }

    #[cfg(test)]
    pub(in crate::engine::durable::representations::recovery) fn edge_count(&self) -> usize {
        self.edges.len()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum ClosureStatus {
    Unknown,
    Visiting,
    Complete,
}

/// The shared borrow prevents insert/take from invalidating successful memos.
/// Only the nodes visited by an unsuccessful traversal are reset.
pub(in crate::engine::durable::representations::recovery) struct HistoricalMapClosure<'a> {
    graph: &'a HistoricalMapGraph,
    status: Vec<ClosureStatus>,
    pending: Vec<NodeIndex>,
    touched: Vec<NodeIndex>,
    complete: usize,
    #[cfg(test)]
    visits: usize,
}

impl HistoricalMapClosure<'_> {
    pub(in crate::engine::durable::representations::recovery) const fn len(&self) -> usize {
        self.complete
    }

    #[cfg(test)]
    pub(in crate::engine::durable::representations::recovery) const fn visits(&self) -> usize {
        self.visits
    }

    pub(in crate::engine::durable::representations::recovery) fn complete(
        &mut self,
        root: Option<PhysicalMapNodeId>,
    ) -> bool {
        let Some(root) = root else {
            return true;
        };
        let Some(root) = self.graph.indices.get(&root).copied() else {
            return false;
        };
        self.pending.push(root);
        while let Some(index) = self.pending.pop() {
            if self.status[index.0] != ClosureStatus::Unknown {
                continue;
            }
            self.status[index.0] = ClosureStatus::Visiting;
            self.touched.push(index);
            let node = &self.graph.nodes[index.0];
            if !matches!(node.body, NodeBody::Available(_)) {
                self.finish(false);
                return false;
            }
            #[cfg(test)]
            {
                self.visits = self.visits.strict_add(1);
            }
            // As in the previous visited-set walk, historical cycles terminate
            // and count as complete when every body exists. Active canonical
            // recovery separately rejects cycles and invalid sharing.
            self.pending
                .extend_from_slice(&self.graph.edges[node.children.clone()]);
        }
        self.finish(true);
        true
    }

    fn finish(&mut self, success: bool) {
        let replacement = if success {
            ClosureStatus::Complete
        } else {
            ClosureStatus::Unknown
        };
        if success {
            self.complete = self.complete.strict_add(self.touched.len());
        }
        for index in self.touched.drain(..) {
            self.status[index.0] = replacement;
        }
        self.pending.clear();
    }
}
