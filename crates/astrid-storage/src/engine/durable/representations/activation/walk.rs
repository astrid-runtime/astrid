//! Carry authenticated child outcomes only along the current traversal path.
use std::collections::BTreeSet;

use super::{Blake3PhysicalIdentity, CompleteNodes, DurableError, MetadataFrame, NodePresence};
use crate::engine::durable::representations::node_view::MapView;
use crate::storage_model::{PhysicalMapNode, PhysicalMapNodeId};

struct Frame {
    id: PhysicalMapNodeId,
    node: PhysicalMapNode,
    next_child: usize,
    children_complete: bool,
}

impl Frame {
    fn next_child(&mut self) -> Option<PhysicalMapNodeId> {
        let child = match &self.node {
            PhysicalMapNode::Branch { zero, one, .. } => match self.next_child {
                0 => Some(*zero),
                1 => Some(*one),
                _ => None,
            },
            PhysicalMapNode::Radix { children, .. } => children.get(self.next_child).copied(),
            PhysicalMapNode::Leaf { .. } | PhysicalMapNode::Page { .. } => None,
        };
        if child.is_some() {
            self.next_child = self.next_child.strict_add(1);
        }
        child
    }

    fn finish(
        self,
        metadata: &mut Vec<MetadataFrame>,
        durable: &impl NodePresence,
        appended: &mut BTreeSet<PhysicalMapNodeId>,
        complete: &mut impl CompleteNodes,
    ) -> Result<bool, DurableError> {
        // The exclusive engine borrow keeps this authenticated membership
        // result valid through proof admission and metadata construction.
        let persisted = durable.has_node(&self.id)?;
        let proven = persisted && self.children_complete;
        if proven {
            complete.remember(self.id)?;
        }
        if !persisted && !appended.contains(&self.id) {
            metadata.push(MetadataFrame::map_node(
                &Blake3PhysicalIdentity,
                &self.node,
            )?);
            appended.insert(self.id);
        }
        Ok(proven)
    }
}

pub(in crate::engine::durable::representations) fn append_new_reachable_map_nodes(
    metadata: &mut Vec<MetadataFrame>,
    map: &(impl MapView + ?Sized),
    durable: &impl NodePresence,
    appended: &mut BTreeSet<PhysicalMapNodeId>,
    complete: &mut impl CompleteNodes,
) -> Result<usize, DurableError> {
    let mut next = map.view_root();
    let mut path: Vec<Frame> = Vec::new();
    let mut visited = BTreeSet::new();
    while next.is_some() || !path.is_empty() {
        if let Some(id) = next.take() {
            let proven = complete.complete(&id)?;
            if proven || !visited.insert(id) {
                note_child(&mut path, proven);
            } else {
                path.push(Frame {
                    id,
                    node: map.view_node(id)?,
                    next_child: 0,
                    children_complete: true,
                });
            }
        } else if let Some(child) = path.last_mut().and_then(Frame::next_child) {
            next = Some(child);
        } else {
            let frame = path.pop().ok_or(DurableError::InvalidRepresentationState(
                "physical closure traversal lost its parent",
            ))?;
            // A newly emitted child is not a durable closure proof. Only an
            // authenticated existing proof or successful remember yields true.
            let proven = frame.finish(metadata, durable, appended, complete)?;
            note_child(&mut path, proven);
        }
    }
    Ok(visited.len())
}

fn note_child(path: &mut [Frame], proven: bool) {
    if let Some(parent) = path.last_mut() {
        parent.children_complete &= proven;
    }
}

#[cfg(test)]
mod tests;
