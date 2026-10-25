//! Complete, fallible traversal shared by resident recovery and cold runtime views.

use super::{DurableError, format::Blake3PhysicalIdentity};
use crate::storage_model::{
    BackedPhysicalMap, CanonicalPhysicalMap, PhysicalMapKey, PhysicalMapNode, PhysicalMapNodeId,
    PhysicalMapNodes,
};

pub(super) trait MapView {
    fn view_root(&self) -> Option<PhysicalMapNodeId>;
    fn view_count(&self) -> u64;
    fn view_node(&self, id: PhysicalMapNodeId) -> Result<PhysicalMapNode, DurableError>;
}

impl MapView for CanonicalPhysicalMap {
    fn view_root(&self) -> Option<PhysicalMapNodeId> {
        self.root()
    }
    fn view_count(&self) -> u64 {
        self.entry_count()
    }
    fn view_node(&self, id: PhysicalMapNodeId) -> Result<PhysicalMapNode, DurableError> {
        self.with_node_provider(self.nodes())
            .node(&Blake3PhysicalIdentity, id)
            .map_err(Into::into)
    }
}
impl<N: PhysicalMapNodes<Error = DurableError>> MapView for BackedPhysicalMap<N> {
    fn view_root(&self) -> Option<PhysicalMapNodeId> {
        self.root()
    }
    fn view_count(&self) -> u64 {
        self.entry_count()
    }
    fn view_node(&self, id: PhysicalMapNodeId) -> Result<PhysicalMapNode, DurableError> {
        self.node(&Blake3PhysicalIdentity, id)
    }
}

pub(super) struct Entries<'a, M: MapView> {
    map: &'a M,
    pending: Vec<(PhysicalMapNodeId, u32)>,
    last: Option<PhysicalMapKey>,
    emitted: u64,
    visited: usize,
    failed: bool,
}
impl<'a, M: MapView> Entries<'a, M> {
    pub(super) fn new(map: &'a M) -> Self {
        Self {
            map,
            pending: map.view_root().map(|id| (id, 0)).into_iter().collect(),
            last: None,
            emitted: 0,
            visited: 0,
            failed: false,
        }
    }
    fn next_entry(&mut self) -> Result<Option<(PhysicalMapKey, Vec<u8>)>, DurableError> {
        while let Some((id, minimum_depth)) = self.pending.pop() {
            self.visited = self
                .visited
                .checked_add(1)
                .ok_or(DurableError::EncodingOverflow)?;
            let entry = match self.map.view_node(id)? {
                PhysicalMapNode::Leaf { key, value, .. } => Some((key, value)),
                PhysicalMapNode::Page { mut entries, .. } => entries.pop(),
                PhysicalMapNode::Branch {
                    prefix_bits,
                    zero,
                    one,
                    ..
                } => {
                    self.push_children(prefix_bits, minimum_depth, 1, [one, zero])?;
                    None
                },
                PhysicalMapNode::Radix {
                    prefix_nibbles,
                    children,
                    ..
                } => {
                    self.push_children(
                        u32::from(prefix_nibbles).strict_mul(4),
                        minimum_depth,
                        4,
                        children.into_iter().rev(),
                    )?;
                    None
                },
            };
            if let Some((key, value)) = entry {
                if self.last.is_some_and(|old| old >= key) {
                    return Err(DurableError::InvalidRepresentationState(
                        "physical entries are not unique and ordered",
                    ));
                }
                self.emitted = self
                    .emitted
                    .checked_add(1)
                    .ok_or(DurableError::EncodingOverflow)?;
                if self.emitted > self.map.view_count() {
                    return Err(DurableError::InvalidRepresentationState(
                        "physical entry count exceeded root",
                    ));
                }
                self.last = Some(key);
                return Ok(Some((key, value)));
            }
        }
        if self.emitted != self.map.view_count() {
            return Err(DurableError::InvalidRepresentationState(
                "physical entry count disagrees with root",
            ));
        }
        Ok(None)
    }
    fn push_children(
        &mut self,
        depth: u32,
        minimum: u32,
        width: u32,
        children: impl IntoIterator<Item = PhysicalMapNodeId>,
    ) -> Result<(), DurableError> {
        if depth < minimum {
            return Err(DurableError::InvalidRepresentationState(
                "physical branch depth did not increase",
            ));
        }
        let next = depth
            .checked_add(width)
            .ok_or(DurableError::EncodingOverflow)?;
        self.pending
            .extend(children.into_iter().map(|id| (id, next)));
        Ok(())
    }
}
impl<M: MapView> Iterator for Entries<'_, M> {
    type Item = Result<(PhysicalMapKey, Vec<u8>), DurableError>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }
        match self.next_entry() {
            Ok(Some(entry)) => Some(Ok(entry)),
            Ok(None) => {
                self.failed = true;
                None
            },
            Err(error) => {
                self.failed = true;
                Some(Err(error))
            },
        }
    }
}

pub(super) fn node_count<M: MapView>(map: &M) -> Result<usize, DurableError> {
    let mut entries = Entries::new(map);
    for entry in entries.by_ref() {
        entry?;
    }
    Ok(entries.visited)
}

/// Emit children before parents using only a bounded path stack. Runtime maps
/// were fully validated before admission; every fetched node is authenticated.
/// Checkpoint verification still validates the complete replacement generation
/// before CURRENT is published.
pub(super) fn visit_nodes<M: MapView>(
    map: &M,
    mut visit: impl FnMut(PhysicalMapNode) -> Result<(), DurableError>,
) -> Result<(), DurableError> {
    let mut pending = map
        .view_root()
        .map(|id| (id, 0_u32, false))
        .into_iter()
        .collect::<Vec<_>>();
    while let Some((id, minimum_depth, expanded)) = pending.pop() {
        let node = map.view_node(id)?;
        if expanded {
            visit(node)?;
            continue;
        }
        let (depth, width, children) = match &node {
            PhysicalMapNode::Branch {
                prefix_bits,
                zero,
                one,
                ..
            } => (*prefix_bits, 1, vec![*one, *zero]),
            PhysicalMapNode::Radix {
                prefix_nibbles,
                children,
                ..
            } => (
                u32::from(*prefix_nibbles).strict_mul(4),
                4,
                children.iter().rev().copied().collect(),
            ),
            PhysicalMapNode::Leaf { .. } | PhysicalMapNode::Page { .. } => {
                visit(node)?;
                continue;
            },
        };
        if depth < minimum_depth || depth >= PhysicalMapKey::SEARCH_BITS {
            return Err(DurableError::InvalidRepresentationState(
                "physical branch depth exceeded its path",
            ));
        }
        pending.push((id, minimum_depth, true));
        pending.extend(
            children
                .into_iter()
                .map(|child| (child, depth.strict_add(width), false)),
        );
    }
    Ok(())
}
