//! Prove the canonical root using the production builders without retaining
//! another node arena or cloning the complete leaf payload set.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec;
use alloc::vec::Vec;

use super::{
    MapConstruction, PhysicalIdentity, PhysicalMapDomain, PhysicalMapNode, PhysicalMapNodeId,
    PhysicalModelError, legacy, radix,
};

/// Canonical construction can retain nodes or only check and discard them.
/// The validation sink borrows the input graph; it owns no second arena.
pub(super) trait CanonicalNodeSink {
    fn put(
        &mut self,
        id: PhysicalMapNodeId,
        node: PhysicalMapNode,
    ) -> Result<(), PhysicalModelError>;
}

impl CanonicalNodeSink for BTreeMap<PhysicalMapNodeId, PhysicalMapNode> {
    fn put(
        &mut self,
        id: PhysicalMapNodeId,
        node: PhysicalMapNode,
    ) -> Result<(), PhysicalModelError> {
        match self.entry(id) {
            alloc::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(node);
                Ok(())
            },
            alloc::collections::btree_map::Entry::Occupied(entry) if entry.get() == &node => Ok(()),
            alloc::collections::btree_map::Entry::Occupied(_) => Err(
                PhysicalModelError::InvalidMap("physical map-node identity collision"),
            ),
        }
    }
}

pub(super) fn validate_root<I: PhysicalIdentity>(
    identity: &I,
    domain: PhysicalMapDomain,
    root: Option<PhysicalMapNodeId>,
    nodes: &BTreeMap<PhysicalMapNodeId, PhysicalMapNode>,
) -> Result<u64, PhysicalModelError> {
    let Some(root) = root else {
        return Ok(0);
    };
    let construction = nodes
        .get(&root)
        .ok_or(PhysicalModelError::InvalidMap("missing map root"))?
        .construction();
    let mut stack = vec![root];
    let mut visited = BTreeSet::new();
    let mut entries = Vec::new();
    while let Some(node_id) = stack.pop() {
        if !visited.insert(node_id) {
            return Err(PhysicalModelError::InvalidMap(
                "node is cyclic or shared by two parents",
            ));
        }
        let node = nodes
            .get(&node_id)
            .ok_or(PhysicalModelError::InvalidMap("missing map node"))?;
        if node.domain() != domain {
            return Err(PhysicalModelError::InvalidMap("map domain mismatch"));
        }
        match node {
            PhysicalMapNode::Leaf { key, value, .. } => entries.push((*key, value.as_slice())),
            PhysicalMapNode::Branch { zero, one, .. } => {
                stack.push(*one);
                stack.push(*zero);
            },
            PhysicalMapNode::Page { entries: page, .. } => {
                entries.extend(page.iter().map(|(key, value)| (*key, value.as_slice())));
            },
            PhysicalMapNode::Radix { children, .. } => stack.extend(children.iter().rev().copied()),
        }
    }
    entries.sort_unstable_by_key(|(key, _)| *key);
    if entries.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(PhysicalModelError::InvalidMap("duplicate leaf key"));
    }
    let count = u64::try_from(entries.len()).map_err(|_| PhysicalModelError::LengthOverflow)?;
    let mut proof = ValidationNodes(nodes);
    let canonical = match construction {
        MapConstruction::LegacyBinary => legacy::build(identity, domain, &entries, &mut proof)?,
        MapConstruction::DenseRadix => radix::build(identity, domain, &entries, &mut proof)?,
    };
    if canonical != root {
        return Err(PhysicalModelError::InvalidMap(
            "node graph is not the unique canonical trie",
        ));
    }
    Ok(count)
}

/// Each production-built node is hashed, then must exist under that identity
/// with the exact same body in the untrusted input. Root equality therefore
/// binds its complete canonical closure without hashing the input graph twice.
/// Missing canonical nodes and unequal colliding bodies both fail closed. The
/// builders remain shared with ordinary creation, not a second shape oracle.
struct ValidationNodes<'a>(&'a BTreeMap<PhysicalMapNodeId, PhysicalMapNode>);

impl CanonicalNodeSink for ValidationNodes<'_> {
    fn put(
        &mut self,
        id: PhysicalMapNodeId,
        node: PhysicalMapNode,
    ) -> Result<(), PhysicalModelError> {
        match self.0.get(&id) {
            Some(existing) if existing == &node => Ok(()),
            Some(_) => Err(PhysicalModelError::InvalidMap(
                "physical map-node identity collision",
            )),
            None => Err(PhysicalModelError::InvalidMap("missing canonical map node")),
        }
    }
}

#[cfg(test)]
mod tests;
