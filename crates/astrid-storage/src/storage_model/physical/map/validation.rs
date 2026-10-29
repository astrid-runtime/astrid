//! Canonical graph validation without retaining a second materialized map.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec;
use alloc::vec::Vec;

use super::{
    PhysicalIdentity, PhysicalMapDomain, PhysicalMapNode, PhysicalMapNodeId, PhysicalModelError,
    build_root,
};

#[cfg(test)]
mod tests;

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
    // Only fixed-width keys and borrowed value slices scale with entry count.
    // The builder owns at most its current node's value copy and encoding;
    // the consuming emitter hashes then drops it instead of retaining an arena.
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
        if node.identify(identity)? != node_id {
            return Err(PhysicalModelError::InvalidMap("map-node identity mismatch"));
        }
        match node {
            PhysicalMapNode::Leaf { key, value, .. } => {
                entries.push((*key, value.as_slice()));
            },
            PhysicalMapNode::Branch { zero, one, .. } => {
                stack.push(*one);
                stack.push(*zero);
            },
            PhysicalMapNode::Page {
                entries: page_entries,
                ..
            } => entries.extend(
                page_entries
                    .iter()
                    .map(|(key, value)| (*key, value.as_slice())),
            ),
            PhysicalMapNode::Radix { children, .. } => {
                stack.extend(children.iter().rev().copied());
            },
        }
    }
    let (rebuilt_root, entry_count) =
        build_root(domain, &mut entries, construction, &mut |node| {
            node.identify(identity)
        })?;
    if rebuilt_root != Some(root) {
        return Err(PhysicalModelError::InvalidMap(
            "node graph is not the unique canonical trie",
        ));
    }
    Ok(entry_count)
}
