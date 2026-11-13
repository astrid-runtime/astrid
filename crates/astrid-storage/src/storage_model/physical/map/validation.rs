//! Prove the canonical root using the production builders without retaining
//! another node arena or cloning the complete leaf payload set.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec;
use alloc::vec::Vec;

use super::{
    MapConstruction, PhysicalIdentity, PhysicalMapDomain, PhysicalMapKey, PhysicalMapNode,
    PhysicalMapNodeId, PhysicalModelError, legacy, radix,
};

/// Canonical construction can retain nodes or only check and discard them.
/// The validation sink borrows the input graph; it owns no second arena.
pub(super) trait CanonicalNodeSink {
    type Error: From<PhysicalModelError>;

    fn put(
        &mut self,
        id: PhysicalMapNodeId,
        canonical_bytes: &[u8],
        node: PhysicalMapNode,
    ) -> Result<(), Self::Error>;
}

impl CanonicalNodeSink for BTreeMap<PhysicalMapNodeId, PhysicalMapNode> {
    type Error = PhysicalModelError;

    fn put(
        &mut self,
        id: PhysicalMapNodeId,
        _canonical_bytes: &[u8],
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

/// A complete canonical proof borrowing its immutable leaf values. Construction
/// is private so callers cannot supply emitter bookkeeping as reachability proof.
pub(crate) struct CanonicalRootProof<'a> {
    visited: BTreeSet<PhysicalMapNodeId>,
    entries: Vec<(PhysicalMapKey, &'a [u8])>,
}

impl<'a> CanonicalRootProof<'a> {
    pub(crate) fn visited(&self) -> &BTreeSet<PhysicalMapNodeId> {
        &self.visited
    }
    pub(crate) fn entries(&self) -> &[(PhysicalMapKey, &'a [u8])] {
        &self.entries
    }
}

pub(super) fn validate_root<I: PhysicalIdentity>(
    identity: &I,
    domain: PhysicalMapDomain,
    root: Option<PhysicalMapNodeId>,
    nodes: &BTreeMap<PhysicalMapNodeId, PhysicalMapNode>,
) -> Result<u64, PhysicalModelError> {
    let proof = prove_root(identity, domain, root, nodes)?;
    u64::try_from(proof.entries.len()).map_err(|_| PhysicalModelError::LengthOverflow)
}

pub(super) fn prove_root<'a, I: PhysicalIdentity>(
    identity: &I,
    domain: PhysicalMapDomain,
    root: Option<PhysicalMapNodeId>,
    nodes: &'a BTreeMap<PhysicalMapNodeId, PhysicalMapNode>,
) -> Result<CanonicalRootProof<'a>, PhysicalModelError> {
    let proof = walk_root(domain, root, nodes)?;
    validate_canonical_root(
        identity,
        domain,
        root,
        nodes,
        &proof.entries,
        &mut ValidationNodes(nodes),
    )?;
    Ok(proof)
}

/// Stream canonical bytes only after their corresponding live body matches.
/// Partial callback effects are private; this function grants no publication right.
pub(super) fn prove_root_into<'a, I: PhysicalIdentity, E: From<PhysicalModelError>>(
    identity: &I,
    domain: PhysicalMapDomain,
    root: Option<PhysicalMapNodeId>,
    nodes: &'a BTreeMap<PhysicalMapNodeId, PhysicalMapNode>,
    expected_count: u64,
    emit: impl FnMut(PhysicalMapNodeId, &[u8]) -> Result<(), E>,
) -> Result<CanonicalRootProof<'a>, E> {
    let proof = walk_root(domain, root, nodes)?;
    if u64::try_from(proof.entries.len()).map_err(|_| PhysicalModelError::LengthOverflow)?
        != expected_count
    {
        return Err(PhysicalModelError::InvalidMap(
            "live physical map count disagrees with canonical validation",
        )
        .into());
    }
    let mut sink = StreamingValidationNodes {
        nodes,
        generated: BTreeSet::new(),
        emit,
    };
    validate_canonical_root(identity, domain, root, nodes, &proof.entries, &mut sink)?;
    ensure_generated_matches_walk(&sink.generated, &proof.visited)?;
    Ok(proof)
}

fn walk_root(
    domain: PhysicalMapDomain,
    root: Option<PhysicalMapNodeId>,
    nodes: &BTreeMap<PhysicalMapNodeId, PhysicalMapNode>,
) -> Result<CanonicalRootProof<'_>, PhysicalModelError> {
    let Some(root) = root else {
        return Ok(CanonicalRootProof {
            visited: BTreeSet::new(),
            entries: Vec::new(),
        });
    };
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
    Ok(CanonicalRootProof { visited, entries })
}

fn validate_canonical_root<I: PhysicalIdentity, N: CanonicalNodeSink>(
    identity: &I,
    domain: PhysicalMapDomain,
    root: Option<PhysicalMapNodeId>,
    nodes: &BTreeMap<PhysicalMapNodeId, PhysicalMapNode>,
    entries: &[(PhysicalMapKey, &[u8])],
    sink: &mut N,
) -> Result<(), N::Error> {
    let Some(root) = root else {
        return Ok(());
    };
    let construction = nodes
        .get(&root)
        .ok_or(PhysicalModelError::InvalidMap("missing map root"))?
        .construction();
    let canonical = match construction {
        MapConstruction::LegacyBinary => legacy::build(identity, domain, entries, sink)?,
        MapConstruction::DenseRadix => radix::build(identity, domain, entries, sink)?,
    };
    if canonical != root {
        return Err(
            PhysicalModelError::InvalidMap("node graph is not the unique canonical trie").into(),
        );
    }
    Ok(())
}

fn ensure_generated_matches_walk(
    generated: &BTreeSet<PhysicalMapNodeId>,
    walked: &BTreeSet<PhysicalMapNodeId>,
) -> Result<(), PhysicalModelError> {
    if generated != walked {
        return Err(PhysicalModelError::InvalidMap(
            "canonical generated nodes disagree with walked closure",
        ));
    }
    Ok(())
}

struct StreamingValidationNodes<'a, F> {
    nodes: &'a BTreeMap<PhysicalMapNodeId, PhysicalMapNode>,
    generated: BTreeSet<PhysicalMapNodeId>,
    emit: F,
}

impl<E: From<PhysicalModelError>, F: FnMut(PhysicalMapNodeId, &[u8]) -> Result<(), E>>
    CanonicalNodeSink for StreamingValidationNodes<'_, F>
{
    type Error = E;

    fn put(
        &mut self,
        id: PhysicalMapNodeId,
        canonical_bytes: &[u8],
        node: PhysicalMapNode,
    ) -> Result<(), E> {
        // Body equality precedes every callback, including IDs already emitted
        // from another map. An identity alone cannot authorize deduplication.
        ValidationNodes(self.nodes).put(id, canonical_bytes, node)?;
        if !self.generated.insert(id) {
            return Err(PhysicalModelError::InvalidMap(
                "canonical builder repeated a generated node",
            )
            .into());
        }
        (self.emit)(id, canonical_bytes)
    }
}

/// Each production-built node is hashed, then must exist under that identity
/// with the exact same body in the untrusted input. Root equality therefore
/// binds its complete canonical closure without hashing the input graph twice.
/// Missing canonical nodes and unequal colliding bodies both fail closed. The
/// builders remain shared with ordinary creation, not a second shape oracle.
struct ValidationNodes<'a>(&'a BTreeMap<PhysicalMapNodeId, PhysicalMapNode>);

impl CanonicalNodeSink for ValidationNodes<'_> {
    type Error = PhysicalModelError;

    fn put(
        &mut self,
        id: PhysicalMapNodeId,
        _canonical_bytes: &[u8],
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
