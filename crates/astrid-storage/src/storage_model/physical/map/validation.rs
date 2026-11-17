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

    fn put_encoded<R>(
        &mut self,
        id: PhysicalMapNodeId,
        canonical_bytes: &[u8],
        retain: R,
    ) -> Result<(), Self::Error>
    where
        R: FnOnce() -> Result<PhysicalMapNode, PhysicalModelError>,
    {
        self.put(id, canonical_bytes, retain()?)
    }
}

impl<N> CanonicalNodeSink for BTreeMap<PhysicalMapNodeId, N>
where
    N: core::borrow::Borrow<PhysicalMapNode> + From<PhysicalMapNode>,
{
    type Error = PhysicalModelError;

    fn put(
        &mut self,
        id: PhysicalMapNodeId,
        _canonical_bytes: &[u8],
        node: PhysicalMapNode,
    ) -> Result<(), PhysicalModelError> {
        match self.entry(id) {
            alloc::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(N::from(node));
                Ok(())
            },
            alloc::collections::btree_map::Entry::Occupied(entry)
                if entry.get().borrow() == &node =>
            {
                Ok(())
            },
            alloc::collections::btree_map::Entry::Occupied(_) => Err(
                PhysicalModelError::InvalidMap("physical map-node identity collision"),
            ),
        }
    }

    fn put_encoded<R>(
        &mut self,
        id: PhysicalMapNodeId,
        canonical_bytes: &[u8],
        retain: R,
    ) -> Result<(), PhysicalModelError>
    where
        R: FnOnce() -> Result<PhysicalMapNode, PhysicalModelError>,
    {
        match self.entry(id) {
            alloc::collections::btree_map::Entry::Occupied(entry) => {
                check_node_encoded(entry.get().borrow(), canonical_bytes)
            },
            alloc::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(N::from(retain()?));
                Ok(())
            },
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

    /// Consume one root proof into its reachability set and borrowed leaves.
    ///
    /// Checkpoint adoption merges the three visited sets into one tip set and
    /// retains only the entry borrows for semantic agreement. Keeping both the
    /// per-root sets and the union would duplicate the same IDs in memory.
    #[cfg(any(test, not(target_family = "wasm")))]
    pub(crate) fn into_parts(
        self,
    ) -> (BTreeSet<PhysicalMapNodeId>, Vec<(PhysicalMapKey, &'a [u8])>) {
        (self.visited, self.entries)
    }
}

pub(super) fn validate_root<I, N>(
    identity: &I,
    domain: PhysicalMapDomain,
    root: Option<PhysicalMapNodeId>,
    nodes: &BTreeMap<PhysicalMapNodeId, N>,
) -> Result<u64, PhysicalModelError>
where
    I: PhysicalIdentity,
    N: core::borrow::Borrow<PhysicalMapNode>,
{
    let proof = prove_root(identity, domain, root, nodes)?;
    u64::try_from(proof.entries.len()).map_err(|_| PhysicalModelError::LengthOverflow)
}

pub(super) fn prove_root<'a, I, N>(
    identity: &I,
    domain: PhysicalMapDomain,
    root: Option<PhysicalMapNodeId>,
    nodes: &'a BTreeMap<PhysicalMapNodeId, N>,
) -> Result<CanonicalRootProof<'a>, PhysicalModelError>
where
    I: PhysicalIdentity,
    N: core::borrow::Borrow<PhysicalMapNode>,
{
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

/// Emit already-authenticated live bodies after an active-closure walk.
///
/// Typed maps use this for automatic sealing so the writer critical section does
/// not rebuild the unique trie or re-identify every node. Cold recovery and
/// compaction retain independent [`prove_root`] / reconstructing consumers.
pub(super) fn encode_live_root_into<E, N>(
    domain: PhysicalMapDomain,
    root: Option<PhysicalMapNodeId>,
    nodes: &BTreeMap<PhysicalMapNodeId, N>,
    expected_count: u64,
    mut emit: impl FnMut(PhysicalMapNodeId, &[u8]) -> Result<(), E>,
) -> Result<CanonicalRootProof<'_>, E>
where
    E: From<PhysicalModelError>,
    N: core::borrow::Borrow<PhysicalMapNode>,
{
    let proof = walk_root(domain, root, nodes)?;
    if u64::try_from(proof.entries.len()).map_err(|_| PhysicalModelError::LengthOverflow)?
        != expected_count
    {
        return Err(PhysicalModelError::InvalidMap(
            "live physical map count disagrees with canonical validation",
        )
        .into());
    }
    let mut encoded = Vec::new();
    for id in &proof.visited {
        let node = nodes
            .get(id)
            .ok_or(PhysicalModelError::InvalidMap("missing map node"))?;
        node.borrow().encode_to_buffer(&mut encoded)?;
        emit(*id, encoded.as_slice())?;
    }
    Ok(proof)
}

pub(super) fn walk_root<N>(
    domain: PhysicalMapDomain,
    root: Option<PhysicalMapNodeId>,
    nodes: &BTreeMap<PhysicalMapNodeId, N>,
) -> Result<CanonicalRootProof<'_>, PhysicalModelError>
where
    N: core::borrow::Borrow<PhysicalMapNode>,
{
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
            .ok_or(PhysicalModelError::InvalidMap("missing map node"))?
            .borrow();
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

fn validate_canonical_root<I, MapN, Sink>(
    identity: &I,
    domain: PhysicalMapDomain,
    root: Option<PhysicalMapNodeId>,
    nodes: &BTreeMap<PhysicalMapNodeId, MapN>,
    entries: &[(PhysicalMapKey, &[u8])],
    sink: &mut Sink,
) -> Result<(), Sink::Error>
where
    I: PhysicalIdentity,
    MapN: core::borrow::Borrow<PhysicalMapNode>,
    Sink: CanonicalNodeSink,
{
    let Some(root) = root else {
        return Ok(());
    };
    let construction = nodes
        .get(&root)
        .ok_or(PhysicalModelError::InvalidMap("missing map root"))?
        .borrow()
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

/// Each production-built node is hashed, then must exist under that identity
/// with the exact same body in the untrusted input. Root equality therefore
/// binds its complete canonical closure without hashing the input graph twice.
/// Missing canonical nodes and unequal colliding bodies both fail closed. The
/// builders remain shared with ordinary creation, not a second shape oracle.
struct ValidationNodes<'a, N>(&'a BTreeMap<PhysicalMapNodeId, N>);

impl<N> CanonicalNodeSink for ValidationNodes<'_, N>
where
    N: core::borrow::Borrow<PhysicalMapNode>,
{
    type Error = PhysicalModelError;

    fn put(
        &mut self,
        id: PhysicalMapNodeId,
        _canonical_bytes: &[u8],
        node: PhysicalMapNode,
    ) -> Result<(), PhysicalModelError> {
        match self.0.get(&id) {
            Some(existing) if existing.borrow() == &node => Ok(()),
            Some(_) => Err(PhysicalModelError::InvalidMap(
                "physical map-node identity collision",
            )),
            None => Err(PhysicalModelError::InvalidMap("missing canonical map node")),
        }
    }

    fn put_encoded<R>(
        &mut self,
        id: PhysicalMapNodeId,
        canonical_bytes: &[u8],
        _retain: R,
    ) -> Result<(), PhysicalModelError>
    where
        R: FnOnce() -> Result<PhysicalMapNode, PhysicalModelError>,
    {
        check_live_encoded(self.0, id, canonical_bytes)
    }
}

pub(super) fn check_node_encoded(
    existing: &PhysicalMapNode,
    canonical_bytes: &[u8],
) -> Result<(), PhysicalModelError> {
    match existing.matches_encoded(canonical_bytes) {
        Ok(()) => Ok(()),
        Err(PhysicalModelError::NonCanonicalEncoding) => Err(PhysicalModelError::InvalidMap(
            "physical map-node identity collision",
        )),
        Err(error) => Err(error),
    }
}

fn check_live_encoded<N>(
    nodes: &BTreeMap<PhysicalMapNodeId, N>,
    id: PhysicalMapNodeId,
    canonical_bytes: &[u8],
) -> Result<(), PhysicalModelError>
where
    N: core::borrow::Borrow<PhysicalMapNode>,
{
    match nodes.get(&id) {
        Some(existing) => check_node_encoded(existing.borrow(), canonical_bytes),
        None => Err(PhysicalModelError::InvalidMap("missing canonical map node")),
    }
}

#[cfg(test)]
mod tests;
