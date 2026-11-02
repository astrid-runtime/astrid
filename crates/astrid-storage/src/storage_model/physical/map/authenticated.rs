//! Owned recovery proof minted from newly reread canonical node bytes.

use alloc::collections::BTreeMap;
use alloc::collections::btree_map::Entry;

use super::validation;
use super::{
    CanonicalPhysicalMap, MapConstruction, PhysicalIdentity, PhysicalMapDomain, PhysicalMapNode,
    PhysicalMapNodeId, PhysicalModelError,
};

/// Accumulator that owns only nodes authenticated from their encoded bytes.
///
/// Proof is the owned arena itself: callers cannot insert a raw node and a
/// claimed ID, and finish consumes the accumulator so the same proof cannot
/// be reused after publication. One identity operation is borrowed at
/// construction; authenticate and finish cannot accept a substitute.
#[must_use]
pub(crate) struct AuthenticatedMapRecovery<'a, I: PhysicalIdentity> {
    identity: &'a I,
    domain: PhysicalMapDomain,
    root: Option<PhysicalMapNodeId>,
    nodes: BTreeMap<PhysicalMapNodeId, PhysicalMapNode>,
}

impl<'a, I: PhysicalIdentity> AuthenticatedMapRecovery<'a, I> {
    /// Bind one identity operation to this recovery.
    pub(crate) fn new(
        identity: &'a I,
        domain: PhysicalMapDomain,
        root: Option<PhysicalMapNodeId>,
    ) -> Self {
        Self {
            identity,
            domain,
            root,
            nodes: BTreeMap::new(),
        }
    }

    pub(crate) fn contains(&self, id: PhysicalMapNodeId) -> bool {
        self.nodes.contains_key(&id)
    }

    pub(crate) fn len(&self) -> usize {
        self.nodes.len()
    }

    pub(super) fn identity(&self) -> &I {
        self.identity
    }

    pub(super) fn domain(&self) -> PhysicalMapDomain {
        self.domain
    }

    pub(super) fn root(&self) -> Option<PhysicalMapNodeId> {
        self.root
    }

    pub(super) fn nodes(&self) -> &BTreeMap<PhysicalMapNodeId, PhysicalMapNode> {
        &self.nodes
    }

    /// Decode and identify `encoded` as `expected_id`, then retain that node.
    ///
    /// `encoded` must be the newly reread canonical node body. Occupied equal
    /// bodies are idempotent; unequal bodies at the same ID collide.
    pub(crate) fn authenticate(
        &mut self,
        expected_id: PhysicalMapNodeId,
        encoded: &[u8],
    ) -> Result<&PhysicalMapNode, PhysicalModelError> {
        let (node, computed) = PhysicalMapNode::decode_and_identify(encoded, self.identity)?;
        if computed != expected_id {
            return Err(PhysicalModelError::InvalidMap("map-node identity mismatch"));
        }
        match self.nodes.entry(expected_id) {
            Entry::Vacant(slot) => Ok(slot.insert(node)),
            Entry::Occupied(existing) if existing.get() == &node => Ok(existing.into_mut()),
            Entry::Occupied(_) => Err(PhysicalModelError::InvalidMap(
                "physical map-node identity collision",
            )),
        }
    }

    /// Consume the owned arena and complete canonical rebuild validation.
    ///
    /// The walk still rejects domain, cycle, sharing, missing, and count
    /// errors. It does not re-encode the already authenticated nodes; rebuild
    /// still identifies the builder's emitted nodes against the claimed root.
    pub(crate) fn finish(self) -> Result<CanonicalPhysicalMap, PhysicalModelError> {
        let entry_count = validation::validate_owned_root(&self)?;
        let construction = self
            .root
            .and_then(|root| self.nodes.get(&root))
            .map_or(MapConstruction::DenseRadix, PhysicalMapNode::construction);
        Ok(CanonicalPhysicalMap {
            domain: self.domain,
            construction,
            root: self.root,
            nodes: self.nodes,
            entry_count,
        })
    }
}
