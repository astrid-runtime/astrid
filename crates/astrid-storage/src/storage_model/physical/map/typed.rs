//! Domain-fixed authenticated physical maps for production representation state.
//!
//! Generic [`super::CanonicalPhysicalMap`] erases which physical identity minted
//! a graph and which domain it belongs to. These wrappers close that hole for
//! the three live `RepresentationStore` slots: only fixed-BLAKE3 constructors
//! and mutations exist, and a `ProfileMap` cannot be assigned into a
//! representation or placement slot.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::super::Blake3PhysicalIdentity;
use super::super::PhysicalModelError;
use super::validation::{self, CanonicalRootProof};
use super::{
    CanonicalPhysicalMap, MapConstruction, PhysicalMapDomain, PhysicalMapKey, PhysicalMapNode,
    PhysicalMapNodeId,
};

fn recover_exact_inner(
    domain: PhysicalMapDomain,
    root: Option<PhysicalMapNodeId>,
    nodes: BTreeMap<PhysicalMapNodeId, PhysicalMapNode>,
) -> Result<CanonicalPhysicalMap, PhysicalModelError> {
    let proof = validation::prove_root(&Blake3PhysicalIdentity, domain, root, &nodes)?;
    if proof.visited().len() != nodes.len() {
        return Err(PhysicalModelError::InvalidMap(
            "unauthenticated historical map nodes outside the active closure",
        ));
    }
    let entry_count =
        u64::try_from(proof.entries().len()).map_err(|_| PhysicalModelError::LengthOverflow)?;
    let construction = root
        .and_then(|root| nodes.get(&root))
        .map_or(MapConstruction::DenseRadix, PhysicalMapNode::construction);
    Ok(CanonicalPhysicalMap {
        domain,
        construction,
        root,
        nodes,
        entry_count,
    })
}

macro_rules! typed_map_views {
    ($name:ident, $domain:expr) => {
        impl $name {
            const DOMAIN: PhysicalMapDomain = $domain;

            /// Recover an exact authenticated active closure.
            ///
            /// Rejects unauthenticated historical extras. Callers that already
            /// extracted the exact reachable set (production recovery) pay one
            /// canonical proof; `visited.len()` then checks the arena bound.
            pub(crate) fn recover_exact(
                root: Option<PhysicalMapNodeId>,
                nodes: BTreeMap<PhysicalMapNodeId, PhysicalMapNode>,
            ) -> Result<Self, PhysicalModelError> {
                Ok(Self {
                    inner: recover_exact_inner(Self::DOMAIN, root, nodes)?,
                })
            }

            /// Emit live bodies for automatic sealing without a rebuild storm.
            pub(crate) fn encode_live_into<E: From<PhysicalModelError>>(
                &self,
                emit: impl FnMut(PhysicalMapNodeId, &[u8]) -> Result<(), E>,
            ) -> Result<CanonicalRootProof<'_>, E> {
                validation::encode_live_root_into(
                    Self::DOMAIN,
                    self.inner.root,
                    &self.inner.nodes,
                    self.inner.entry_count,
                    emit,
                )
            }

            /// Independent full canonical proof for cold recovery / compaction /
            /// adversarial tests. Not used by automatic seal.
            #[cfg(test)]
            pub(crate) fn prove_root(&self) -> Result<CanonicalRootProof<'_>, PhysicalModelError> {
                let proof = validation::prove_root(
                    &Blake3PhysicalIdentity,
                    Self::DOMAIN,
                    self.inner.root,
                    &self.inner.nodes,
                )?;
                if u64::try_from(proof.entries().len())
                    .map_err(|_| PhysicalModelError::LengthOverflow)?
                    != self.inner.entry_count
                {
                    return Err(PhysicalModelError::InvalidMap(
                        "live physical map count disagrees with canonical validation",
                    ));
                }
                Ok(proof)
            }

            #[must_use]
            pub(crate) const fn root(&self) -> Option<PhysicalMapNodeId> {
                self.inner.root()
            }

            #[must_use]
            pub(crate) const fn entry_count(&self) -> u64 {
                self.inner.entry_count()
            }

            #[must_use]
            pub(crate) const fn nodes(&self) -> &BTreeMap<PhysicalMapNodeId, PhysicalMapNode> {
                self.inner.nodes()
            }

            #[must_use]
            pub(crate) fn get(&self, key: PhysicalMapKey) -> Option<&[u8]> {
                self.inner.get(key)
            }

            /// Borrow the authenticated generic view for shared read-only helpers.
            #[must_use]
            pub(crate) const fn as_canonical(&self) -> &CanonicalPhysicalMap {
                &self.inner
            }

            pub(crate) fn reclaim_unreachable_nodes(&mut self) -> Result<(), PhysicalModelError> {
                self.inner.reclaim_unreachable_nodes()
            }
        }
    };
}

/// Authenticated profile catalogue map (Blake3, profile domain).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProfileMap {
    inner: CanonicalPhysicalMap,
}

typed_map_views!(ProfileMap, PhysicalMapDomain::Profile);

impl ProfileMap {
    /// Build the dense canonical nibble-radix construction.
    pub(crate) fn build_dense(
        entries: Vec<(PhysicalMapKey, Vec<u8>)>,
    ) -> Result<Self, PhysicalModelError> {
        Ok(Self {
            inner: CanonicalPhysicalMap::build_dense(
                &Blake3PhysicalIdentity,
                Self::DOMAIN,
                entries,
            )?,
        })
    }
}

/// Authenticated representation record map (Blake3, representation domain).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RepresentationMap {
    inner: CanonicalPhysicalMap,
}

typed_map_views!(RepresentationMap, PhysicalMapDomain::Representation);

impl RepresentationMap {
    /// Build the unique legacy canonical trie under the representation domain.
    #[cfg(test)]
    pub(crate) fn build(
        entries: Vec<(PhysicalMapKey, Vec<u8>)>,
    ) -> Result<Self, PhysicalModelError> {
        Ok(Self {
            inner: CanonicalPhysicalMap::build(&Blake3PhysicalIdentity, Self::DOMAIN, entries)?,
        })
    }

    /// Build the dense canonical nibble-radix construction.
    pub(crate) fn build_dense(
        entries: Vec<(PhysicalMapKey, Vec<u8>)>,
    ) -> Result<Self, PhysicalModelError> {
        Ok(Self {
            inner: CanonicalPhysicalMap::build_dense(
                &Blake3PhysicalIdentity,
                Self::DOMAIN,
                entries,
            )?,
        })
    }

    /// Insert one immutable entry by path-copying the affected trie path.
    pub(crate) fn insert(
        &mut self,
        key: PhysicalMapKey,
        value: Vec<u8>,
    ) -> Result<bool, PhysicalModelError> {
        self.inner.insert(&Blake3PhysicalIdentity, key, value)
    }

    /// Rebuild from the complete leaf set after a bulk update.
    pub(crate) fn rebuild_with_entries(
        &mut self,
        additions: Vec<(PhysicalMapKey, Vec<u8>)>,
    ) -> Result<u64, PhysicalModelError> {
        self.inner
            .rebuild_with_entries(&Blake3PhysicalIdentity, additions)
    }
}

/// Authenticated placement entry map (Blake3, placement domain).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PlacementMap {
    inner: CanonicalPhysicalMap,
}

typed_map_views!(PlacementMap, PhysicalMapDomain::Placement);

impl PlacementMap {
    /// Build the dense canonical nibble-radix construction.
    pub(crate) fn build_dense(
        entries: Vec<(PhysicalMapKey, Vec<u8>)>,
    ) -> Result<Self, PhysicalModelError> {
        Ok(Self {
            inner: CanonicalPhysicalMap::build_dense(
                &Blake3PhysicalIdentity,
                Self::DOMAIN,
                entries,
            )?,
        })
    }

    /// Insert one immutable entry by path-copying the affected trie path.
    pub(crate) fn insert(
        &mut self,
        key: PhysicalMapKey,
        value: Vec<u8>,
    ) -> Result<bool, PhysicalModelError> {
        self.inner.insert(&Blake3PhysicalIdentity, key, value)
    }

    /// Rebuild from the complete leaf set after a bulk update.
    pub(crate) fn rebuild_with_entries(
        &mut self,
        additions: Vec<(PhysicalMapKey, Vec<u8>)>,
    ) -> Result<u64, PhysicalModelError> {
        self.inner
            .rebuild_with_entries(&Blake3PhysicalIdentity, additions)
    }
}

#[cfg(test)]
impl ProfileMap {
    /// Adversarial media tests only: place an unreachable node into the arena
    /// without minting a typed certificate from untrusted recover input.
    /// Refuses to overwrite an existing id so active tip nodes cannot be
    /// silently replaced through this fault injector.
    pub(crate) fn insert_unreachable_adversarial_node(
        &mut self,
        id: PhysicalMapNodeId,
        node: PhysicalMapNode,
    ) -> bool {
        use alloc::collections::btree_map::Entry;
        match self.inner.nodes.entry(id) {
            Entry::Vacant(slot) => {
                slot.insert(node);
                true
            },
            Entry::Occupied(_) => false,
        }
    }

    /// Adversarial tests only: replace one already-present arena node.
    /// Explicit tip/fault mutation for wrong-domain and foreign-body cases.
    pub(crate) fn replace_arena_node_for_fault(
        &mut self,
        id: PhysicalMapNodeId,
        node: PhysicalMapNode,
    ) -> bool {
        use alloc::collections::btree_map::Entry;
        match self.inner.nodes.entry(id) {
            Entry::Occupied(mut slot) => {
                slot.insert(node);
                true
            },
            Entry::Vacant(_) => false,
        }
    }
}

#[cfg(test)]
impl RepresentationMap {
    /// Adversarial tests only: replace one already-present arena node.
    /// This is explicit tip/fault mutation, not a typed recover factory.
    pub(crate) fn replace_arena_node_for_fault(
        &mut self,
        id: PhysicalMapNodeId,
        node: PhysicalMapNode,
    ) -> bool {
        use alloc::collections::btree_map::Entry;
        match self.inner.nodes.entry(id) {
            Entry::Occupied(mut slot) => {
                slot.insert(node);
                true
            },
            Entry::Vacant(_) => false,
        }
    }
}

#[cfg(test)]
impl PlacementMap {
    pub(crate) fn corrupt_root_for_reclaim_fault(&mut self, root: PhysicalMapNodeId) {
        self.inner.corrupt_root_for_reclaim_fault(root);
    }
}
