//! Canonical map operations over a fallible node provider.
//!
//! The resident model remains the format oracle. Runtime views may release its
//! decoded nodes after complete recovery validation and fetch paths on demand.

use alloc::vec;
use alloc::vec::Vec;

use super::nodes::{self, PhysicalMapMutNodes, PhysicalMapNodes};
use super::{
    CanonicalPhysicalMap, MapConstruction, PhysicalIdentity, PhysicalMapDomain, PhysicalMapKey,
    PhysicalMapNode, PhysicalMapNodeId, PhysicalModelError, SEARCH_KEY_BITS, legacy, radix,
    radix_common_prefix,
};

#[derive(Debug)]
pub(crate) struct BackedPhysicalMap<N> {
    domain: PhysicalMapDomain,
    construction: MapConstruction,
    root: Option<PhysicalMapNodeId>,
    entry_count: u64,
    nodes: N,
}

impl CanonicalPhysicalMap {
    /// Replace decoded ownership after the caller has indexed the same complete
    /// validated node closure. A missing provider node remains a read error.
    pub(crate) fn with_node_provider<N: PhysicalMapNodes>(&self, nodes: N) -> BackedPhysicalMap<N> {
        BackedPhysicalMap {
            domain: self.domain,
            construction: self.construction,
            root: self.root,
            entry_count: self.entry_count,
            nodes,
        }
    }
}

impl<N: PhysicalMapNodes> BackedPhysicalMap<N> {
    /// Rebind the same immutable map header to an operation-scoped provider.
    /// Reads still validate node identity, domain and construction below.
    pub(crate) fn with_node_provider<M: PhysicalMapNodes>(&self, nodes: M) -> BackedPhysicalMap<M> {
        BackedPhysicalMap {
            domain: self.domain,
            construction: self.construction,
            root: self.root,
            entry_count: self.entry_count,
            nodes,
        }
    }

    pub(super) fn new(
        domain: PhysicalMapDomain,
        construction: MapConstruction,
        root: Option<PhysicalMapNodeId>,
        entry_count: u64,
        nodes: N,
    ) -> Self {
        Self {
            domain,
            construction,
            root,
            entry_count,
            nodes,
        }
    }

    pub(crate) const fn root(&self) -> Option<PhysicalMapNodeId> {
        self.root
    }
    pub(crate) const fn entry_count(&self) -> u64 {
        self.entry_count
    }

    pub(crate) fn node<I: PhysicalIdentity>(
        &self,
        identity: &I,
        id: PhysicalMapNodeId,
    ) -> Result<PhysicalMapNode, N::Error> {
        let node = nodes::read(identity, &self.nodes, self.domain, id)
            .inspect_err(|_| self.nodes.note_read_failure())?;
        if node.construction() != self.construction {
            self.nodes.note_read_failure();
            return Err(PhysicalModelError::InvalidMap("map contains mixed constructions").into());
        }
        Ok(node)
    }

    pub(crate) fn try_get<I: PhysicalIdentity>(
        &self,
        identity: &I,
        key: PhysicalMapKey,
    ) -> Result<Option<Vec<u8>>, N::Error> {
        self.get_checked(identity, key)
            .inspect_err(|_| self.nodes.note_read_failure())
    }

    fn get_checked<I: PhysicalIdentity>(
        &self,
        identity: &I,
        key: PhysicalMapKey,
    ) -> Result<Option<Vec<u8>>, N::Error> {
        let Some(mut current) = self.root else {
            return Ok(None);
        };
        let search = key.search_key();
        let mut minimum_depth = 0;
        // Both frozen constructions consume at least one search bit per branch.
        // This bounds malformed traversal without a catalogue-sized visited set.
        for _ in 0..=SEARCH_KEY_BITS {
            match self.node(identity, current)? {
                PhysicalMapNode::Leaf {
                    key: stored, value, ..
                } => return Ok((stored == key).then_some(value)),
                PhysicalMapNode::Page { mut entries, .. } => {
                    return Ok(entries
                        .binary_search_by_key(&key, |entry| entry.0)
                        .ok()
                        .map(|at| entries.swap_remove(at).1));
                },
                PhysicalMapNode::Branch {
                    prefix_bits,
                    prefix,
                    zero,
                    one,
                    ..
                } => {
                    if prefix_bits < minimum_depth {
                        return Err(PhysicalModelError::InvalidMap(
                            "non-increasing map branch depth",
                        )
                        .into());
                    }
                    if !legacy::matches_prefix(&search, prefix_bits, &prefix) {
                        return Ok(None);
                    }
                    minimum_depth = prefix_bits
                        .checked_add(1)
                        .ok_or(PhysicalModelError::LengthOverflow)?;
                    current = if legacy::bit(&search, prefix_bits) {
                        one
                    } else {
                        zero
                    };
                },
                PhysicalMapNode::Radix {
                    prefix_nibbles,
                    prefix,
                    child_bitmap,
                    children,
                    ..
                } => {
                    let depth = u32::from(prefix_nibbles).strict_mul(4);
                    if depth < minimum_depth {
                        return Err(PhysicalModelError::InvalidMap(
                            "non-increasing radix branch depth",
                        )
                        .into());
                    }
                    if radix_common_prefix(key, prefix_nibbles, &prefix) < prefix_nibbles {
                        return Ok(None);
                    }
                    let mask = 1_u16 << radix::nibble(key, prefix_nibbles);
                    if child_bitmap & mask == 0 {
                        return Ok(None);
                    }
                    let at = usize::try_from((child_bitmap & mask.wrapping_sub(1)).count_ones())
                        .map_err(|_| PhysicalModelError::LengthOverflow)?;
                    current = *children.get(at).ok_or(PhysicalModelError::InvalidMap(
                        "radix child bitmap mismatch",
                    ))?;
                    minimum_depth = depth
                        .checked_add(4)
                        .ok_or(PhysicalModelError::LengthOverflow)?;
                },
            }
        }
        Err(PhysicalModelError::InvalidMap("physical map path exceeded search width").into())
    }
}

impl<N: PhysicalMapMutNodes> BackedPhysicalMap<N> {
    /// Merge dense batches directly into final canonical paths; legacy maps
    /// retain per-row path copying. On error the previous root and
    /// count remain authoritative. Providers may retain immutable orphan nodes
    /// written before failure; installing bytes never publishes root authority.
    pub(crate) fn insert_entries<I: PhysicalIdentity>(
        &mut self,
        identity: &I,
        additions: Vec<(PhysicalMapKey, Vec<u8>)>,
    ) -> Result<u64, N::Error> {
        if self.construction == MapConstruction::DenseRadix {
            let (root, added) = radix::insert_entries(
                identity,
                self.domain,
                &mut self.nodes,
                self.root,
                additions,
            )?;
            let count = self
                .entry_count
                .checked_add(added)
                .ok_or(PhysicalModelError::LengthOverflow)?;
            self.root = root;
            self.entry_count = count;
            return Ok(added);
        }
        let previous = (self.root, self.entry_count);
        let result = (|| {
            let mut count = 0_u64;
            for (key, value) in additions {
                if self.insert(identity, key, value)? {
                    count = count
                        .checked_add(1)
                        .ok_or(PhysicalModelError::LengthOverflow)?;
                }
            }
            Ok(count)
        })();
        if result.is_err() {
            (self.root, self.entry_count) = previous;
        }
        result
    }

    pub(crate) fn insert<I: PhysicalIdentity>(
        &mut self,
        identity: &I,
        key: PhysicalMapKey,
        value: Vec<u8>,
    ) -> Result<bool, N::Error> {
        let (replacement, inserted) = if let Some(root) = self.root {
            match self.construction {
                MapConstruction::LegacyBinary => {
                    legacy::insert(identity, self.domain, &mut self.nodes, root, key, value)?
                },
                MapConstruction::DenseRadix => {
                    radix::insert(identity, self.domain, &mut self.nodes, root, key, value)?
                },
            }
        } else {
            let node = match self.construction {
                MapConstruction::LegacyBinary => PhysicalMapNode::leaf(self.domain, key, value),
                MapConstruction::DenseRadix => {
                    PhysicalMapNode::page(self.domain, vec![(key, value)])?
                },
            };
            (nodes::store(identity, &mut self.nodes, node)?, true)
        };
        if inserted {
            let count = self
                .entry_count
                .checked_add(1)
                .ok_or(PhysicalModelError::LengthOverflow)?;
            self.root = Some(replacement);
            self.entry_count = count;
        }
        Ok(inserted)
    }
}

#[cfg(test)]
mod tests;
