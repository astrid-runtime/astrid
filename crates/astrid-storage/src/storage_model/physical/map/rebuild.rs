//! Transactional rebuild of the active canonical map from borrowed history.

use alloc::borrow::Cow;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec;
use alloc::vec::Vec;

use super::validation::CanonicalNodeSink;
use super::{
    CanonicalPhysicalMap, MapConstruction, PhysicalIdentity, PhysicalMapKey, PhysicalMapNode,
    PhysicalMapNodeId, PhysicalModelError, legacy, radix,
};

/// Retains only nodes absent from the existing arena. Equal bodies under an
/// already-authenticated id are dropped; unequal bodies fail closed. The
/// source arena stays immutable until the caller commits `fresh` after a
/// successful root build.
struct NewOnlySink<'a> {
    existing: &'a BTreeMap<PhysicalMapNodeId, PhysicalMapNode>,
    fresh: BTreeMap<PhysicalMapNodeId, PhysicalMapNode>,
}

impl CanonicalNodeSink for NewOnlySink<'_> {
    type Error = PhysicalModelError;

    fn put(
        &mut self,
        id: PhysicalMapNodeId,
        _canonical_bytes: &[u8],
        node: PhysicalMapNode,
    ) -> Result<(), PhysicalModelError> {
        if let Some(existing) = self.fresh.get(&id).or_else(|| self.existing.get(&id)) {
            return if existing == &node {
                Ok(())
            } else {
                Err(PhysicalModelError::InvalidMap(
                    "physical map-node identity collision",
                ))
            };
        }
        self.fresh.insert(id, node);
        Ok(())
    }
}

fn collect_active_entries<'a>(
    root: Option<PhysicalMapNodeId>,
    nodes: &'a BTreeMap<PhysicalMapNodeId, PhysicalMapNode>,
    entry_count: u64,
) -> Result<BTreeMap<PhysicalMapKey, Cow<'a, [u8]>>, PhysicalModelError> {
    let mut entries = BTreeMap::<PhysicalMapKey, Cow<'a, [u8]>>::new();
    if let Some(root) = root {
        let mut stack = vec![root];
        let mut visited = BTreeSet::new();
        while let Some(node_id) = stack.pop() {
            if !visited.insert(node_id) {
                return Err(PhysicalModelError::InvalidMap(
                    "active map traversal revisited a node",
                ));
            }
            match nodes
                .get(&node_id)
                .ok_or(PhysicalModelError::InvalidMap("missing active map node"))?
            {
                PhysicalMapNode::Leaf { key, value, .. } => {
                    if entries
                        .insert(*key, Cow::Borrowed(value.as_slice()))
                        .is_some()
                    {
                        return Err(PhysicalModelError::InvalidMap(
                            "active map has duplicate leaf keys",
                        ));
                    }
                },
                PhysicalMapNode::Branch { zero, one, .. } => {
                    stack.push(*one);
                    stack.push(*zero);
                },
                PhysicalMapNode::Page {
                    entries: page_entries,
                    ..
                } => {
                    for (key, value) in page_entries {
                        if entries
                            .insert(*key, Cow::Borrowed(value.as_slice()))
                            .is_some()
                        {
                            return Err(PhysicalModelError::InvalidMap(
                                "active map has duplicate page keys",
                            ));
                        }
                    }
                },
                PhysicalMapNode::Radix { children, .. } => {
                    stack.extend(children.iter().rev().copied());
                },
            }
        }
    }
    if u64::try_from(entries.len()).map_err(|_| PhysicalModelError::LengthOverflow)? != entry_count
    {
        return Err(PhysicalModelError::InvalidMap(
            "active map count does not match its leaves",
        ));
    }
    Ok(entries)
}

fn merge_additions(
    entries: &mut BTreeMap<PhysicalMapKey, Cow<'_, [u8]>>,
    additions: Vec<(PhysicalMapKey, Vec<u8>)>,
) -> Result<u64, PhysicalModelError> {
    let mut inserted = 0_u64;
    for (key, value) in additions {
        match entries.get(&key) {
            Some(existing) if existing.as_ref() == value.as_slice() => {},
            Some(_) => {
                return Err(PhysicalModelError::InvalidMap(
                    "leaf key has unequal canonical bytes",
                ));
            },
            None => {
                entries.insert(key, Cow::Owned(value));
                inserted = inserted
                    .checked_add(1)
                    .ok_or(PhysicalModelError::LengthOverflow)?;
            },
        }
    }
    Ok(inserted)
}

impl CanonicalPhysicalMap {
    /// Atomically rebuild the active canonical trie with additional entries.
    ///
    /// The resulting root is byte-identical to [`Self::build`] over the
    /// complete entry set. Historical nodes remain available for older roots,
    /// while only nodes reachable from the replacement root become active.
    /// This is intended for batches whose final-tree construction is cheaper
    /// than repeated path copying.
    ///
    /// Existing leaf and page payloads are borrowed for the build. Only nodes
    /// whose identities are absent from the current arena are retained and
    /// merged after a successful root identity is known. Any error leaves
    /// `root`, `entry_count`, and `nodes` unchanged.
    ///
    /// # Errors
    ///
    /// Rejects unequal bytes under one key, malformed existing state, physical
    /// node-identity collisions, and arithmetic overflow without changing the
    /// active map.
    pub fn rebuild_with_entries<I: PhysicalIdentity>(
        &mut self,
        identity: &I,
        additions: Vec<(PhysicalMapKey, Vec<u8>)>,
    ) -> Result<u64, PhysicalModelError> {
        let outcome = {
            let mut entries = collect_active_entries(self.root, &self.nodes, self.entry_count)?;
            let inserted = merge_additions(&mut entries, additions)?;
            if inserted == 0 {
                return Ok(0);
            }

            let sorted: Vec<(PhysicalMapKey, Cow<'_, [u8]>)> = entries.into_iter().collect();
            let new_count =
                u64::try_from(sorted.len()).map_err(|_| PhysicalModelError::LengthOverflow)?;
            let mut sink = NewOnlySink {
                existing: &self.nodes,
                fresh: BTreeMap::new(),
            };
            let new_root = match self.construction {
                MapConstruction::LegacyBinary => {
                    legacy::build(identity, self.domain, &sorted, &mut sink)?
                },
                MapConstruction::DenseRadix => {
                    radix::build(identity, self.domain, &sorted, &mut sink)?
                },
            };
            (new_root, sink.fresh, inserted, new_count)
        };
        let (new_root, fresh, inserted, new_count) = outcome;
        self.nodes.extend(fresh);
        self.root = Some(new_root);
        self.entry_count = new_count;
        Ok(inserted)
    }
}
