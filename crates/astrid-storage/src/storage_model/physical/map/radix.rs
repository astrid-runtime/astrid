//! Dense canonical nibble-radix construction.

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use super::{
    DIGEST_NIBBLES, PhysicalIdentity, PhysicalMapDomain, PhysicalMapKey, PhysicalMapNode,
    PhysicalMapNodeId, PhysicalModelError, RADIX_PAGE_CAPACITY, nibble_prefix_byte_len,
};

pub(super) fn build<I: PhysicalIdentity>(
    identity: &I,
    domain: PhysicalMapDomain,
    entries: &[(PhysicalMapKey, Vec<u8>)],
    nodes: &mut BTreeMap<PhysicalMapNodeId, PhysicalMapNode>,
) -> Result<PhysicalMapNodeId, PhysicalModelError> {
    build_range(identity, domain, entries, 0, nodes)
}

pub(super) fn insert<I: PhysicalIdentity>(
    identity: &I,
    domain: PhysicalMapDomain,
    nodes: &mut BTreeMap<PhysicalMapNodeId, PhysicalMapNode>,
    root: PhysicalMapNodeId,
    key: PhysicalMapKey,
    value: Vec<u8>,
) -> Result<(PhysicalMapNodeId, bool), PhysicalModelError> {
    DenseInsertion {
        identity,
        domain,
        nodes,
    }
    .insert_at(root, key, value)
}

fn build_range<I: PhysicalIdentity>(
    identity: &I,
    domain: PhysicalMapDomain,
    entries: &[(PhysicalMapKey, Vec<u8>)],
    depth: u8,
    nodes: &mut BTreeMap<PhysicalMapNodeId, PhysicalMapNode>,
) -> Result<PhysicalMapNodeId, PhysicalModelError> {
    if entries.is_empty() {
        return Err(PhysicalModelError::InvalidMap("empty radix range"));
    }
    if entries.len() <= RADIX_PAGE_CAPACITY {
        return insert_node(
            identity,
            nodes,
            PhysicalMapNode::page(domain, entries.to_vec())?,
        );
    }

    let prefix_nibbles = common_prefix_nibbles(
        entries
            .first()
            .ok_or(PhysicalModelError::InvalidMap("empty radix range"))?
            .0,
        entries
            .last()
            .ok_or(PhysicalModelError::InvalidMap("empty radix range"))?
            .0,
        depth,
    );
    if prefix_nibbles >= DIGEST_NIBBLES {
        return Err(PhysicalModelError::InvalidMap("duplicate radix key"));
    }

    let mut child_bitmap = 0_u16;
    let mut children = Vec::new();
    let mut start = 0;
    while start < entries.len() {
        let selector = nibble(entries[start].0, prefix_nibbles);
        let mut end = start
            .checked_add(1)
            .ok_or(PhysicalModelError::LengthOverflow)?;
        while end < entries.len() && nibble(entries[end].0, prefix_nibbles) == selector {
            end = end
                .checked_add(1)
                .ok_or(PhysicalModelError::LengthOverflow)?;
        }
        child_bitmap |= 1_u16 << selector;
        children.push(build_range(
            identity,
            domain,
            &entries[start..end],
            prefix_nibbles
                .checked_add(1)
                .ok_or(PhysicalModelError::LengthOverflow)?,
            nodes,
        )?);
        start = end;
    }
    let node = PhysicalMapNode::radix(
        domain,
        prefix_nibbles,
        canonical_nibble_prefix(entries[0].0, prefix_nibbles),
        child_bitmap,
        children,
        u64::try_from(entries.len()).map_err(|_| PhysicalModelError::LengthOverflow)?,
    )?;
    insert_node(identity, nodes, node)
}

struct DenseInsertion<'a, I> {
    identity: &'a I,
    domain: PhysicalMapDomain,
    nodes: &'a mut BTreeMap<PhysicalMapNodeId, PhysicalMapNode>,
}

impl<I: PhysicalIdentity> DenseInsertion<'_, I> {
    fn insert_at(
        &mut self,
        node_id: PhysicalMapNodeId,
        key: PhysicalMapKey,
        value: Vec<u8>,
    ) -> Result<(PhysicalMapNodeId, bool), PhysicalModelError> {
        let node = self
            .nodes
            .get(&node_id)
            .cloned()
            .ok_or(PhysicalModelError::InvalidMap(
                "missing radix insertion node",
            ))?;
        if node.domain() != self.domain {
            return Err(PhysicalModelError::InvalidMap(
                "radix insertion crossed a map domain",
            ));
        }
        match node {
            PhysicalMapNode::Page { mut entries, .. } => {
                match entries.binary_search_by_key(&key, |(stored, _)| *stored) {
                    Ok(index) if entries[index].1 == value => return Ok((node_id, false)),
                    Ok(_) => {
                        return Err(PhysicalModelError::InvalidMap(
                            "page key has unequal canonical bytes",
                        ));
                    },
                    Err(index) => entries.insert(index, (key, value)),
                }
                let replacement = if entries.len() <= RADIX_PAGE_CAPACITY {
                    self.insert_node(PhysicalMapNode::page(self.domain, entries)?)?
                } else {
                    build_range(self.identity, self.domain, &entries, 0, self.nodes)?
                };
                Ok((replacement, true))
            },
            PhysicalMapNode::Radix {
                prefix_nibbles,
                prefix,
                child_bitmap,
                children,
                subtree_entries,
                ..
            } => self.insert_at_branch(
                node_id,
                key,
                value,
                Branch {
                    prefix_nibbles,
                    prefix,
                    child_bitmap,
                    children,
                    subtree_entries,
                },
            ),
            PhysicalMapNode::Leaf { .. } | PhysicalMapNode::Branch { .. } => Err(
                PhysicalModelError::InvalidMap("radix map contains a legacy node"),
            ),
        }
    }

    fn insert_at_branch(
        &mut self,
        node_id: PhysicalMapNodeId,
        key: PhysicalMapKey,
        value: Vec<u8>,
        mut branch: Branch,
    ) -> Result<(PhysicalMapNodeId, bool), PhysicalModelError> {
        let common = common_with_prefix(key, branch.prefix_nibbles, &branch.prefix);
        if common < branch.prefix_nibbles {
            let page = self.insert_node(PhysicalMapNode::page(self.domain, vec![(key, value)])?)?;
            let existing_selector = nibble_from_bytes(&branch.prefix, common);
            let inserted_selector = nibble(key, common);
            if existing_selector == inserted_selector {
                return Err(PhysicalModelError::InvalidMap(
                    "radix split did not diverge",
                ));
            }
            let bitmap = (1_u16 << existing_selector) | (1_u16 << inserted_selector);
            let children = if existing_selector < inserted_selector {
                vec![node_id, page]
            } else {
                vec![page, node_id]
            };
            let replacement = self.insert_node(PhysicalMapNode::radix(
                self.domain,
                common,
                canonical_nibble_prefix(key, common),
                bitmap,
                children,
                branch
                    .subtree_entries
                    .checked_add(1)
                    .ok_or(PhysicalModelError::LengthOverflow)?,
            )?)?;
            return Ok((replacement, true));
        }

        let selector = nibble(key, branch.prefix_nibbles);
        let mask = 1_u16 << selector;
        let index = usize::try_from((branch.child_bitmap & mask.wrapping_sub(1)).count_ones())
            .map_err(|_| PhysicalModelError::LengthOverflow)?;
        if branch.child_bitmap & mask == 0 {
            let page = self.insert_node(PhysicalMapNode::page(self.domain, vec![(key, value)])?)?;
            branch.child_bitmap |= mask;
            branch.children.insert(index, page);
        } else {
            let child = *branch
                .children
                .get(index)
                .ok_or(PhysicalModelError::InvalidMap(
                    "radix child bitmap mismatch",
                ))?;
            let (replacement, inserted) = self.insert_at(child, key, value)?;
            if !inserted {
                return Ok((node_id, false));
            }
            branch.children[index] = replacement;
        }
        branch.subtree_entries = branch
            .subtree_entries
            .checked_add(1)
            .ok_or(PhysicalModelError::LengthOverflow)?;
        let replacement = self.insert_node(PhysicalMapNode::radix(
            self.domain,
            branch.prefix_nibbles,
            branch.prefix,
            branch.child_bitmap,
            branch.children,
            branch.subtree_entries,
        )?)?;
        Ok((replacement, true))
    }

    fn insert_node(
        &mut self,
        node: PhysicalMapNode,
    ) -> Result<PhysicalMapNodeId, PhysicalModelError> {
        insert_node(self.identity, self.nodes, node)
    }
}

struct Branch {
    prefix_nibbles: u8,
    prefix: Vec<u8>,
    child_bitmap: u16,
    children: Vec<PhysicalMapNodeId>,
    subtree_entries: u64,
}

fn insert_node<I: PhysicalIdentity>(
    identity: &I,
    nodes: &mut BTreeMap<PhysicalMapNodeId, PhysicalMapNode>,
    node: PhysicalMapNode,
) -> Result<PhysicalMapNodeId, PhysicalModelError> {
    let id = node.identify(identity)?;
    nodes.entry(id).or_insert(node);
    Ok(id)
}

pub(super) fn nibble(key: PhysicalMapKey, index: u8) -> u8 {
    nibble_from_bytes(key.as_bytes(), index)
}

fn nibble_from_bytes(bytes: &[u8], index: u8) -> u8 {
    let byte = bytes[usize::from(index / 2)];
    if index.is_multiple_of(2) {
        byte >> 4
    } else {
        byte & 0x0f
    }
}

fn common_prefix_nibbles(left: PhysicalMapKey, right: PhysicalMapKey, mut depth: u8) -> u8 {
    while depth < DIGEST_NIBBLES && nibble(left, depth) == nibble(right, depth) {
        depth = depth.saturating_add(1);
    }
    depth
}

fn common_with_prefix(key: PhysicalMapKey, prefix_nibbles: u8, prefix: &[u8]) -> u8 {
    let mut common = 0;
    while common < prefix_nibbles && nibble(key, common) == nibble_from_bytes(prefix, common) {
        common = common.saturating_add(1);
    }
    common
}

fn canonical_nibble_prefix(key: PhysicalMapKey, nibbles: u8) -> Vec<u8> {
    let mut prefix = key.as_bytes()[..nibble_prefix_byte_len(nibbles)].to_vec();
    if !nibbles.is_multiple_of(2)
        && let Some(last) = prefix.last_mut()
    {
        *last &= 0xf0;
    }
    prefix
}
