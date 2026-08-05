//! Frozen binary Patricia-map construction retained for format-one recovery.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::{
    PhysicalIdentity, PhysicalMapDomain, PhysicalMapKey, PhysicalMapNode, PhysicalMapNodeId,
    PhysicalModelError, SEARCH_KEY_BITS,
};

pub(super) fn insert<I: PhysicalIdentity>(
    identity: &I,
    domain: PhysicalMapDomain,
    nodes: &mut BTreeMap<PhysicalMapNodeId, PhysicalMapNode>,
    root: PhysicalMapNodeId,
    key: PhysicalMapKey,
    value: Vec<u8>,
) -> Result<(PhysicalMapNodeId, bool), PhysicalModelError> {
    Insertion {
        identity,
        domain,
        nodes,
    }
    .insert_at(root, key, value)
}

pub(super) fn build<I: PhysicalIdentity>(
    identity: &I,
    domain: PhysicalMapDomain,
    entries: &[(PhysicalMapKey, Vec<u8>)],
    nodes: &mut BTreeMap<PhysicalMapNodeId, PhysicalMapNode>,
) -> Result<PhysicalMapNodeId, PhysicalModelError> {
    if entries.len() == 1 {
        let node = PhysicalMapNode::leaf(domain, entries[0].0, entries[0].1.clone());
        let id = node.identify(identity)?;
        nodes.insert(id, node);
        return Ok(id);
    }
    let first = entries
        .first()
        .ok_or(PhysicalModelError::InvalidMap("empty branch range"))?
        .0
        .search_key();
    let last = entries
        .last()
        .ok_or(PhysicalModelError::InvalidMap("empty branch range"))?
        .0
        .search_key();
    let prefix_bits = common_prefix_bits(&first, &last)?;
    if prefix_bits >= SEARCH_KEY_BITS {
        return Err(PhysicalModelError::InvalidMap("duplicate branch key"));
    }
    let split = entries.partition_point(|(key, _)| !bit(&key.search_key(), prefix_bits));
    if split == 0 || split == entries.len() {
        return Err(PhysicalModelError::InvalidMap("canonical branch is unary"));
    }
    let zero = build(identity, domain, &entries[..split], nodes)?;
    let one = build(identity, domain, &entries[split..], nodes)?;
    let node = PhysicalMapNode::branch(
        domain,
        prefix_bits,
        canonical_prefix(&first, prefix_bits)?,
        zero,
        one,
        u64::try_from(entries.len()).map_err(|_| PhysicalModelError::LengthOverflow)?,
    )?;
    let id = node.identify(identity)?;
    nodes.insert(id, node);
    Ok(id)
}

struct Leaf {
    key: PhysicalMapKey,
    value: Vec<u8>,
}

struct Branch {
    prefix_bits: u32,
    prefix: Vec<u8>,
    zero: PhysicalMapNodeId,
    one: PhysicalMapNodeId,
    subtree_entries: u64,
}

struct Insertion<'a, I> {
    identity: &'a I,
    domain: PhysicalMapDomain,
    nodes: &'a mut BTreeMap<PhysicalMapNodeId, PhysicalMapNode>,
}

impl<I: PhysicalIdentity> Insertion<'_, I> {
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
            .ok_or(PhysicalModelError::InvalidMap("missing insertion node"))?;
        if node.domain() != self.domain {
            return Err(PhysicalModelError::InvalidMap(
                "insertion crossed a map domain",
            ));
        }
        match node {
            PhysicalMapNode::Leaf {
                key: old,
                value: old_value,
                ..
            } => self.insert_at_leaf(
                node_id,
                &Leaf {
                    key: old,
                    value: old_value,
                },
                key,
                value,
            ),
            PhysicalMapNode::Branch {
                prefix_bits,
                prefix,
                zero,
                one,
                subtree_entries,
                ..
            } => self.insert_at_branch(
                node_id,
                Branch {
                    prefix_bits,
                    prefix,
                    zero,
                    one,
                    subtree_entries,
                },
                key,
                value,
            ),
            PhysicalMapNode::Page { .. } | PhysicalMapNode::Radix { .. } => Err(
                PhysicalModelError::InvalidMap("legacy map contains a radix node"),
            ),
        }
    }

    fn insert_at_leaf(
        &mut self,
        node_id: PhysicalMapNodeId,
        existing: &Leaf,
        key: PhysicalMapKey,
        value: Vec<u8>,
    ) -> Result<(PhysicalMapNodeId, bool), PhysicalModelError> {
        if existing.key == key {
            if existing.value == value {
                return Ok((node_id, false));
            }
            return Err(PhysicalModelError::InvalidMap(
                "leaf key has unequal canonical bytes",
            ));
        }
        let existing_search = existing.key.search_key();
        let new_search = key.search_key();
        let prefix_bits = common_prefix_bits(&existing_search, &new_search)?;
        let new_leaf_id = self.insert_leaf(key, value)?;
        let (zero, one) = ordered_children(node_id, new_leaf_id, &new_search, prefix_bits);
        let branch = PhysicalMapNode::branch(
            self.domain,
            prefix_bits,
            canonical_prefix(&new_search, prefix_bits)?,
            zero,
            one,
            2,
        )?;
        self.insert_node(branch)
            .map(|replacement| (replacement, true))
    }

    fn insert_at_branch(
        &mut self,
        node_id: PhysicalMapNodeId,
        branch: Branch,
        key: PhysicalMapKey,
        value: Vec<u8>,
    ) -> Result<(PhysicalMapNodeId, bool), PhysicalModelError> {
        let search = key.search_key();
        let common = common_prefix_with_prefix(&search, branch.prefix_bits, &branch.prefix)?;
        if common < branch.prefix_bits {
            return self.split_branch(node_id, &branch, key, value, &search, common);
        }
        let descend_one = bit(&search, branch.prefix_bits);
        let child = if descend_one { branch.one } else { branch.zero };
        let (replacement, inserted) = self.insert_at(child, key, value)?;
        if !inserted {
            return Ok((node_id, false));
        }
        let parent = PhysicalMapNode::branch(
            self.domain,
            branch.prefix_bits,
            branch.prefix,
            if descend_one {
                branch.zero
            } else {
                replacement
            },
            if descend_one { replacement } else { branch.one },
            increment_count(branch.subtree_entries)?,
        )?;
        self.insert_node(parent).map(|id| (id, true))
    }

    fn split_branch(
        &mut self,
        node_id: PhysicalMapNodeId,
        branch: &Branch,
        key: PhysicalMapKey,
        value: Vec<u8>,
        search: &[u8],
        common: u32,
    ) -> Result<(PhysicalMapNodeId, bool), PhysicalModelError> {
        let new_leaf_id = self.insert_leaf(key, value)?;
        if bit(&branch.prefix, common) == bit(search, common) {
            return Err(PhysicalModelError::InvalidMap(
                "branch prefix split did not diverge",
            ));
        }
        let (zero, one) = ordered_children(node_id, new_leaf_id, search, common);
        let parent = PhysicalMapNode::branch(
            self.domain,
            common,
            canonical_prefix(search, common)?,
            zero,
            one,
            increment_count(branch.subtree_entries)?,
        )?;
        self.insert_node(parent).map(|id| (id, true))
    }

    fn insert_leaf(
        &mut self,
        key: PhysicalMapKey,
        value: Vec<u8>,
    ) -> Result<PhysicalMapNodeId, PhysicalModelError> {
        self.insert_node(PhysicalMapNode::leaf(self.domain, key, value))
    }

    fn insert_node(
        &mut self,
        node: PhysicalMapNode,
    ) -> Result<PhysicalMapNodeId, PhysicalModelError> {
        let id = node.identify(self.identity)?;
        self.nodes.entry(id).or_insert(node);
        Ok(id)
    }
}

fn ordered_children(
    existing: PhysicalMapNodeId,
    inserted: PhysicalMapNodeId,
    inserted_key: &[u8],
    split_bit: u32,
) -> (PhysicalMapNodeId, PhysicalMapNodeId) {
    if bit(inserted_key, split_bit) {
        (existing, inserted)
    } else {
        (inserted, existing)
    }
}

fn increment_count(count: u64) -> Result<u64, PhysicalModelError> {
    count
        .checked_add(1)
        .ok_or(PhysicalModelError::LengthOverflow)
}

pub(super) fn validate_branch(
    prefix_bits: u32,
    prefix: &[u8],
    zero: PhysicalMapNodeId,
    one: PhysicalMapNodeId,
    subtree_entries: u64,
) -> Result<(), PhysicalModelError> {
    if prefix_bits >= SEARCH_KEY_BITS {
        return Err(PhysicalModelError::InvalidMap("branch prefix consumes key"));
    }
    if prefix.len() != prefix_byte_len(prefix_bits)? {
        return Err(PhysicalModelError::InvalidMap(
            "branch prefix length mismatch",
        ));
    }
    let remainder = prefix_bits % 8;
    if !prefix_bits.is_multiple_of(8)
        && prefix.last().is_some_and(|last| {
            let unused = 8_u32.saturating_sub(remainder);
            let unused_mask = 1_u8
                .checked_shl(unused)
                .and_then(|value| value.checked_sub(1))
                .unwrap_or(u8::MAX);
            *last & unused_mask != 0
        })
    {
        return Err(PhysicalModelError::InvalidMap(
            "branch prefix has non-zero unused bits",
        ));
    }
    if zero == one {
        return Err(PhysicalModelError::InvalidMap(
            "branch aliases its children",
        ));
    }
    if subtree_entries < 2 {
        return Err(PhysicalModelError::InvalidMap("branch is unary"));
    }
    Ok(())
}

pub(super) fn prefix_byte_len(bits: u32) -> Result<usize, PhysicalModelError> {
    usize::try_from(bits.div_ceil(8)).map_err(|_| PhysicalModelError::LengthOverflow)
}

fn common_prefix_bits(left: &[u8], right: &[u8]) -> Result<u32, PhysicalModelError> {
    let equal_bytes = left
        .iter()
        .zip(right)
        .position(|(left, right)| left != right)
        .unwrap_or(left.len());
    let equal_bits = u32::try_from(equal_bytes)
        .map_err(|_| PhysicalModelError::LengthOverflow)?
        .checked_mul(8)
        .ok_or(PhysicalModelError::LengthOverflow)?;
    if equal_bytes == left.len() {
        return Ok(equal_bits);
    }
    equal_bits
        .checked_add((left[equal_bytes] ^ right[equal_bytes]).leading_zeros())
        .ok_or(PhysicalModelError::LengthOverflow)
}

fn common_prefix_with_prefix(
    key: &[u8],
    prefix_bits: u32,
    prefix: &[u8],
) -> Result<u32, PhysicalModelError> {
    let mut common = 0_u32;
    while common < prefix_bits {
        if bit(key, common) != bit(prefix, common) {
            return Ok(common);
        }
        common = common
            .checked_add(1)
            .ok_or(PhysicalModelError::LengthOverflow)?;
    }
    Ok(common)
}

fn canonical_prefix(key: &[u8], bits: u32) -> Result<Vec<u8>, PhysicalModelError> {
    let byte_len = prefix_byte_len(bits)?;
    let mut prefix = key[..byte_len].to_vec();
    if !bits.is_multiple_of(8)
        && let Some(last) = prefix.last_mut()
    {
        *last &= u8::MAX
            .checked_shl(8_u32.saturating_sub(bits % 8))
            .unwrap_or(0);
    }
    Ok(prefix)
}

pub(super) fn matches_prefix(key: &[u8], bits: u32, expected: &[u8]) -> bool {
    canonical_prefix(key, bits).is_ok_and(|prefix| prefix == expected)
}

pub(super) fn bit(key: &[u8], offset: u32) -> bool {
    let byte = usize::try_from(offset / 8).unwrap_or(usize::MAX);
    let shift = 7_u32.saturating_sub(offset % 8);
    key.get(byte).is_some_and(|value| value & (1 << shift) != 0)
}
