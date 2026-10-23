//! Merge a sorted update batch without constructing superseded trie paths.
use super::{
    Branch, PhysicalIdentity, PhysicalMapDomain, PhysicalMapKey, PhysicalMapMutNodes,
    PhysicalMapNode, PhysicalMapNodeId, PhysicalModelError, build_range, canonical_nibble_prefix,
    common_with_prefix, insert_node, nibble, nibble_from_bytes, nodes,
};
use alloc::vec::Vec;

type Row = (PhysicalMapKey, Vec<u8>);

pub(in crate::storage_model::physical::map) fn insert_entries<
    I: PhysicalIdentity,
    N: PhysicalMapMutNodes,
>(
    identity: &I,
    domain: PhysicalMapDomain,
    nodes: &mut N,
    root: Option<PhysicalMapNodeId>,
    mut additions: Vec<Row>,
) -> Result<(Option<PhysicalMapNodeId>, u64), N::Error> {
    additions.sort_unstable_by_key(|row| row.0);
    if additions
        .windows(2)
        .any(|pair| pair[0].0 == pair[1].0 && pair[0].1 != pair[1].1)
    {
        return Err(PhysicalModelError::InvalidMap("page key has unequal canonical bytes").into());
    }
    additions.dedup_by(|left, right| left.0 == right.0);
    if additions.is_empty() {
        return Ok((root, 0));
    }
    let mut merge = Batch {
        identity,
        domain,
        nodes,
    };
    let (root, added) = match root {
        Some(root) => merge.at(root, &additions)?,
        None => (merge.build(&additions)?, count(additions.len())?),
    };
    Ok((Some(root), added))
}

struct Batch<'a, I, N> {
    identity: &'a I,
    domain: PhysicalMapDomain,
    nodes: &'a mut N,
}

impl<I: PhysicalIdentity, N: PhysicalMapMutNodes> Batch<'_, I, N> {
    fn build(&mut self, rows: &[Row]) -> Result<PhysicalMapNodeId, N::Error> {
        build_range(self.identity, self.domain, rows, 0, self.nodes)
    }

    fn at(
        &mut self,
        id: PhysicalMapNodeId,
        additions: &[Row],
    ) -> Result<(PhysicalMapNodeId, u64), N::Error> {
        if additions.is_empty() {
            return Ok((id, 0));
        }
        match nodes::read(self.identity, self.nodes, self.domain, id)? {
            PhysicalMapNode::Page { mut entries, .. } => {
                let mut added = 0_u64;
                for (key, value) in additions {
                    match entries.binary_search_by_key(key, |row| row.0) {
                        Ok(index) if entries[index].1 == *value => {},
                        Ok(_) => {
                            return Err(PhysicalModelError::InvalidMap(
                                "page key has unequal canonical bytes",
                            )
                            .into());
                        },
                        Err(index) => {
                            entries.insert(index, (*key, value.clone()));
                            added = added
                                .checked_add(1)
                                .ok_or(PhysicalModelError::LengthOverflow)?;
                        },
                    }
                }
                if added == 0 {
                    Ok((id, 0))
                } else {
                    Ok((self.build(&entries)?, added))
                }
            },
            PhysicalMapNode::Radix {
                prefix_nibbles,
                prefix,
                child_bitmap,
                children,
                subtree_entries,
                ..
            } => self.branch(
                id,
                Branch {
                    prefix_nibbles,
                    prefix,
                    child_bitmap,
                    children,
                    subtree_entries,
                },
                additions,
            ),
            PhysicalMapNode::Leaf { .. } | PhysicalMapNode::Branch { .. } => {
                Err(PhysicalModelError::InvalidMap("radix map contains a legacy node").into())
            },
        }
    }

    fn branch(
        &mut self,
        id: PhysicalMapNodeId,
        branch: Branch,
        additions: &[Row],
    ) -> Result<(PhysicalMapNodeId, u64), N::Error> {
        let first = additions
            .first()
            .ok_or(PhysicalModelError::InvalidMap("empty radix batch"))?
            .0;
        let last = additions
            .last()
            .ok_or(PhysicalModelError::InvalidMap("empty radix batch"))?
            .0;
        let common = common_with_prefix(first, branch.prefix_nibbles, &branch.prefix).min(
            common_with_prefix(last, branch.prefix_nibbles, &branch.prefix),
        );
        if common < branch.prefix_nibbles {
            return self.split(id, branch, additions, common);
        }
        let mut children = Vec::new();
        let mut bitmap = branch.child_bitmap;
        let mut added = 0_u64;
        let mut remaining = additions;
        for selector in 0..16_u8 {
            let end = remaining.partition_point(|row| nibble(row.0, common) == selector);
            let (selected, rest) = remaining.split_at(end);
            remaining = rest;
            let mask = 1_u16 << selector;
            let child = if branch.child_bitmap & mask == 0 {
                None
            } else {
                let index =
                    usize::try_from((branch.child_bitmap & mask.wrapping_sub(1)).count_ones())
                        .map_err(|_| PhysicalModelError::LengthOverflow)?;
                Some(
                    *branch
                        .children
                        .get(index)
                        .ok_or(PhysicalModelError::InvalidMap(
                            "radix child bitmap mismatch",
                        ))?,
                )
            };
            let (replacement, inserted) = match (child, selected.is_empty()) {
                (Some(child), _) => self.at(child, selected)?,
                (None, false) => {
                    bitmap |= mask;
                    (self.build(selected)?, count(selected.len())?)
                },
                (None, true) => continue,
            };
            children.push(replacement);
            added = added
                .checked_add(inserted)
                .ok_or(PhysicalModelError::LengthOverflow)?;
        }
        if !remaining.is_empty() {
            return Err(PhysicalModelError::InvalidMap("unpartitioned radix batch").into());
        }
        if added == 0 {
            return Ok((id, 0));
        }
        let node = PhysicalMapNode::radix(
            self.domain,
            common,
            branch.prefix,
            bitmap,
            children,
            branch
                .subtree_entries
                .checked_add(added)
                .ok_or(PhysicalModelError::LengthOverflow)?,
        )?;
        Ok((insert_node(self.identity, self.nodes, node)?, added))
    }

    fn split(
        &mut self,
        id: PhysicalMapNodeId,
        branch: Branch,
        additions: &[Row],
        common: u8,
    ) -> Result<(PhysicalMapNodeId, u64), N::Error> {
        let existing_selector = nibble_from_bytes(&branch.prefix, common);
        let old_count = branch.subtree_entries;
        let mut existing = Some(branch);
        let mut remaining = additions;
        let mut children = Vec::new();
        let mut bitmap = 0_u16;
        let mut added = 0_u64;
        for selector in 0..16_u8 {
            let end = remaining.partition_point(|row| nibble(row.0, common) == selector);
            let (selected, rest) = remaining.split_at(end);
            remaining = rest;
            let (child, inserted) = if selector == existing_selector {
                let branch = existing.take().ok_or(PhysicalModelError::InvalidMap(
                    "radix batch reused its existing branch",
                ))?;
                if selected.is_empty() {
                    (id, 0)
                } else {
                    self.branch(id, branch, selected)?
                }
            } else if selected.is_empty() {
                continue;
            } else {
                (self.build(selected)?, count(selected.len())?)
            };
            children.push(child);
            bitmap |= 1_u16 << selector;
            added = added
                .checked_add(inserted)
                .ok_or(PhysicalModelError::LengthOverflow)?;
        }
        if !remaining.is_empty() {
            return Err(PhysicalModelError::InvalidMap("unpartitioned radix split batch").into());
        }
        let first = additions
            .first()
            .ok_or(PhysicalModelError::InvalidMap("empty radix batch"))?
            .0;
        let node = PhysicalMapNode::radix(
            self.domain,
            common,
            canonical_nibble_prefix(first, common),
            bitmap,
            children,
            old_count
                .checked_add(added)
                .ok_or(PhysicalModelError::LengthOverflow)?,
        )?;
        Ok((insert_node(self.identity, self.nodes, node)?, added))
    }
}

fn count(len: usize) -> Result<u64, PhysicalModelError> {
    u64::try_from(len).map_err(|_| PhysicalModelError::LengthOverflow)
}
