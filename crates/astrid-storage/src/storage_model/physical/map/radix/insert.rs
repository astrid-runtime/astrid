//! Dense batch radix insertion that also serves single insert.

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;
use core::borrow::Borrow;

use super::super::validation::CanonicalNodeSink;
use super::super::{
    DIGEST_NIBBLES, PhysicalIdentity, PhysicalMapDomain, PhysicalMapKey, PhysicalMapNode,
    PhysicalMapNodeId, PhysicalModelError, RADIX_PAGE_CAPACITY,
};
use super::{
    canonical_nibble_prefix, common_prefix_nibbles, common_with_prefix, nibble, nibble_from_bytes,
};

const RADIX_FANOUT: usize = 16;

/// Sorted insert payload. Single insert keeps the entry on the stack.
pub(in super::super) enum InsertBatch {
    Single(Option<(PhysicalMapKey, Vec<u8>)>),
    Many(Vec<(PhysicalMapKey, Vec<u8>)>),
}

#[derive(Clone, Copy)]
struct BatchRange {
    start: usize,
    end: usize,
}

struct SelectorRuns {
    runs: [(u8, BatchRange); RADIX_FANOUT],
    len: usize,
}

impl SelectorRuns {
    fn iter(&self) -> impl Iterator<Item = (u8, BatchRange)> + '_ {
        self.runs[..self.len].iter().copied()
    }
}

struct RadixView {
    prefix_nibbles: u8,
    prefix: Vec<u8>,
    child_bitmap: u16,
    children: Vec<PhysicalMapNodeId>,
    subtree_entries: u64,
}

enum InsertPlan {
    Unchanged,
    Page(PhysicalMapKey),
    Radix(RadixView),
}

struct ExistingChild {
    id: PhysicalMapNodeId,
    selector: u8,
    entries: u64,
}

struct DenseBatchInsertion<'a, I, N> {
    identity: &'a I,
    domain: PhysicalMapDomain,
    nodes: &'a mut BTreeMap<PhysicalMapNodeId, N>,
    batch: &'a mut InsertBatch,
}

impl InsertBatch {
    pub(in super::super) fn single(key: PhysicalMapKey, value: Vec<u8>) -> Self {
        Self::Single(Some((key, value)))
    }

    pub(in super::super) fn many(
        mut entries: Vec<(PhysicalMapKey, Vec<u8>)>,
    ) -> Result<Self, PhysicalModelError> {
        compact_sorted_entries(&mut entries)?;
        Ok(Self::Many(entries))
    }

    pub(in super::super) fn as_slice(&self) -> &[(PhysicalMapKey, Vec<u8>)] {
        match self {
            Self::Single(slot) => slot.as_slice(),
            Self::Many(entries) => entries.as_slice(),
        }
    }

    pub(in super::super) fn for_each_owned<F>(self, mut visit: F) -> Result<(), PhysicalModelError>
    where
        F: FnMut(PhysicalMapKey, Vec<u8>) -> Result<(), PhysicalModelError>,
    {
        match self {
            Self::Single(slot) => {
                if let Some((key, value)) = slot {
                    visit(key, value)?;
                }
            },
            Self::Many(entries) => {
                for (key, value) in entries {
                    visit(key, value)?;
                }
            },
        }
        Ok(())
    }

    fn take(&mut self, index: usize) -> Result<(PhysicalMapKey, Vec<u8>), PhysicalModelError> {
        match self {
            Self::Single(slot) => {
                if index != 0 {
                    return Err(PhysicalModelError::InvalidMap("empty radix range"));
                }
                slot.take()
                    .ok_or(PhysicalModelError::InvalidMap("empty radix range"))
            },
            Self::Many(entries) => {
                let entry = entries
                    .get_mut(index)
                    .ok_or(PhysicalModelError::InvalidMap("empty radix range"))?;
                Ok((entry.0, core::mem::take(&mut entry.1)))
            },
        }
    }
}

fn compact_sorted_entries(
    entries: &mut Vec<(PhysicalMapKey, Vec<u8>)>,
) -> Result<(), PhysicalModelError> {
    entries.sort_unstable_by_key(|(key, _)| *key);
    let mut unequal = false;
    entries.dedup_by(|right, left| {
        if left.0 != right.0 {
            return false;
        }
        if left.1 != right.1 {
            unequal = true;
        }
        true
    });
    if unequal {
        return Err(PhysicalModelError::InvalidMap(
            "page key has unequal canonical bytes",
        ));
    }
    Ok(())
}

pub(in super::super) fn insert_batch<I, N>(
    identity: &I,
    domain: PhysicalMapDomain,
    nodes: &mut BTreeMap<PhysicalMapNodeId, N>,
    root: PhysicalMapNodeId,
    batch: &mut InsertBatch,
) -> Result<(PhysicalMapNodeId, u64), PhysicalModelError>
where
    I: PhysicalIdentity,
    N: Borrow<PhysicalMapNode> + From<PhysicalMapNode>,
{
    let end = batch.as_slice().len();
    DenseBatchInsertion {
        identity,
        domain,
        nodes,
        batch,
    }
    .insert_at(root, BatchRange { start: 0, end }, 0)
}

pub(in super::super) fn insert_new<I, N>(
    identity: &I,
    domain: PhysicalMapDomain,
    nodes: &mut BTreeMap<PhysicalMapNodeId, N>,
    batch: &mut InsertBatch,
) -> Result<(PhysicalMapNodeId, u64), PhysicalModelError>
where
    I: PhysicalIdentity,
    N: Borrow<PhysicalMapNode> + From<PhysicalMapNode>,
{
    let end = batch.as_slice().len();
    DenseBatchInsertion {
        identity,
        domain,
        nodes,
        batch,
    }
    .build_new_range(BatchRange { start: 0, end }, 0)
}

impl<I, N> DenseBatchInsertion<'_, I, N>
where
    I: PhysicalIdentity,
    N: Borrow<PhysicalMapNode> + From<PhysicalMapNode>,
{
    fn insert_at(
        &mut self,
        node_id: PhysicalMapNodeId,
        range: BatchRange,
        depth: u8,
    ) -> Result<(PhysicalMapNodeId, u64), PhysicalModelError> {
        match self.plan_insert(node_id, range)? {
            InsertPlan::Unchanged => Ok((node_id, 0)),
            InsertPlan::Page(old_key) => self.insert_into_page(node_id, old_key, range, depth),
            InsertPlan::Radix(view) => self.insert_into_radix(node_id, range, depth, view),
        }
    }

    fn plan_insert(
        &self,
        node_id: PhysicalMapNodeId,
        range: BatchRange,
    ) -> Result<InsertPlan, PhysicalModelError> {
        let node = self
            .nodes
            .get(&node_id)
            .ok_or(PhysicalModelError::InvalidMap(
                "missing radix insertion node",
            ))?
            .borrow();
        if node.domain() != self.domain {
            return Err(PhysicalModelError::InvalidMap(
                "radix insertion crossed a map domain",
            ));
        }
        match node {
            PhysicalMapNode::Page { entries, .. } => self.plan_page(entries, range),
            PhysicalMapNode::Radix {
                prefix_nibbles,
                prefix,
                child_bitmap,
                children,
                subtree_entries,
                ..
            } => Ok(InsertPlan::Radix(RadixView {
                prefix_nibbles: *prefix_nibbles,
                prefix: prefix.clone(),
                child_bitmap: *child_bitmap,
                children: children.clone(),
                subtree_entries: *subtree_entries,
            })),
            PhysicalMapNode::Leaf { .. } | PhysicalMapNode::Branch { .. } => Err(
                PhysicalModelError::InvalidMap("radix map contains a legacy node"),
            ),
        }
    }

    fn plan_page(
        &self,
        entries: &[(PhysicalMapKey, Vec<u8>)],
        range: BatchRange,
    ) -> Result<InsertPlan, PhysicalModelError> {
        let (old_key, old_value) = entries.first().ok_or(PhysicalModelError::InvalidMap(
            "radix page count is outside its bound",
        ))?;
        let additions = self.range_slice(range);
        match additions.binary_search_by_key(old_key, |(key, _)| *key) {
            Ok(relative) if additions[relative].1 == *old_value => {
                if additions.len() == 1 {
                    Ok(InsertPlan::Unchanged)
                } else {
                    Ok(InsertPlan::Page(*old_key))
                }
            },
            Ok(_) => Err(PhysicalModelError::InvalidMap(
                "page key has unequal canonical bytes",
            )),
            Err(_) => Ok(InsertPlan::Page(*old_key)),
        }
    }

    fn insert_into_page(
        &mut self,
        node_id: PhysicalMapNodeId,
        old_key: PhysicalMapKey,
        range: BatchRange,
        depth: u8,
    ) -> Result<(PhysicalMapNodeId, u64), PhysicalModelError> {
        if depth >= DIGEST_NIBBLES {
            return Err(PhysicalModelError::InvalidMap("duplicate radix key"));
        }
        let split = union_split(old_key, self.range_slice(range), depth);
        if split >= DIGEST_NIBBLES {
            return Err(PhysicalModelError::InvalidMap("duplicate radix key"));
        }
        let runs = collect_selector_runs(self.batch.as_slice(), range, split)?;
        self.wrap_with_existing(
            ExistingChild {
                id: node_id,
                selector: nibble(old_key, split),
                entries: 1,
            },
            runs,
            old_key,
            split,
        )
    }

    fn insert_into_radix(
        &mut self,
        node_id: PhysicalMapNodeId,
        range: BatchRange,
        depth: u8,
        view: RadixView,
    ) -> Result<(PhysicalMapNodeId, u64), PhysicalModelError> {
        if view.prefix_nibbles < depth {
            return Err(PhysicalModelError::InvalidMap("radix prefix retreated"));
        }
        let common = radix_union_split(
            self.range_slice(range),
            depth,
            view.prefix_nibbles,
            &view.prefix,
        )?;
        if common < depth {
            return Err(PhysicalModelError::InvalidMap("radix prefix retreated"));
        }
        if common >= DIGEST_NIBBLES {
            return Err(PhysicalModelError::InvalidMap("duplicate radix key"));
        }
        if common >= view.prefix_nibbles {
            return self.descend_radix(node_id, range, view);
        }
        // Wrap first. Inserting matching keys into E and then wrapping would
        // birth a superseded E that the new parent never names.
        let prefix_key = self.range_slice(range)[0].0;
        let existing = ExistingChild {
            id: node_id,
            selector: nibble_from_bytes(&view.prefix, common),
            entries: view.subtree_entries,
        };
        let runs = collect_selector_runs(self.batch.as_slice(), range, common)?;
        self.wrap_with_existing(existing, runs, prefix_key, common)
    }

    fn descend_radix(
        &mut self,
        node_id: PhysicalMapNodeId,
        range: BatchRange,
        mut view: RadixView,
    ) -> Result<(PhysicalMapNodeId, u64), PhysicalModelError> {
        let runs = collect_selector_runs(self.batch.as_slice(), range, view.prefix_nibbles)?;
        let next = next_depth(view.prefix_nibbles)?;
        let mut inserted = 0_u64;
        let mut changed = false;
        for (selector, run) in runs.iter() {
            let mask = 1_u16 << selector;
            let (child, count) = if view.child_bitmap & mask == 0 {
                self.build_new_range(run, next)?
            } else {
                let child_index = child_index(view.child_bitmap, selector)?;
                let child =
                    *view
                        .children
                        .get(child_index)
                        .ok_or(PhysicalModelError::InvalidMap(
                            "radix child bitmap mismatch",
                        ))?;
                self.insert_at(child, run, next)?
            };
            if count == 0 {
                continue;
            }
            if view.child_bitmap & mask == 0 {
                push_child(&mut view.child_bitmap, &mut view.children, selector, child)?;
            } else {
                view.children[child_index(view.child_bitmap, selector)?] = child;
            }
            inserted = inserted
                .checked_add(count)
                .ok_or(PhysicalModelError::LengthOverflow)?;
            changed = true;
        }
        if !changed {
            return Ok((node_id, 0));
        }
        view.subtree_entries = view
            .subtree_entries
            .checked_add(inserted)
            .ok_or(PhysicalModelError::LengthOverflow)?;
        let replacement = self.put_radix(view)?;
        Ok((replacement, inserted))
    }

    fn wrap_with_existing(
        &mut self,
        existing: ExistingChild,
        runs: SelectorRuns,
        prefix_key: PhysicalMapKey,
        split: u8,
    ) -> Result<(PhysicalMapNodeId, u64), PhysicalModelError> {
        let next = next_depth(split)?;
        let mut child_bitmap = 0_u16;
        let mut children = Vec::new();
        let mut inserted = 0_u64;
        let mut placed = false;
        for (selector, run) in runs.iter() {
            if !placed && existing.selector < selector {
                push_child(
                    &mut child_bitmap,
                    &mut children,
                    existing.selector,
                    existing.id,
                )?;
                placed = true;
            }
            let (child, count) = if selector == existing.selector {
                placed = true;
                self.insert_at(existing.id, run, next)?
            } else {
                self.build_new_range(run, next)?
            };
            inserted = inserted
                .checked_add(count)
                .ok_or(PhysicalModelError::LengthOverflow)?;
            push_child(&mut child_bitmap, &mut children, selector, child)?;
        }
        if !placed {
            push_child(
                &mut child_bitmap,
                &mut children,
                existing.selector,
                existing.id,
            )?;
        }
        let subtree_entries = existing
            .entries
            .checked_add(inserted)
            .ok_or(PhysicalModelError::LengthOverflow)?;
        let replacement = self.put_radix(RadixView {
            prefix_nibbles: split,
            prefix: canonical_nibble_prefix(prefix_key, split),
            child_bitmap,
            children,
            subtree_entries,
        })?;
        Ok((replacement, inserted))
    }

    fn build_new_range(
        &mut self,
        range: BatchRange,
        depth: u8,
    ) -> Result<(PhysicalMapNodeId, u64), PhysicalModelError> {
        let len = range.end.saturating_sub(range.start);
        if len == 0 {
            return Err(PhysicalModelError::InvalidMap("empty radix range"));
        }
        if len <= RADIX_PAGE_CAPACITY {
            return Ok((self.put_page(range.start)?, 1));
        }
        if depth >= DIGEST_NIBBLES {
            return Err(PhysicalModelError::InvalidMap("duplicate radix key"));
        }
        let prefix_nibbles = {
            let entries = self.range_slice(range);
            common_prefix_nibbles(entries[0].0, entries[len - 1].0, depth)
        };
        if prefix_nibbles >= DIGEST_NIBBLES {
            return Err(PhysicalModelError::InvalidMap("duplicate radix key"));
        }
        if prefix_nibbles < depth {
            return Err(PhysicalModelError::InvalidMap("radix prefix retreated"));
        }
        let runs = collect_selector_runs(self.batch.as_slice(), range, prefix_nibbles)?;
        let next = next_depth(prefix_nibbles)?;
        let mut child_bitmap = 0_u16;
        let mut children = Vec::new();
        for (selector, run) in runs.iter() {
            let (child, _) = self.build_new_range(run, next)?;
            push_child(&mut child_bitmap, &mut children, selector, child)?;
        }
        let subtree_entries = u64::try_from(len).map_err(|_| PhysicalModelError::LengthOverflow)?;
        let prefix_key = self.range_slice(range)[0].0;
        let id = self.put_radix(RadixView {
            prefix_nibbles,
            prefix: canonical_nibble_prefix(prefix_key, prefix_nibbles),
            child_bitmap,
            children,
            subtree_entries,
        })?;
        Ok((id, subtree_entries))
    }

    fn put_page(&mut self, index: usize) -> Result<PhysicalMapNodeId, PhysicalModelError> {
        let entry = self.batch.take(index)?;
        self.insert_node(PhysicalMapNode::page(self.domain, vec![entry])?)
    }

    fn put_radix(&mut self, view: RadixView) -> Result<PhysicalMapNodeId, PhysicalModelError> {
        self.insert_node(PhysicalMapNode::radix(
            self.domain,
            view.prefix_nibbles,
            view.prefix,
            view.child_bitmap,
            view.children,
            view.subtree_entries,
        )?)
    }

    fn insert_node(
        &mut self,
        node: PhysicalMapNode,
    ) -> Result<PhysicalMapNodeId, PhysicalModelError> {
        // Empty-root birth shares this fence: unequal historical bodies under
        // one id reject; equal bodies may reactivate without overwrite.
        let (bytes, id) = node.encode_and_identify(self.identity)?;
        self.nodes.put(id, &bytes, node)?;
        Ok(id)
    }

    fn range_slice(&self, range: BatchRange) -> &[(PhysicalMapKey, Vec<u8>)] {
        &self.batch.as_slice()[range.start..range.end]
    }
}

fn union_split(old_key: PhysicalMapKey, additions: &[(PhysicalMapKey, Vec<u8>)], depth: u8) -> u8 {
    match additions {
        [] => depth,
        [only] => common_prefix_nibbles(old_key.min(only.0), old_key.max(only.0), depth),
        [first, .., last] => {
            common_prefix_nibbles(old_key.min(first.0), old_key.max(last.0), depth)
        },
    }
}

fn radix_union_split(
    additions: &[(PhysicalMapKey, Vec<u8>)],
    depth: u8,
    prefix_nibbles: u8,
    prefix: &[u8],
) -> Result<u8, PhysicalModelError> {
    let first = additions
        .first()
        .ok_or(PhysicalModelError::InvalidMap("empty radix range"))?
        .0;
    let last = additions
        .last()
        .ok_or(PhysicalModelError::InvalidMap("empty radix range"))?
        .0;
    Ok(common_prefix_nibbles(first, last, depth)
        .min(common_with_prefix(first, prefix_nibbles, prefix))
        .min(common_with_prefix(last, prefix_nibbles, prefix)))
}

fn collect_selector_runs(
    entries: &[(PhysicalMapKey, Vec<u8>)],
    range: BatchRange,
    at: u8,
) -> Result<SelectorRuns, PhysicalModelError> {
    let mut runs = SelectorRuns {
        runs: [(0, BatchRange { start: 0, end: 0 }); RADIX_FANOUT],
        len: 0,
    };
    let mut index = range.start;
    while index < range.end {
        let selector = nibble(entries[index].0, at);
        let mut end = next_index(index)?;
        while end < range.end && nibble(entries[end].0, at) == selector {
            end = next_index(end)?;
        }
        if runs.len >= RADIX_FANOUT {
            return Err(PhysicalModelError::InvalidMap(
                "radix branch is non-canonical or incomplete",
            ));
        }
        runs.runs[runs.len] = (selector, BatchRange { start: index, end });
        runs.len += 1;
        index = end;
    }
    Ok(runs)
}

fn push_child(
    child_bitmap: &mut u16,
    children: &mut Vec<PhysicalMapNodeId>,
    selector: u8,
    child: PhysicalMapNodeId,
) -> Result<(), PhysicalModelError> {
    let mask = 1_u16 << selector;
    if *child_bitmap & mask != 0 {
        return Err(PhysicalModelError::InvalidMap(
            "radix branch aliases its children",
        ));
    }
    let index = child_index(*child_bitmap, selector)?;
    *child_bitmap |= mask;
    children.insert(index, child);
    Ok(())
}

fn child_index(child_bitmap: u16, selector: u8) -> Result<usize, PhysicalModelError> {
    let mask = 1_u16 << selector;
    usize::try_from((child_bitmap & mask.wrapping_sub(1)).count_ones())
        .map_err(|_| PhysicalModelError::LengthOverflow)
}

fn next_depth(depth: u8) -> Result<u8, PhysicalModelError> {
    depth
        .checked_add(1)
        .ok_or(PhysicalModelError::LengthOverflow)
}

fn next_index(index: usize) -> Result<usize, PhysicalModelError> {
    index
        .checked_add(1)
        .ok_or(PhysicalModelError::LengthOverflow)
}
