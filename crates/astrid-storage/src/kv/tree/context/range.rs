//! Prefix traversal over one authenticated checkpoint and its current overlay.

use std::collections::BTreeMap;

use super::{
    ChildPointer, KvProjectionEngine, LeafEntry, Node, ObjectId, PreviousValue, Replacement,
    StorageError, StorageResult, TreeContext, TreeHeader, ValueSlot, decode_node, invalid,
};

mod key_projection;

#[cfg(test)]
mod tests;

impl<P: Ord, E: KvProjectionEngine<P>> TreeContext<'_, P, E> {
    // Each range consumes its authenticated pages once. Deletion observations
    // carry validated values forward, so subsequent accounting needs no page memo.
    fn visit_slots_in_range(
        &mut self,
        root: Option<ObjectId>,
        start: &[u8],
        end: &[u8],
        mut visit: impl FnMut(&Self, LeafEntry) -> StorageResult<()>,
    ) -> StorageResult<()> {
        let Some(root) = root else {
            return Ok(());
        };
        let mut stack: Vec<(ObjectId, Option<ChildPointer>)> = vec![(root, None)];
        while let Some((object, expected)) = stack.pop() {
            let handle = decode_node(object, &self.record(object)?)?;
            if expected.is_some_and(|expected| handle.pointer() != expected) {
                return Err(invalid(object, "persistent KV child summary disagrees"));
            }
            match handle.node {
                Node::Leaf(leaf) => {
                    for entry in leaf.entries {
                        if crate::kv::encoding::entry_in_range(&entry.key, start, end) {
                            visit(self, entry)?;
                        }
                    }
                },
                Node::Branch(branch) => {
                    for (index, child) in branch.children.iter().enumerate().rev() {
                        let upper = branch
                            .children
                            .get(index.saturating_add(1))
                            .map(|next| next.lower_bound.as_slice());
                        if !crate::kv::encoding::visit_child(&child.lower_bound, upper, start, end)
                        {
                            continue;
                        }
                        stack.push((child.object, Some(child.clone())));
                    }
                },
            }
        }
        Ok(())
    }

    pub(in crate::kv::tree) fn projected_deletions_in_range(
        &mut self,
        header: &TreeHeader<P>,
        start: &[u8],
        end: &[u8],
    ) -> StorageResult<Vec<Replacement>> {
        let mut observed = BTreeMap::new();
        self.visit_slots_in_range(header.tree, start, end, |context, entry| {
            if header.overlay.get(&entry.key).is_none() {
                // Preserve the existing body validation before deletion, but
                // reuse this authenticated slot instead of looking it up again.
                let value = match header.boundary {
                    Some(certificate) => {
                        context.read_certified_tree_slot(header, &entry.value, certificate)?
                    },
                    None => context.value_bytes(&entry.value)?,
                };
                let previous_len = Some(value.len());
                drop(value);
                observed.insert(
                    entry.key,
                    PreviousValue::Loaded {
                        previous_len,
                        unchanged: false,
                    },
                );
            }
            Ok(())
        })?;
        for (key, value) in header.overlay.range(start, end) {
            if value.is_some() {
                // apply_mutations reads the current overlay before consulting
                // this hint, retaining its established live-value accounting.
                observed.insert(key.to_vec(), PreviousValue::Unread);
            }
        }
        Ok(observed
            .into_iter()
            .map(|(key, previous)| Replacement {
                key,
                previous,
                value: None,
            })
            .collect())
    }

    pub(in crate::kv::tree) fn projected_keys_in_range(
        &mut self,
        header: &TreeHeader<P>,
        start: &[u8],
        end: &[u8],
        strip: usize,
    ) -> StorageResult<Vec<String>> {
        let mut keys = BTreeMap::new();
        self.visit_slots_in_range(header.tree, start, end, |_, entry| {
            key_projection::checkpoint(&mut keys, entry.key);
            Ok(())
        })?;
        for (key, value) in header.overlay.range(start, end) {
            key_projection::overlay(&mut keys, key.to_vec(), value);
        }
        key_projection::collect(&keys, |key| suffix(key, strip).map(str::to_owned))
    }

    pub(in crate::kv::tree) fn projected_entries_in_range(
        &mut self,
        header: &TreeHeader<P>,
        start: &[u8],
        end: &[u8],
        strip: usize,
    ) -> StorageResult<Vec<(String, Vec<u8>)>> {
        let mut entries = Vec::new();
        self.visit_projected_entries_in_range(header, start, end, strip, |key, value| {
            entries.push((key.to_owned(), value.to_vec()));
            Ok(())
        })?;
        entries.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
        Ok(entries)
    }

    pub(in crate::kv::tree) fn visit_projected_entries_in_range(
        &mut self,
        header: &TreeHeader<P>,
        start: &[u8],
        end: &[u8],
        strip: usize,
        mut visit: impl FnMut(&str, &[u8]) -> StorageResult<()>,
    ) -> StorageResult<()> {
        self.visit_slots_in_range(header.tree, start, end, |context, entry| {
            // Replacements and tombstones shadow checkpoint values before
            // body reconstruction, just as in a point read.
            if header.overlay.get(&entry.key).is_none() {
                let key = suffix(&entry.key, strip)?;
                match &entry.value {
                    ValueSlot::Inline(value) => visit(key, value)?,
                    ValueSlot::Spilled { .. } => {
                        let value = context.value_bytes(&entry.value)?;
                        visit(key, &value)?;
                    },
                }
            }
            Ok(())
        })?;
        for (key, value) in header.overlay.range(start, end) {
            if let Some(value) = value {
                visit(suffix(key, strip)?, value)?;
            }
        }
        Ok(())
    }
}

fn suffix(key: &[u8], strip: usize) -> StorageResult<&str> {
    let key = key_projection::suffix(key, strip)
        .ok_or_else(|| invalid(ObjectId::new([0; 32]), "KV key prefix underflow"))?;
    std::str::from_utf8(key).map_err(|error| StorageError::Serialization(error.to_string()))
}
