//! Prefix traversal over one authenticated checkpoint and its current overlay.

use std::collections::BTreeMap;

use super::{
    ChildPointer, KvProjectionEngine, LeafEntry, Node, NodeHandle, ObjectId, StorageError,
    StorageResult, TreeContext, TreeHeader, ValueSlot, decode_node, invalid,
};

#[cfg(test)]
mod tests;

impl<P: Ord, E: KvProjectionEngine<P>> TreeContext<'_, P, E> {
    fn visit_slots_in_range(
        &mut self,
        root: Option<ObjectId>,
        start: &[u8],
        end: &[u8],
        visit: impl FnMut(&Self, LeafEntry) -> StorageResult<()>,
    ) -> StorageResult<()> {
        self.walk_slots_in_range(root, start, end, Self::node, visit)
    }

    fn walk_slots_in_range(
        &mut self,
        root: Option<ObjectId>,
        start: &[u8],
        end: &[u8],
        mut load: impl FnMut(&mut Self, ObjectId) -> StorageResult<NodeHandle>,
        mut visit: impl FnMut(&Self, LeafEntry) -> StorageResult<()>,
    ) -> StorageResult<()> {
        let Some(root) = root else {
            return Ok(());
        };
        let mut stack: Vec<(ObjectId, Option<ChildPointer>)> = vec![(root, None)];
        while let Some((object, expected)) = stack.pop() {
            let handle = load(self, object)?;
            if expected.is_some_and(|expected| handle.pointer() != expected) {
                return Err(invalid(object, "persistent KV child summary disagrees"));
            }
            match handle.node {
                Node::Leaf(leaf) => {
                    for entry in leaf.entries {
                        if entry.key.as_slice() >= start && entry.key.as_slice() < end {
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
                        if upper.is_some_and(|upper| upper <= start)
                            || child.lower_bound.as_slice() >= end
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

    pub(in crate::kv::tree) fn raw_keys_in_range(
        &mut self,
        root: Option<ObjectId>,
        start: &[u8],
        end: &[u8],
    ) -> StorageResult<Vec<Vec<u8>>> {
        let mut keys = Vec::new();
        self.visit_slots_in_range(root, start, end, |_, entry| {
            keys.push(entry.key);
            Ok(())
        })?;
        Ok(keys)
    }

    pub(in crate::kv::tree) fn projected_keys_in_range(
        &mut self,
        header: &TreeHeader<P>,
        start: &[u8],
        end: &[u8],
        strip: usize,
    ) -> StorageResult<Vec<String>> {
        let mut keys = BTreeMap::new();
        self.walk_slots_in_range(
            header.tree,
            start,
            end,
            |context, object| decode_node(object, &context.record(object)?),
            |_, entry| {
                keys.insert(entry.key, true);
                Ok(())
            },
        )?;
        for (key, value) in header.overlay.range(start, end) {
            keys.insert(key.to_vec(), value.is_some());
        }
        keys.into_iter()
            .filter(|(_, present)| *present)
            .map(|(key, _)| {
                key.get(strip..)
                    .ok_or_else(|| invalid(ObjectId::new([0; 32]), "KV key prefix underflow"))
                    .and_then(|key| {
                        std::str::from_utf8(key)
                            .map(str::to_owned)
                            .map_err(|error| StorageError::Serialization(error.to_string()))
                    })
            })
            .collect()
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
        self.walk_slots_in_range(
            header.tree,
            start,
            end,
            // A read-only walk uses each decoded page once. Keep the existing
            // mutation-side memo policy for key collection, but do not retain
            // an entire checkpoint's decoded bodies as scan scratch.
            |context, object| decode_node(object, &context.record(object)?),
            |context, entry| {
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
            },
        )?;
        for (key, value) in header.overlay.range(start, end) {
            if let Some(value) = value {
                visit(suffix(key, strip)?, value)?;
            }
        }
        Ok(())
    }
}

fn suffix(key: &[u8], strip: usize) -> StorageResult<&str> {
    let key = key
        .get(strip..)
        .ok_or_else(|| invalid(ObjectId::new([0; 32]), "KV key prefix underflow"))?;
    std::str::from_utf8(key).map_err(|error| StorageError::Serialization(error.to_string()))
}
