//! Prefix traversal over one authenticated checkpoint and its current overlay.

use std::collections::BTreeMap;

use super::{
    KvProjectionEngine, LeafEntry, Node, ObjectId, StorageError, StorageResult, TreeContext,
    TreeHeader, invalid,
};

#[cfg(test)]
mod tests;

impl<P: Ord, E: KvProjectionEngine<P>> TreeContext<'_, P, E> {
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
        let mut stack = vec![root];
        while let Some(object) = stack.pop() {
            match self.node(object)?.node {
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
                        self.validate_pointer(child)?;
                        stack.push(child.object);
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
        let mut keys = self
            .raw_keys_in_range(header.tree, start, end)?
            .into_iter()
            .map(|key| (key, true))
            .collect::<BTreeMap<_, _>>();
        for (key, value) in header.overlay.range(start, end) {
            keys.insert(key, value.is_some());
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
        let mut entries = BTreeMap::new();
        self.visit_slots_in_range(header.tree, start, end, |context, entry| {
            // A replacement or tombstone shadows the old immutable value.
            // Match point-read semantics without reconstructing stale bodies.
            if header.overlay.get(&entry.key).is_none() {
                let value = context.value_bytes(&entry.value)?;
                entries.insert(entry.key, value);
            }
            Ok(())
        })?;
        for (key, value) in header.overlay.range(start, end) {
            if let Some(value) = value {
                entries.insert(key, value);
            }
        }
        entries
            .into_iter()
            .map(|(key, value)| {
                let suffix = key
                    .get(strip..)
                    .ok_or_else(|| invalid(ObjectId::new([0; 32]), "KV key prefix underflow"))?;
                let key = std::str::from_utf8(suffix)
                    .map_err(|error| StorageError::Serialization(error.to_string()))?;
                Ok((key.to_owned(), value))
            })
            .collect()
    }
}
