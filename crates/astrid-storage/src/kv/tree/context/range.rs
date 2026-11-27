//! Prefix traversal over one authenticated checkpoint and its current overlay.

use std::collections::BTreeMap;

use super::{
    KvProjectionEngine, LeafEntry, Node, ObjectId, PreviousValue, Replacement, StorageError,
    StorageResult, TreeContext, TreeHeader, ValueSlot, decode_node, invalid,
};

use crate::kv::tree::{
    checkpoint_leaf,
    checkpoint_range::Page,
    checkpoint_walk::{self, Contents},
    key_projection,
};

#[cfg(test)]
mod tests;

impl<P: Ord, E: KvProjectionEngine<P>> TreeContext<'_, P, E> {
    // Each range consumes its authenticated pages once. Deletion observations
    // carry validated values forward, so subsequent accounting needs no page memo.
    fn fold_slots_in_range<S>(
        &self,
        root: Option<ObjectId>,
        start: &[u8],
        end: &[u8],
        state: S,
        visit: impl Fn(S, LeafEntry) -> StorageResult<S> + Copy,
    ) -> StorageResult<S> {
        checkpoint_walk::fold(
            root,
            start,
            end,
            state,
            |page| {
                let object = page.object();
                let handle = decode_node(object, &self.record(object)?)?;
                if let Page::Child(expected) = page
                    && !expected.matches(
                        &handle.object,
                        handle.node.minimum_key(),
                        handle.node.level(),
                        &handle.node.totals(),
                    )
                {
                    return Err(invalid(object, "persistent KV child summary disagrees"));
                }
                Ok(match handle.node {
                    Node::Leaf(leaf) => Contents::Leaf(leaf.entries),
                    Node::Branch(branch) => Contents::Branch(branch.level, branch.children),
                })
            },
            visit,
        )
    }

    pub(in crate::kv::tree) fn projected_deletions_in_range(
        &mut self,
        header: &TreeHeader<P>,
        start: &[u8],
        end: &[u8],
    ) -> StorageResult<Vec<Replacement>> {
        let mut observed = self.fold_slots_in_range(
            header.tree,
            start,
            end,
            BTreeMap::new(),
            |mut observed, entry| {
                if header.overlay.get(&entry.key).is_none() {
                    // Preserve the existing body validation before deletion, but
                    // reuse this authenticated slot instead of looking it up again.
                    let value = match header.boundary {
                        Some(certificate) => {
                            self.read_certified_tree_slot(header, &entry.value, certificate)?
                        },
                        None => self.value_bytes(&entry.value)?,
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
                Ok(observed)
            },
        )?;
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
        let mut keys = self.fold_slots_in_range(
            header.tree,
            start,
            end,
            BTreeMap::new(),
            checkpoint_leaf::mark,
        )?;
        header.overlay.project_presence(&mut keys, start, end);
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
        self.fold_slots_in_range(header.tree, start, end, &mut visit, |visitor, entry| {
            // Replacements and tombstones shadow checkpoint values before
            // body reconstruction, just as in a point read.
            if header.overlay.get(&entry.key).is_none() {
                let key = suffix(&entry.key, strip)?;
                match &entry.value {
                    ValueSlot::Inline(value) => visitor(key, value)?,
                    ValueSlot::Spilled { .. } => {
                        let value = self.value_bytes(&entry.value)?;
                        visitor(key, &value)?;
                    },
                }
            }
            Ok(visitor)
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
