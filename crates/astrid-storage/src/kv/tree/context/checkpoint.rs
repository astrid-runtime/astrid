//! Reuse sealed leaf partitions while folding a checked KV projection.

use std::collections::{BTreeMap, BTreeSet};

use super::{
    ChildPointer, Head, KvProjectionEngine, LeafEntry, NODE_MAX_ENTRIES, Node, NodeHandle,
    NodeTotals, ObjectId, StorageError, StorageResult, TreeContext, TreeHeader,
    arithmetic_overflow, decode_head, invalid, leaf_record, page_fits,
};

struct CheckpointRows {
    entries: Vec<LeafEntry>,
    leaves: Vec<ChildPointer>,
}

impl<P: Ord, E: KvProjectionEngine<P>> TreeContext<'_, P, E> {
    /// The caller checks the exact owner and sealed source-tree certificate.
    /// Keep its existing leaf windows so one removal does not shift every
    /// later page. All resolved rows and aggregate accounting are still checked.
    pub(in crate::kv::tree) fn rebuild_checkpoint(
        &mut self,
        header: &TreeHeader<P>,
    ) -> StorageResult<Option<ObjectId>> {
        let CheckpointRows { entries, leaves } = self.checkpoint_rows(header)?;
        if leaves.is_empty() {
            return self.build_sorted_slots(entries);
        }
        if leaves
            .windows(2)
            .any(|pair| pair[0].lower_bound >= pair[1].lower_bound)
        {
            return Err(StorageError::Serialization(
                "sealed KV leaf windows are not strictly ordered".to_owned(),
            ));
        }
        let mut rows = entries.into_iter().peekable();
        let mut rebuilt = Vec::new();
        for (index, source) in leaves.iter().enumerate() {
            let upper = leaves
                .get(index.strict_add(1))
                .map(|next| next.lower_bound.as_slice());
            let mut window = Vec::new();
            while let Some(entry) =
                rows.next_if(|entry| upper.is_none_or(|bound| entry.key.as_slice() < bound))
            {
                window.push(entry);
            }
            if window.is_empty() {
                continue;
            }
            let original = self.node(source.object)?;
            let Node::Leaf(leaf) = &original.node else {
                return Err(invalid(
                    source.object,
                    "sealed KV leaf window is not a leaf",
                ));
            };
            if leaf.entries == window {
                rebuilt.push(original);
            } else {
                rebuilt.extend(self.pack_leaf_entries(window)?);
            }
        }
        if rows.next().is_some() {
            return Err(StorageError::Internal(
                "KV checkpoint left unresolved rows".to_owned(),
            ));
        }
        let leaves = self.coalesce_checkpoint_leaves(rebuilt)?;
        self.build_leaf_level(leaves)
    }

    // Merge adjacent sparse windows whenever their existing page grammar fits.
    // This releases obsolete partitions during retirement without a second
    // occupancy policy or a separate maintenance pass.
    fn coalesce_checkpoint_leaves(
        &mut self,
        leaves: Vec<NodeHandle>,
    ) -> StorageResult<Vec<NodeHandle>> {
        let mut packed: Vec<NodeHandle> = Vec::new();
        for leaf in leaves {
            let Some(previous) = packed.last() else {
                packed.push(leaf);
                continue;
            };
            let (Node::Leaf(left), Node::Leaf(right)) = (&previous.node, &leaf.node) else {
                return Err(invalid(
                    leaf.object,
                    "KV checkpoint coalescing requires leaves",
                ));
            };
            if left.entries.len().strict_add(right.entries.len()) > NODE_MAX_ENTRIES {
                packed.push(leaf);
                continue;
            }
            let mut combined = left.entries.clone();
            combined.extend(right.entries.iter().cloned());
            if page_fits(leaf_record(&combined), combined.len(), 1)? {
                packed.pop();
                packed.push(self.make_leaf_page(&combined)?);
            } else {
                packed.push(leaf);
            }
        }
        Ok(packed)
    }

    // Repack the exact head's previously admitted, content-addressed value
    // slots. Header validation and root admission establish the immutable
    // closure; metadata checkpointing does not need a second content audit.
    fn checkpoint_rows(&mut self, header: &TreeHeader<P>) -> StorageResult<CheckpointRows> {
        let mut entries = BTreeMap::new();
        let mut leaves = Vec::new();
        let mut stack = header.tree.into_iter().collect::<Vec<_>>();
        while let Some(object) = stack.pop() {
            let page = self.node(object)?;
            let pointer = page.pointer();
            match page.node {
                Node::Leaf(leaf) => {
                    leaves.push(pointer);
                    for entry in leaf.entries {
                        if entries.insert(entry.key, entry.value).is_some() {
                            return Err(invalid(object, "KV checkpoint contains duplicate keys"));
                        }
                    }
                },
                Node::Branch(branch) => {
                    for child in branch.children.iter().rev() {
                        self.validate_pointer(child)?;
                        stack.push(child.object);
                    }
                },
            }
        }

        // Latest occurrence wins. Values are immutable slots from the exact
        // authoritative delta chain, rather than reconstructed overlay bytes.
        let mut updates = BTreeMap::new();
        let mut cursor = header.head;
        let mut visited = BTreeSet::new();
        let mut depth = 0_u64;
        let mut checkpoint_tree = None;
        while let Some(object) = cursor {
            if !visited.insert(object) {
                return Err(invalid(object, "KV delta chain contains a cycle"));
            }
            match decode_head(object, &self.record(object)?)? {
                Head::Checkpoint { tree, .. } => {
                    checkpoint_tree = tree;
                    break;
                },
                Head::Delta {
                    previous,
                    mutations,
                    ..
                } => {
                    depth = depth.checked_add(1).ok_or_else(arithmetic_overflow)?;
                    for mutation in mutations {
                        updates.entry(mutation.key).or_insert(mutation.value);
                    }
                    cursor = previous;
                },
            }
        }
        if checkpoint_tree != header.tree || depth != header.delta_depth {
            return Err(StorageError::Serialization(
                "KV checkpoint source disagrees with validated projection".to_owned(),
            ));
        }
        for (key, value) in updates {
            match value {
                Some(value) => {
                    entries.insert(key, value);
                },
                None => {
                    entries.remove(&key);
                },
            }
        }
        let resolved = entries
            .into_iter()
            .map(|(key, value)| LeafEntry { key, value })
            .collect::<Vec<_>>();
        let totals = resolved
            .iter()
            .try_fold(NodeTotals::default(), |totals, entry| {
                totals.add(entry.totals()?)
            })?;
        if totals.entries != header.entries
            || totals.logical_bytes != header.logical_bytes
            || totals.quota_bytes != header.quota_bytes
        {
            return Err(StorageError::Serialization(
                "KV checkpoint slot accounting disagrees with validated projection".to_owned(),
            ));
        }
        Ok(CheckpointRows {
            entries: resolved,
            leaves,
        })
    }
}
