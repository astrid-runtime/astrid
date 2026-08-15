//! Path-copy operations over canonical KV pages.

use std::collections::{BTreeMap, BTreeSet};
use std::marker::PhantomData;

use crate::engine::{KvProjectionEngine, RootTransaction};
use crate::storage_model::{
    ModelError, ObjectClass, ObjectId, ObjectKind, ObjectRecord, ObjectReference, ReferenceKind,
};

use super::delta::{
    Head, Mutation, Projection, checkpoint_record, decode_head, delta_record,
    mutation_payload_bytes,
};
use super::header::TreeHeader;
use super::node::{
    ChildPointer, INLINE_VALUE_MAX, LeafEntry, NODE_MAX_ENTRIES, NODE_MAX_RETAINED_BYTES, Node,
    NodeHandle, NodeTotals, ValueSlot, branch_record, decode_node, decode_value, leaf_record,
    value_record,
};
use super::{FORMAT_VERSION, KV_LABEL, PARENT_LABEL, STATE_LABEL};
use crate::error::{StorageError, StorageResult};
use crate::kv::tree_error::{invalid, map_engine};

pub(super) struct TreeContext<'a, P, E> {
    engine: &'a E,
    principal: &'a P,
    records: BTreeMap<ObjectId, ObjectRecord>,
    nodes: BTreeMap<ObjectId, NodeHandle>,
    marker: PhantomData<fn() -> P>,
}

impl<'a, P, E> TreeContext<'a, P, E>
where
    P: Ord,
    E: KvProjectionEngine<P>,
{
    pub(super) fn new(engine: &'a E, principal: &'a P) -> Self {
        Self {
            engine,
            principal,
            records: BTreeMap::new(),
            nodes: BTreeMap::new(),
            marker: PhantomData,
        }
    }

    #[cfg(test)]
    pub(super) fn height(&mut self, root: Option<ObjectId>) -> StorageResult<u32> {
        root.map_or(Ok(0), |root| {
            u32::from(self.node(root)?.node.level())
                .checked_add(1)
                .ok_or_else(arithmetic_overflow)
        })
    }

    pub(super) fn get(
        &mut self,
        mut root: Option<ObjectId>,
        key: &[u8],
    ) -> StorageResult<Option<Vec<u8>>> {
        while let Some(object) = root {
            let handle = self.node(object)?;
            match handle.node {
                Node::Leaf(leaf) => {
                    return leaf
                        .entries
                        .binary_search_by(|entry| entry.key.as_slice().cmp(key))
                        .ok()
                        .map(|index| self.value_bytes(&leaf.entries[index].value))
                        .transpose();
                },
                Node::Branch(branch) => {
                    let index = child_index(&branch.children, key);
                    let child = &branch.children[index];
                    self.validate_pointer(child)?;
                    root = Some(child.object);
                },
            }
        }
        Ok(None)
    }

    pub(super) fn projected_get(
        &mut self,
        header: &TreeHeader<P>,
        key: &[u8],
    ) -> StorageResult<Option<Vec<u8>>> {
        match header.overlay.get(key) {
            Some(value) => Ok(value.clone()),
            None => self.get(header.tree, key),
        }
    }

    pub(super) fn build_sorted(
        &mut self,
        entries: Vec<(Vec<u8>, Vec<u8>)>,
    ) -> StorageResult<Option<ObjectId>> {
        if entries.is_empty() {
            return Ok(None);
        }
        if entries
            .windows(2)
            .any(|pair| pair[0].0.as_slice() >= pair[1].0.as_slice())
        {
            return Err(StorageError::Serialization(
                "KV migration entries are not strictly ordered".to_owned(),
            ));
        }

        let mut leaves = Vec::new();
        let mut current = Vec::new();
        for (key, bytes) in entries {
            let entry = LeafEntry {
                key,
                value: self.make_value(bytes)?,
            };
            current.push(entry);
            if current.len() > 1 && !page_fits(leaf_record(&current), current.len(), 1)? {
                let overflow = current.pop().ok_or_else(|| {
                    StorageError::Internal("KV bulk leaf lost its overflow entry".to_owned())
                })?;
                let completed = std::mem::take(&mut current);
                leaves.push(self.make_leaf_page(&completed)?);
                current.push(overflow);
            }
        }
        if !current.is_empty() {
            leaves.push(self.make_leaf_page(&current)?);
        }

        let mut level = leaves;
        while level.len() > 1 {
            let mut next = Vec::new();
            let mut children = Vec::new();
            for page in level {
                let pointer = page.pointer();
                let mut candidate = children.clone();
                candidate.push(pointer.clone());
                if children.len() >= 2 && !page_fits(branch_record(&candidate), candidate.len(), 2)?
                {
                    let completed = std::mem::take(&mut children);
                    next.push(self.make_branch_page(&completed)?);
                }
                children.push(pointer);
            }
            if children.len() == 1 {
                let orphan = children.remove(0);
                let previous = next.pop().ok_or_else(|| {
                    StorageError::Internal("KV bulk branch has an orphan child".to_owned())
                })?;
                let mut combined = match previous.node {
                    Node::Branch(branch) => branch.children,
                    Node::Leaf(_) => {
                        return Err(StorageError::Internal(
                            "KV bulk branch levels disagree".to_owned(),
                        ));
                    },
                };
                combined.push(orphan);
                next.extend(self.pack_branches(&combined)?);
            } else if !children.is_empty() {
                next.push(self.make_branch_page(&children)?);
            }
            level = next;
        }
        level
            .pop()
            .map(|root| Some(root.object))
            .ok_or_else(|| StorageError::Internal("KV bulk root is missing".to_owned()))
    }

    pub(super) fn raw_keys_in_range(
        &mut self,
        root: Option<ObjectId>,
        start: &[u8],
        end: &[u8],
    ) -> StorageResult<Vec<Vec<u8>>> {
        let mut keys = Vec::new();
        let Some(root) = root else {
            return Ok(keys);
        };
        let mut stack = vec![root];
        while let Some(object) = stack.pop() {
            match self.node(object)?.node {
                Node::Leaf(leaf) => {
                    keys.extend(
                        leaf.entries
                            .into_iter()
                            .filter(|entry| {
                                entry.key.as_slice() >= start && entry.key.as_slice() < end
                            })
                            .map(|entry| entry.key),
                    );
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
        Ok(keys)
    }

    pub(super) fn projected_keys_in_range(
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

    pub(super) fn visit_entries(
        &mut self,
        root: Option<ObjectId>,
        mut visit: impl FnMut(&[u8], &[u8]) -> StorageResult<()>,
    ) -> StorageResult<()> {
        let Some(root) = root else {
            return Ok(());
        };
        let mut stack = vec![root];
        while let Some(object) = stack.pop() {
            match self.node(object)?.node {
                Node::Leaf(leaf) => {
                    for entry in leaf.entries {
                        let value = self.value_bytes(&entry.value)?;
                        visit(&entry.key, &value)?;
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
        Ok(())
    }

    pub(super) fn finish(
        mut self,
        header: TreeHeader<P>,
        tree: Option<ObjectId>,
    ) -> StorageResult<RootTransaction<P>> {
        let totals = tree.map_or(Ok(NodeTotals::default()), |tree| {
            Ok(self.node(tree)?.node.totals())
        })?;
        let head = self.insert(checkpoint_record(tree, totals)?)?;
        self.finish_head(header, head)
    }

    pub(super) fn apply_mutations(
        &mut self,
        header: &TreeHeader<P>,
        mut replacements: Vec<(Vec<u8>, Option<Vec<u8>>)>,
    ) -> StorageResult<Projection> {
        replacements.sort_by(|left, right| left.0.cmp(&right.0));
        if replacements.is_empty() || replacements.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(StorageError::Serialization(
                "KV mutation batch is empty or has duplicate keys".to_owned(),
            ));
        }
        let mut totals = NodeTotals {
            entries: header.entries,
            logical_bytes: header.logical_bytes,
            quota_bytes: header.quota_bytes,
        };
        let mut current = header.overlay.clone();
        let mut mutations = Vec::with_capacity(replacements.len());
        for (key, replacement) in replacements {
            let previous = match current.get(&key) {
                Some(value) => value.clone(),
                None => self.get(header.tree, &key)?,
            };
            if previous == replacement {
                return Err(StorageError::Serialization(
                    "KV mutation batch contains a no-op".to_owned(),
                ));
            }
            update_totals(
                &mut totals,
                &key,
                previous.as_deref(),
                replacement.as_deref(),
            )?;
            let value = replacement
                .map(|value| self.make_value(value))
                .transpose()?;
            current.insert(
                key.clone(),
                value
                    .as_ref()
                    .map(|value| self.value_bytes(value))
                    .transpose()?,
            );
            mutations.push(Mutation { key, value });
        }
        let record = delta_record(
            header.head,
            header.delta_depth,
            header.delta_bytes,
            &mutations,
            totals,
        )?;
        let head = self.insert(record)?;
        let delta_bytes = header
            .delta_bytes
            .checked_add(mutation_payload_bytes(&mutations)?)
            .ok_or_else(arithmetic_overflow)?;
        Ok(Projection {
            head: Some(head),
            tree: header.tree,
            overlay: current,
            depth: header
                .delta_depth
                .checked_add(1)
                .ok_or_else(arithmetic_overflow)?,
            delta_bytes,
            totals,
        })
    }

    pub(super) fn finish_projection(
        self,
        header: TreeHeader<P>,
        projection: &Projection,
    ) -> StorageResult<RootTransaction<P>> {
        let head = projection.head.ok_or_else(|| {
            StorageError::Internal("KV projection mutation has no head".to_owned())
        })?;
        self.finish_head(header, head)
    }

    pub(super) fn rebase_checkpoint(
        mut self,
        base_head: Option<ObjectId>,
        header: TreeHeader<P>,
        tree: Option<ObjectId>,
        checkpoint_totals: NodeTotals,
    ) -> StorageResult<Option<(RootTransaction<P>, Projection)>> {
        let mut tail = Vec::new();
        let mut cursor = header.head;
        while cursor != base_head {
            let Some(object) = cursor else {
                return Ok(None);
            };
            match decode_head(object, &self.record(object)?)? {
                Head::Delta {
                    previous,
                    mutations,
                    totals,
                    ..
                } => {
                    tail.push((mutations, totals));
                    cursor = previous;
                },
                Head::Checkpoint { .. } => return Ok(None),
            }
        }
        tail.reverse();

        let mut head = self.insert(checkpoint_record(tree, checkpoint_totals)?)?;
        let mut overlay = super::overlay::OverlayMap::default();
        let mut depth = 0_u64;
        let mut delta_bytes = 0_u64;
        let mut totals = checkpoint_totals;
        for (mutations, declared_totals) in tail {
            let record = delta_record(Some(head), depth, delta_bytes, &mutations, declared_totals)?;
            head = self.insert(record)?;
            depth = depth.checked_add(1).ok_or_else(arithmetic_overflow)?;
            delta_bytes = delta_bytes
                .checked_add(mutation_payload_bytes(&mutations)?)
                .ok_or_else(arithmetic_overflow)?;
            for mutation in mutations {
                let value = mutation
                    .value
                    .as_ref()
                    .map(|value| self.value_bytes(value))
                    .transpose()?;
                overlay.insert(mutation.key, value);
            }
            totals = declared_totals;
        }
        let projection = Projection {
            head: Some(head),
            tree,
            overlay,
            depth,
            delta_bytes,
            totals,
        };
        let transaction = self.finish_projection(header, &projection)?;
        Ok(Some((transaction, projection)))
    }

    fn finish_head(
        mut self,
        header: TreeHeader<P>,
        head: ObjectId,
    ) -> StorageResult<RootTransaction<P>> {
        let mut state_references = header.preserved_state;
        state_references.push(ObjectReference::owns(KV_LABEL.to_vec().into(), head));
        state_references.sort();
        let state = ObjectRecord::new(
            ObjectKind::PrincipalState,
            FORMAT_VERSION,
            Vec::new(),
            state_references,
            0,
            ObjectClass::Metadata,
        )
        .map_err(|error| model_error(&error))?;
        let state = self.insert(state)?;

        let mut commit_references = header.preserved_commit;
        if let Some(previous) = header.root {
            commit_references.push(ObjectReference::new(
                PARENT_LABEL.to_vec().into(),
                previous.commit,
                ReferenceKind::Lineage,
            ));
        }
        commit_references.push(ObjectReference::owns(STATE_LABEL.to_vec().into(), state));
        commit_references.sort();
        let commit = ObjectRecord::new(
            ObjectKind::Commit,
            FORMAT_VERSION,
            Vec::new(),
            commit_references,
            0,
            ObjectClass::Metadata,
        )
        .map_err(|error| model_error(&error))?;
        let commit = self.insert(commit)?;
        self.retain_reachable(commit);
        Ok(RootTransaction::new(
            header.owner,
            header.root,
            commit,
            self.records.into_iter().collect(),
        ))
    }

    fn pack_branches(&mut self, children: &[ChildPointer]) -> StorageResult<Vec<NodeHandle>> {
        if children.len() < 2 {
            return Err(StorageError::Serialization(
                "persistent KV branch underflow".to_owned(),
            ));
        }
        if page_fits(branch_record(children), children.len(), 2)? {
            return Ok(vec![self.make_branch_page(children)?]);
        }
        let split = best_split(children.len(), 2, |range| {
            branch_record(&children[range]).and_then(|record| page_retained(&record))
        })?;
        let right = &children[split..];
        let left = &children[..split];
        Ok(vec![
            self.make_branch_page(left)?,
            self.make_branch_page(right)?,
        ])
    }

    fn make_value(&mut self, bytes: Vec<u8>) -> StorageResult<ValueSlot> {
        if bytes.len() <= INLINE_VALUE_MAX {
            return Ok(ValueSlot::Inline(bytes));
        }
        let length = u64::try_from(bytes.len()).map_err(|_| arithmetic_overflow())?;
        let object = self.insert(value_record(bytes)?)?;
        Ok(ValueSlot::Spilled { object, length })
    }

    fn make_leaf_page(&mut self, entries: &[LeafEntry]) -> StorageResult<NodeHandle> {
        let record = leaf_record(entries)?;
        self.insert_node(&record)
    }

    fn make_branch_page(&mut self, children: &[ChildPointer]) -> StorageResult<NodeHandle> {
        let record = branch_record(children)?;
        self.insert_node(&record)
    }

    pub(super) fn value_bytes(&self, value: &ValueSlot) -> StorageResult<Vec<u8>> {
        match value {
            ValueSlot::Inline(bytes) => Ok(bytes.clone()),
            ValueSlot::Spilled { object, length } => {
                let record = self.record(*object)?;
                decode_value(*object, *length, &record)
            },
        }
    }

    fn validate_pointer(&mut self, pointer: &ChildPointer) -> StorageResult<()> {
        let actual = self.node(pointer.object)?.pointer();
        if actual != *pointer {
            return Err(invalid(
                pointer.object,
                "persistent KV child summary disagrees",
            ));
        }
        Ok(())
    }

    pub(super) fn node(&mut self, object: ObjectId) -> StorageResult<NodeHandle> {
        if let Some(handle) = self.nodes.get(&object) {
            return Ok(handle.clone());
        }
        let record = self.record(object)?;
        let handle = decode_node(object, &record)?;
        self.nodes.insert(object, handle.clone());
        Ok(handle)
    }

    pub(super) fn record(&self, object: ObjectId) -> StorageResult<ObjectRecord> {
        if let Some(record) = self.records.get(&object) {
            return Ok(record.clone());
        }
        self.engine
            .load_kv_object_for(self.principal, object)
            .map_err(|error| map_engine(&error))?
            .ok_or_else(|| map_engine(&ModelError::MissingObject(object).into()))
    }

    fn insert_node(&mut self, record: &ObjectRecord) -> StorageResult<NodeHandle> {
        let object = self.insert(record.clone())?;
        let handle = decode_node(object, record)?;
        self.nodes.insert(object, handle.clone());
        Ok(handle)
    }

    pub(super) fn insert(&mut self, record: ObjectRecord) -> StorageResult<ObjectId> {
        let object = self.engine.identify_kv_object(&record);
        match self.records.get(&object) {
            Some(existing) if existing == &record => {},
            Some(_) => return Err(map_engine(&ModelError::ObjectCollision(object).into())),
            None => {
                self.records.insert(object, record);
            },
        }
        Ok(object)
    }

    fn retain_reachable(&mut self, root: ObjectId) {
        let mut reachable = BTreeSet::new();
        let mut stack = vec![root];
        while let Some(object) = stack.pop() {
            if !reachable.insert(object) {
                continue;
            }
            if let Some(record) = self.records.get(&object) {
                stack.extend(record.owning_references());
            }
        }
        self.records.retain(|object, _| reachable.contains(object));
    }
}

fn update_totals(
    totals: &mut NodeTotals,
    key: &[u8],
    previous: Option<&[u8]>,
    replacement: Option<&[u8]>,
) -> StorageResult<()> {
    let key_bytes = u64::try_from(key.len()).map_err(|_| arithmetic_overflow())?;
    let previous_bytes = previous.map_or(0, |value| value.len() as u64);
    let replacement_bytes = replacement.map_or(0, |value| value.len() as u64);
    totals.entries = match (previous, replacement) {
        (None, Some(_)) => totals.entries.checked_add(1),
        (Some(_), None) => totals.entries.checked_sub(1),
        _ => Some(totals.entries),
    }
    .ok_or_else(arithmetic_overflow)?;
    totals.logical_bytes = totals
        .logical_bytes
        .checked_sub(previous_bytes)
        .and_then(|total| total.checked_add(replacement_bytes))
        .ok_or_else(arithmetic_overflow)?;
    totals.quota_bytes = totals
        .quota_bytes
        .checked_sub(previous_bytes)
        .and_then(|total| {
            if previous.is_none() {
                total.checked_add(key_bytes)
            } else if replacement.is_none() {
                total.checked_sub(key_bytes)
            } else {
                Some(total)
            }
        })
        .and_then(|total| total.checked_add(replacement_bytes))
        .ok_or_else(arithmetic_overflow)?;
    Ok(())
}

fn child_index(children: &[ChildPointer], key: &[u8]) -> usize {
    children
        .partition_point(|child| child.lower_bound.as_slice() <= key)
        .saturating_sub(1)
}

fn page_retained(record: &ObjectRecord) -> StorageResult<u64> {
    record.retained_bytes().map_err(|error| model_error(&error))
}

fn page_fits(
    record: StorageResult<ObjectRecord>,
    slots: usize,
    minimum_slots: usize,
) -> StorageResult<bool> {
    if slots > NODE_MAX_ENTRIES {
        return Ok(false);
    }
    let retained = page_retained(&record?)?;
    Ok(retained <= NODE_MAX_RETAINED_BYTES || slots < minimum_slots.saturating_mul(2))
}

fn best_split(
    length: usize,
    minimum_slots: usize,
    mut retained: impl FnMut(std::ops::Range<usize>) -> StorageResult<u64>,
) -> StorageResult<usize> {
    let mut best = None::<(u64, usize)>;
    for split in minimum_slots..length {
        if split > NODE_MAX_ENTRIES || length.saturating_sub(split) > NODE_MAX_ENTRIES {
            continue;
        }
        let right_slots = length.saturating_sub(split);
        if right_slots < minimum_slots {
            continue;
        }
        let left = retained(0..split)?;
        let right = retained(split..length)?;
        let left_fits = left <= NODE_MAX_RETAINED_BYTES || split < minimum_slots.saturating_mul(2);
        let right_fits =
            right <= NODE_MAX_RETAINED_BYTES || right_slots < minimum_slots.saturating_mul(2);
        if !left_fits || !right_fits {
            continue;
        }
        let imbalance = left.abs_diff(right);
        if best.is_none_or(|candidate| (imbalance, split) < candidate) {
            best = Some((imbalance, split));
        }
    }
    best.map(|(_, split)| split)
        .ok_or_else(|| StorageError::Serialization("persistent KV page cannot split".to_owned()))
}

fn arithmetic_overflow() -> StorageError {
    StorageError::Internal("persistent KV tree arithmetic overflow".to_owned())
}

fn model_error(error: &crate::storage_model::ModelError) -> StorageError {
    StorageError::Serialization(error.to_string())
}
