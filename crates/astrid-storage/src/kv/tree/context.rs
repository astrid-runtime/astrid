//! Path-copy operations over canonical KV pages.

use std::collections::{BTreeMap, BTreeSet};
use std::marker::PhantomData;

use crate::engine::{KvIdentitySession, KvProjectionEngine, RootTransaction};
use crate::storage_model::{
    ModelError, ObjectClass, ObjectId, ObjectKind, ObjectRecord, ObjectReference, ReferenceKind,
};

use super::delta::{
    Head, Projection, checkpoint_record, decode_head, delta_record, mutation_payload_bytes,
};
use super::header::TreeHeader;
use super::node::{
    ChildPointer, INLINE_VALUE_MAX, LeafEntry, NODE_MAX_ENTRIES, NODE_MAX_RETAINED_BYTES, Node,
    NodeHandle, NodeTotals, ValueSlot, branch_record, leaf_record,
};
use super::{FORMAT_VERSION, KV_LABEL, PARENT_LABEL, STATE_LABEL};
use crate::error::{StorageError, StorageResult};
use crate::kv::tree_error::{invalid, map_engine};

mod checkpoint;
mod range;
pub(super) mod value;

mod replacement;
use replacement::PreviousValue;
pub(super) use replacement::Replacement;

pub(super) struct TreeContext<'a, P, E> {
    engine: &'a E,
    records: BTreeMap<ObjectId, ObjectRecord>,
    nodes: super::checkpoint_cache::Cache<'a, P>,
    identity_session: Option<KvIdentitySession<'a>>,
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
            records: BTreeMap::new(),
            nodes: super::checkpoint_cache::Cache::new(principal),
            identity_session: engine.kv_identity_session(),
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
        root: Option<ObjectId>,
        key: &[u8],
    ) -> StorageResult<Option<Vec<u8>>> {
        self.get_slot(root, key)?
            .map(|value| self.value_bytes(&value))
            .transpose()
    }

    /// Authoritative leaf lookup used by ordinary and certified point-reads.
    pub(super) fn get_slot(
        &mut self,
        root: Option<ObjectId>,
        key: &[u8],
    ) -> StorageResult<Option<ValueSlot>> {
        use super::checkpoint_descent;
        checkpoint_descent::lookup(self, root, key, |context, object| {
            let handle = context.node(object)?;
            Ok((context, handle))
        })
        .map_err(|error| match error {
            checkpoint_descent::Error::Source(error) => error,
            checkpoint_descent::Error::Mismatch(object) => {
                invalid(object, "persistent KV child summary disagrees")
            },
            checkpoint_descent::Error::Branch(object) => {
                invalid(object, "invalid persistent KV branch descent")
            },
        })
    }

    pub(super) fn projected_get(
        &mut self,
        header: &TreeHeader<P>,
        key: &[u8],
    ) -> StorageResult<Option<Vec<u8>>> {
        match header.overlay.get(key) {
            Some(value) => Ok(value.clone()),
            None => match header
                .boundary
                .filter(|certificate| certificate.matches_tree(header.tree))
            {
                Some(certificate) => self.read_certified_tree_value(header, key, certificate),
                None => self.get(header.tree, key),
            },
        }
    }

    /// Live principal bound to this context.
    pub(super) fn principal(&self) -> &P {
        self.nodes.principal()
    }

    pub(super) fn build_sorted(
        &mut self,
        entries: Vec<(Vec<u8>, Vec<u8>)>,
    ) -> StorageResult<Option<ObjectId>> {
        if entries.windows(2).any(|pair| pair[0].0 >= pair[1].0) {
            return Err(StorageError::Serialization(
                "KV migration entries are not strictly ordered".to_owned(),
            ));
        }
        let entries = entries
            .into_iter()
            .map(|(key, bytes)| {
                Ok(LeafEntry {
                    key,
                    value: self.make_value(bytes)?,
                })
            })
            .collect::<StorageResult<Vec<_>>>()?;
        self.build_sorted_slots(entries)
    }

    pub(super) fn build_sorted_slots(
        &mut self,
        entries: Vec<LeafEntry>,
    ) -> StorageResult<Option<ObjectId>> {
        if entries.is_empty() {
            return Ok(None);
        }
        if entries.windows(2).any(|pair| pair[0].key >= pair[1].key) {
            return Err(StorageError::Serialization(
                "KV migration entries are not strictly ordered".to_owned(),
            ));
        }

        let leaves = self.pack_leaf_entries(entries)?;
        self.build_leaf_level(leaves)
    }

    fn pack_leaf_entries(&mut self, entries: Vec<LeafEntry>) -> StorageResult<Vec<NodeHandle>> {
        let mut leaves = Vec::new();
        let mut current = Vec::new();
        for entry in entries {
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

        Ok(leaves)
    }

    fn build_leaf_level(&mut self, leaves: Vec<NodeHandle>) -> StorageResult<Option<ObjectId>> {
        if leaves.is_empty() {
            return Ok(None);
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
        let head = self.insert(checkpoint_record(tree, totals))?;
        self.finish_head(header, head)
    }

    pub(super) fn apply_mutations(
        &mut self,
        header: &TreeHeader<P>,
        mut replacements: Vec<Replacement>,
    ) -> StorageResult<Projection> {
        replacements.sort_by(|left, right| left.key.cmp(&right.key));
        if replacements.is_empty()
            || replacements
                .windows(2)
                .any(|pair| pair[0].key == pair[1].key)
        {
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
        for row in replacements {
            let (key, previous, replacement) = row.into_parts();
            let (previous_len, unchanged) = if let Some(value) = current.get(&key) {
                (value.as_ref().map(Vec::len), value == &replacement)
            } else {
                match previous {
                    PreviousValue::Loaded {
                        previous_len,
                        unchanged,
                    } => (previous_len, unchanged),
                    PreviousValue::Unread => {
                        let value = self.projected_get(header, &key)?;
                        (value.as_ref().map(Vec::len), value == replacement)
                    },
                }
            };
            totals = super::delta_totals::admit(
                totals,
                key.len(),
                previous_len,
                replacement.as_ref().map(Vec::len),
                unchanged,
            )
            .map_err(|error| match error {
                super::delta_totals::ReplayError::Unchanged => {
                    StorageError::Serialization("KV mutation batch contains a no-op".to_owned())
                },
                super::delta_totals::ReplayError::Accounting(_) => arithmetic_overflow(),
            })?;
            mutations.push(current.stage(key, replacement, |data| {
                super::delta_mutation::encode(data, |bytes, length| {
                    self.spill_value(bytes.into(), length)
                })
            })?);
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
            boundary: header
                .boundary
                .filter(|certificate| certificate.matches_tree(header.tree)),
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
        certificate: super::validation::ValidatedCheckpoint,
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

        let mut head = self.insert(checkpoint_record(tree, checkpoint_totals))?;
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
            boundary: Some(certificate).filter(|certificate| certificate.matches_tree(tree)),
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
        let records = self.records.into_iter().collect();
        Ok(match self.identity_session {
            Some(session) => session.seal_transaction(header.owner, header.root, commit, records),
            None => RootTransaction::new(header.owner, header.root, commit, records),
        })
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

    fn make_leaf_page(&mut self, entries: &[LeafEntry]) -> StorageResult<NodeHandle> {
        let record = leaf_record(entries)?;
        self.insert_node(&record)
    }

    fn make_branch_page(&mut self, children: &[ChildPointer]) -> StorageResult<NodeHandle> {
        let record = branch_record(children)?;
        self.insert_node(&record)
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
        use super::checkpoint_cache::Error;
        let records = &self.records;
        let engine = self.engine;
        self.nodes
            .lookup(
                object,
                FORMAT_VERSION,
                |principal, id| {
                    Self::load_record(
                        records,
                        principal,
                        id,
                        ObjectRecord::owned_record,
                        |owner, address| engine.load_kv_object_for(owner, address),
                    )
                },
                |key| super::validation::validate_composite_key(object, key),
            )
            .map_err(|e| match e {
                Error::Load(e) => e,
                Error::Decode(e) => super::node::decode_error(object, e),
            })
    }

    pub(super) fn record(&self, object: ObjectId) -> StorageResult<ObjectRecord> {
        Self::load_record(
            &self.records,
            self.principal(),
            object,
            ObjectRecord::owned_record,
            |principal, id| self.engine.load_kv_object_for(principal, id),
        )
    }

    fn load_record<T>(
        records: &BTreeMap<ObjectId, ObjectRecord>,
        principal: &P,
        object: ObjectId,
        copy: impl FnOnce(&ObjectRecord) -> T,
        engine: impl FnOnce(&P, ObjectId) -> Result<Option<T>, crate::engine::KvProjectionError>,
    ) -> StorageResult<T> {
        use super::record_source::{self, Error};
        record_source::load(records, principal, object, copy, engine).map_err(|error| match error {
            Error::Source(error) => map_engine(&error),
            Error::Missing(id) => map_engine(&ModelError::MissingObject(id).into()),
        })
    }

    fn insert_node(&mut self, record: &ObjectRecord) -> StorageResult<NodeHandle> {
        let object = self.insert(record.clone())?;
        self.nodes
            .admit(object, record, FORMAT_VERSION, |key| {
                super::validation::validate_composite_key(object, key)
            })
            .map_err(|e| super::node::decode_error(object, e))
    }

    pub(super) fn insert(&mut self, record: ObjectRecord) -> StorageResult<ObjectId> {
        let (id, record) =
            crate::engine::transaction_records::identify(record, |r| self.identify_record(r));
        self.stage_identified_record(id, record)
    }

    pub(super) fn identify_record(&self, record: &ObjectRecord) -> ObjectId {
        match self.identity_session {
            Some(session) => session.identify(record),
            None => self.engine.identify_kv_object(record),
        }
    }

    // Transaction-local staging only. Writers are insert after identify_record
    // and make_chunked_value immediately after build_content(self). A captured
    // session lets admission trust these identities; keep this set of callers closed.
    fn stage_identified_record(
        &mut self,
        object: ObjectId,
        record: ObjectRecord,
    ) -> StorageResult<ObjectId> {
        crate::engine::transaction_records::insert(&mut self.records, object, record)
            .map_err(|id| map_engine(&ModelError::ObjectCollision(id).into()))
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
