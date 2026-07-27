//! Height-bounded persistent key/value tree for the native principal store.
//!
//! The compatibility projection rebuilds a principal's complete map and is
//! intentionally retained only as a differential oracle. This implementation
//! stores composite namespace/key entries in a persistent AVL tree. A point
//! mutation copies one search path plus at most a constant number of rotation
//! nodes, then publishes one principal-root CAS.
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt;
use std::marker::PhantomData;
use std::sync::Arc;

use astrid_storage_engine::{KvProjectionEngine, KvProjectionError, RootTransaction};
use astrid_storage_model::{
    ModelError, ObjectClass, ObjectFormatVersion, ObjectId, ObjectKind, ObjectRecord,
    ObjectReference, ReferenceKind, ReferenceLabel, RootState,
};
use parking_lot::Mutex;

#[cfg(all(feature = "legacy-surrealkv", not(target_family = "wasm")))]
use super::KvEntry;
#[cfg(all(feature = "legacy-surrealkv", not(target_family = "wasm")))]
use super::composite_key;
use super::principal::{KvPrincipalResolver, KvQuotaResolver};
use super::tree_error::{exact_owned_reference, invalid, map_engine};
use super::{validate_key, validate_namespace};
use crate::error::{StorageError, StorageResult};

mod adapter;

pub(super) const FORMAT_VERSION: ObjectFormatVersion = match ObjectFormatVersion::new(3) {
    Some(version) => version,
    None => unreachable!(),
};
pub(super) const KV_LABEL: &[u8] = b"kv";
pub(super) const LEFT_LABEL: &[u8] = b"left";
const PARENT_LABEL: &[u8] = b"parent";
const RIGHT_LABEL: &[u8] = b"right";
pub(super) const ROOT_LABEL: &[u8] = b"root";
pub(super) const STATE_LABEL: &[u8] = b"state";
pub(super) const VALUE_LABEL: &[u8] = b"value";
const NODE_FIXED_BYTES: usize = 28;

/// Production point-operation KV adapter over a persistent balanced tree.
pub struct TreeKvStore<P: Ord, I, R, E> {
    engine: Arc<E>,
    resolver: R,
    quota: Option<Arc<dyn KvQuotaResolver<P>>>,
    validated_trees: Arc<Mutex<BTreeMap<P, TreeValidation>>>,
    marker: PhantomData<fn() -> (P, I)>,
}

struct BlockingTreeStore<P: Ord, E> {
    engine: Arc<E>,
    quota: Option<Arc<dyn KvQuotaResolver<P>>>,
    validated_trees: Arc<Mutex<BTreeMap<P, TreeValidation>>>,
}

impl<P: Ord, I, R, E> TreeKvStore<P, I, R, E> {
    /// Construct a tree adapter without logical quota policy.
    #[must_use]
    pub fn from_engine(engine: Arc<E>, resolver: R) -> Self {
        Self {
            engine,
            resolver,
            quota: None,
            validated_trees: Arc::new(Mutex::new(BTreeMap::new())),
            marker: PhantomData,
        }
    }

    /// Construct a tree adapter with live logical quota policy.
    #[must_use]
    pub fn from_engine_with_quota(
        engine: Arc<E>,
        resolver: R,
        quota: Arc<dyn KvQuotaResolver<P>>,
    ) -> Self {
        Self {
            engine,
            resolver,
            quota: Some(quota),
            validated_trees: Arc::new(Mutex::new(BTreeMap::new())),
            marker: PhantomData,
        }
    }

    fn blocking_store(&self) -> BlockingTreeStore<P, E> {
        BlockingTreeStore {
            engine: Arc::clone(&self.engine),
            quota: self.quota.clone(),
            validated_trees: Arc::clone(&self.validated_trees),
        }
    }
}

impl<P: Ord, I, R, E> fmt::Debug for TreeKvStore<P, I, R, E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TreeKvStore")
            .finish_non_exhaustive()
    }
}

impl<P, E> BlockingTreeStore<P, E>
where
    P: Clone + Ord + Send + Sync,
    E: KvProjectionEngine<P>,
{
    fn header(&self, owner: P) -> StorageResult<TreeHeader<P>> {
        let Some(root) = self
            .engine
            .current_kv_root(&owner)
            .map_err(|error| map_engine(&error))?
        else {
            return Ok(TreeHeader::empty(owner));
        };
        decode_header(
            self.engine.as_ref(),
            owner,
            root,
            self.validated_trees.as_ref(),
        )
    }

    fn read<T>(
        &self,
        owner: P,
        read: impl FnOnce(&mut TreeContext<'_, P, E>, Option<ObjectId>) -> StorageResult<T>,
    ) -> StorageResult<T> {
        let header = self.header(owner)?;
        let mut context = TreeContext::new(self.engine.as_ref());
        read(&mut context, header.tree)
    }

    fn mutate<T>(
        &self,
        owner: &P,
        mut mutation: impl FnMut(
            &mut TreeContext<'_, P, E>,
            Option<ObjectId>,
        ) -> StorageResult<(T, Option<ObjectId>, bool)>,
    ) -> StorageResult<T> {
        loop {
            let header = self.header(owner.clone())?;
            let mut context = TreeContext::new(self.engine.as_ref());
            let (result, tree, changed) = mutation(&mut context, header.tree)?;
            if !changed {
                return Ok(result);
            }
            let logical_bytes = context.logical_total(tree)?;
            let used = context.quota_total(tree)?;
            if let Some(quota) = &self.quota
                && let Some(limit) = quota.max_logical_bytes(owner)?
                && used > limit
                && used > header.quota_bytes
            {
                return Err(StorageError::quota_exceeded(used, limit));
            }
            let transaction = context.finish(header, tree, logical_bytes, used)?;
            match self.engine.commit_kv_root(transaction) {
                Ok(_) => {
                    self.validated_trees.lock().insert(
                        owner.clone(),
                        TreeValidation {
                            root: tree,
                            logical_bytes,
                            quota_bytes: used,
                        },
                    );
                    return Ok(result);
                },
                Err(KvProjectionError::Model(ModelError::RootConflict { .. })) => {},
                Err(error) => return Err(map_engine(&error)),
            }
        }
    }

    fn clear_range(&self, owner: &P, start: &[u8], end: &[u8]) -> StorageResult<u64> {
        self.mutate(owner, |context, tree| {
            let keys = context.raw_keys_in_range(tree, start, end)?;
            let count = u64::try_from(keys.len())
                .map_err(|_| StorageError::Internal("KV key count overflow".to_owned()))?;
            let mut updated = tree;
            for key in &keys {
                (updated, _) = context.delete(updated, key)?;
            }
            Ok((count, updated, count != 0))
        })
    }
}

impl<P, I, R, E> TreeKvStore<P, I, R, E>
where
    P: Clone + Ord + Send + Sync,
    E: KvProjectionEngine<P>,
    R: KvPrincipalResolver<P>,
{
    #[cfg(all(feature = "legacy-surrealkv", not(target_family = "wasm")))]
    pub(crate) fn import_entries_for_migration(
        &self,
        owner: &P,
        entries: &[KvEntry],
    ) -> StorageResult<()> {
        self.blocking_store().mutate(owner, |context, mut tree| {
            for entry in entries {
                let key = composite_key(&entry.namespace, &entry.key);
                let value_len = u64::try_from(entry.value.len())
                    .map_err(|_| StorageError::Internal("KV value length overflow".to_owned()))?;
                let value = context.make_leaf(entry.value.clone())?;
                tree = Some(context.set(tree, key, value, value_len)?);
            }
            Ok(((), tree, !entries.is_empty()))
        })
    }

    #[cfg(all(feature = "legacy-surrealkv", not(target_family = "wasm")))]
    pub(crate) fn visit_entries_for_migration(
        &self,
        owner: &P,
        mut visit: impl FnMut(&str, &str, &[u8]) -> StorageResult<()>,
    ) -> StorageResult<()> {
        let blocking = self.blocking_store();
        let header = blocking.header(owner.clone())?;
        let mut context = TreeContext::new(blocking.engine.as_ref());
        context.visit_entries(header.tree, |composite, value| {
            let separator = composite
                .iter()
                .position(|byte| *byte == 0)
                .ok_or_else(|| {
                    StorageError::Serialization(
                        "persistent KV key has no namespace separator".to_owned(),
                    )
                })?;
            let namespace = std::str::from_utf8(&composite[..separator])
                .map_err(|error| StorageError::Serialization(error.to_string()))?;
            let key = std::str::from_utf8(&composite[separator.saturating_add(1)..])
                .map_err(|error| StorageError::Serialization(error.to_string()))?;
            visit(namespace, key, value)
        })
    }
}

impl<P, I, R, E> TreeKvStore<P, I, R, E>
where
    P: Clone + Ord + Send + Sync,
    E: KvProjectionEngine<P>,
    R: KvPrincipalResolver<P>,
{
    #[cfg(test)]
    pub(super) fn height_for_test(&self, owner: P) -> StorageResult<u32> {
        let blocking = self.blocking_store();
        let header = blocking.header(owner)?;
        TreeContext::new(blocking.engine.as_ref()).height(header.tree)
    }
}

#[derive(Clone, Debug)]
struct TreeHeader<P> {
    owner: P,
    root: Option<RootState>,
    tree: Option<ObjectId>,
    quota_bytes: u64,
    preserved_state: Vec<ObjectReference>,
    preserved_commit: Vec<ObjectReference>,
}

impl<P> TreeHeader<P> {
    fn empty(owner: P) -> Self {
        Self {
            owner,
            root: None,
            tree: None,
            quota_bytes: 0,
            preserved_state: Vec::new(),
            preserved_commit: Vec::new(),
        }
    }
}

fn decode_header<P, E>(
    engine: &E,
    owner: P,
    root: RootState,
    validated_trees: &Mutex<BTreeMap<P, TreeValidation>>,
) -> StorageResult<TreeHeader<P>>
where
    P: Clone + Ord,
    E: KvProjectionEngine<P>,
{
    let commit = load_typed(engine, root.commit, ObjectKind::Commit)?;
    require_structural(root.commit, &commit)?;
    let state_id = owned_target(root.commit, &commit, STATE_LABEL)?;
    let state = load_typed(engine, state_id, ObjectKind::PrincipalState)?;
    require_structural(state_id, &state)?;
    let wrapper_id = owned_target(state_id, &state, KV_LABEL)?;
    let wrapper = load_typed(engine, wrapper_id, ObjectKind::NamespaceMap)?;
    if wrapper.canonical_bytes().len() != std::mem::size_of::<u64>()
        || wrapper.class() != ObjectClass::Metadata
    {
        return Err(invalid(wrapper_id, "invalid KV tree root wrapper"));
    }
    let quota_bytes = u64::from_le_bytes(
        wrapper
            .canonical_bytes()
            .try_into()
            .map_err(|_| invalid(wrapper_id, "invalid KV tree quota total"))?,
    );
    let tree = match wrapper.reference(&ReferenceLabel::new(ROOT_LABEL)) {
        None if wrapper.references().is_empty() => None,
        Some(reference)
            if reference.kind() == ReferenceKind::Owns && wrapper.references().len() == 1 =>
        {
            Some(reference.target())
        },
        _ => return Err(invalid(wrapper_id, "invalid KV tree root reference")),
    };
    let cached = validated_trees
        .lock()
        .get(&owner)
        .copied()
        .filter(|validation| validation.root == tree);
    let validation = if let Some(validation) = cached {
        validation
    } else {
        let mut context = TreeContext::<P, E>::new(engine);
        let validation = context.validate_tree(tree)?;
        validated_trees.lock().insert(owner.clone(), validation);
        validation
    };
    if validation.logical_bytes != wrapper.logical_bytes() || validation.quota_bytes != quota_bytes
    {
        return Err(invalid(wrapper_id, "KV tree accounting totals disagree"));
    }
    let preserved_state = state
        .references()
        .iter()
        .filter(|reference| reference.label().as_bytes() != KV_LABEL)
        .cloned()
        .collect();
    let preserved_commit = commit
        .references()
        .iter()
        .filter(|reference| {
            reference.label().as_bytes() != STATE_LABEL
                && reference.label().as_bytes() != PARENT_LABEL
        })
        .cloned()
        .collect();
    Ok(TreeHeader {
        owner,
        root: Some(root),
        tree,
        quota_bytes,
        preserved_state,
        preserved_commit,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TreeValidation {
    root: Option<ObjectId>,
    logical_bytes: u64,
    quota_bytes: u64,
}

impl TreeValidation {
    const EMPTY: Self = Self {
        root: None,
        logical_bytes: 0,
        quota_bytes: 0,
    };
}

fn load_typed<P, E>(engine: &E, id: ObjectId, kind: ObjectKind) -> StorageResult<ObjectRecord>
where
    E: KvProjectionEngine<P>,
{
    let record = engine
        .load_kv_object(id)
        .map_err(|error| map_engine(&error))?
        .ok_or_else(|| map_engine(&ModelError::MissingObject(id).into()))?;
    if record.kind() != kind || record.format_version() != FORMAT_VERSION {
        return Err(invalid(id, "object has the wrong KV tree kind or version"));
    }
    Ok(record)
}

fn require_structural(id: ObjectId, record: &ObjectRecord) -> StorageResult<()> {
    if !record.canonical_bytes().is_empty()
        || record.logical_bytes() != 0
        || record.class() != ObjectClass::Metadata
    {
        return Err(invalid(id, "structural KV tree object carries payload"));
    }
    Ok(())
}

fn owned_target(id: ObjectId, record: &ObjectRecord, label: &[u8]) -> StorageResult<ObjectId> {
    let reference = record
        .reference(&ReferenceLabel::new(label))
        .ok_or_else(|| invalid(id, "required KV tree reference is missing"))?;
    if reference.kind() != ReferenceKind::Owns {
        return Err(invalid(id, "required KV tree reference is not owning"));
    }
    Ok(reference.target())
}

#[derive(Clone, Debug)]
struct TreeNode {
    key: Vec<u8>,
    value: ObjectId,
    value_len: u64,
    left: Option<ObjectId>,
    right: Option<ObjectId>,
    height: u32,
    logical_total: u64,
    quota_total: u64,
}

#[derive(Clone, Debug)]
struct ValidatedNode {
    minimum_key: Vec<u8>,
    maximum_key: Vec<u8>,
    height: u32,
    logical_total: u64,
    quota_total: u64,
}

fn validated_child(
    parent: ObjectId,
    child: Option<ObjectId>,
    missing: &'static str,
    computed: &mut BTreeMap<ObjectId, ValidatedNode>,
) -> StorageResult<Option<ValidatedNode>> {
    child
        .map(|id| computed.remove(&id).ok_or_else(|| invalid(parent, missing)))
        .transpose()
}

fn validate_composite_key(id: ObjectId, key: &[u8]) -> StorageResult<()> {
    let Some(separator) = key.iter().position(|byte| *byte == 0) else {
        return Err(invalid(id, "persistent KV key has no namespace separator"));
    };
    if separator == 0
        || separator.saturating_add(1) >= key.len()
        || key[separator.saturating_add(1)..].contains(&0)
    {
        return Err(invalid(id, "persistent KV composite key is non-canonical"));
    }
    let namespace = std::str::from_utf8(&key[..separator])
        .map_err(|_| invalid(id, "persistent KV namespace is not UTF-8"))?;
    let name = std::str::from_utf8(&key[separator.saturating_add(1)..])
        .map_err(|_| invalid(id, "persistent KV key is not UTF-8"))?;
    validate_namespace(namespace)
        .and_then(|()| validate_key(name))
        .map_err(|_| invalid(id, "persistent KV composite key is invalid"))
}

struct TreeContext<'a, P, E> {
    engine: &'a E,
    records: BTreeMap<ObjectId, ObjectRecord>,
    nodes: BTreeMap<ObjectId, TreeNode>,
    marker: PhantomData<fn() -> P>,
}

impl<'a, P, E> TreeContext<'a, P, E>
where
    P: Ord,
    E: KvProjectionEngine<P>,
{
    fn new(engine: &'a E) -> Self {
        Self {
            engine,
            records: BTreeMap::new(),
            nodes: BTreeMap::new(),
            marker: PhantomData,
        }
    }

    fn record(&self, id: ObjectId) -> StorageResult<ObjectRecord> {
        if let Some(record) = self.records.get(&id) {
            return Ok(record.clone());
        }
        self.engine
            .load_kv_object(id)
            .map_err(|error| map_engine(&error))?
            .ok_or_else(|| map_engine(&ModelError::MissingObject(id).into()))
    }

    fn insert(&mut self, record: ObjectRecord) -> StorageResult<ObjectId> {
        let id = self.engine.identify_kv_object(&record);
        match self.records.get(&id) {
            Some(existing) if existing == &record => {},
            Some(_) => return Err(map_engine(&ModelError::ObjectCollision(id).into())),
            None => {
                self.records.insert(id, record);
            },
        }
        Ok(id)
    }

    fn make_leaf(&mut self, value: Vec<u8>) -> StorageResult<ObjectId> {
        let leaf = ObjectRecord::new(
            ObjectKind::KvLeaf,
            FORMAT_VERSION,
            value,
            Vec::new(),
            0,
            ObjectClass::Data,
        )
        .map_err(|error| map_engine(&error.into()))?;
        self.insert(leaf)
    }

    fn node(&mut self, id: ObjectId) -> StorageResult<TreeNode> {
        if let Some(node) = self.nodes.get(&id) {
            return Ok(node.clone());
        }
        let record = self.record(id)?;
        if record.kind() != ObjectKind::KvBranch
            || record.format_version() != FORMAT_VERSION
            || record.class() != ObjectClass::Metadata
            || record.logical_bytes() != 0
        {
            return Err(invalid(id, "invalid persistent KV tree node"));
        }
        let bytes = record.canonical_bytes();
        if bytes.len() < NODE_FIXED_BYTES {
            return Err(invalid(id, "truncated persistent KV tree node"));
        }
        let height = u32::from_le_bytes(
            bytes[0..4]
                .try_into()
                .map_err(|_| invalid(id, "invalid KV node height"))?,
        );
        let logical_total = u64::from_le_bytes(
            bytes[4..12]
                .try_into()
                .map_err(|_| invalid(id, "invalid KV node logical total"))?,
        );
        let quota_total = u64::from_le_bytes(
            bytes[12..20]
                .try_into()
                .map_err(|_| invalid(id, "invalid KV node quota total"))?,
        );
        let value_len = u64::from_le_bytes(
            bytes[20..28]
                .try_into()
                .map_err(|_| invalid(id, "invalid KV node value length"))?,
        );
        let key = bytes[NODE_FIXED_BYTES..].to_vec();
        if height == 0 {
            return Err(invalid(id, "invalid persistent KV tree key"));
        }
        validate_composite_key(id, &key)?;
        let value = exact_owned_reference(id, &record, VALUE_LABEL, true)?;
        let left = exact_owned_reference(id, &record, LEFT_LABEL, false)?;
        let right = exact_owned_reference(id, &record, RIGHT_LABEL, false)?;
        if record.references().len()
            != 1_usize
                .saturating_add(usize::from(left.is_some()))
                .saturating_add(usize::from(right.is_some()))
        {
            return Err(invalid(id, "unexpected persistent KV tree reference"));
        }
        let node = TreeNode {
            key,
            value: value.ok_or_else(|| invalid(id, "KV node value is missing"))?,
            value_len,
            left,
            right,
            height,
            logical_total,
            quota_total,
        };
        self.nodes.insert(id, node.clone());
        Ok(node)
    }

    fn validate_tree(&mut self, root: Option<ObjectId>) -> StorageResult<TreeValidation> {
        let Some(root) = root else {
            return Ok(TreeValidation::EMPTY);
        };
        let mut marks = BTreeMap::<ObjectId, u8>::new();
        let mut computed = BTreeMap::<ObjectId, ValidatedNode>::new();
        let mut stack = vec![(root, false)];

        while let Some((id, expanded)) = stack.pop() {
            if !expanded {
                match marks.insert(id, 1) {
                    Some(1) => return Err(invalid(id, "persistent KV tree contains a cycle")),
                    Some(2) => {
                        return Err(invalid(id, "persistent KV tree reuses a branch"));
                    },
                    Some(_) | None => {},
                }
                let node = self.node(id)?;
                stack.push((id, true));
                if let Some(right) = node.right {
                    stack.push((right, false));
                }
                if let Some(left) = node.left {
                    stack.push((left, false));
                }
                continue;
            }

            let node = self.node(id)?;
            let validated = self.validate_node(id, &node, &mut computed)?;
            computed.insert(id, validated);
            marks.insert(id, 2);
        }

        let validated = computed
            .remove(&root)
            .ok_or_else(|| invalid(root, "persistent KV root validation is missing"))?;
        Ok(TreeValidation {
            root: Some(root),
            logical_bytes: validated.logical_total,
            quota_bytes: validated.quota_total,
        })
    }

    fn validate_node(
        &mut self,
        id: ObjectId,
        node: &TreeNode,
        computed: &mut BTreeMap<ObjectId, ValidatedNode>,
    ) -> StorageResult<ValidatedNode> {
        self.value_bytes(id, node)?;
        let left = validated_child(
            id,
            node.left,
            "KV left child validation is missing",
            computed,
        )?;
        let right = validated_child(
            id,
            node.right,
            "KV right child validation is missing",
            computed,
        )?;
        if left
            .as_ref()
            .is_some_and(|child| child.maximum_key >= node.key)
            || right
                .as_ref()
                .is_some_and(|child| child.minimum_key <= node.key)
        {
            return Err(invalid(id, "persistent KV tree key order is invalid"));
        }

        let left_height = left.as_ref().map_or(0, |child| child.height);
        let right_height = right.as_ref().map_or(0, |child| child.height);
        let height = left_height
            .max(right_height)
            .checked_add(1)
            .ok_or_else(|| invalid(id, "persistent KV tree height overflow"))?;
        if node.height != height || left_height.abs_diff(right_height) > 1 {
            return Err(invalid(id, "persistent KV tree is not canonical AVL"));
        }
        let logical_total = left
            .as_ref()
            .map_or(0, |child| child.logical_total)
            .checked_add(node.value_len)
            .and_then(|total| {
                total.checked_add(right.as_ref().map_or(0, |child| child.logical_total))
            })
            .ok_or_else(|| invalid(id, "persistent KV tree logical total overflow"))?;
        let key_len = u64::try_from(node.key.len())
            .map_err(|_| invalid(id, "persistent KV tree key length overflow"))?;
        let quota_total = left
            .as_ref()
            .map_or(0, |child| child.quota_total)
            .checked_add(node.value_len)
            .and_then(|total| total.checked_add(key_len))
            .and_then(|total| {
                total.checked_add(right.as_ref().map_or(0, |child| child.quota_total))
            })
            .ok_or_else(|| invalid(id, "persistent KV tree quota total overflow"))?;
        if node.logical_total != logical_total || node.quota_total != quota_total {
            return Err(invalid(id, "persistent KV tree node totals disagree"));
        }

        let minimum_key = left.map_or_else(|| node.key.clone(), |child| child.minimum_key);
        let maximum_key = right.map_or_else(|| node.key.clone(), |child| child.maximum_key);
        Ok(ValidatedNode {
            minimum_key,
            maximum_key,
            height,
            logical_total,
            quota_total,
        })
    }

    fn height(&mut self, node: Option<ObjectId>) -> StorageResult<u32> {
        node.map_or(Ok(0), |id| self.node(id).map(|node| node.height))
    }

    fn logical_total(&mut self, node: Option<ObjectId>) -> StorageResult<u64> {
        node.map_or(Ok(0), |id| self.node(id).map(|node| node.logical_total))
    }

    fn quota_total(&mut self, node: Option<ObjectId>) -> StorageResult<u64> {
        node.map_or(Ok(0), |id| self.node(id).map(|node| node.quota_total))
    }

    fn make_node(
        &mut self,
        key: Vec<u8>,
        value: ObjectId,
        value_len: u64,
        left: Option<ObjectId>,
        right: Option<ObjectId>,
    ) -> StorageResult<ObjectId> {
        let height = self
            .height(left)?
            .max(self.height(right)?)
            .checked_add(1)
            .ok_or_else(|| StorageError::Internal("KV tree height overflow".to_owned()))?;
        let left_logical = self.logical_total(left)?;
        let right_logical = self.logical_total(right)?;
        let logical_total = left_logical
            .checked_add(value_len)
            .and_then(|sum| sum.checked_add(right_logical))
            .ok_or_else(|| StorageError::Internal("KV tree logical bytes overflow".to_owned()))?;
        let key_len = u64::try_from(key.len())
            .map_err(|_| StorageError::Internal("KV tree key length overflow".to_owned()))?;
        let left_quota = self.quota_total(left)?;
        let right_quota = self.quota_total(right)?;
        let quota_total = left_quota
            .checked_add(value_len)
            .and_then(|sum| sum.checked_add(key_len))
            .and_then(|sum| sum.checked_add(right_quota))
            .ok_or_else(|| StorageError::Internal("KV tree quota bytes overflow".to_owned()))?;
        let mut bytes = Vec::with_capacity(NODE_FIXED_BYTES.saturating_add(key.len()));
        bytes.extend_from_slice(&height.to_le_bytes());
        bytes.extend_from_slice(&logical_total.to_le_bytes());
        bytes.extend_from_slice(&quota_total.to_le_bytes());
        bytes.extend_from_slice(&value_len.to_le_bytes());
        bytes.extend_from_slice(&key);
        let mut references = vec![ObjectReference::owns(VALUE_LABEL.to_vec().into(), value)];
        if let Some(left) = left {
            references.push(ObjectReference::owns(LEFT_LABEL.to_vec().into(), left));
        }
        if let Some(right) = right {
            references.push(ObjectReference::owns(RIGHT_LABEL.to_vec().into(), right));
        }
        references.sort();
        let record = ObjectRecord::new(
            ObjectKind::KvBranch,
            FORMAT_VERSION,
            bytes,
            references,
            0,
            ObjectClass::Metadata,
        )
        .map_err(|error| map_engine(&error.into()))?;
        let id = self.insert(record)?;
        self.nodes.insert(
            id,
            TreeNode {
                key,
                value,
                value_len,
                left,
                right,
                height,
                logical_total,
                quota_total,
            },
        );
        Ok(id)
    }

    fn get(&mut self, mut root: Option<ObjectId>, key: &[u8]) -> StorageResult<Option<Vec<u8>>> {
        while let Some(id) = root {
            let node = self.node(id)?;
            match key.cmp(node.key.as_slice()) {
                Ordering::Less => root = node.left,
                Ordering::Greater => root = node.right,
                Ordering::Equal => {
                    return self.value_bytes(id, &node).map(Some);
                },
            }
        }
        Ok(None)
    }

    fn value_bytes(&self, node_id: ObjectId, node: &TreeNode) -> StorageResult<Vec<u8>> {
        let leaf = self.record(node.value)?;
        if leaf.kind() != ObjectKind::KvLeaf
            || leaf.format_version() != FORMAT_VERSION
            || leaf.class() != ObjectClass::Data
            || leaf.logical_bytes() != 0
            || !leaf.references().is_empty()
        {
            return Err(invalid(node.value, "invalid persistent KV value leaf"));
        }
        if u64::try_from(leaf.canonical_bytes().len()).ok() != Some(node.value_len) {
            return Err(invalid(node_id, "KV node value length does not match leaf"));
        }
        Ok(leaf.canonical_bytes().to_vec())
    }

    fn set(
        &mut self,
        root: Option<ObjectId>,
        key: Vec<u8>,
        value: ObjectId,
        value_len: u64,
    ) -> StorageResult<ObjectId> {
        let Some(id) = root else {
            return self.make_node(key, value, value_len, None, None);
        };
        let node = self.node(id)?;
        let rebuilt = match key.as_slice().cmp(node.key.as_slice()) {
            Ordering::Less => {
                let left = Some(self.set(node.left, key, value, value_len)?);
                self.make_node(node.key, node.value, node.value_len, left, node.right)?
            },
            Ordering::Greater => {
                let right = Some(self.set(node.right, key, value, value_len)?);
                self.make_node(node.key, node.value, node.value_len, node.left, right)?
            },
            Ordering::Equal => self.make_node(node.key, value, value_len, node.left, node.right)?,
        };
        self.rebalance(rebuilt)
    }

    fn delete(
        &mut self,
        root: Option<ObjectId>,
        key: &[u8],
    ) -> StorageResult<(Option<ObjectId>, bool)> {
        let Some(id) = root else {
            return Ok((None, false));
        };
        let node = self.node(id)?;
        let rebuilt = match key.cmp(node.key.as_slice()) {
            Ordering::Less => {
                let (left, removed) = self.delete(node.left, key)?;
                if !removed {
                    return Ok((Some(id), false));
                }
                Some(self.make_node(node.key, node.value, node.value_len, left, node.right)?)
            },
            Ordering::Greater => {
                let (right, removed) = self.delete(node.right, key)?;
                if !removed {
                    return Ok((Some(id), false));
                }
                Some(self.make_node(node.key, node.value, node.value_len, node.left, right)?)
            },
            Ordering::Equal => match (node.left, node.right) {
                (None, right) => return Ok((right, true)),
                (left, None) => return Ok((left, true)),
                (left, Some(right)) => {
                    let successor = self.minimum(right)?;
                    let (new_right, removed) = self.delete(Some(right), &successor.key)?;
                    debug_assert!(removed);
                    Some(self.make_node(
                        successor.key,
                        successor.value,
                        successor.value_len,
                        left,
                        new_right,
                    )?)
                },
            },
        };
        Ok((rebuilt.map(|id| self.rebalance(id)).transpose()?, true))
    }

    fn minimum(&mut self, mut id: ObjectId) -> StorageResult<TreeNode> {
        loop {
            let node = self.node(id)?;
            match node.left {
                Some(left) => id = left,
                None => return Ok(node),
            }
        }
    }

    fn rebalance(&mut self, id: ObjectId) -> StorageResult<ObjectId> {
        let node = self.node(id)?;
        let balance =
            i64::from(self.height(node.left)?).saturating_sub(i64::from(self.height(node.right)?));
        if balance > 1 {
            let left_id = node
                .left
                .ok_or_else(|| invalid(id, "left-heavy KV node has no left child"))?;
            let left = self.node(left_id)?;
            if self.height(left.left)? < self.height(left.right)? {
                let rotated = self.rotate_left(left_id)?;
                let rebuilt = self.make_node(
                    node.key,
                    node.value,
                    node.value_len,
                    Some(rotated),
                    node.right,
                )?;
                return self.rotate_right(rebuilt);
            }
            return self.rotate_right(id);
        }
        if balance < -1 {
            let right_id = node
                .right
                .ok_or_else(|| invalid(id, "right-heavy KV node has no right child"))?;
            let right = self.node(right_id)?;
            if self.height(right.right)? < self.height(right.left)? {
                let rotated = self.rotate_right(right_id)?;
                let rebuilt = self.make_node(
                    node.key,
                    node.value,
                    node.value_len,
                    node.left,
                    Some(rotated),
                )?;
                return self.rotate_left(rebuilt);
            }
            return self.rotate_left(id);
        }
        Ok(id)
    }

    fn rotate_left(&mut self, id: ObjectId) -> StorageResult<ObjectId> {
        let node = self.node(id)?;
        let right_id = node
            .right
            .ok_or_else(|| invalid(id, "KV left rotation has no right child"))?;
        let right = self.node(right_id)?;
        let left = self.make_node(node.key, node.value, node.value_len, node.left, right.left)?;
        self.make_node(
            right.key,
            right.value,
            right.value_len,
            Some(left),
            right.right,
        )
    }

    fn rotate_right(&mut self, id: ObjectId) -> StorageResult<ObjectId> {
        let node = self.node(id)?;
        let left_id = node
            .left
            .ok_or_else(|| invalid(id, "KV right rotation has no left child"))?;
        let left = self.node(left_id)?;
        let right = self.make_node(node.key, node.value, node.value_len, left.right, node.right)?;
        self.make_node(left.key, left.value, left.value_len, left.left, Some(right))
    }

    fn raw_keys_in_range(
        &mut self,
        root: Option<ObjectId>,
        start: &[u8],
        end: &[u8],
    ) -> StorageResult<Vec<Vec<u8>>> {
        let mut keys = Vec::new();
        self.collect_range(root, start, end, &mut keys)?;
        Ok(keys)
    }

    fn collect_range(
        &mut self,
        root: Option<ObjectId>,
        start: &[u8],
        end: &[u8],
        keys: &mut Vec<Vec<u8>>,
    ) -> StorageResult<()> {
        let Some(id) = root else {
            return Ok(());
        };
        let node = self.node(id)?;
        if node.key.as_slice() >= start {
            self.collect_range(node.left, start, end, keys)?;
        }
        if node.key.as_slice() >= start && node.key.as_slice() < end {
            keys.push(node.key.clone());
        }
        if node.key.as_slice() < end {
            self.collect_range(node.right, start, end, keys)?;
        }
        Ok(())
    }

    #[cfg(all(feature = "legacy-surrealkv", not(target_family = "wasm")))]
    fn visit_entries(
        &mut self,
        root: Option<ObjectId>,
        mut visit: impl FnMut(&[u8], &[u8]) -> StorageResult<()>,
    ) -> StorageResult<()> {
        let mut stack = Vec::new();
        let mut current = root;
        loop {
            while let Some(id) = current {
                let node = self.node(id)?;
                stack.push(id);
                current = node.left;
            }
            let Some(id) = stack.pop() else {
                return Ok(());
            };
            let node = self.node(id)?;
            let value = self.value_bytes(id, &node)?;
            visit(&node.key, &value)?;
            current = node.right;
        }
    }

    fn keys_in_range(
        &mut self,
        root: Option<ObjectId>,
        start: &[u8],
        end: &[u8],
        strip: usize,
    ) -> StorageResult<Vec<String>> {
        self.raw_keys_in_range(root, start, end)?
            .into_iter()
            .map(|key| {
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

    fn finish(
        mut self,
        header: TreeHeader<P>,
        tree: Option<ObjectId>,
        logical_bytes: u64,
        quota_bytes: u64,
    ) -> StorageResult<RootTransaction<P>> {
        let references = tree
            .map(|tree| vec![ObjectReference::owns(ROOT_LABEL.to_vec().into(), tree)])
            .unwrap_or_default();
        let wrapper = ObjectRecord::new(
            ObjectKind::NamespaceMap,
            FORMAT_VERSION,
            quota_bytes.to_le_bytes().to_vec(),
            references,
            logical_bytes,
            ObjectClass::Metadata,
        )
        .map_err(|error| map_engine(&error.into()))?;
        let wrapper = self.insert(wrapper)?;

        let mut state_references = header.preserved_state;
        state_references.push(ObjectReference::owns(KV_LABEL.to_vec().into(), wrapper));
        state_references.sort();
        let state = ObjectRecord::new(
            ObjectKind::PrincipalState,
            FORMAT_VERSION,
            Vec::new(),
            state_references,
            0,
            ObjectClass::Metadata,
        )
        .map_err(|error| map_engine(&error.into()))?;
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
        .map_err(|error| map_engine(&error.into()))?;
        let commit = self.insert(commit)?;
        self.retain_reachable(commit);
        Ok(RootTransaction::new(
            header.owner,
            header.root,
            commit,
            self.records.into_iter().collect(),
        ))
    }

    fn retain_reachable(&mut self, root: ObjectId) {
        let mut reachable = std::collections::BTreeSet::new();
        let mut stack = vec![root];
        while let Some(id) = stack.pop() {
            if !reachable.insert(id) {
                continue;
            }
            if let Some(record) = self.records.get(&id) {
                stack.extend(record.owning_references());
            }
        }
        self.records.retain(|id, _| reachable.contains(id));
    }
}
