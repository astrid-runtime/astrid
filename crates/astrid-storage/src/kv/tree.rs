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
    ObjectReference, ReferenceKind, RootState,
};
use async_trait::async_trait;

use super::principal::{KvPrincipalResolver, KvQuotaResolver};
use super::{
    KvEntry, KvStore, composite_key, namespace_range_end, namespace_range_start, prefix_range_end,
    validate_key, validate_namespace, validate_prefix,
};
use crate::error::{StorageError, StorageResult};

const FORMAT_VERSION: ObjectFormatVersion = ObjectFormatVersion::new(2);
const KV_LABEL: &[u8] = b"kv";
const LEFT_LABEL: &[u8] = b"left";
const PARENT_LABEL: &[u8] = b"parent";
const RIGHT_LABEL: &[u8] = b"right";
const ROOT_LABEL: &[u8] = b"root";
const STATE_LABEL: &[u8] = b"state";
const VALUE_LABEL: &[u8] = b"value";
const NODE_FIXED_BYTES: usize = 20;

/// Production point-operation KV adapter over a persistent balanced tree.
pub struct TreeKvStore<P: Ord, I, R, E> {
    engine: Arc<E>,
    resolver: R,
    quota: Option<Arc<dyn KvQuotaResolver<P>>>,
    marker: PhantomData<fn() -> (P, I)>,
}

impl<P: Ord, I, R, E> TreeKvStore<P, I, R, E> {
    /// Construct a tree adapter without logical quota policy.
    #[must_use]
    pub const fn from_engine(engine: Arc<E>, resolver: R) -> Self {
        Self {
            engine,
            resolver,
            quota: None,
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
            marker: PhantomData,
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

impl<P, I, R, E> TreeKvStore<P, I, R, E>
where
    P: Clone + Ord + Send + Sync,
    E: KvProjectionEngine<P>,
    R: KvPrincipalResolver<P>,
{
    fn header(&self, owner: P) -> StorageResult<TreeHeader<P>> {
        let Some(root) = self
            .engine
            .current_kv_root(&owner)
            .map_err(|error| map_engine(&error))?
        else {
            return Ok(TreeHeader::empty(owner));
        };
        decode_header(self.engine.as_ref(), owner, root)
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
            let used = context.total(tree)?;
            if let Some(quota) = &self.quota
                && let Some(limit) = quota.max_logical_bytes(owner)?
                && used > limit
                && used > header.logical_bytes
            {
                return Err(StorageError::QuotaExceeded { used, limit });
            }
            let transaction = context.finish(header, tree, used)?;
            match self.engine.commit_kv_root(transaction) {
                Ok(_) => return Ok(result),
                Err(KvProjectionError::Model(ModelError::RootConflict { .. })) => {},
                Err(error) => return Err(map_engine(&error)),
            }
        }
    }

    pub(crate) fn import_entries_for_migration(
        &self,
        owner: &P,
        entries: &[KvEntry],
    ) -> StorageResult<()> {
        self.mutate(owner, |context, mut tree| {
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

    pub(crate) fn entries_for_migration(&self, owner: &P) -> StorageResult<Vec<KvEntry>> {
        let header = self.header(owner.clone())?;
        let mut context = TreeContext::new(self.engine.as_ref());
        let mut raw = Vec::new();
        context.collect_entries(header.tree, &mut raw)?;
        raw.into_iter()
            .map(|(composite, value)| {
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
                Ok(KvEntry {
                    namespace: namespace.to_owned(),
                    key: key.to_owned(),
                    value,
                })
            })
            .collect()
    }
}

#[async_trait]
impl<P, I, R, E> KvStore for TreeKvStore<P, I, R, E>
where
    P: Clone + Ord + Send + Sync + 'static,
    I: Send + Sync + 'static,
    E: KvProjectionEngine<P> + 'static,
    R: KvPrincipalResolver<P> + Send + Sync + 'static,
{
    async fn close(&self) -> StorageResult<()> {
        self.engine.flush_kv().map_err(|error| map_engine(&error))
    }

    async fn get(&self, namespace: &str, key: &str) -> StorageResult<Option<Vec<u8>>> {
        validate_namespace(namespace)?;
        validate_key(key)?;
        let owner = self.resolver.resolve(namespace)?;
        let composite = composite_key(namespace, key);
        self.read(owner, |context, tree| context.get(tree, &composite))
    }

    async fn set(&self, namespace: &str, key: &str, value: Vec<u8>) -> StorageResult<()> {
        validate_namespace(namespace)?;
        validate_key(key)?;
        let owner = self.resolver.resolve(namespace)?;
        let composite = composite_key(namespace, key);
        self.mutate(&owner, |context, tree| {
            if context.get(tree, &composite)?.as_deref() == Some(value.as_slice()) {
                return Ok(((), tree, false));
            }
            let value_len = u64::try_from(value.len())
                .map_err(|_| StorageError::Internal("KV value length overflow".to_owned()))?;
            let leaf = context.make_leaf(value.clone())?;
            let tree = Some(context.set(tree, composite.clone(), leaf, value_len)?);
            Ok(((), tree, true))
        })
    }

    async fn delete(&self, namespace: &str, key: &str) -> StorageResult<bool> {
        validate_namespace(namespace)?;
        validate_key(key)?;
        let owner = self.resolver.resolve(namespace)?;
        let composite = composite_key(namespace, key);
        self.mutate(&owner, |context, tree| {
            let (tree, removed) = context.delete(tree, &composite)?;
            Ok((removed, tree, removed))
        })
    }

    async fn exists(&self, namespace: &str, key: &str) -> StorageResult<bool> {
        Ok(self.get(namespace, key).await?.is_some())
    }

    async fn list_keys(&self, namespace: &str) -> StorageResult<Vec<String>> {
        validate_namespace(namespace)?;
        let owner = self.resolver.resolve(namespace)?;
        let start = namespace_range_start(namespace);
        let end = namespace_range_end(namespace);
        self.read(owner, |context, tree| {
            context.keys_in_range(tree, &start, &end, start.len())
        })
    }

    async fn list_keys_with_prefix(
        &self,
        namespace: &str,
        prefix: &str,
    ) -> StorageResult<Vec<String>> {
        validate_namespace(namespace)?;
        validate_prefix(prefix)?;
        let owner = self.resolver.resolve(namespace)?;
        let start = composite_key(namespace, prefix);
        let end = prefix_range_end(namespace, prefix);
        let strip = namespace.len().saturating_add(1);
        self.read(owner, |context, tree| {
            context.keys_in_range(tree, &start, &end, strip)
        })
    }

    async fn compare_and_swap(
        &self,
        namespace: &str,
        key: &str,
        expected: Option<&[u8]>,
        new: Vec<u8>,
    ) -> StorageResult<bool> {
        validate_namespace(namespace)?;
        validate_key(key)?;
        let owner = self.resolver.resolve(namespace)?;
        let composite = composite_key(namespace, key);
        self.mutate(&owner, |context, tree| {
            let current = context.get(tree, &composite)?;
            if current.as_deref() != expected {
                return Ok((false, tree, false));
            }
            if current.as_deref() == Some(new.as_slice()) {
                return Ok((true, tree, false));
            }
            let value_len = u64::try_from(new.len())
                .map_err(|_| StorageError::Internal("KV value length overflow".to_owned()))?;
            let leaf = context.make_leaf(new.clone())?;
            let tree = Some(context.set(tree, composite.clone(), leaf, value_len)?);
            Ok((true, tree, true))
        })
    }

    async fn clear_namespace(&self, namespace: &str) -> StorageResult<u64> {
        validate_namespace(namespace)?;
        let owner = self.resolver.resolve(namespace)?;
        let start = namespace_range_start(namespace);
        let end = namespace_range_end(namespace);
        self.clear_range(&owner, &start, &end)
    }

    async fn clear_prefix(&self, namespace: &str, prefix: &str) -> StorageResult<u64> {
        validate_namespace(namespace)?;
        validate_prefix(prefix)?;
        let owner = self.resolver.resolve(namespace)?;
        let start = composite_key(namespace, prefix);
        let end = prefix_range_end(namespace, prefix);
        self.clear_range(&owner, &start, &end)
    }
}

impl<P, I, R, E> TreeKvStore<P, I, R, E>
where
    P: Clone + Ord + Send + Sync,
    E: KvProjectionEngine<P>,
    R: KvPrincipalResolver<P>,
{
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

    #[cfg(test)]
    pub(super) fn height_for_test(&self, owner: P) -> StorageResult<u32> {
        let header = self.header(owner)?;
        TreeContext::new(self.engine.as_ref()).height(header.tree)
    }
}

#[derive(Clone, Debug)]
struct TreeHeader<P> {
    owner: P,
    root: Option<RootState>,
    tree: Option<ObjectId>,
    logical_bytes: u64,
    preserved_state: Vec<ObjectReference>,
    preserved_commit: Vec<ObjectReference>,
}

impl<P> TreeHeader<P> {
    fn empty(owner: P) -> Self {
        Self {
            owner,
            root: None,
            tree: None,
            logical_bytes: 0,
            preserved_state: Vec::new(),
            preserved_commit: Vec::new(),
        }
    }
}

fn decode_header<P, E>(engine: &E, owner: P, root: RootState) -> StorageResult<TreeHeader<P>>
where
    E: KvProjectionEngine<P>,
{
    let commit = load_typed(engine, root.commit, ObjectKind::Commit)?;
    require_structural(root.commit, &commit)?;
    let state_id = owned_target(root.commit, &commit, STATE_LABEL)?;
    let state = load_typed(engine, state_id, ObjectKind::PrincipalState)?;
    require_structural(state_id, &state)?;
    let wrapper_id = owned_target(state_id, &state, KV_LABEL)?;
    let wrapper = load_typed(engine, wrapper_id, ObjectKind::NamespaceMap)?;
    if !wrapper.canonical_bytes().is_empty() || wrapper.class() != ObjectClass::Metadata {
        return Err(invalid(wrapper_id, "invalid KV tree root wrapper"));
    }
    let tree = match wrapper.reference(ROOT_LABEL) {
        None if wrapper.references().is_empty() => None,
        Some(reference)
            if reference.kind() == ReferenceKind::Owns && wrapper.references().len() == 1 =>
        {
            Some(reference.target())
        },
        _ => return Err(invalid(wrapper_id, "invalid KV tree root reference")),
    };
    let preserved_state = state
        .references()
        .iter()
        .filter(|reference| reference.label() != KV_LABEL)
        .cloned()
        .collect();
    let preserved_commit = commit
        .references()
        .iter()
        .filter(|reference| reference.label() != STATE_LABEL && reference.label() != PARENT_LABEL)
        .cloned()
        .collect();
    Ok(TreeHeader {
        owner,
        root: Some(root),
        tree,
        logical_bytes: wrapper.logical_bytes(),
        preserved_state,
        preserved_commit,
    })
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
        .reference(label)
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
    total: u64,
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
        let total = u64::from_le_bytes(
            bytes[4..12]
                .try_into()
                .map_err(|_| invalid(id, "invalid KV node total"))?,
        );
        let value_len = u64::from_le_bytes(
            bytes[12..20]
                .try_into()
                .map_err(|_| invalid(id, "invalid KV node value length"))?,
        );
        let key = bytes[NODE_FIXED_BYTES..].to_vec();
        if height == 0 || key.is_empty() || !key.contains(&0) {
            return Err(invalid(id, "invalid persistent KV tree key"));
        }
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
            total,
        };
        self.nodes.insert(id, node.clone());
        Ok(node)
    }

    fn height(&mut self, node: Option<ObjectId>) -> StorageResult<u32> {
        node.map_or(Ok(0), |id| self.node(id).map(|node| node.height))
    }

    fn total(&mut self, node: Option<ObjectId>) -> StorageResult<u64> {
        node.map_or(Ok(0), |id| self.node(id).map(|node| node.total))
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
        let left_total = self.total(left)?;
        let right_total = self.total(right)?;
        let total = left_total
            .checked_add(value_len)
            .and_then(|sum| sum.checked_add(right_total))
            .ok_or_else(|| StorageError::Internal("KV tree logical bytes overflow".to_owned()))?;
        let mut bytes = Vec::with_capacity(NODE_FIXED_BYTES.saturating_add(key.len()));
        bytes.extend_from_slice(&height.to_le_bytes());
        bytes.extend_from_slice(&total.to_le_bytes());
        bytes.extend_from_slice(&value_len.to_le_bytes());
        bytes.extend_from_slice(&key);
        let mut references = vec![ObjectReference::owns(VALUE_LABEL.to_vec(), value)];
        if let Some(left) = left {
            references.push(ObjectReference::owns(LEFT_LABEL.to_vec(), left));
        }
        if let Some(right) = right {
            references.push(ObjectReference::owns(RIGHT_LABEL.to_vec(), right));
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
                total,
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
                        return Err(invalid(id, "KV node value length does not match leaf"));
                    }
                    return Ok(Some(leaf.canonical_bytes().to_vec()));
                },
            }
        }
        Ok(None)
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

    fn collect_entries(
        &mut self,
        root: Option<ObjectId>,
        entries: &mut Vec<(Vec<u8>, Vec<u8>)>,
    ) -> StorageResult<()> {
        let Some(id) = root else {
            return Ok(());
        };
        let node = self.node(id)?;
        self.collect_entries(node.left, entries)?;
        let value = self
            .get(Some(id), &node.key)?
            .ok_or_else(|| invalid(id, "persistent KV node lost its value"))?;
        entries.push((node.key.clone(), value));
        self.collect_entries(node.right, entries)
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
    ) -> StorageResult<RootTransaction<P>> {
        let references = tree
            .map(|tree| vec![ObjectReference::owns(ROOT_LABEL.to_vec(), tree)])
            .unwrap_or_default();
        let wrapper = ObjectRecord::new(
            ObjectKind::NamespaceMap,
            FORMAT_VERSION,
            Vec::new(),
            references,
            logical_bytes,
            ObjectClass::Metadata,
        )
        .map_err(|error| map_engine(&error.into()))?;
        let wrapper = self.insert(wrapper)?;

        let mut state_references = header.preserved_state;
        state_references.push(ObjectReference::owns(KV_LABEL.to_vec(), wrapper));
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
                PARENT_LABEL.to_vec(),
                previous.commit,
                ReferenceKind::Lineage,
            ));
        }
        commit_references.push(ObjectReference::owns(STATE_LABEL.to_vec(), state));
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

fn exact_owned_reference(
    id: ObjectId,
    record: &ObjectRecord,
    label: &[u8],
    required: bool,
) -> StorageResult<Option<ObjectId>> {
    match record.reference(label) {
        Some(reference) if reference.kind() == ReferenceKind::Owns => Ok(Some(reference.target())),
        Some(_) => Err(invalid(id, "KV tree reference is not owning")),
        None if required => Err(invalid(id, "required KV tree reference is missing")),
        None => Ok(None),
    }
}

fn map_engine(error: &KvProjectionError) -> StorageError {
    StorageError::Internal(format!("persistent KV tree: {error}"))
}

fn invalid(id: ObjectId, detail: &'static str) -> StorageError {
    StorageError::Serialization(format!("invalid persistent KV object {id:?}: {detail}"))
}
