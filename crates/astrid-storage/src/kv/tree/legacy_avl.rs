//! Read-only decoder for the predecessor AVL representation.
//!
//! The ordered store migration owns the only caller. No live operation writes
//! this grammar after the B+-tree transition marker is durable.

use std::collections::BTreeMap;

use crate::engine::{KvProjectionEngine, KvProjectionError};
use crate::storage_model::{
    ModelError, ObjectClass, ObjectId, ObjectKind, ObjectRecord, ReferenceKind, ReferenceLabel,
    RootState,
};

use super::context::TreeContext;
use super::header::{TreeHeader, validated_projection};
use super::overlay::OverlayMap;
use super::validation::validate_composite_key;
use super::{FORMAT_VERSION, KV_LABEL, KvValidationCache, PARENT_LABEL, ROOT_LABEL, STATE_LABEL};
use crate::error::{StorageError, StorageResult};
use crate::kv::tree_error::{exact_owned_reference, invalid, map_engine};
use crate::principal_graph::{LEGACY_PRINCIPAL_GRAPH_VERSION, PRINCIPAL_GRAPH_VERSION};

const LEFT_LABEL: &[u8] = b"left";
const RIGHT_LABEL: &[u8] = b"right";
const VALUE_LABEL: &[u8] = b"value";
const NODE_FIXED_BYTES: usize = 28;

#[derive(Clone, Debug)]
struct LegacyNode {
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
struct ValidatedLegacyNode {
    minimum_key: Vec<u8>,
    maximum_key: Vec<u8>,
    height: u32,
    logical_total: u64,
    quota_total: u64,
}

struct LegacyContext<'a, P, E> {
    engine: &'a E,
    nodes: BTreeMap<ObjectId, LegacyNode>,
    marker: std::marker::PhantomData<fn() -> P>,
}

impl<'a, P, E> LegacyContext<'a, P, E>
where
    P: Ord,
    E: KvProjectionEngine<P>,
{
    fn new(engine: &'a E) -> Self {
        Self {
            engine,
            nodes: BTreeMap::new(),
            marker: std::marker::PhantomData,
        }
    }

    fn record(&self, object: ObjectId) -> StorageResult<ObjectRecord> {
        self.engine
            .load_kv_object(object)
            .map_err(|error| map_engine(&error))?
            .ok_or_else(|| map_engine(&ModelError::MissingObject(object).into()))
    }

    fn node(&mut self, object: ObjectId) -> StorageResult<LegacyNode> {
        if let Some(node) = self.nodes.get(&object) {
            return Ok(node.clone());
        }
        let record = self.record(object)?;
        if record.kind() != ObjectKind::KvBranch
            || record.format_version() != LEGACY_PRINCIPAL_GRAPH_VERSION
            || record.class() != ObjectClass::Metadata
            || record.logical_bytes() != 0
        {
            return Err(invalid(object, "invalid legacy KV tree node"));
        }
        let bytes = record.canonical_bytes();
        if bytes.len() < NODE_FIXED_BYTES {
            return Err(invalid(object, "truncated legacy KV tree node"));
        }
        let height = u32::from_le_bytes(
            bytes[0..4]
                .try_into()
                .map_err(|_| invalid(object, "invalid legacy KV node height"))?,
        );
        let logical_total = u64::from_le_bytes(
            bytes[4..12]
                .try_into()
                .map_err(|_| invalid(object, "invalid legacy KV logical total"))?,
        );
        let quota_total = u64::from_le_bytes(
            bytes[12..20]
                .try_into()
                .map_err(|_| invalid(object, "invalid legacy KV quota total"))?,
        );
        let value_len = u64::from_le_bytes(
            bytes[20..28]
                .try_into()
                .map_err(|_| invalid(object, "invalid legacy KV value length"))?,
        );
        let key = bytes[NODE_FIXED_BYTES..].to_vec();
        if height == 0 {
            return Err(invalid(object, "invalid legacy KV tree height"));
        }
        validate_composite_key(object, &key)?;
        let value = exact_owned_reference(object, &record, VALUE_LABEL, true)?
            .ok_or_else(|| invalid(object, "legacy KV node value is missing"))?;
        let left = exact_owned_reference(object, &record, LEFT_LABEL, false)?;
        let right = exact_owned_reference(object, &record, RIGHT_LABEL, false)?;
        if record.references().len()
            != 1_usize
                .saturating_add(usize::from(left.is_some()))
                .saturating_add(usize::from(right.is_some()))
        {
            return Err(invalid(object, "unexpected legacy KV tree reference"));
        }
        let node = LegacyNode {
            key,
            value,
            value_len,
            left,
            right,
            height,
            logical_total,
            quota_total,
        };
        self.nodes.insert(object, node.clone());
        Ok(node)
    }

    fn value(&self, node_id: ObjectId, node: &LegacyNode) -> StorageResult<Vec<u8>> {
        let record = self.record(node.value)?;
        if record.kind() != ObjectKind::KvLeaf
            || record.format_version() != LEGACY_PRINCIPAL_GRAPH_VERSION
            || record.class() != ObjectClass::Data
            || record.logical_bytes() != 0
            || !record.references().is_empty()
            || u64::try_from(record.canonical_bytes().len()).ok() != Some(node.value_len)
        {
            return Err(invalid(node_id, "invalid legacy KV value leaf"));
        }
        Ok(record.canonical_bytes().to_vec())
    }

    fn validate(&mut self, root: Option<ObjectId>) -> StorageResult<(u64, u64)> {
        let Some(root) = root else {
            return Ok((0, 0));
        };
        let mut marks = BTreeMap::<ObjectId, u8>::new();
        let mut computed = BTreeMap::<ObjectId, ValidatedLegacyNode>::new();
        let mut stack = vec![(root, false)];
        while let Some((object, expanded)) = stack.pop() {
            if !expanded {
                match marks.insert(object, 1) {
                    Some(1) => return Err(invalid(object, "legacy KV tree contains a cycle")),
                    Some(2) => return Err(invalid(object, "legacy KV tree reuses a branch")),
                    Some(_) | None => {},
                }
                let node = self.node(object)?;
                stack.push((object, true));
                if let Some(right) = node.right {
                    stack.push((right, false));
                }
                if let Some(left) = node.left {
                    stack.push((left, false));
                }
                continue;
            }
            let node = self.node(object)?;
            self.value(object, &node)?;
            let left = take_child(object, node.left, &mut computed)?;
            let right = take_child(object, node.right, &mut computed)?;
            if left
                .as_ref()
                .is_some_and(|child| child.maximum_key >= node.key)
                || right
                    .as_ref()
                    .is_some_and(|child| child.minimum_key <= node.key)
            {
                return Err(invalid(object, "legacy KV tree key order is invalid"));
            }
            let left_height = left.as_ref().map_or(0, |child| child.height);
            let right_height = right.as_ref().map_or(0, |child| child.height);
            let height = left_height
                .max(right_height)
                .checked_add(1)
                .ok_or_else(arithmetic_overflow)?;
            if node.height != height || left_height.abs_diff(right_height) > 1 {
                return Err(invalid(object, "legacy KV tree is not canonical AVL"));
            }
            let logical_total = left
                .as_ref()
                .map_or(0, |child| child.logical_total)
                .checked_add(node.value_len)
                .and_then(|total| {
                    total.checked_add(right.as_ref().map_or(0, |child| child.logical_total))
                })
                .ok_or_else(arithmetic_overflow)?;
            let key_len = u64::try_from(node.key.len()).map_err(|_| arithmetic_overflow())?;
            let quota_total = left
                .as_ref()
                .map_or(0, |child| child.quota_total)
                .checked_add(node.value_len)
                .and_then(|total| total.checked_add(key_len))
                .and_then(|total| {
                    total.checked_add(right.as_ref().map_or(0, |child| child.quota_total))
                })
                .ok_or_else(arithmetic_overflow)?;
            if node.logical_total != logical_total || node.quota_total != quota_total {
                return Err(invalid(object, "legacy KV tree totals disagree"));
            }
            let minimum_key = left.map_or_else(|| node.key.clone(), |child| child.minimum_key);
            let maximum_key = right.map_or_else(|| node.key.clone(), |child| child.maximum_key);
            computed.insert(
                object,
                ValidatedLegacyNode {
                    minimum_key,
                    maximum_key,
                    height,
                    logical_total,
                    quota_total,
                },
            );
            marks.insert(object, 2);
        }
        let root = computed
            .remove(&root)
            .ok_or_else(|| invalid(root, "legacy KV root validation is missing"))?;
        Ok((root.logical_total, root.quota_total))
    }

    fn entries(&mut self, root: Option<ObjectId>) -> StorageResult<Vec<(Vec<u8>, Vec<u8>)>> {
        let mut entries = Vec::new();
        let mut stack = Vec::new();
        let mut current = root;
        loop {
            while let Some(object) = current {
                let node = self.node(object)?;
                stack.push(object);
                current = node.left;
            }
            let Some(object) = stack.pop() else {
                return Ok(entries);
            };
            let node = self.node(object)?;
            entries.push((node.key.clone(), self.value(object, &node)?));
            current = node.right;
        }
    }
}

pub(crate) fn migrate_principal<P, E>(engine: &E, owner: &P) -> StorageResult<bool>
where
    P: Clone + Ord + Send + Sync,
    E: KvProjectionEngine<P>,
{
    loop {
        let Some(root) = engine
            .current_kv_root(owner)
            .map_err(|error| map_engine(&error))?
        else {
            return Ok(false);
        };
        let Some(source) = migration_source(engine, owner, root)? else {
            return Ok(false);
        };
        let mut context = TreeContext::new(engine, owner);
        let tree = context.build_sorted(source.entries)?;
        let transaction = context.finish(source.header, tree)?;
        match engine.commit_kv_root(transaction) {
            Ok(_) => return Ok(true),
            Err(KvProjectionError::Model(ModelError::RootConflict { .. })) => {},
            Err(error) => return Err(map_engine(&error)),
        }
    }
}

struct MigrationSource<P> {
    header: TreeHeader<P>,
    entries: LegacyEntries,
}

type LegacyEntries = Vec<(Vec<u8>, Vec<u8>)>;

fn migration_source<P, E>(
    engine: &E,
    owner: &P,
    root: RootState,
) -> StorageResult<Option<MigrationSource<P>>>
where
    P: Clone + Ord,
    E: KvProjectionEngine<P>,
{
    let commit = load_graph(engine, root.commit, ObjectKind::Commit)?;
    require_structural(root.commit, &commit)?;
    let state_id = owned_target(root.commit, &commit, STATE_LABEL)?;
    let state = load_graph(engine, state_id, ObjectKind::PrincipalState)?;
    require_structural(state_id, &state)?;
    let kv_reference = state.reference(&ReferenceLabel::new(KV_LABEL));
    if let Some(reference) = kv_reference
        && reference.kind() != ReferenceKind::Owns
    {
        return Err(invalid(state_id, "principal KV component is not owning"));
    }
    if graph_is_current(engine, owner, &commit, &state, kv_reference)? {
        return Ok(None);
    }
    let (entries, previous_quota) = legacy_entries(engine, kv_reference)?;
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
    Ok(Some(MigrationSource {
        header: TreeHeader {
            owner: owner.clone(),
            root: Some(root),
            head: None,
            tree: None,
            overlay: OverlayMap::default(),
            delta_depth: 0,
            delta_bytes: 0,
            entries: u64::try_from(entries.len()).map_err(|_| arithmetic_overflow())?,
            logical_bytes: entries.iter().try_fold(0_u64, |total, (_, value)| {
                total
                    .checked_add(u64::try_from(value.len()).map_err(|_| arithmetic_overflow())?)
                    .ok_or_else(arithmetic_overflow)
            })?,
            quota_bytes: previous_quota,
            other_quota_bytes: 0,
            preserved_state,
            preserved_commit,
        },
        entries,
    }))
}

fn graph_is_current<P, E>(
    engine: &E,
    owner: &P,
    commit: &ObjectRecord,
    state: &ObjectRecord,
    kv_reference: Option<&crate::storage_model::ObjectReference>,
) -> StorageResult<bool>
where
    P: Clone + Ord,
    E: KvProjectionEngine<P>,
{
    let kv_is_current = match kv_reference {
        None => true,
        Some(reference) => {
            let object = reference.target();
            let record = engine
                .load_kv_object(object)
                .map_err(|error| map_engine(&error))?
                .ok_or_else(|| map_engine(&ModelError::MissingObject(object).into()))?;
            if record.format_version() == FORMAT_VERSION {
                validated_projection(engine, owner, object, &KvValidationCache::default())?;
                true
            } else {
                false
            }
        },
    };
    Ok(commit.format_version() == PRINCIPAL_GRAPH_VERSION
        && state.format_version() == PRINCIPAL_GRAPH_VERSION
        && kv_is_current)
}

fn legacy_entries<P, E>(
    engine: &E,
    kv_reference: Option<&crate::storage_model::ObjectReference>,
) -> StorageResult<(LegacyEntries, u64)>
where
    P: Ord,
    E: KvProjectionEngine<P>,
{
    let Some(reference) = kv_reference else {
        return Ok((Vec::new(), 0));
    };
    let wrapper_id = reference.target();
    let wrapper = engine
        .load_kv_object(wrapper_id)
        .map_err(|error| map_engine(&error))?
        .ok_or_else(|| map_engine(&ModelError::MissingObject(wrapper_id).into()))?;
    if wrapper.kind() != ObjectKind::NamespaceMap
        || wrapper.format_version() != LEGACY_PRINCIPAL_GRAPH_VERSION
        || wrapper.class() != ObjectClass::Metadata
        || wrapper.canonical_bytes().len() != 8
    {
        return Err(invalid(wrapper_id, "invalid legacy KV root wrapper"));
    }
    let quota = u64::from_le_bytes(
        wrapper
            .canonical_bytes()
            .try_into()
            .map_err(|_| invalid(wrapper_id, "invalid legacy KV quota total"))?,
    );
    let tree = exact_owned_reference(wrapper_id, &wrapper, ROOT_LABEL, false)?;
    if wrapper.references().len() != usize::from(tree.is_some()) {
        return Err(invalid(wrapper_id, "unexpected legacy KV root reference"));
    }
    let mut legacy = LegacyContext::<P, E>::new(engine);
    let (logical, validated_quota) = legacy.validate(tree)?;
    if logical != wrapper.logical_bytes() || validated_quota != quota {
        return Err(invalid(wrapper_id, "legacy KV root totals disagree"));
    }
    Ok((legacy.entries(tree)?, quota))
}

fn load_graph<P, E>(engine: &E, object: ObjectId, kind: ObjectKind) -> StorageResult<ObjectRecord>
where
    E: KvProjectionEngine<P>,
{
    let record = engine
        .load_kv_object(object)
        .map_err(|error| map_engine(&error))?
        .ok_or_else(|| map_engine(&ModelError::MissingObject(object).into()))?;
    if record.kind() != kind
        || (record.format_version() != LEGACY_PRINCIPAL_GRAPH_VERSION
            && record.format_version() != PRINCIPAL_GRAPH_VERSION)
    {
        return Err(invalid(
            object,
            "principal migration object has wrong kind or version",
        ));
    }
    Ok(record)
}

fn require_structural(object: ObjectId, record: &ObjectRecord) -> StorageResult<()> {
    if !record.canonical_bytes().is_empty()
        || record.logical_bytes() != 0
        || record.class() != ObjectClass::Metadata
    {
        return Err(invalid(
            object,
            "principal migration object carries payload",
        ));
    }
    Ok(())
}

fn owned_target(object: ObjectId, record: &ObjectRecord, label: &[u8]) -> StorageResult<ObjectId> {
    let reference = record
        .reference(&ReferenceLabel::new(label))
        .ok_or_else(|| invalid(object, "required principal reference is missing"))?;
    if reference.kind() != ReferenceKind::Owns {
        return Err(invalid(
            object,
            "required principal reference is not owning",
        ));
    }
    Ok(reference.target())
}

fn take_child(
    parent: ObjectId,
    child: Option<ObjectId>,
    computed: &mut BTreeMap<ObjectId, ValidatedLegacyNode>,
) -> StorageResult<Option<ValidatedLegacyNode>> {
    child
        .map(|child| {
            computed
                .remove(&child)
                .ok_or_else(|| invalid(parent, "legacy KV child validation is missing"))
        })
        .transpose()
}

fn arithmetic_overflow() -> StorageError {
    StorageError::Internal("legacy KV tree arithmetic overflow".to_owned())
}
