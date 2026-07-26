use std::collections::BTreeMap;

use astrid_storage_engine::KvProjectionEngine;
use astrid_storage_model::{
    ModelError, ObjectClass, ObjectId, ObjectKind, ObjectRecord, ObjectReference, ReferenceKind,
    ReferenceLabel, RootState,
};
use parking_lot::Mutex;

use super::{
    FORMAT_VERSION, KV_LABEL, PARENT_LABEL, ROOT_LABEL, STATE_LABEL, TreeContext, TreeValidation,
};
use crate::content::{CONTENT_COMPONENT_LABEL, catalog_quota};
use crate::error::{StorageError, StorageResult};
use crate::kv::tree_error::{invalid, map_engine};

#[derive(Clone, Debug)]
pub(super) struct TreeHeader<P> {
    pub(super) owner: P,
    pub(super) root: Option<RootState>,
    pub(super) tree: Option<ObjectId>,
    pub(super) quota_bytes: u64,
    pub(super) other_quota_bytes: u64,
    pub(super) preserved_state: Vec<ObjectReference>,
    pub(super) preserved_commit: Vec<ObjectReference>,
}

impl<P> TreeHeader<P> {
    pub(super) fn empty(owner: P) -> Self {
        Self {
            owner,
            root: None,
            tree: None,
            quota_bytes: 0,
            other_quota_bytes: 0,
            preserved_state: Vec::new(),
            preserved_commit: Vec::new(),
        }
    }
}

pub(super) fn decode_header<P, E>(
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
    let (tree, quota_bytes) = match state.reference(&ReferenceLabel::new(KV_LABEL)) {
        None => {
            validated_trees
                .lock()
                .insert(owner.clone(), TreeValidation::EMPTY);
            (None, 0)
        },
        Some(reference) if reference.kind() == ReferenceKind::Owns => {
            decode_kv_component::<P, E>(engine, &owner, reference.target(), validated_trees)?
        },
        Some(_) => {
            return Err(invalid(state_id, "principal KV component is not owning"));
        },
    };
    let mut preserved_state = Vec::new();
    let mut other_quota_bytes = 0_u64;
    for reference in state
        .references()
        .iter()
        .filter(|reference| reference.label().as_bytes() != KV_LABEL)
    {
        if reference.label().as_bytes() == CONTENT_COMPONENT_LABEL {
            let record = engine
                .load_kv_object(reference.target())
                .map_err(|error| map_engine(&error))?
                .ok_or_else(|| map_engine(&ModelError::MissingObject(reference.target()).into()))?;
            let content_quota = catalog_quota(reference.target(), &record)
                .map_err(|error| StorageError::Serialization(error.to_string()))?;
            other_quota_bytes = other_quota_bytes
                .checked_add(content_quota)
                .ok_or_else(|| {
                    StorageError::Internal("principal quota total overflow".to_owned())
                })?;
        }
        preserved_state.push(reference.clone());
    }
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
        other_quota_bytes,
        preserved_state,
        preserved_commit,
    })
}

fn decode_kv_component<P, E>(
    engine: &E,
    owner: &P,
    wrapper_id: ObjectId,
    validated_trees: &Mutex<BTreeMap<P, TreeValidation>>,
) -> StorageResult<(Option<ObjectId>, u64)>
where
    P: Clone + Ord,
    E: KvProjectionEngine<P>,
{
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
        .get(owner)
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
    Ok((tree, quota_bytes))
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
