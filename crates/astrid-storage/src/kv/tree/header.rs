use std::collections::{BTreeMap, BTreeSet};

use astrid_storage_engine::{KvProjectionEngine, PrincipalProjectionError};
use astrid_storage_model::{
    ModelError, ObjectClass, ObjectId, ObjectKind, ObjectRecord, ObjectReference, ReferenceKind,
    ReferenceLabel, RootState,
};
use parking_lot::Mutex;

use super::delta::{Head, Mutation, Projection, decode_head, mutation_payload_bytes};
use super::node::NodeTotals;
use super::overlay::OverlayMap;
use super::{
    FORMAT_VERSION, KV_LABEL, KvValidationCache, PARENT_LABEL, STATE_LABEL, TreeContext,
    TreeValidation,
};
use crate::content::{
    CONTENT_COMPONENT_LABEL, CatalogValidation, PrincipalContentError, root_from_record,
    validate_catalog,
};
use crate::error::{StorageError, StorageResult};
use crate::kv::tree_error::{invalid, map_engine};

#[derive(Clone, Debug)]
pub(super) struct TreeHeader<P> {
    pub(super) owner: P,
    pub(super) root: Option<RootState>,
    pub(super) head: Option<ObjectId>,
    pub(super) tree: Option<ObjectId>,
    pub(super) overlay: OverlayMap,
    pub(super) delta_depth: u64,
    pub(super) delta_bytes: u64,
    pub(super) entries: u64,
    pub(super) logical_bytes: u64,
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
            head: None,
            tree: None,
            overlay: OverlayMap::default(),
            delta_depth: 0,
            delta_bytes: 0,
            entries: 0,
            logical_bytes: 0,
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
    validation: &KvValidationCache<P>,
    validated_content: &Mutex<BTreeMap<P, CatalogValidation>>,
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
    let projection = match state.reference(&ReferenceLabel::new(KV_LABEL)) {
        None => {
            validation
                .trees
                .lock()
                .insert(owner.clone(), TreeValidation::EMPTY);
            Projection::empty()
        },
        Some(reference) if reference.kind() == ReferenceKind::Owns => {
            let cached = validation
                .projections
                .lock()
                .get(&owner)
                .filter(|projection| projection.head == Some(reference.target()))
                .cloned();
            if let Some(cached) = cached {
                cached
            } else {
                let decoded = decode_kv_component::<P, E>(
                    engine,
                    &owner,
                    reference.target(),
                    &validation.trees,
                )?;
                validation
                    .projections
                    .lock()
                    .insert(owner.clone(), decoded.clone());
                decoded
            }
        },
        Some(_) => {
            return Err(invalid(state_id, "principal KV component is not owning"));
        },
    };
    let (preserved_state, other_quota_bytes) =
        decode_other_components(engine, &owner, state_id, &state, validated_content)?;
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
        head: projection.head,
        tree: projection.tree,
        overlay: projection.overlay,
        delta_depth: projection.depth,
        delta_bytes: projection.delta_bytes,
        entries: projection.totals.entries,
        logical_bytes: projection.totals.logical_bytes,
        quota_bytes: projection.totals.quota_bytes,
        other_quota_bytes,
        preserved_state,
        preserved_commit,
    })
}

pub(crate) fn validated_projection<P, E>(
    engine: &E,
    owner: &P,
    head: ObjectId,
    validation: &KvValidationCache<P>,
) -> StorageResult<Projection>
where
    P: Clone + Ord,
    E: KvProjectionEngine<P>,
{
    let cached = validation
        .projections
        .lock()
        .get(owner)
        .filter(|projection| projection.head == Some(head))
        .cloned();
    if let Some(cached) = cached {
        return Ok(cached);
    }
    let decoded = decode_kv_component(engine, owner, head, &validation.trees)?;
    validation
        .projections
        .lock()
        .insert(owner.clone(), decoded.clone());
    Ok(decoded)
}

pub(crate) fn validated_projection_quota<P, E>(
    engine: &E,
    owner: &P,
    head: ObjectId,
    validation: &KvValidationCache<P>,
) -> StorageResult<u64>
where
    P: Clone + Ord,
    E: KvProjectionEngine<P>,
{
    validated_projection(engine, owner, head, validation)
        .map(|projection| projection.totals.quota_bytes)
}

fn decode_other_components<P, E>(
    engine: &E,
    owner: &P,
    state_id: ObjectId,
    state: &ObjectRecord,
    validated_content: &Mutex<BTreeMap<P, CatalogValidation>>,
) -> StorageResult<(Vec<ObjectReference>, u64)>
where
    P: Clone + Ord,
    E: KvProjectionEngine<P>,
{
    let mut preserved = Vec::new();
    let mut quota_bytes = 0_u64;
    for reference in state
        .references()
        .iter()
        .filter(|reference| reference.label().as_bytes() != KV_LABEL)
    {
        if reference.label().as_bytes() == CONTENT_COMPONENT_LABEL {
            quota_bytes = quota_bytes
                .checked_add(validate_content_component(
                    engine,
                    owner,
                    state_id,
                    reference,
                    validated_content,
                )?)
                .ok_or_else(|| {
                    StorageError::Internal("principal quota total overflow".to_owned())
                })?;
        }
        preserved.push(reference.clone());
    }
    Ok((preserved, quota_bytes))
}

fn validate_content_component<P, E>(
    engine: &E,
    owner: &P,
    state_id: ObjectId,
    reference: &ObjectReference,
    validated_content: &Mutex<BTreeMap<P, CatalogValidation>>,
) -> StorageResult<u64>
where
    P: Clone + Ord,
    E: KvProjectionEngine<P>,
{
    if reference.kind() != ReferenceKind::Owns {
        return Err(invalid(
            state_id,
            "principal content component is not owning",
        ));
    }
    let record = engine
        .load_kv_object(reference.target())
        .map_err(|error| map_engine(&error))?
        .ok_or_else(|| map_engine(&ModelError::MissingObject(reference.target()).into()))?;
    let catalog_root = root_from_record(reference.target(), &record)
        .map_err(|error| StorageError::Serialization(error.to_string()))?;
    let cached = validated_content
        .lock()
        .get(owner)
        .copied()
        .filter(|validation| validation.root == Some(catalog_root.object));
    let validation = if let Some(validation) = cached {
        validation
    } else {
        let validation = validate_catalog(Some(catalog_root), &mut |object| {
            engine
                .load_kv_object(object)
                .map_err(|error| {
                    PrincipalContentError::Projection(PrincipalProjectionError::Engine(
                        error.to_string(),
                    ))
                })
                .and_then(|record| {
                    record.ok_or(PrincipalContentError::Projection(
                        PrincipalProjectionError::Model(ModelError::MissingObject(object)),
                    ))
                })
        })
        .map_err(|error| StorageError::Serialization(error.to_string()))?;
        validated_content.lock().insert(owner.clone(), validation);
        validation
    };
    if validation.summary != catalog_root.summary {
        return Err(invalid(
            reference.target(),
            "content catalog accounting totals disagree",
        ));
    }
    Ok(validation.summary.quota_bytes)
}

fn decode_kv_component<P, E>(
    engine: &E,
    owner: &P,
    head_id: ObjectId,
    validated_trees: &Mutex<BTreeMap<P, TreeValidation>>,
) -> StorageResult<Projection>
where
    P: Clone + Ord,
    E: KvProjectionEngine<P>,
{
    let mut deltas = Vec::<(ObjectId, u64, u64, Vec<Mutation>, NodeTotals)>::new();
    let mut cursor = Some(head_id);
    let mut visited = BTreeSet::new();
    let (tree, checkpoint_totals) = loop {
        let object = cursor.ok_or_else(|| invalid(head_id, "KV delta chain has no checkpoint"))?;
        if !visited.insert(object) {
            return Err(invalid(object, "KV delta chain contains a cycle"));
        }
        let record = load_typed(engine, object, ObjectKind::NamespaceMap)?;
        match decode_head(object, &record)? {
            Head::Checkpoint { tree, totals } => break (tree, totals),
            Head::Delta {
                previous,
                depth,
                delta_bytes,
                mutations,
                totals,
            } => {
                deltas.push((object, depth, delta_bytes, mutations, totals));
                cursor = previous;
                if cursor.is_none() {
                    break (None, NodeTotals::default());
                }
            },
        }
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
    if validation.entries != checkpoint_totals.entries
        || validation.logical_bytes != checkpoint_totals.logical_bytes
        || validation.quota_bytes != checkpoint_totals.quota_bytes
    {
        return Err(invalid(head_id, "KV checkpoint accounting totals disagree"));
    }
    let mut context = TreeContext::<P, E>::new(engine);
    let mut overlay = OverlayMap::default();
    let mut totals = checkpoint_totals;
    let mut prior_depth = 0_u64;
    let mut prior_delta_bytes = 0_u64;
    for (object, depth, delta_bytes, mutations, declared) in deltas.into_iter().rev() {
        if depth != prior_depth.saturating_add(1)
            || delta_bytes
                != prior_delta_bytes
                    .checked_add(mutation_payload_bytes(&mutations)?)
                    .ok_or_else(|| invalid(object, "KV delta byte total overflow"))?
        {
            return Err(invalid(object, "KV delta chain counters disagree"));
        }
        apply_validated_mutations(
            object,
            &mut context,
            tree,
            &mut overlay,
            &mut totals,
            &mutations,
        )?;
        if totals != declared {
            return Err(invalid(object, "KV delta accounting totals disagree"));
        }
        prior_depth = depth;
        prior_delta_bytes = delta_bytes;
    }
    Ok(Projection {
        head: Some(head_id),
        tree,
        overlay,
        depth: prior_depth,
        delta_bytes: prior_delta_bytes,
        totals,
    })
}

fn apply_validated_mutations<P, E>(
    object: ObjectId,
    context: &mut TreeContext<'_, P, E>,
    tree: Option<ObjectId>,
    overlay: &mut OverlayMap,
    totals: &mut NodeTotals,
    mutations: &[Mutation],
) -> StorageResult<()>
where
    P: Ord,
    E: KvProjectionEngine<P>,
{
    for mutation in mutations {
        let previous = match overlay.get(&mutation.key) {
            Some(value) => value.clone(),
            None => context.get(tree, &mutation.key)?,
        };
        let replacement = mutation
            .value
            .as_ref()
            .map(|value| context.value_bytes(value))
            .transpose()?;
        if previous == replacement {
            return Err(invalid(object, "KV delta contains a no-op mutation"));
        }
        update_totals(
            totals,
            &mutation.key,
            previous.as_deref(),
            replacement.as_deref(),
        )?;
        overlay.insert(mutation.key.clone(), replacement);
    }
    Ok(())
}

fn update_totals(
    totals: &mut NodeTotals,
    key: &[u8],
    previous: Option<&[u8]>,
    replacement: Option<&[u8]>,
) -> StorageResult<()> {
    let key_bytes = u64::try_from(key.len())
        .map_err(|_| StorageError::Internal("KV key length overflow".to_owned()))?;
    let previous_bytes = previous.map_or(0, |value| value.len() as u64);
    let replacement_bytes = replacement.map_or(0, |value| value.len() as u64);
    totals.entries = match (previous, replacement) {
        (None, Some(_)) => totals.entries.checked_add(1),
        (Some(_), None) => totals.entries.checked_sub(1),
        _ => Some(totals.entries),
    }
    .ok_or_else(|| StorageError::Internal("KV entry total overflow".to_owned()))?;
    totals.logical_bytes = totals
        .logical_bytes
        .checked_sub(previous_bytes)
        .and_then(|total| total.checked_add(replacement_bytes))
        .ok_or_else(|| StorageError::Internal("KV logical total overflow".to_owned()))?;
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
        .ok_or_else(|| StorageError::Internal("KV quota total overflow".to_owned()))?;
    Ok(())
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
