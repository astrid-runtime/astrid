use std::collections::BTreeMap;
use std::sync::Arc;

use crate::engine::{KvProjectionEngine, PrincipalProjectionError};
use crate::storage_model::{
    ModelError, ObjectClass, ObjectId, ObjectKind, ObjectRecord, ObjectReference, ReferenceKind,
    ReferenceLabel, RootState,
};
use parking_lot::Mutex;

use super::delta::{Mutation, Projection};
use super::memo::MemoSnapshot;
use super::node::NodeTotals;
use super::overlay::OverlayMap;
use super::{
    FORMAT_VERSION, KV_LABEL, KvValidationCache, PARENT_LABEL, STATE_LABEL, TreeContext,
    TreeValidation,
};
use crate::content::{
    CONTENT_COMPONENT_LABEL, CatalogValidation, PrincipalContentError, is_workspace_branch_label,
    root_from_record, validate_catalog, workspace_branch_quota_from_loader,
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
    pub(super) boundary: Option<super::validation::ValidatedCheckpoint>,
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
            boundary: Some(super::validation::ValidatedCheckpoint::empty()),
        }
    }
}

pub(super) fn decode_header<P, E>(
    engine: &E,
    owner: P,
    root: RootState,
    validation: &KvValidationCache<P>,
    validated_content: &Mutex<BTreeMap<P, CatalogValidation>>,
    captured_projection: Option<Projection>,
    epoch: super::MemoEpoch,
) -> StorageResult<TreeHeader<P>>
where
    P: Clone + Ord,
    E: KvProjectionEngine<P>,
{
    let commit = load_typed(engine, &owner, root.commit, ObjectKind::Commit)?;
    require_structural(root.commit, &commit)?;
    let state_id = owned_target(root.commit, &commit, STATE_LABEL)?;
    let state = load_typed(engine, &owner, state_id, ObjectKind::PrincipalState)?;
    require_structural(state_id, &state)?;
    let (projection, checkpoint) = match state.reference(&ReferenceLabel::new(KV_LABEL)) {
        None => (Projection::empty(), Some(TreeValidation::EMPTY)),
        Some(reference) if reference.kind() == ReferenceKind::Owns => {
            let cached = captured_projection
                .filter(|projection| projection.head == Some(reference.target()))
                .or_else(|| {
                    validation
                        .projections
                        .lock()
                        .get(&owner)
                        .filter(|projection| projection.head == Some(reference.target()))
                        .cloned()
                });
            if let Some(cached) = cached {
                (cached, None)
            } else {
                let (decoded, checkpoint) =
                    decode_kv_component::<P, E>(engine, &owner, reference.target(), validation)?;
                (decoded, Some(checkpoint))
            }
        },
        Some(_) => {
            return Err(invalid(state_id, "principal KV component is not owning"));
        },
    };
    let (preserved_state, other_quota_bytes) = decode_other_components(
        engine,
        &owner,
        state_id,
        &state,
        validated_content,
        validation,
        MemoSnapshot { root, epoch },
    )?;
    let preserved_commit = commit
        .references()
        .iter()
        .filter(|reference| {
            reference.label().as_bytes() != STATE_LABEL
                && reference.label().as_bytes() != PARENT_LABEL
        })
        .cloned()
        .collect();
    if let Some(checkpoint) = checkpoint {
        validation.publish_if_current(
            engine,
            owner.clone(),
            root,
            projection.clone(),
            Some(checkpoint),
            epoch,
        );
    }
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
        boundary: projection
            .boundary
            .filter(|certificate| certificate.matches_tree(projection.tree)),
    })
}

// A captured root authorizes publication only when the caller retrieved `head`
// from that exact root's owning KV component. Historical callers pass None.
pub(crate) fn validated_projection<P, E>(
    engine: &E,
    owner: &P,
    head: ObjectId,
    captured_root: Option<RootState>,
    validation: &KvValidationCache<P>,
    epoch: super::MemoEpoch,
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
    let (decoded, checkpoint) = decode_kv_component(engine, owner, head, validation)?;
    if let Some(root) = captured_root {
        validation.publish_if_current(
            engine,
            owner.clone(),
            root,
            decoded.clone(),
            Some(checkpoint),
            epoch,
        );
    }
    Ok(decoded)
}

pub(crate) fn validated_projection_quota<P, E>(
    engine: &E,
    owner: &P,
    head: ObjectId,
    captured_root: Option<RootState>,
    validation: &KvValidationCache<P>,
    epoch: super::MemoEpoch,
) -> StorageResult<u64>
where
    P: Clone + Ord,
    E: KvProjectionEngine<P>,
{
    validated_projection(engine, owner, head, captured_root, validation, epoch)
        .map(|projection| projection.totals.quota_bytes)
}

fn decode_other_components<P, E>(
    engine: &E,
    owner: &P,
    state_id: ObjectId,
    state: &ObjectRecord,
    validated_content: &Mutex<BTreeMap<P, CatalogValidation>>,
    validation_cache: &KvValidationCache<P>,
    snapshot: MemoSnapshot,
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
                    validation_cache,
                    snapshot,
                )?)
                .ok_or_else(|| {
                    StorageError::Internal("principal quota total overflow".to_owned())
                })?;
        } else if is_workspace_branch_label(reference.label().as_bytes()) {
            quota_bytes = quota_bytes
                .checked_add(
                    workspace_branch_quota_from_loader(reference, &mut |object| {
                        engine
                            .load_kv_object_for(owner, object)
                            .map_err(|error| {
                                PrincipalContentError::Projection(PrincipalProjectionError::Engine(
                                    error.to_string(),
                                ))
                            })
                            .and_then(|record| {
                                record.ok_or(PrincipalContentError::Projection(
                                    PrincipalProjectionError::Model(ModelError::MissingObject(
                                        object,
                                    )),
                                ))
                            })
                    })
                    .map_err(|error| StorageError::Serialization(error.to_string()))?,
                )
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
    validation_cache: &KvValidationCache<P>,
    snapshot: MemoSnapshot,
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
        .load_kv_object_for(owner, reference.target())
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
                .load_kv_object_for(owner, object)
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
        validation_cache.publish_catalog_if_current(
            validated_content, owner, snapshot.epoch, validation,
            || matches!(engine.current_kv_root(owner), Ok(Some(current)) if current == snapshot.root),
        );
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
    validation_cache: &KvValidationCache<P>,
) -> StorageResult<(Projection, TreeValidation)>
where
    P: Clone + Ord,
    E: KvProjectionEngine<P>,
{
    use super::{checkpoint_replay, delta_chain, delta_recovery::CounterError, delta_replay};
    let validated_trees = &validation_cache.trees;
    let chain = delta_chain::walk(owner, head_id, |principal, object| {
        use super::projection_record::{self, LoadError};
        projection_record::read_at(
            principal,
            object,
            FORMAT_VERSION,
            super::ROOT_LABEL,
            |p, id| load_typed(engine, p, id, ObjectKind::NamespaceMap),
            |key| super::validation::validate_composite_key(object, key).err(),
        )
        .map_err(|error| match error {
            LoadError::Source(e) => e,
            LoadError::Record(id, e) => super::delta::projection_error(id, e),
        })
    })
    .map_err(|error| match error {
        delta_chain::Error::Cycle(id) => invalid(id, "KV delta chain contains a cycle"),
        delta_chain::Error::Source(e) => e,
    })?;
    let tree = chain.tree;
    let cached = validated_trees
        .lock()
        .get(owner)
        .copied()
        .filter(|validation| validation.root() == tree);
    let validation = if let Some(validation) = cached {
        validation
    } else {
        #[cfg(test)]
        validation_cache.record_tree_validation_for_test();
        let mut context = TreeContext::<P, E>::new(engine, owner);
        context.validate_tree(tree)?
    };
    let replay = checkpoint_replay::recover(
        chain,
        validation.root(),
        NodeTotals {
            entries: validation.entries,
            logical_bytes: validation.logical_bytes,
            quota_bytes: validation.quota_bytes,
        },
        || {
            (
                TreeContext::<P, E>::new(engine, owner),
                OverlayMap::default(),
            )
        },
        |(mut context, mut overlay), base, object, mutations, mut totals| {
            apply_validated_mutations(
                object,
                &mut context,
                base,
                &mut overlay,
                &mut totals,
                mutations,
            )?;
            Ok(((context, overlay), totals))
        },
    )
    .map_err(|error| match error {
        checkpoint_replay::Error::Root => {
            invalid(head_id, "KV checkpoint validation root disagrees")
        },
        checkpoint_replay::Error::Totals => {
            invalid(head_id, "KV checkpoint accounting totals disagree")
        },
        checkpoint_replay::Error::Replay(error) => match error {
            delta_replay::Error::Counter(id, CounterError::Disagree) => {
                invalid(id, "KV delta chain counters disagree")
            },
            delta_replay::Error::Counter(_, CounterError::RowOverflow) => {
                super::delta::arithmetic_overflow()
            },
            delta_replay::Error::Counter(id, CounterError::ChainOverflow) => {
                invalid(id, "KV delta byte total overflow")
            },
            delta_replay::Error::Apply(error) => error,
            delta_replay::Error::Totals(id) => invalid(id, "KV delta accounting totals disagree"),
        },
    })?;
    let (_, overlay) = replay.state;
    Ok((
        Projection {
            head: Some(head_id),
            tree,
            overlay,
            depth: replay.depth,
            delta_bytes: replay.bytes,
            totals: replay.totals,
            boundary: Some(validation.certificate()),
        },
        validation,
    ))
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
        use super::delta_totals::ApplyError;
        overlay
            .apply(totals, mutation, |key, slot, needs_checkpoint| {
                super::replay_values::resolve(
                    &mut *context,
                    tree,
                    key,
                    slot.as_ref(),
                    needs_checkpoint,
                    |context, base, address| {
                        let prior = context.get(base, address)?;
                        Ok((context, prior))
                    },
                    |context, value| context.value_bytes(value),
                )
            })
            .map_err(|error| match error {
                ApplyError::Load(e) => e,
                ApplyError::Change(super::delta_totals::ReplayError::Unchanged) => {
                    invalid(object, "KV delta contains a no-op mutation")
                },
                ApplyError::Change(super::delta_totals::ReplayError::Accounting(e)) => {
                    replay_accounting_error(e)
                },
            })?;
    }
    Ok(())
}

fn replay_accounting_error(error: super::delta_totals::Error) -> StorageError {
    use super::delta_totals::Error;
    StorageError::Internal(
        match error {
            Error::Key => "KV key length overflow",
            Error::Entries => "KV entry total overflow",
            Error::Logical => "KV logical total overflow",
            Error::Quota => "KV quota total overflow",
        }
        .to_owned(),
    )
}

pub(super) fn load_typed<P, E>(
    engine: &E,
    owner: &P,
    id: ObjectId,
    kind: ObjectKind,
) -> StorageResult<Arc<ObjectRecord>>
where
    E: KvProjectionEngine<P>,
{
    let record = engine
        .load_shared_kv_object_for(owner, id)
        .map_err(|error| map_engine(&error))?
        .ok_or_else(|| map_engine(&ModelError::MissingObject(id).into()))?;
    if record.kind() != kind || record.format_version() != FORMAT_VERSION {
        return Err(invalid(id, "object has the wrong KV tree kind or version"));
    }
    Ok(record)
}

pub(super) fn require_structural(id: ObjectId, record: &ObjectRecord) -> StorageResult<()> {
    if !record.canonical_bytes().is_empty()
        || record.logical_bytes() != 0
        || record.class() != ObjectClass::Metadata
    {
        return Err(invalid(id, "structural KV tree object carries payload"));
    }
    Ok(())
}

pub(super) fn owned_target(
    id: ObjectId,
    record: &ObjectRecord,
    label: &[u8],
) -> StorageResult<ObjectId> {
    let reference = record
        .reference(&ReferenceLabel::new(label))
        .ok_or_else(|| invalid(id, "required KV tree reference is missing"))?;
    if reference.kind() != ReferenceKind::Owns {
        return Err(invalid(id, "required KV tree reference is not owning"));
    }
    Ok(reference.target())
}

#[cfg(test)]
mod tests;
