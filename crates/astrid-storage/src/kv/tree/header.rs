use std::collections::BTreeMap;
use std::sync::Arc;

use crate::engine::{KvProjectionEngine, PrincipalProjectionError};
use crate::storage_model::{
    ModelError, ObjectId, ObjectKind, ObjectRecord, ObjectReference, ReferenceKind, RootState,
};
use parking_lot::Mutex;

#[cfg(test)]
use super::delta::Mutation;
use super::delta::Projection;
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
    let (graph, head) = read_kv_graph(engine, &owner, root)?;
    let crate::storage_model::header_graph::Graph {
        commit,
        state_id,
        state,
    } = graph;
    let (projection, checkpoint) = match head {
        None => (Projection::empty(), Some(TreeValidation::EMPTY)),
        Some(component) => {
            resolve_projection(engine, &owner, component, captured_projection, validation)?
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
    let (decoded, checkpoint) = resolve_projection(engine, owner, head, None, validation)?;
    if let (Some(root), Some(checkpoint)) = (captured_root, checkpoint) {
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

fn resolve_projection<P: Clone + Ord, E: KvProjectionEngine<P>>(
    engine: &E,
    owner: &P,
    head: ObjectId,
    captured: Option<Projection>,
    validation: &KvValidationCache<P>,
) -> StorageResult<(Projection, Option<TreeValidation>)> {
    super::memo_projection::resolve(
        owner,
        head,
        captured,
        |owner, id| super::memo_projection::current(&validation.projections.lock(), owner, id),
        |owner, id| decode_kv_component(engine, owner, id, validation),
    )
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
    use super::{
        checkpoint_replay, delta_chain, delta_recovery::CounterError, delta_replay,
        projection_recovery,
    };
    projection_recovery::read(
        owner,
        head_id,
        |principal, object| {
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
        },
        |owner, tree| {
            let cached = validation_cache
                .trees
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
            Ok(projection_recovery::Measured {
                root: validation.root(),
                totals: NodeTotals {
                    entries: validation.entries,
                    logical_bytes: validation.logical_bytes,
                    quota_bytes: validation.quota_bytes,
                },
                boundary: validation.certificate(),
                validation,
            })
        },
        |principal| TreeContext::<P, E>::new(engine, principal),
        (
            |mut context: TreeContext<'_, P, E>, base, key: &Vec<u8>| {
                let old = context.get(base, key)?;
                Ok((context, old))
            },
            |context: TreeContext<'_, P, E>, slot: &super::node::ValueSlot| {
                let bytes = context.value_bytes(slot)?;
                Ok((context, bytes))
            },
        ),
        mutation_error,
    )
    .map_err(|error| match error {
        projection_recovery::Error::Chain(delta_chain::Error::Cycle(id)) => {
            invalid(id, "KV delta chain contains a cycle")
        },
        projection_recovery::Error::Chain(delta_chain::Error::Source(e))
        | projection_recovery::Error::Validation(e) => e,
        projection_recovery::Error::Checkpoint(error) => match error {
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
                delta_replay::Error::Totals(id) => {
                    invalid(id, "KV delta accounting totals disagree")
                },
            },
        },
    })
}

#[cfg(test)]
fn apply_validated_mutations<P, E>(
    object: ObjectId,
    context: &mut TreeContext<'_, P, E>,
    tree: Option<ObjectId>,
    overlay: OverlayMap,
    totals: NodeTotals,
    mutations: &[Mutation],
) -> StorageResult<(OverlayMap, NodeTotals)>
where
    P: Ord,
    E: KvProjectionEngine<P>,
{
    let (_, overlay, totals) = overlay
        .recover(
            (context, totals),
            tree,
            object,
            mutations,
            |context, base, key| {
                let old = context.get(base, key)?;
                Ok((context, old))
            },
            |context, slot| {
                let data = context.value_bytes(slot)?;
                Ok((context, data))
            },
        )
        .map_err(|(_, (object, error))| mutation_error(object, error))?;
    Ok((overlay, totals))
}

fn mutation_error(
    object: ObjectId,
    error: super::delta_totals::ApplyError<StorageError>,
) -> StorageError {
    use super::delta_totals::ApplyError;
    match error {
        ApplyError::Load(e) => e,
        ApplyError::Change(super::delta_totals::ReplayError::Unchanged) => {
            invalid(object, "KV delta contains a no-op mutation")
        },
        ApplyError::Change(super::delta_totals::ReplayError::Accounting(e)) => {
            replay_accounting_error(e)
        },
    }
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

pub(super) fn read_kv_graph<P, E: KvProjectionEngine<P>>(
    engine: &E,
    owner: &P,
    root: RootState,
) -> StorageResult<(crate::storage_model::header_graph::Graph, Option<ObjectId>)> {
    use crate::storage_model::header_graph::{self, Error, Invalid, KvError};
    header_graph::read_kv(owner, root, FORMAT_VERSION, |principal, id| {
        engine
            .load_shared_kv_object_for(principal, id)
            .map_err(|e| map_engine(&e))?
            .ok_or_else(|| map_engine(&ModelError::MissingObject(id).into()))
    })
    .map_err(|e| match e {
        KvError::Graph(Error::Read(e)) => e,
        KvError::Graph(Error::Invalid(id, reason)) => invalid(
            id,
            match reason {
                Invalid::KindOrVersion => "object has the wrong KV tree kind or version",
                Invalid::Payload => "structural KV tree object carries payload",
                Invalid::MissingState => "required KV tree reference is missing",
                Invalid::NonOwningState => "required KV tree reference is not owning",
            },
        ),
        KvError::NonOwning(id) => invalid(id, "principal KV component is not owning"),
    })
}

#[cfg(test)]
mod tests;
