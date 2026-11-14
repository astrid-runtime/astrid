//! Authenticated KV validation-memo transfer across retirement handoff.
//!
//! Copies only already-validated owner facts into fresh cache containers after
//! the durable engine has moved. A projection seeds only with a matching tree
//! certificate; missing or mismatched facts leave the destination cold.

use crate::engine::KvProjectionEngine;
use crate::storage_model::{ObjectId, ObjectKind, ReferenceKind, ReferenceLabel, RootState};

use super::delta::Projection;
use super::header::{load_typed, owned_target, require_structural};
use super::validation::TreeValidation;
use super::{KV_LABEL, KvValidationCache, STATE_LABEL};
use crate::error::StorageResult;
use crate::kv::tree_error::invalid;

impl<P: Clone + Ord> KvValidationCache<P> {
    /// Snapshot one owner only when projection and tree certificate match.
    fn snapshot_owner(&self, owner: &P) -> Option<(Projection, TreeValidation)> {
        let projection = self.projections.lock().get(owner).cloned()?;
        let tree = self.trees.lock().get(owner).copied()?;
        if tree.root() != projection.tree
            || projection.boundary != Some(tree.certificate())
            || !tree.certificate().matches_tree(projection.tree)
        {
            return None;
        }
        Some((projection, tree))
    }

    /// Insert a previously validated owner memo when it still names the live KV head.
    fn try_seed_owner_if_live<E: KvProjectionEngine<P>>(
        &self,
        engine: &E,
        owner: P,
        projection: Projection,
        tree: TreeValidation,
    ) -> bool {
        if tree.root() != projection.tree
            || projection.boundary != Some(tree.certificate())
            || !tree.certificate().matches_tree(projection.tree)
        {
            return false;
        }
        let Ok(live_root) = engine.current_kv_root(&owner) else {
            return false;
        };
        match live_root {
            None => {
                if projection.head.is_some() || projection.tree.is_some() || tree.root().is_some() {
                    return false;
                }
            },
            Some(root) => {
                let Ok(live_head) = live_kv_component_head(engine, &owner, root) else {
                    return false;
                };
                if projection.head != live_head {
                    return false;
                }
            },
        }
        // Mirror publish_if_current lock order: projections, then trees.
        let mut projections = self.projections.lock();
        let Ok(current) = engine.current_kv_root(&owner) else {
            return false;
        };
        if current != live_root {
            return false;
        }
        self.trees.lock().insert(owner.clone(), tree);
        projections.insert(owner, projection);
        true
    }

    /// Test-only: insert without live rebind. Used to plant stale/foreign owners.
    #[cfg(test)]
    fn insert_unchecked_for_test(
        &self,
        owner: P,
        projection: Projection,
        tree: Option<TreeValidation>,
    ) {
        if let Some(tree) = tree {
            self.trees.lock().insert(owner.clone(), tree);
        } else {
            self.trees.lock().remove(&owner);
        }
        self.projections.lock().insert(owner, projection);
    }

    /// Test-only empty owner marker that must never rebind across handoff.
    #[cfg(test)]
    pub(crate) fn insert_empty_owner_for_test(&self, owner: P) {
        self.insert_unchecked_for_test(owner, Projection::empty(), Some(TreeValidation::EMPTY));
    }

    /// Drop the tree certificate while leaving any projection memo in place.
    #[cfg(test)]
    pub(crate) fn clear_tree_validation_for_test(&self, owner: &P) {
        self.trees.lock().remove(owner);
    }

    #[cfg(test)]
    pub(crate) fn cached_owners_for_test(&self) -> Vec<P> {
        self.projections.lock().keys().cloned().collect()
    }

    #[cfg(test)]
    pub(crate) fn tree_validation_invocations_for_test(&self) -> u64 {
        self.tree_validation_invocations
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(crate) fn record_tree_validation_for_test(&self) {
        self.tree_validation_invocations
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Seed one owner from `source` into a fresh `destination` against `engine`.
pub(crate) fn seed_owner_memo_if_live<P, E>(
    engine: &E,
    source: &KvValidationCache<P>,
    destination: &KvValidationCache<P>,
    owner: P,
) -> bool
where
    P: Clone + Ord,
    E: KvProjectionEngine<P>,
{
    let Some((projection, tree)) = source.snapshot_owner(&owner) else {
        return false;
    };
    destination.try_seed_owner_if_live(engine, owner, projection, tree)
}

fn live_kv_component_head<P, E>(
    engine: &E,
    owner: &P,
    root: RootState,
) -> StorageResult<Option<ObjectId>>
where
    E: KvProjectionEngine<P>,
{
    let commit = load_typed(engine, owner, root.commit, ObjectKind::Commit)?;
    require_structural(root.commit, &commit)?;
    let state_id = owned_target(root.commit, &commit, STATE_LABEL)?;
    let state = load_typed(engine, owner, state_id, ObjectKind::PrincipalState)?;
    require_structural(state_id, &state)?;
    match state.reference(&ReferenceLabel::new(KV_LABEL)) {
        None => Ok(None),
        Some(reference) if reference.kind() == ReferenceKind::Owns => Ok(Some(reference.target())),
        Some(_) => Err(invalid(state_id, "principal KV component is not owning")),
    }
}
