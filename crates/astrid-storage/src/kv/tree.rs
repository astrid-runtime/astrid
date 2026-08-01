//! Canonical key/value transitions over immutable B+-tree checkpoints.
//!
//! Point mutations append compact transition records. Background checkpointing
//! folds accumulated transitions into page-bounded B+-trees without changing
//! the logical projection.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::marker::PhantomData;
use std::sync::Arc;

use astrid_storage_engine::{KvProjectionEngine, KvProjectionError};
use astrid_storage_model::ModelError;
use parking_lot::Mutex;

use self::context::TreeContext;
use self::delta::Projection;
use self::header::{TreeHeader, decode_header};
#[cfg(all(feature = "legacy-surrealkv", not(target_family = "wasm")))]
use super::KvEntry;
#[cfg(all(feature = "legacy-surrealkv", not(target_family = "wasm")))]
use super::composite_key;
use super::principal::{KvPrincipalResolver, KvQuotaResolver};
use super::tree_error::map_engine;
use crate::error::{StorageError, StorageResult};
use crate::principal_graph::PRINCIPAL_GRAPH_VERSION;

mod adapter;
mod context;
mod delta;
mod header;
mod legacy_avl;
mod node;
mod overlay;
mod validation;

pub(crate) use self::header::validated_projection_quota;
pub(crate) use self::legacy_avl::migrate_principal as migrate_legacy_avl;
pub(super) use self::validation::TreeValidation;

pub(super) const FORMAT_VERSION: astrid_storage_model::ObjectFormatVersion =
    PRINCIPAL_GRAPH_VERSION;
pub(super) const KV_LABEL: &[u8] = b"kv";
const PARENT_LABEL: &[u8] = b"parent";
pub(super) const ROOT_LABEL: &[u8] = b"root";
pub(super) const STATE_LABEL: &[u8] = b"state";
// Soft maintenance batch target. This is neither a quota nor a format limit.
const CHECKPOINT_MIN_DELTA_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug)]
pub(crate) struct KvValidationCache<P: Ord> {
    trees: Mutex<BTreeMap<P, TreeValidation>>,
    projections: Mutex<BTreeMap<P, Projection>>,
}

impl<P: Ord> Default for KvValidationCache<P> {
    fn default() -> Self {
        Self {
            trees: Mutex::new(BTreeMap::new()),
            projections: Mutex::new(BTreeMap::new()),
        }
    }
}

/// Production point-operation KV adapter over a persistent balanced tree.
pub struct TreeKvStore<P: Ord, I, R, E> {
    engine: Arc<E>,
    resolver: R,
    quota: Option<Arc<dyn KvQuotaResolver<P>>>,
    validation: Arc<KvValidationCache<P>>,
    validated_content: Arc<Mutex<BTreeMap<P, crate::content::CatalogValidation>>>,
    checkpointing: Arc<Mutex<BTreeSet<P>>>,
    marker: PhantomData<fn() -> (P, I)>,
}

struct BlockingTreeStore<P: Ord, E> {
    engine: Arc<E>,
    quota: Option<Arc<dyn KvQuotaResolver<P>>>,
    validation: Arc<KvValidationCache<P>>,
    validated_content: Arc<Mutex<BTreeMap<P, crate::content::CatalogValidation>>>,
    checkpointing: Arc<Mutex<BTreeSet<P>>>,
}

impl<P: Ord, E> Clone for BlockingTreeStore<P, E> {
    fn clone(&self) -> Self {
        Self {
            engine: Arc::clone(&self.engine),
            quota: self.quota.clone(),
            validation: Arc::clone(&self.validation),
            validated_content: Arc::clone(&self.validated_content),
            checkpointing: Arc::clone(&self.checkpointing),
        }
    }
}

impl<P: Ord, I, R, E> TreeKvStore<P, I, R, E> {
    /// Construct a tree adapter without logical quota policy.
    #[must_use]
    pub fn from_engine(engine: Arc<E>, resolver: R) -> Self {
        Self {
            engine,
            resolver,
            quota: None,
            validation: Arc::new(KvValidationCache::default()),
            validated_content: Arc::new(Mutex::new(BTreeMap::new())),
            checkpointing: Arc::new(Mutex::new(BTreeSet::new())),
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
            validation: Arc::new(KvValidationCache::default()),
            validated_content: Arc::new(Mutex::new(BTreeMap::new())),
            checkpointing: Arc::new(Mutex::new(BTreeSet::new())),
            marker: PhantomData,
        }
    }

    pub(crate) fn from_engine_with_quota_and_content_validation(
        engine: Arc<E>,
        resolver: R,
        quota: Arc<dyn KvQuotaResolver<P>>,
        validation: Arc<KvValidationCache<P>>,
        validated_content: Arc<Mutex<BTreeMap<P, crate::content::CatalogValidation>>>,
    ) -> Self {
        Self {
            engine,
            resolver,
            quota: Some(quota),
            validation,
            validated_content,
            checkpointing: Arc::new(Mutex::new(BTreeSet::new())),
            marker: PhantomData,
        }
    }

    fn blocking_store(&self) -> BlockingTreeStore<P, E> {
        BlockingTreeStore {
            engine: Arc::clone(&self.engine),
            quota: self.quota.clone(),
            validation: Arc::clone(&self.validation),
            validated_content: Arc::clone(&self.validated_content),
            checkpointing: Arc::clone(&self.checkpointing),
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
    P: Clone + Ord + Send + Sync + 'static,
    E: KvProjectionEngine<P> + 'static,
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
            self.validation.as_ref(),
            self.validated_content.as_ref(),
        )
    }

    fn read<T>(
        &self,
        owner: P,
        read: impl FnOnce(&mut TreeContext<'_, P, E>, &TreeHeader<P>) -> StorageResult<T>,
    ) -> StorageResult<T> {
        let header = self.header(owner)?;
        let mut context = TreeContext::new(self.engine.as_ref(), &header.owner);
        read(&mut context, &header)
    }

    fn mutate<T>(
        &self,
        owner: &P,
        mut mutation: impl FnMut(
            &mut TreeContext<'_, P, E>,
            &TreeHeader<P>,
        ) -> StorageResult<(T, Vec<(Vec<u8>, Option<Vec<u8>>)>, bool)>,
    ) -> StorageResult<T> {
        loop {
            let header = self.header(owner.clone())?;
            let mut context = TreeContext::new(self.engine.as_ref(), owner);
            let (result, mutations, changed) = mutation(&mut context, &header)?;
            if !changed {
                return Ok(result);
            }
            let projection = context.apply_mutations(&header, mutations)?;
            let logical_bytes = projection.totals.logical_bytes;
            let projection_used = projection.totals.quota_bytes;
            let used = projection_used
                .checked_add(header.other_quota_bytes)
                .ok_or_else(|| {
                    StorageError::Internal("principal quota total overflow".to_owned())
                })?;
            let previous_used = header
                .quota_bytes
                .checked_add(header.other_quota_bytes)
                .ok_or_else(|| {
                    StorageError::Internal("principal quota total overflow".to_owned())
                })?;
            if let Some(quota) = &self.quota
                && let Some(limit) = quota.max_logical_bytes(owner)?
                && used > limit
                && used > previous_used
            {
                return Err(StorageError::quota_exceeded(used, limit));
            }
            let tree = projection.tree;
            let validated_projection = projection.clone();
            let transaction = context.finish_projection(header, &projection)?;
            match self.engine.commit_kv_root(transaction) {
                Ok(_) => {
                    self.validation.trees.lock().insert(
                        owner.clone(),
                        TreeValidation {
                            root: tree,
                            entries: projection.totals.entries,
                            logical_bytes,
                            quota_bytes: projection_used,
                        },
                    );
                    self.validation
                        .projections
                        .lock()
                        .insert(owner.clone(), validated_projection);
                    if should_checkpoint(&projection) {
                        self.schedule_checkpoint(owner.clone());
                    }
                    return Ok(result);
                },
                Err(KvProjectionError::Model(ModelError::RootConflict { .. })) => {},
                Err(error) => return Err(map_engine(&error)),
            }
        }
    }

    fn clear_range(&self, owner: &P, start: &[u8], end: &[u8]) -> StorageResult<u64> {
        self.mutate(owner, |context, header| {
            let mut keys = context
                .raw_keys_in_range(header.tree, start, end)?
                .into_iter()
                .collect::<BTreeSet<_>>();
            for (key, value) in header.overlay.range(start, end) {
                match value {
                    Some(_) => {
                        keys.insert(key);
                    },
                    None => {
                        keys.remove(&key);
                    },
                }
            }
            let count = u64::try_from(keys.len())
                .map_err(|_| StorageError::Internal("KV key count overflow".to_owned()))?;
            let mutations = keys.into_iter().map(|key| (key, None)).collect();
            Ok((count, mutations, count != 0))
        })
    }

    fn schedule_checkpoint(&self, owner: P) {
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        self.schedule_checkpoint_on(owner, runtime);
    }

    fn schedule_checkpoint_on(&self, owner: P, runtime: tokio::runtime::Handle) {
        if !self.checkpointing.lock().insert(owner.clone()) {
            return;
        }
        let store = self.clone();
        let spawn_runtime = runtime.clone();
        let _task = spawn_runtime.spawn_blocking(move || {
            let outcome = store.checkpoint_once(owner.clone(), false);
            store.checkpointing.lock().remove(&owner);
            let retry = if matches!(outcome.as_ref(), Ok(false)) {
                match store.header(owner.clone()) {
                    Ok(header) => should_checkpoint(&projection_from_header(&header)),
                    Err(error) => {
                        tracing::warn!(%error, "principal KV checkpoint retry check failed");
                        false
                    },
                }
            } else {
                false
            };
            if let Err(error) = outcome {
                tracing::warn!(%error, "principal KV checkpoint failed");
            }
            if retry {
                std::thread::yield_now();
                store.schedule_checkpoint_on(owner, runtime);
            }
        });
    }

    fn checkpoint_once(&self, owner: P, force: bool) -> StorageResult<bool> {
        self.checkpoint_once_after(owner, force, || Ok(()))
    }

    fn checkpoint_once_after(
        &self,
        owner: P,
        force: bool,
        interleave: impl FnOnce() -> StorageResult<()>,
    ) -> StorageResult<bool> {
        let base = self.header(owner.clone())?;
        let base_projection = projection_from_header(&base);
        if !force && !should_checkpoint(&base_projection) {
            return Ok(false);
        }
        let mut context = TreeContext::new(self.engine.as_ref(), &base.owner);
        let mut entries = BTreeMap::<Vec<u8>, Vec<u8>>::new();
        context.visit_entries(base.tree, |key, value| {
            entries.insert(key.to_vec(), value.to_vec());
            Ok(())
        })?;
        for (key, value) in base.overlay.all() {
            match value {
                Some(value) => {
                    entries.insert(key, value);
                },
                None => {
                    entries.remove(&key);
                },
            }
        }
        let tree = context.build_sorted(entries.into_iter().collect())?;
        let checkpoint_totals = base_projection.totals;
        interleave()?;
        let current = self.header(owner.clone())?;
        let current_projection = projection_from_header(&current);
        if !force && !should_checkpoint(&current_projection) {
            return Ok(false);
        }
        let Some((transaction, rebased)) =
            context.rebase_checkpoint(base.head, current, tree, checkpoint_totals)?
        else {
            return Ok(false);
        };
        match self.engine.commit_kv_root(transaction) {
            Ok(_) => {
                self.validation.trees.lock().insert(
                    owner.clone(),
                    TreeValidation {
                        root: tree,
                        entries: checkpoint_totals.entries,
                        logical_bytes: checkpoint_totals.logical_bytes,
                        quota_bytes: checkpoint_totals.quota_bytes,
                    },
                );
                self.validation.projections.lock().insert(owner, rebased);
                Ok(true)
            },
            Err(KvProjectionError::Model(ModelError::RootConflict { .. })) => Ok(false),
            Err(error) => Err(map_engine(&error)),
        }
    }
}

fn projection_from_header<P>(header: &TreeHeader<P>) -> Projection {
    Projection {
        head: header.head,
        tree: header.tree,
        overlay: header.overlay.clone(),
        depth: header.delta_depth,
        delta_bytes: header.delta_bytes,
        totals: crate::kv::tree::node::NodeTotals {
            entries: header.entries,
            logical_bytes: header.logical_bytes,
            quota_bytes: header.quota_bytes,
        },
    }
}

fn should_checkpoint(projection: &Projection) -> bool {
    let live_bytes = projection
        .totals
        .logical_bytes
        .max(projection.totals.quota_bytes);
    projection.delta_bytes >= CHECKPOINT_MIN_DELTA_BYTES.max(live_bytes)
}

impl<P, I, R, E> TreeKvStore<P, I, R, E>
where
    P: Clone + Ord + Send + Sync + 'static,
    E: KvProjectionEngine<P> + 'static,
    R: KvPrincipalResolver<P>,
{
    #[cfg(all(feature = "legacy-surrealkv", not(target_family = "wasm")))]
    pub(crate) fn import_entries_for_migration(
        &self,
        owner: &P,
        entries: &[KvEntry],
    ) -> StorageResult<()> {
        self.blocking_store().mutate(owner, |_context, _header| {
            let mutations = entries
                .iter()
                .map(|entry| {
                    (
                        composite_key(&entry.namespace, &entry.key),
                        Some(entry.value.clone()),
                    )
                })
                .collect();
            Ok(((), mutations, !entries.is_empty()))
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
        let mut context = TreeContext::new(blocking.engine.as_ref(), owner);
        let mut entries = BTreeMap::<Vec<u8>, Option<Vec<u8>>>::new();
        context.visit_entries(header.tree, |composite, value| {
            entries.insert(composite.to_vec(), Some(value.to_vec()));
            Ok(())
        })?;
        for (key, value) in header.overlay.all() {
            entries.insert(key, value);
        }
        for (composite, value) in entries {
            let Some(value) = value else {
                continue;
            };
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
            visit(namespace, key, &value)?;
        }
        Ok(())
    }
}

impl<P, I, R, E> TreeKvStore<P, I, R, E>
where
    P: Clone + Ord + Send + Sync + 'static,
    E: KvProjectionEngine<P> + 'static,
    R: KvPrincipalResolver<P>,
{
    #[cfg(test)]
    pub(super) fn height_for_test(&self, owner: P) -> StorageResult<u32> {
        let blocking = self.blocking_store();
        let header = blocking.header(owner)?;
        TreeContext::new(blocking.engine.as_ref(), &header.owner).height(header.tree)
    }

    #[cfg(test)]
    pub(super) fn delta_depth_for_test(&self, owner: P) -> StorageResult<u64> {
        self.blocking_store()
            .header(owner)
            .map(|header| header.delta_depth)
    }

    #[cfg(test)]
    pub(super) fn checkpoint_for_test(&self, owner: P) -> StorageResult<bool> {
        self.blocking_store().checkpoint_once(owner, true)
    }

    #[cfg(test)]
    pub(super) fn checkpoint_after_mutation_for_test(
        &self,
        owner: P,
        key: Vec<u8>,
        value: Vec<u8>,
    ) -> StorageResult<bool> {
        let blocking = self.blocking_store();
        let interleaved = blocking.clone();
        let mutation_owner = owner.clone();
        blocking.checkpoint_once_after(owner, true, move || {
            interleaved.mutate(&mutation_owner, |context, header| {
                if context.projected_get(header, &key)?.as_deref() == Some(value.as_slice()) {
                    return Ok(((), Vec::new(), false));
                }
                Ok(((), vec![(key.clone(), Some(value.clone()))], true))
            })
        })
    }

    #[cfg(test)]
    pub(super) fn seed_sorted_for_test(
        &self,
        owner: P,
        entries: Vec<(Vec<u8>, Vec<u8>)>,
    ) -> StorageResult<()> {
        let blocking = self.blocking_store();
        let header = blocking.header(owner)?;
        if header.tree.is_some() {
            return Err(StorageError::Internal(
                "KV benchmark seed requires an empty principal".to_owned(),
            ));
        }
        let principal = header.owner.clone();
        let mut context = TreeContext::new(blocking.engine.as_ref(), &principal);
        let tree = context.build_sorted(entries)?;
        let transaction = context.finish(header, tree)?;
        blocking
            .engine
            .commit_kv_root(transaction)
            .map(|_| ())
            .map_err(|error| map_engine(&error))
    }
}
