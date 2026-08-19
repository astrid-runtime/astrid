//! Async adapter for the blocking persistent-tree implementation.
//!
//! Native durable I/O and engine mutex acquisition run on Tokio's blocking
//! pool. The WASM build has no blocking executor and delegates inline to its
//! host-backed engine.

use crate::engine::KvProjectionEngine;
use async_trait::async_trait;

use super::hot_cache::HotRead;
use super::{BlockingTreeStore, TreeKvStore, map_engine};
use crate::error::{StorageError, StorageResult};
use crate::kv::principal::KvPrincipalResolver;
use crate::kv::{
    KvBatchCondition, KvBatchMutation, KvBatchOutcome, KvConditionResult, KvMutationBatch, KvStore,
    composite_key, namespace_range_end, namespace_range_start, prefix_range_end, validate_key,
    validate_namespace, validate_prefix,
};

#[async_trait]
impl<P, I, R, E> KvStore for TreeKvStore<P, I, R, E>
where
    P: Clone + Ord + Send + Sync + 'static,
    I: Send + Sync + 'static,
    E: KvProjectionEngine<P> + 'static,
    R: KvPrincipalResolver<P> + Send + Sync + 'static,
{
    fn supports_atomic_batch(&self) -> bool {
        true
    }

    async fn close(&self) -> StorageResult<()> {
        self.reclaim_read_cache();
        let blocking = self.blocking_store();
        run_blocking(move || {
            blocking
                .engine
                .close_kv()
                .map_err(|error| map_engine(&error))
        })
        .await
    }

    async fn get(&self, namespace: &str, key: &str) -> StorageResult<Option<Vec<u8>>> {
        validate_namespace(namespace)?;
        validate_key(key)?;
        let owner = self.resolver.resolve(namespace)?;
        let composite = composite_key(namespace, key);
        if let (Some(cache), Some(root)) = (
            self.hot_cache.as_ref(),
            self.engine.current_kv_root_if_ready(&owner),
        ) && let HotRead::Hit(value) = cache.get(&owner, root.get(), &composite)
        {
            return Ok(value);
        }
        let blocking = self.blocking_store();
        let cache = self.hot_cache.clone();
        let cache_owner = owner.clone();
        let cache_key = composite.clone();
        run_blocking(move || {
            let (read_root, value) = blocking.read(owner, |context, header| {
                context
                    .projected_get(header, &composite)
                    .map(|value| (header.root, value))
            })?;
            if let Some(cache) = cache {
                cache.insert(&cache_owner, read_root, cache_key, value.as_deref());
            }
            Ok(value)
        })
        .await
    }

    async fn set(&self, namespace: &str, key: &str, value: Vec<u8>) -> StorageResult<()> {
        validate_namespace(namespace)?;
        validate_key(key)?;
        let owner = self.resolver.resolve(namespace)?;
        let composite = composite_key(namespace, key);
        let blocking = self.blocking_store();
        run_blocking(move || {
            blocking.mutate(&owner, |context, header| {
                if context.projected_get(header, &composite)?.as_deref() == Some(value.as_slice()) {
                    return Ok(((), Vec::new(), false));
                }
                Ok(((), vec![(composite.clone(), Some(value.clone()))], true))
            })
        })
        .await
    }

    async fn delete(&self, namespace: &str, key: &str) -> StorageResult<bool> {
        validate_namespace(namespace)?;
        validate_key(key)?;
        let owner = self.resolver.resolve(namespace)?;
        let composite = composite_key(namespace, key);
        let blocking = self.blocking_store();
        run_blocking(move || {
            blocking.mutate(&owner, |context, header| {
                let removed = context.projected_get(header, &composite)?.is_some();
                Ok((
                    removed,
                    removed
                        .then(|| (composite.clone(), None))
                        .into_iter()
                        .collect(),
                    removed,
                ))
            })
        })
        .await
    }

    async fn exists(&self, namespace: &str, key: &str) -> StorageResult<bool> {
        Ok(self.get(namespace, key).await?.is_some())
    }

    async fn list_keys(&self, namespace: &str) -> StorageResult<Vec<String>> {
        validate_namespace(namespace)?;
        let owner = self.resolver.resolve(namespace)?;
        let start = namespace_range_start(namespace);
        let end = namespace_range_end(namespace);
        let blocking = self.blocking_store();
        run_blocking(move || {
            blocking.read(owner, |context, header| {
                context.projected_keys_in_range(header, &start, &end, start.len())
            })
        })
        .await
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
        let blocking = self.blocking_store();
        run_blocking(move || {
            blocking.read(owner, |context, header| {
                context.projected_keys_in_range(header, &start, &end, strip)
            })
        })
        .await
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
        let expected = expected.map(<[u8]>::to_vec);
        let blocking = self.blocking_store();
        run_blocking(move || {
            blocking.mutate(&owner, |context, header| {
                let current = context.projected_get(header, &composite)?;
                if current.as_deref() != expected.as_deref() {
                    return Ok((false, Vec::new(), false));
                }
                if current.as_deref() == Some(new.as_slice()) {
                    return Ok((true, Vec::new(), false));
                }
                Ok((true, vec![(composite.clone(), Some(new.clone()))], true))
            })
        })
        .await
    }

    async fn apply_batch(&self, batch: &KvMutationBatch) -> StorageResult<KvBatchOutcome> {
        let owner = resolve_batch_owner(self, batch)?;
        let blocking = self.blocking_store();
        let batch = batch.clone();
        run_blocking(move || apply_batch_blocking(&blocking, &owner, &batch)).await
    }

    async fn clear_namespace(&self, namespace: &str) -> StorageResult<u64> {
        validate_namespace(namespace)?;
        let owner = self.resolver.resolve(namespace)?;
        let start = namespace_range_start(namespace);
        let end = namespace_range_end(namespace);
        let blocking = self.blocking_store();
        run_blocking(move || blocking.clear_range(&owner, &start, &end)).await
    }

    async fn clear_prefix(&self, namespace: &str, prefix: &str) -> StorageResult<u64> {
        validate_namespace(namespace)?;
        validate_prefix(prefix)?;
        let owner = self.resolver.resolve(namespace)?;
        let start = composite_key(namespace, prefix);
        let end = prefix_range_end(namespace, prefix);
        let blocking = self.blocking_store();
        run_blocking(move || blocking.clear_range(&owner, &start, &end)).await
    }
}

fn resolve_batch_owner<P, I, R, E>(
    store: &TreeKvStore<P, I, R, E>,
    batch: &KvMutationBatch,
) -> StorageResult<P>
where
    P: Clone + Ord + Send + Sync + 'static,
    E: KvProjectionEngine<P> + 'static,
    R: KvPrincipalResolver<P>,
{
    let keys = batch
        .conditions()
        .iter()
        .map(KvBatchCondition::key)
        .chain(batch.mutations().iter().map(KvBatchMutation::key));
    let mut owner = None;
    for key in keys {
        // `KvEntryKey` validates at construction. Revalidate at the backend
        // boundary as well so every key is checked before any owner is used.
        validate_namespace(key.namespace())?;
        validate_key(key.key())?;
        let candidate = store.resolver.resolve(key.namespace())?;
        if let Some(current) = owner.as_ref()
            && &candidate != current
        {
            return Err(StorageError::InvalidKey(
                "KV mutation batch spans multiple principal owners".to_owned(),
            ));
        }
        owner = Some(candidate);
    }
    owner.ok_or_else(|| StorageError::Serialization("KV mutation batch has no keys".to_owned()))
}

fn apply_batch_blocking<P, E>(
    blocking: &BlockingTreeStore<P, E>,
    owner: &P,
    batch: &KvMutationBatch,
) -> StorageResult<KvBatchOutcome>
where
    P: Clone + Ord + Send + Sync + 'static,
    E: KvProjectionEngine<P> + 'static,
{
    blocking.mutate(owner, |context, header| {
        let mut conditions = Vec::with_capacity(batch.conditions().len());
        let mut all_match = true;
        for condition in batch.conditions() {
            let KvBatchCondition::ValueEquals { key, expected } = condition;
            let composite = key.composite();
            let current = context.projected_get(header, &composite)?;
            let matched = current.as_deref() == expected.as_deref();
            all_match &= matched;
            conditions.push(KvConditionResult {
                key: key.clone(),
                matched,
            });
        }
        let outcome = KvBatchOutcome {
            applied: all_match,
            conditions,
        };
        if !all_match {
            return Ok((outcome, Vec::new(), false));
        }

        // The mutation projection rejects no-op replacements. Filter those
        // against this same header so a successful batch can legitimately
        // overwrite a value with itself or delete an already-missing key
        // without generating an unnecessary root.
        let mut mutations = Vec::with_capacity(batch.mutations().len());
        for mutation in batch.mutations() {
            let key = mutation.key().composite();
            let replacement = mutation.replacement().map(<[u8]>::to_vec);
            if context.projected_get(header, &key)? != replacement {
                mutations.push((key, replacement));
            }
        }
        let changed = !mutations.is_empty();
        Ok((outcome, mutations, changed))
    })
}

#[cfg(not(target_family = "wasm"))]
async fn run_blocking<T, F>(operation: F) -> StorageResult<T>
where
    T: Send + 'static,
    F: FnOnce() -> StorageResult<T> + Send + 'static,
{
    tokio::task::spawn_blocking(operation)
        .await
        .map_err(|error| {
            StorageError::Internal(format!("durable storage worker failed: {error}"))
        })?
}

#[cfg(target_family = "wasm")]
async fn run_blocking<T, F>(operation: F) -> StorageResult<T>
where
    F: FnOnce() -> StorageResult<T>,
{
    operation()
}
