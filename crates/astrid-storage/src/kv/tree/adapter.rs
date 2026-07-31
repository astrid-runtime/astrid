//! Async adapter for the blocking persistent-tree implementation.
//!
//! Native durable I/O and engine mutex acquisition run on Tokio's blocking
//! pool. The WASM build has no blocking executor and delegates inline to its
//! host-backed engine.

use astrid_storage_engine::KvProjectionEngine;
use async_trait::async_trait;

use super::{TreeKvStore, map_engine};
use crate::error::{StorageError, StorageResult};
use crate::kv::principal::KvPrincipalResolver;
use crate::kv::{
    KvStore, composite_key, namespace_range_end, namespace_range_start, prefix_range_end,
    validate_key, validate_namespace, validate_prefix,
};

#[async_trait]
impl<P, I, R, E> KvStore for TreeKvStore<P, I, R, E>
where
    P: Clone + Ord + Send + Sync + 'static,
    I: Send + Sync + 'static,
    E: KvProjectionEngine<P> + 'static,
    R: KvPrincipalResolver<P> + Send + Sync + 'static,
{
    async fn close(&self) -> StorageResult<()> {
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
        let blocking = self.blocking_store();
        run_blocking(move || {
            blocking.read(owner, |context, header| {
                context.projected_get(header, &composite)
            })
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
