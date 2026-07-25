//! `KvStore` compatibility adapter over the principal-state engine.
//!
//! Namespace ownership is injected instead of parsed by the storage layer.
//! The caller that possesses the host-stamped principal context remains
//! responsible for mapping an existing namespace onto its domain-bearing
//! principal identifier.

use std::fmt;
use std::marker::PhantomData;
use std::sync::Arc;

use astrid_storage_engine::{
    InMemoryEngine, KvProjectionEngine, KvProjectionError, KvState, commit_kv_with_engine,
    kv_snapshot_with_engine,
};
use astrid_storage_model::ModelError;
use async_trait::async_trait;

use super::{KvStore, validate_key, validate_namespace, validate_prefix};
use crate::error::{StorageError, StorageResult};

/// Resolves an existing KV namespace to the principal that owns its state.
///
/// Implementations belong at an authority-aware integration boundary. The
/// adapter deliberately does not infer a principal by splitting an arbitrary
/// namespace string.
pub trait KvPrincipalResolver<P>: Send + Sync {
    /// Resolve the principal that owns `namespace`.
    ///
    /// System namespaces should resolve to an explicit domain value distinct
    /// from every user principal. Otherwise-unowned namespaces should return
    /// [`StorageError::InvalidKey`] rather than being silently assigned.
    ///
    /// # Errors
    ///
    /// Returns a stable storage error when the namespace is invalid, unowned,
    /// or cannot be resolved at the caller's authority boundary.
    fn resolve(&self, namespace: &str) -> StorageResult<P>;
}

impl<P, F> KvPrincipalResolver<P> for F
where
    F: Fn(&str) -> StorageResult<P> + Send + Sync,
{
    fn resolve(&self, namespace: &str) -> StorageResult<P> {
        self(namespace)
    }
}

/// Resolves the current stable storage ceiling for one state owner.
///
/// Quota policy remains outside the engine because the authoritative value can
/// change while the process is running. `None` means that the owner is exempt
/// from a principal quota, as is appropriate for kernel-owned system state.
/// A projection may charge canonical principal-controlled metadata in addition
/// to user-visible value bytes so zero-length values cannot bypass the ceiling.
pub trait KvQuotaResolver<P>: Send + Sync {
    /// Return the owner's current stable byte ceiling.
    ///
    /// # Errors
    ///
    /// Returns a storage error when policy cannot be resolved. Mutations fail
    /// closed in that case.
    fn max_logical_bytes(&self, principal: &P) -> StorageResult<Option<u64>>;
}

impl<P, F> KvQuotaResolver<P> for F
where
    F: Fn(&P) -> StorageResult<Option<u64>> + Send + Sync,
{
    fn max_logical_bytes(&self, principal: &P) -> StorageResult<Option<u64>> {
        self(principal)
    }
}

/// Existing [`KvStore`] behavior projected onto atomic principal roots.
///
/// Each successful mutation replaces one principal's typed `kv` component
/// using exact root compare-and-swap. Root conflicts are retried from a fresh
/// snapshot, so concurrent mutations do not lose updates. No persistent
/// encoding, production digest, and migration policy remain selected by the
/// native composition root. Quota policy is optionally injected and resolved
/// on every mutation so runtime profile invalidation takes effect immediately.
pub struct PrincipalKvStore<P: Ord, I, R, E = InMemoryEngine<P, I>> {
    engine: Arc<E>,
    resolver: R,
    quota: Option<Arc<dyn KvQuotaResolver<P>>>,
    marker: PhantomData<fn() -> (P, I)>,
}

impl<P: Ord, I, R> PrincipalKvStore<P, I, R> {
    /// Construct an additive compatibility adapter.
    #[must_use]
    pub const fn new(engine: Arc<InMemoryEngine<P, I>>, resolver: R) -> Self {
        Self {
            engine,
            resolver,
            quota: None,
            marker: PhantomData,
        }
    }
}

impl<P: Ord, I, R, E> PrincipalKvStore<P, I, R, E> {
    /// Construct an adapter over any engine implementing the typed projection
    /// contract.
    #[must_use]
    pub const fn from_engine(engine: Arc<E>, resolver: R) -> Self {
        Self {
            engine,
            resolver,
            quota: None,
            marker: PhantomData,
        }
    }

    /// Construct an adapter with live logical-byte quota policy.
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

impl<P: Ord, I, R, E> fmt::Debug for PrincipalKvStore<P, I, R, E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrincipalKvStore")
            .finish_non_exhaustive()
    }
}

impl<P, I, R, E> PrincipalKvStore<P, I, R, E>
where
    P: Clone + Ord + Send + Sync,
    E: KvProjectionEngine<P>,
    R: KvPrincipalResolver<P>,
{
    fn snapshot(&self, principal: &P) -> StorageResult<astrid_storage_engine::KvStateSnapshot<P>> {
        kv_snapshot_with_engine(self.engine.as_ref(), principal.clone())
            .map_err(|error| map_projection_error(&error))
    }

    fn update<T, F>(&self, principal: &P, mut update: F) -> StorageResult<T>
    where
        F: FnMut(&mut KvState) -> StorageResult<(T, bool)>,
    {
        loop {
            let mut snapshot = self.snapshot(principal)?;
            let before = snapshot
                .state()
                .logical_bytes()
                .map_err(|error| map_projection_error(&error))?;
            let (result, changed) = update(snapshot.state_mut())?;
            if !changed {
                return Ok(result);
            }
            if let Some(quota) = &self.quota
                && let Some(limit) = quota.max_logical_bytes(principal)?
            {
                let used = snapshot
                    .state()
                    .logical_bytes()
                    .map_err(|error| map_projection_error(&error))?;
                if used > limit && used > before {
                    return Err(StorageError::QuotaExceeded { used, limit });
                }
            }
            match commit_kv_with_engine(self.engine.as_ref(), snapshot) {
                Ok(_) => return Ok(result),
                Err(KvProjectionError::Model(ModelError::RootConflict { .. })) => {},
                Err(error) => return Err(map_projection_error(&error)),
            }
        }
    }
}

#[async_trait]
impl<P, I, R, E> KvStore for PrincipalKvStore<P, I, R, E>
where
    P: Clone + Ord + Send + Sync + 'static,
    I: Send + Sync + 'static,
    E: KvProjectionEngine<P> + 'static,
    R: KvPrincipalResolver<P> + Send + Sync + 'static,
{
    async fn close(&self) -> StorageResult<()> {
        self.engine
            .flush_kv()
            .map_err(|error| map_projection_error(&error))
    }

    async fn get(&self, namespace: &str, key: &str) -> StorageResult<Option<Vec<u8>>> {
        validate_namespace(namespace)?;
        validate_key(key)?;
        let principal = self.resolver.resolve(namespace)?;
        Ok(self
            .snapshot(&principal)?
            .state()
            .get(namespace, key)
            .map(<[u8]>::to_vec))
    }

    async fn set(&self, namespace: &str, key: &str, value: Vec<u8>) -> StorageResult<()> {
        validate_namespace(namespace)?;
        validate_key(key)?;
        let principal = self.resolver.resolve(namespace)?;
        self.update(&principal, |state| {
            if state.get(namespace, key) == Some(value.as_slice()) {
                return Ok(((), false));
            }
            state
                .set(namespace.to_owned(), key.to_owned(), value.clone())
                .map_err(|error| map_projection_error(&error))?;
            Ok(((), true))
        })
    }

    async fn delete(&self, namespace: &str, key: &str) -> StorageResult<bool> {
        validate_namespace(namespace)?;
        validate_key(key)?;
        let principal = self.resolver.resolve(namespace)?;
        self.update(&principal, |state| {
            let removed = state.delete(namespace, key).is_some();
            Ok((removed, removed))
        })
    }

    async fn exists(&self, namespace: &str, key: &str) -> StorageResult<bool> {
        validate_namespace(namespace)?;
        validate_key(key)?;
        let principal = self.resolver.resolve(namespace)?;
        Ok(self
            .snapshot(&principal)?
            .state()
            .contains_key(namespace, key))
    }

    async fn list_keys(&self, namespace: &str) -> StorageResult<Vec<String>> {
        validate_namespace(namespace)?;
        let principal = self.resolver.resolve(namespace)?;
        Ok(self.snapshot(&principal)?.state().keys(namespace))
    }

    async fn list_keys_with_prefix(
        &self,
        namespace: &str,
        prefix: &str,
    ) -> StorageResult<Vec<String>> {
        validate_namespace(namespace)?;
        validate_prefix(prefix)?;
        let principal = self.resolver.resolve(namespace)?;
        Ok(self
            .snapshot(&principal)?
            .state()
            .keys_with_prefix(namespace, prefix))
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
        let principal = self.resolver.resolve(namespace)?;
        self.update(&principal, |state| {
            if state.get(namespace, key) != expected {
                return Ok((false, false));
            }
            if state.get(namespace, key) == Some(new.as_slice()) {
                return Ok((true, false));
            }
            state
                .set(namespace.to_owned(), key.to_owned(), new.clone())
                .map_err(|error| map_projection_error(&error))?;
            Ok((true, true))
        })
    }

    async fn clear_namespace(&self, namespace: &str) -> StorageResult<u64> {
        validate_namespace(namespace)?;
        let principal = self.resolver.resolve(namespace)?;
        self.update(&principal, |state| {
            let count = state.clear_namespace(namespace);
            Ok((count, count != 0))
        })
    }

    async fn clear_prefix(&self, namespace: &str, prefix: &str) -> StorageResult<u64> {
        validate_namespace(namespace)?;
        validate_prefix(prefix)?;
        let principal = self.resolver.resolve(namespace)?;
        self.update(&principal, |state| {
            let count = state.clear_prefix(namespace, prefix);
            Ok((count, count != 0))
        })
    }
}

fn map_projection_error(error: &KvProjectionError) -> StorageError {
    StorageError::Internal(format!("principal KV projection: {error}"))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use astrid_storage_engine::InMemoryEngine;
    use astrid_storage_model::{
        ObjectClass, ObjectId, ObjectIdentity, ObjectRecord, ReferenceKind,
    };

    use super::*;
    use crate::MemoryKvStore;

    const NAMESPACES: [&str; 3] = [
        "alice:capsule:build",
        "alice:capsule:shell",
        "bob:capsule:build",
    ];
    const KEYS: [&str; 5] = ["a", "alpha", "build.cache", "build.meta", "z"];

    #[derive(Clone, Copy, Debug)]
    struct TestIdentity;

    impl ObjectIdentity for TestIdentity {
        fn identify(&self, record: &ObjectRecord) -> ObjectId {
            let mut hasher =
                blake3::Hasher::new_derive_key("astrid storage principal KV adapter test v1");
            hasher.update(&record.kind().code().to_le_bytes());
            hasher.update(&record.format_version().get().to_le_bytes());
            hasher.update(&(record.canonical_bytes().len() as u128).to_le_bytes());
            hasher.update(record.canonical_bytes());
            hasher.update(&record.logical_bytes().to_le_bytes());
            hasher.update(&[match record.class() {
                ObjectClass::Data => 0,
                ObjectClass::Metadata => 1,
            }]);
            hasher.update(&(record.references().len() as u128).to_le_bytes());
            for reference in record.references() {
                hasher.update(&(reference.label().as_bytes().len() as u128).to_le_bytes());
                hasher.update(reference.label().as_bytes());
                hasher.update(reference.target().as_bytes());
                hasher.update(&[match reference.kind() {
                    ReferenceKind::Owns => 0,
                    ReferenceKind::Evidence => 1,
                    ReferenceKind::Lineage => 2,
                    ReferenceKind::Derived => 3,
                }]);
            }
            ObjectId::new(*hasher.finalize().as_bytes())
        }
    }

    #[derive(Clone, Copy, Debug)]
    struct TestResolver;

    impl KvPrincipalResolver<String> for TestResolver {
        fn resolve(&self, namespace: &str) -> StorageResult<String> {
            namespace
                .split_once(":capsule:")
                .filter(|(principal, capsule)| !principal.is_empty() && !capsule.is_empty())
                .map(|(principal, _)| principal.to_owned())
                .ok_or_else(|| {
                    StorageError::InvalidKey(
                        "namespace is not a host-stamped principal capsule scope".to_owned(),
                    )
                })
        }
    }

    type TestAdapter = PrincipalKvStore<String, TestIdentity, TestResolver>;

    fn adapter() -> (Arc<InMemoryEngine<String, TestIdentity>>, Arc<TestAdapter>) {
        let engine = Arc::new(InMemoryEngine::new(TestIdentity));
        let adapter = Arc::new(PrincipalKvStore::new(Arc::clone(&engine), TestResolver));
        (engine, adapter)
    }

    #[derive(Clone, Debug)]
    enum Action {
        Set {
            namespace: &'static str,
            key: &'static str,
            value: Vec<u8>,
        },
        Get {
            namespace: &'static str,
            key: &'static str,
        },
        Delete {
            namespace: &'static str,
            key: &'static str,
        },
        Exists {
            namespace: &'static str,
            key: &'static str,
        },
        List {
            namespace: &'static str,
        },
        ListPrefix {
            namespace: &'static str,
            prefix: &'static str,
        },
        CompareAndSwap {
            namespace: &'static str,
            key: &'static str,
            expected: Option<Vec<u8>>,
            new: Vec<u8>,
        },
        ClearPrefix {
            namespace: &'static str,
            prefix: &'static str,
        },
        ClearNamespace {
            namespace: &'static str,
        },
    }

    #[derive(Debug, PartialEq, Eq)]
    enum Observation {
        Unit,
        Value(Option<Vec<u8>>),
        Bool(bool),
        Keys(Vec<String>),
        Count(u64),
    }

    async fn apply(store: &dyn KvStore, action: &Action) -> StorageResult<Observation> {
        match action {
            Action::Set {
                namespace,
                key,
                value,
            } => {
                store.set(namespace, key, value.clone()).await?;
                Ok(Observation::Unit)
            },
            Action::Get { namespace, key } => {
                Ok(Observation::Value(store.get(namespace, key).await?))
            },
            Action::Delete { namespace, key } => {
                Ok(Observation::Bool(store.delete(namespace, key).await?))
            },
            Action::Exists { namespace, key } => {
                Ok(Observation::Bool(store.exists(namespace, key).await?))
            },
            Action::List { namespace } => {
                let mut keys = store.list_keys(namespace).await?;
                keys.sort();
                Ok(Observation::Keys(keys))
            },
            Action::ListPrefix { namespace, prefix } => {
                let mut keys = store.list_keys_with_prefix(namespace, prefix).await?;
                keys.sort();
                Ok(Observation::Keys(keys))
            },
            Action::CompareAndSwap {
                namespace,
                key,
                expected,
                new,
            } => Ok(Observation::Bool(
                store
                    .compare_and_swap(namespace, key, expected.as_deref(), new.clone())
                    .await?,
            )),
            Action::ClearPrefix { namespace, prefix } => Ok(Observation::Count(
                store.clear_prefix(namespace, prefix).await?,
            )),
            Action::ClearNamespace { namespace } => {
                Ok(Observation::Count(store.clear_namespace(namespace).await?))
            },
        }
    }

    async fn assert_same_state(left: &dyn KvStore, right: &dyn KvStore) {
        for namespace in NAMESPACES {
            let mut left_keys = left.list_keys(namespace).await.unwrap();
            let mut right_keys = right.list_keys(namespace).await.unwrap();
            left_keys.sort();
            right_keys.sort();
            assert_eq!(left_keys, right_keys, "namespace {namespace}");
            for key in left_keys {
                assert_eq!(
                    left.get(namespace, &key).await.unwrap(),
                    right.get(namespace, &key).await.unwrap(),
                    "namespace {namespace}, key {key}"
                );
            }
        }
    }

    fn next(seed: &mut u64) -> u64 {
        *seed ^= *seed << 13;
        *seed ^= *seed >> 7;
        *seed ^= *seed << 17;
        *seed
    }

    fn bounded_index(value: u64, length: usize) -> usize {
        let modulus = u64::try_from(length).unwrap();
        usize::try_from(value.checked_rem(modulus).unwrap()).unwrap()
    }

    fn generated_action(seed: &mut u64) -> Action {
        let bits = next(seed);
        let namespace = NAMESPACES[bounded_index(bits, NAMESPACES.len())];
        let key = KEYS[bounded_index(bits >> 8, KEYS.len())];
        let prefix = match (bits >> 16) % 3 {
            0 => "",
            1 => "build.",
            _ => "a",
        };
        let value = if bits & (1 << 20) == 0 {
            Vec::new()
        } else {
            bits.to_le_bytes()[..=bounded_index(bits, 8)].to_vec()
        };

        match (bits >> 24) % 9 {
            0 => Action::Set {
                namespace,
                key,
                value,
            },
            1 => Action::Get { namespace, key },
            2 => Action::Delete { namespace, key },
            3 => Action::Exists { namespace, key },
            4 => Action::List { namespace },
            5 => Action::ListPrefix { namespace, prefix },
            6 => Action::CompareAndSwap {
                namespace,
                key,
                expected: match (bits >> 32) % 3 {
                    0 => None,
                    1 => Some(Vec::new()),
                    _ => Some((bits.rotate_left(9)).to_le_bytes()[..4].to_vec()),
                },
                new: value,
            },
            7 => Action::ClearPrefix { namespace, prefix },
            _ => Action::ClearNamespace { namespace },
        }
    }

    async fn run_differential_trace(left: &dyn KvStore, right: &dyn KvStore, steps: usize) {
        let mut seed = 0x4b56_5354_4f52_4531;
        for step in 0..steps {
            let action = generated_action(&mut seed);
            let left_result = apply(left, &action).await.unwrap();
            let right_result = apply(right, &action).await.unwrap();
            assert_eq!(
                left_result, right_result,
                "observation diverged at step {step}: {action:?}"
            );
            assert_same_state(left, right).await;
        }
    }

    #[tokio::test]
    async fn principal_resolver_is_authoritative_and_namespaces_share_one_root() {
        let (engine, store) = adapter();
        store
            .set("alice:capsule:build", "a", b"one".to_vec())
            .await
            .unwrap();
        store
            .set("alice:capsule:shell", "b", b"two".to_vec())
            .await
            .unwrap();
        store
            .set("bob:capsule:build", "a", b"bob".to_vec())
            .await
            .unwrap();

        assert_eq!(
            engine.root(&"alice".to_owned()).unwrap().generation.get(),
            1
        );
        assert_eq!(engine.root(&"bob".to_owned()).unwrap().generation.get(), 0);
        assert!(matches!(
            store.get("system:identity", "user").await,
            Err(StorageError::InvalidKey(_))
        ));
    }

    #[tokio::test]
    async fn generated_trace_matches_memory_store() {
        let memory = MemoryKvStore::new();
        let (_, principal) = adapter();

        run_differential_trace(&memory, principal.as_ref(), 2_048).await;
    }

    #[cfg(feature = "legacy-surrealkv")]
    #[tokio::test]
    async fn generated_trace_matches_surreal_kv() {
        let directory = tempfile::tempdir().unwrap();
        let surreal = crate::SurrealKvStore::open(directory.path()).unwrap();
        let (_, principal) = adapter();

        run_differential_trace(&surreal, principal.as_ref(), 1_024).await;
        surreal.close().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_insert_if_absent_has_one_winner() {
        let (_, store) = adapter();
        let barrier = Arc::new(tokio::sync::Barrier::new(17));
        let mut handles = Vec::new();
        for value in 0_u8..16 {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            handles.push(tokio::spawn(async move {
                barrier.wait().await;
                store
                    .compare_and_swap("alice:capsule:build", "winner", None, vec![value])
                    .await
                    .unwrap()
            }));
        }
        barrier.wait().await;

        let mut winners = 0;
        for handle in handles {
            winners += usize::from(handle.await.unwrap());
        }
        assert_eq!(winners, 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_distinct_writes_do_not_lose_updates() {
        let (_, store) = adapter();
        let barrier = Arc::new(tokio::sync::Barrier::new(17));
        let mut handles = Vec::new();
        for value in 0_u8..16 {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            handles.push(tokio::spawn(async move {
                barrier.wait().await;
                store
                    .set(
                        "alice:capsule:build",
                        &format!("key-{value:02}"),
                        vec![value],
                    )
                    .await
                    .unwrap();
            }));
        }
        barrier.wait().await;
        for handle in handles {
            handle.await.unwrap();
        }

        let keys = store.list_keys("alice:capsule:build").await.unwrap();
        assert_eq!(keys.len(), 16);
        for value in 0_u8..16 {
            assert_eq!(
                store
                    .get("alice:capsule:build", &format!("key-{value:02}"))
                    .await
                    .unwrap(),
                Some(vec![value])
            );
        }
    }

    #[tokio::test]
    async fn all_backends_reject_invalid_raw_names_and_accept_empty_values() {
        let memory = MemoryKvStore::new();
        let (_, principal) = adapter();
        let stores: [&dyn KvStore; 2] = [&memory, principal.as_ref()];

        for store in stores {
            assert!(matches!(
                store.set("", "key", Vec::new()).await,
                Err(StorageError::InvalidKey(_))
            ));
            assert!(matches!(
                store.set("namespace", "", Vec::new()).await,
                Err(StorageError::InvalidKey(_))
            ));
            assert!(matches!(
                store
                    .list_keys_with_prefix("namespace", "bad\0prefix")
                    .await,
                Err(StorageError::InvalidKey(_))
            ));
            store
                .set("alice:capsule:build", "empty", Vec::new())
                .await
                .unwrap();
            assert_eq!(
                store.get("alice:capsule:build", "empty").await.unwrap(),
                Some(Vec::new())
            );
        }
    }

    #[cfg(feature = "legacy-surrealkv")]
    #[tokio::test]
    async fn surreal_kv_rejects_the_same_invalid_raw_names() {
        let directory = tempfile::tempdir().unwrap();
        let surreal = crate::SurrealKvStore::open(directory.path()).unwrap();

        assert!(matches!(
            surreal.set("", "key", Vec::new()).await,
            Err(StorageError::InvalidKey(_))
        ));
        assert!(matches!(
            surreal.set("namespace", "", Vec::new()).await,
            Err(StorageError::InvalidKey(_))
        ));
        assert!(matches!(
            surreal
                .list_keys_with_prefix("namespace", "bad\0prefix")
                .await,
            Err(StorageError::InvalidKey(_))
        ));
        surreal.close().await.unwrap();
    }
}
