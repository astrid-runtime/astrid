//! Namespace-scoped view into a [`KvStore`].
//!
//! Constructed once per capsule (`namespace = "wasm:{capsule_id}"`), this
//! is the primary API surfaced to host functions — guests never see the
//! namespace string. Provides typed JSON convenience and forwards every
//! op (including `compare_and_swap`) to the underlying store.

use std::sync::Arc;

use super::{KvStore, validate_key, validate_namespace};
use crate::error::{StorageError, StorageResult};

/// A namespace-scoped view into a [`KvStore`].
///
/// This is the primary API for WASM guests. The host creates a `ScopedKvStore`
/// per plugin with `namespace = "wasm:{plugin_id}"`, giving the guest simple
/// `get` / `set` / `delete` without ever seeing namespaces.
///
/// Also provides typed convenience via [`get_json`](Self::get_json) /
/// [`set_json`](Self::set_json).
///
/// # Example
///
/// ```rust,ignore
/// use astrid_storage::kv::{ScopedKvStore, MemoryKvStore};
/// use std::sync::Arc;
///
/// let store = Arc::new(MemoryKvStore::new());
/// let scoped = ScopedKvStore::new(store, "wasm:my-plugin")?;
///
/// scoped.set("config", b"{}".to_vec()).await?;
/// let val = scoped.get("config").await?;
/// ```
#[derive(Clone)]
pub struct ScopedKvStore {
    inner: Arc<dyn KvStore>,
    namespace: String,
}

impl std::fmt::Debug for ScopedKvStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScopedKvStore")
            .field("namespace", &self.namespace)
            .finish_non_exhaustive()
    }
}

impl ScopedKvStore {
    /// Create a scoped view into the given store for `namespace`.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::InvalidKey`] if the namespace is empty
    /// or contains null bytes.
    pub fn new(store: Arc<dyn KvStore>, namespace: impl Into<String>) -> StorageResult<Self> {
        let namespace = namespace.into();
        validate_namespace(&namespace)?;
        Ok(Self {
            inner: store,
            namespace,
        })
    }

    /// The namespace this store is scoped to.
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// Create a new scoped view sharing the same underlying store but with
    /// a different namespace. Used for per-invocation principal scoping.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::InvalidKey`] if the namespace is empty
    /// or contains null bytes.
    pub fn with_namespace(&self, namespace: impl Into<String>) -> StorageResult<Self> {
        Self::new(Arc::clone(&self.inner), namespace)
    }

    /// Get a raw byte value by key.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::InvalidKey`] if the key is empty or invalid.
    pub async fn get(&self, key: &str) -> StorageResult<Option<Vec<u8>>> {
        validate_key(key)?;
        self.inner.get(&self.namespace, key).await
    }

    /// Set a raw byte value.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::InvalidKey`] if the key is empty or invalid.
    pub async fn set(&self, key: &str, value: Vec<u8>) -> StorageResult<()> {
        validate_key(key)?;
        self.inner.set(&self.namespace, key, value).await
    }

    /// Delete a key.
    ///
    /// Returns `true` if the key existed.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::InvalidKey`] if the key is empty or invalid.
    pub async fn delete(&self, key: &str) -> StorageResult<bool> {
        validate_key(key)?;
        self.inner.delete(&self.namespace, key).await
    }

    /// Check if a key exists.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::InvalidKey`] if the key is empty or invalid.
    pub async fn exists(&self, key: &str) -> StorageResult<bool> {
        validate_key(key)?;
        self.inner.exists(&self.namespace, key).await
    }

    /// List all keys in this namespace.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying store operation fails.
    pub async fn list_keys(&self) -> StorageResult<Vec<String>> {
        self.inner.list_keys(&self.namespace).await
    }

    /// Delete all keys in this namespace.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying store operation fails.
    pub async fn clear(&self) -> StorageResult<u64> {
        self.inner.clear_namespace(&self.namespace).await
    }

    /// Atomically replace `key` with `new` iff its current value
    /// matches `expected`.
    ///
    /// See [`KvStore::compare_and_swap`] for the semantics. Returns
    /// `Ok(true)` when the swap happened, `Ok(false)` when the
    /// `expected` predicate did not match (either now or by the time
    /// the underlying transactional store committed).
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::InvalidKey`] if the key is empty or invalid.
    pub async fn compare_and_swap(
        &self,
        key: &str,
        expected: Option<&[u8]>,
        new: Vec<u8>,
    ) -> StorageResult<bool> {
        validate_key(key)?;
        self.inner
            .compare_and_swap(&self.namespace, key, expected, new)
            .await
    }

    // -- Prefix operations --

    /// List all keys matching a given prefix within this namespace.
    ///
    /// Returns an empty vec if no keys match.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying store operation fails.
    pub async fn list_keys_with_prefix(&self, prefix: &str) -> StorageResult<Vec<String>> {
        self.inner
            .list_keys_with_prefix(&self.namespace, prefix)
            .await
    }

    /// Delete all keys matching a given prefix within this namespace.
    ///
    /// Returns the number of keys deleted.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying store operation fails.
    pub async fn clear_prefix(&self, prefix: &str) -> StorageResult<u64> {
        self.inner.clear_prefix(&self.namespace, prefix).await
    }

    // -- Typed convenience (JSON) --

    /// Deserialize a JSON value from the store.
    ///
    /// Returns `None` if the key does not exist.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::Serialization`] if deserialization fails.
    pub async fn get_json<T: serde::de::DeserializeOwned>(
        &self,
        key: &str,
    ) -> StorageResult<Option<T>> {
        let bytes = self.get(key).await?;
        bytes
            .map(|b| {
                serde_json::from_slice(&b).map_err(|e| StorageError::Serialization(e.to_string()))
            })
            .transpose()
    }

    /// Serialize a value as JSON and store it.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::Serialization`] if serialization fails.
    pub async fn set_json<T: serde::Serialize>(&self, key: &str, value: &T) -> StorageResult<()> {
        let bytes =
            serde_json::to_vec(value).map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.set(key, bytes).await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::super::MemoryKvStore;
    use super::*;

    #[tokio::test]
    async fn test_scoped_get_set() {
        let store = Arc::new(MemoryKvStore::new());
        let scoped = ScopedKvStore::new(store, "wasm:plugin-a").unwrap();

        scoped.set("greeting", b"hello".to_vec()).await.unwrap();
        assert_eq!(
            scoped.get("greeting").await.unwrap(),
            Some(b"hello".to_vec())
        );
    }

    #[tokio::test]
    async fn test_scoped_isolation() {
        let store: Arc<dyn KvStore> = Arc::new(MemoryKvStore::new());
        let a = ScopedKvStore::new(Arc::clone(&store), "wasm:plugin-a").unwrap();
        let b = ScopedKvStore::new(Arc::clone(&store), "wasm:plugin-b").unwrap();

        a.set("key", b"a-value".to_vec()).await.unwrap();
        b.set("key", b"b-value".to_vec()).await.unwrap();

        assert_eq!(a.get("key").await.unwrap(), Some(b"a-value".to_vec()));
        assert_eq!(b.get("key").await.unwrap(), Some(b"b-value".to_vec()));
    }

    #[tokio::test]
    async fn test_scoped_delete_and_exists() {
        let store = Arc::new(MemoryKvStore::new());
        let scoped = ScopedKvStore::new(store, "ns").unwrap();

        assert!(!scoped.exists("k").await.unwrap());
        scoped.set("k", b"v".to_vec()).await.unwrap();
        assert!(scoped.exists("k").await.unwrap());
        assert!(scoped.delete("k").await.unwrap());
        assert!(!scoped.exists("k").await.unwrap());
    }

    #[tokio::test]
    async fn test_scoped_list_and_clear() {
        let store = Arc::new(MemoryKvStore::new());
        let scoped = ScopedKvStore::new(store, "ns").unwrap();

        scoped.set("a", b"1".to_vec()).await.unwrap();
        scoped.set("b", b"2".to_vec()).await.unwrap();

        let mut keys = scoped.list_keys().await.unwrap();
        keys.sort();
        assert_eq!(keys, vec!["a", "b"]);

        assert_eq!(scoped.clear().await.unwrap(), 2);
        assert!(scoped.list_keys().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_scoped_json_round_trip() {
        #[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
        struct Config {
            name: String,
            retries: u32,
        }

        let store = Arc::new(MemoryKvStore::new());
        let scoped = ScopedKvStore::new(store, "ns").unwrap();

        let cfg = Config {
            name: "my-plugin".into(),
            retries: 3,
        };
        scoped.set_json("config", &cfg).await.unwrap();

        let loaded: Config = scoped.get_json("config").await.unwrap().unwrap();
        assert_eq!(loaded, cfg);
    }

    #[tokio::test]
    async fn test_scoped_json_missing_returns_none() {
        let store = Arc::new(MemoryKvStore::new());
        let scoped = ScopedKvStore::new(store, "ns").unwrap();

        let val: Option<String> = scoped.get_json("missing").await.unwrap();
        assert!(val.is_none());
    }

    #[tokio::test]
    async fn test_scoped_rejects_empty_key() {
        let store = Arc::new(MemoryKvStore::new());
        let scoped = ScopedKvStore::new(store, "ns").unwrap();
        assert!(scoped.get("").await.is_err());
    }

    #[test]
    fn test_scoped_rejects_empty_namespace() {
        let store = Arc::new(MemoryKvStore::new());
        assert!(ScopedKvStore::new(store, "").is_err());
    }

    // -- ScopedKvStore prefix operations --

    #[tokio::test]
    async fn test_scoped_list_keys_with_prefix() {
        let store = Arc::new(MemoryKvStore::new());
        let scoped = ScopedKvStore::new(store, "ns").unwrap();

        scoped.set("react.turn.abc", b"1".to_vec()).await.unwrap();
        scoped.set("react.turn.def", b"2".to_vec()).await.unwrap();
        scoped
            .set("react.req2sess.xyz", b"3".to_vec())
            .await
            .unwrap();
        scoped.set("session.data.abc", b"4".to_vec()).await.unwrap();

        let mut keys = scoped.list_keys_with_prefix("react.turn.").await.unwrap();
        keys.sort();
        assert_eq!(keys, vec!["react.turn.abc", "react.turn.def"]);

        let keys = scoped
            .list_keys_with_prefix("react.req2sess.")
            .await
            .unwrap();
        assert_eq!(keys, vec!["react.req2sess.xyz"]);

        let keys = scoped.list_keys_with_prefix("session.").await.unwrap();
        assert_eq!(keys, vec!["session.data.abc"]);
    }

    #[tokio::test]
    async fn test_scoped_clear_prefix() {
        let store = Arc::new(MemoryKvStore::new());
        let scoped = ScopedKvStore::new(store, "ns").unwrap();

        scoped.set("react.turn.a", b"1".to_vec()).await.unwrap();
        scoped.set("react.turn.b", b"2".to_vec()).await.unwrap();
        scoped.set("session.data.a", b"3".to_vec()).await.unwrap();

        let cleared = scoped.clear_prefix("react.turn.").await.unwrap();
        assert_eq!(cleared, 2);

        // Session data untouched
        assert!(scoped.exists("session.data.a").await.unwrap());
        // React turn state cleared
        assert!(!scoped.exists("react.turn.a").await.unwrap());
        assert!(!scoped.exists("react.turn.b").await.unwrap());
    }

    #[tokio::test]
    async fn test_scoped_clear_prefix_no_matches() {
        let store = Arc::new(MemoryKvStore::new());
        let scoped = ScopedKvStore::new(store, "ns").unwrap();

        scoped.set("other.key", b"1".to_vec()).await.unwrap();

        let cleared = scoped.clear_prefix("react.turn.").await.unwrap();
        assert_eq!(cleared, 0);
        assert!(scoped.exists("other.key").await.unwrap());
    }

    #[tokio::test]
    async fn test_scoped_list_keys_empty_prefix_returns_all() {
        let store = Arc::new(MemoryKvStore::new());
        let scoped = ScopedKvStore::new(store, "ns").unwrap();

        scoped.set("a", b"1".to_vec()).await.unwrap();
        scoped.set("b", b"2".to_vec()).await.unwrap();
        scoped.set("c", b"3".to_vec()).await.unwrap();

        // Empty prefix matches all keys (every string starts with "")
        let mut keys = scoped.list_keys_with_prefix("").await.unwrap();
        keys.sort();
        assert_eq!(keys, vec!["a", "b", "c"]);
    }

    #[tokio::test]
    async fn test_scoped_clear_prefix_empty_clears_all() {
        let store = Arc::new(MemoryKvStore::new());
        let scoped = ScopedKvStore::new(store, "ns").unwrap();

        scoped.set("a", b"1".to_vec()).await.unwrap();
        scoped.set("b", b"2".to_vec()).await.unwrap();

        // Empty prefix matches all keys
        let cleared = scoped.clear_prefix("").await.unwrap();
        assert_eq!(cleared, 2);
        assert!(scoped.list_keys().await.unwrap().is_empty());
    }

    // -- compare_and_swap --

    #[tokio::test]
    async fn scoped_cas_forwards_to_inner() {
        let store = Arc::new(MemoryKvStore::new());
        let scoped = ScopedKvStore::new(store, "wasm:plugin-x").unwrap();

        // None → present: insert-if-absent path.
        assert!(
            scoped
                .compare_and_swap("counter", None, b"1".to_vec())
                .await
                .unwrap()
        );
        // None → present: now occupied, fails.
        assert!(
            !scoped
                .compare_and_swap("counter", None, b"2".to_vec())
                .await
                .unwrap()
        );
        // Some(matching) → success.
        assert!(
            scoped
                .compare_and_swap("counter", Some(b"1"), b"2".to_vec())
                .await
                .unwrap()
        );
        // Some(wrong) → failure, value preserved.
        assert!(
            !scoped
                .compare_and_swap("counter", Some(b"99"), b"3".to_vec())
                .await
                .unwrap()
        );
        assert_eq!(scoped.get("counter").await.unwrap(), Some(b"2".to_vec()));
    }

    #[tokio::test]
    async fn scoped_cas_namespace_isolation() {
        let store: Arc<dyn KvStore> = Arc::new(MemoryKvStore::new());
        let a = ScopedKvStore::new(Arc::clone(&store), "wasm:a").unwrap();
        let b = ScopedKvStore::new(Arc::clone(&store), "wasm:b").unwrap();

        // Inserting "k" via `a` must not interfere with `b`'s view.
        assert!(
            a.compare_and_swap("k", None, b"a-1".to_vec())
                .await
                .unwrap()
        );
        // `b` still sees the key as absent.
        assert!(
            b.compare_and_swap("k", None, b"b-1".to_vec())
                .await
                .unwrap()
        );
        assert_eq!(a.get("k").await.unwrap(), Some(b"a-1".to_vec()));
        assert_eq!(b.get("k").await.unwrap(), Some(b"b-1".to_vec()));
    }

    #[tokio::test]
    async fn scoped_cas_rejects_empty_key() {
        let store = Arc::new(MemoryKvStore::new());
        let scoped = ScopedKvStore::new(store, "ns").unwrap();
        assert!(
            scoped
                .compare_and_swap("", None, b"v".to_vec())
                .await
                .is_err()
        );
    }
}
