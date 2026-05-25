//! Persistent `KvStore` backed by `SurrealKV`.
//!
//! All operations use `SurrealKV` transactions. The store is MVCC, so
//! `compare_and_swap` runs as a single read-then-conditional-write
//! transaction: a concurrent commit that mutates the same key
//! invalidates the comparison and the swap returns `Ok(false)` rather
//! than overwriting a value the caller didn't expect.

use async_trait::async_trait;

use super::{
    KvStore, composite_key, namespace_range_end, namespace_range_start, prefix_range_end,
    validate_key, validate_namespace, validate_prefix,
};
use crate::error::{StorageError, StorageResult};

/// Persistent key-value store backed by `SurrealKV`.
///
/// ACID-compliant, versioned, embedded LSM-tree storage.
/// All operations use transactions internally.
///
/// # Example
///
/// ```rust,ignore
/// use astrid_storage::kv::SurrealKvStore;
///
/// let store = SurrealKvStore::open("./data/kv")?;
/// store.set("wasm:my-plugin", "config", b"{}".to_vec()).await?;
/// ```
pub struct SurrealKvStore {
    tree: surrealkv::Tree,
    /// Serializes `compare_and_swap` calls.
    ///
    /// `SurrealKV`'s `Transaction::validate_write_conflicts` reads the
    /// memtable *before* `Core::commit` acquires its write mutex.
    /// Concurrent CAS calls on the same key can therefore both pass
    /// validation (memtable still empty) before either commit writes,
    /// and both succeed — which violates the CAS contract.
    ///
    /// We close that TOCTOU window with a backend-level mutex held
    /// across read+conditional-write+commit. CAS is a rare operation
    /// (no current capsule hot-loops on it), so a single global lock
    /// is acceptable; if contention becomes a problem we can shard
    /// by key prefix without changing the API.
    cas_lock: tokio::sync::Mutex<()>,
}

impl std::fmt::Debug for SurrealKvStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SurrealKvStore").finish_non_exhaustive()
    }
}

impl SurrealKvStore {
    /// Open a persistent KV store at the given directory path.
    ///
    /// Creates the directory if it does not exist.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::Connection`] if the store cannot be opened.
    pub fn open(path: impl AsRef<std::path::Path>) -> StorageResult<Self> {
        let tree = surrealkv::TreeBuilder::new()
            .with_path(path.as_ref().to_path_buf())
            .build()
            .map_err(|e| StorageError::Connection(e.to_string()))?;
        Ok(Self {
            tree,
            cas_lock: tokio::sync::Mutex::new(()),
        })
    }

    /// Open a persistent KV store with custom options.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::Connection`] if the store cannot be opened.
    pub fn open_with_options(opts: surrealkv::Options) -> StorageResult<Self> {
        let tree = surrealkv::TreeBuilder::with_options(opts)
            .build()
            .map_err(|e| StorageError::Connection(e.to_string()))?;
        Ok(Self {
            tree,
            cas_lock: tokio::sync::Mutex::new(()),
        })
    }

    /// Close the store, flushing any pending writes.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::Internal`] if the flush fails.
    pub async fn close(&self) -> StorageResult<()> {
        self.tree
            .close()
            .await
            .map_err(|e| StorageError::Internal(e.to_string()))
    }
}

fn map_kv_err(e: &surrealkv::Error) -> StorageError {
    StorageError::Internal(e.to_string())
}

/// Returns `true` for surrealkv errors that mean "a concurrent commit
/// changed the key between this transaction's snapshot and its commit".
/// We translate these to `Ok(false)` for `compare_and_swap` so callers
/// see "your expected value is stale" rather than a generic error.
///
/// Matches the explicit `surrealkv::Error` variants rather than string
/// scraping so a future error-message rewording in surrealkv can't
/// silently make us return spurious `Ok(true)` results.
fn is_transaction_conflict(e: &surrealkv::Error) -> bool {
    matches!(
        e,
        surrealkv::Error::TransactionWriteConflict | surrealkv::Error::TransactionRetry
    )
}

#[async_trait]
impl KvStore for SurrealKvStore {
    async fn get(&self, namespace: &str, key: &str) -> StorageResult<Option<Vec<u8>>> {
        validate_namespace(namespace)?;
        validate_key(key)?;
        let ck = composite_key(namespace, key);
        let tx = self
            .tree
            .begin_with_mode(surrealkv::Mode::ReadOnly)
            .map_err(|ref e| map_kv_err(e))?;
        tx.get(&ck).map_err(|ref e| map_kv_err(e))
    }

    async fn set(&self, namespace: &str, key: &str, value: Vec<u8>) -> StorageResult<()> {
        validate_namespace(namespace)?;
        validate_key(key)?;
        let ck = composite_key(namespace, key);
        let mut tx = self.tree.begin().map_err(|ref e| map_kv_err(e))?;
        tx.set(&ck, &value).map_err(|ref e| map_kv_err(e))?;
        tx.commit().await.map_err(|ref e| map_kv_err(e))
    }

    async fn delete(&self, namespace: &str, key: &str) -> StorageResult<bool> {
        validate_namespace(namespace)?;
        validate_key(key)?;
        let ck = composite_key(namespace, key);
        let mut tx = self.tree.begin().map_err(|ref e| map_kv_err(e))?;
        let existed = tx.get(&ck).map_err(|ref e| map_kv_err(e))?.is_some();
        if existed {
            tx.delete(&ck).map_err(|ref e| map_kv_err(e))?;
            tx.commit().await.map_err(|ref e| map_kv_err(e))?;
        }
        Ok(existed)
    }

    async fn exists(&self, namespace: &str, key: &str) -> StorageResult<bool> {
        validate_namespace(namespace)?;
        validate_key(key)?;
        let ck = composite_key(namespace, key);
        let tx = self
            .tree
            .begin_with_mode(surrealkv::Mode::ReadOnly)
            .map_err(|ref e| map_kv_err(e))?;
        Ok(tx.get(&ck).map_err(|ref e| map_kv_err(e))?.is_some())
    }

    async fn list_keys(&self, namespace: &str) -> StorageResult<Vec<String>> {
        validate_namespace(namespace)?;
        let start = namespace_range_start(namespace);
        let end = namespace_range_end(namespace);
        let prefix_len = namespace.len().saturating_add(1); // namespace + \0

        let tx = self
            .tree
            .begin_with_mode(surrealkv::Mode::ReadOnly)
            .map_err(|ref e| map_kv_err(e))?;
        let mut iter = tx.range(&start, &end).map_err(|ref e| map_kv_err(e))?;
        iter.seek_first().map_err(|ref e| map_kv_err(e))?;

        let mut keys = Vec::new();
        while iter.valid() {
            let raw_key = iter.key();
            if raw_key.len() > prefix_len
                && let Ok(key_str) = std::str::from_utf8(&raw_key[prefix_len..])
            {
                keys.push(key_str.to_string());
            }
            iter.next().map_err(|ref e| map_kv_err(e))?;
        }
        Ok(keys)
    }

    async fn list_keys_with_prefix(
        &self,
        namespace: &str,
        prefix: &str,
    ) -> StorageResult<Vec<String>> {
        validate_namespace(namespace)?;
        let start = composite_key(namespace, prefix);
        let end = prefix_range_end(namespace, prefix);
        let prefix_len = namespace.len().saturating_add(1); // namespace + \0

        let tx = self
            .tree
            .begin_with_mode(surrealkv::Mode::ReadOnly)
            .map_err(|ref e| map_kv_err(e))?;
        let mut iter = tx.range(&start, &end).map_err(|ref e| map_kv_err(e))?;
        iter.seek_first().map_err(|ref e| map_kv_err(e))?;

        let mut keys = Vec::new();
        while iter.valid() {
            let raw_key = iter.key();
            if raw_key.len() > prefix_len
                && let Ok(key_str) = std::str::from_utf8(&raw_key[prefix_len..])
            {
                keys.push(key_str.to_string());
            }
            iter.next().map_err(|ref e| map_kv_err(e))?;
        }
        Ok(keys)
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
        let ck = composite_key(namespace, key);

        // Serialize CAS across the whole store. See `cas_lock`'s
        // docstring for why surrealkv's transaction conflict
        // detection alone isn't sufficient.
        let _guard = self.cas_lock.lock().await;

        let mut tx = self.tree.begin().map_err(|ref e| map_kv_err(e))?;
        let current = tx.get(&ck).map_err(|ref e| map_kv_err(e))?;
        if current.as_deref() != expected {
            return Ok(false);
        }
        tx.set(&ck, &new).map_err(|ref e| map_kv_err(e))?;
        match tx.commit().await {
            Ok(()) => Ok(true),
            Err(e) if is_transaction_conflict(&e) => {
                // Defensive: even with the global lock, surrealkv may
                // surface conflicts from background flush activity
                // racing the commit. Treat that as "stale expected".
                Ok(false)
            },
            Err(e) => Err(map_kv_err(&e)),
        }
    }

    async fn clear_namespace(&self, namespace: &str) -> StorageResult<u64> {
        validate_namespace(namespace)?;
        let start = namespace_range_start(namespace);
        let end = namespace_range_end(namespace);

        let mut tx = self.tree.begin().map_err(|ref e| map_kv_err(e))?;

        // Collect keys first, then delete (iterator borrows tx immutably).
        let keys_to_delete = {
            let mut iter = tx.range(&start, &end).map_err(|ref e| map_kv_err(e))?;
            iter.seek_first().map_err(|ref e| map_kv_err(e))?;
            let mut keys = Vec::new();
            while iter.valid() {
                keys.push(iter.key());
                iter.next().map_err(|ref e| map_kv_err(e))?;
            }
            keys
        }; // iterator dropped — releases immutable borrow on tx

        let count = keys_to_delete.len() as u64;
        for key in &keys_to_delete {
            tx.delete(key).map_err(|ref e| map_kv_err(e))?;
        }
        if count > 0 {
            tx.commit().await.map_err(|ref e| map_kv_err(e))?;
        }
        Ok(count)
    }

    async fn clear_prefix(&self, namespace: &str, prefix: &str) -> StorageResult<u64> {
        validate_namespace(namespace)?;
        validate_prefix(prefix)?;
        let start = composite_key(namespace, prefix);
        let end = prefix_range_end(namespace, prefix);

        let mut tx = self.tree.begin().map_err(|ref e| map_kv_err(e))?;

        // Collect keys first, then delete (iterator borrows tx immutably).
        let keys_to_delete = {
            let mut iter = tx.range(&start, &end).map_err(|ref e| map_kv_err(e))?;
            iter.seek_first().map_err(|ref e| map_kv_err(e))?;
            let mut keys = Vec::new();
            while iter.valid() {
                keys.push(iter.key());
                iter.next().map_err(|ref e| map_kv_err(e))?;
            }
            keys
        }; // iterator dropped — releases immutable borrow on tx

        let count = u64::try_from(keys_to_delete.len()).unwrap_or(u64::MAX);
        for key in &keys_to_delete {
            tx.delete(key).map_err(|ref e| map_kv_err(e))?;
        }
        if count > 0 {
            tx.commit().await.map_err(|ref e| map_kv_err(e))?;
        }
        // When count == 0, tx is dropped without commit. SurrealKV's MVCC
        // model aborts uncommitted transactions on Drop (same as clear_namespace).
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    fn make_store() -> (SurrealKvStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = SurrealKvStore::open(dir.path()).unwrap();
        (store, dir)
    }

    #[tokio::test]
    async fn test_surreal_get_set() {
        let (store, _dir) = make_store();
        store.set("ns1", "key1", b"hello".to_vec()).await.unwrap();
        let val = store.get("ns1", "key1").await.unwrap();
        assert_eq!(val, Some(b"hello".to_vec()));
    }

    #[tokio::test]
    async fn test_surreal_get_missing() {
        let (store, _dir) = make_store();
        let val = store.get("ns1", "missing").await.unwrap();
        assert!(val.is_none());
    }

    #[tokio::test]
    async fn test_surreal_overwrite() {
        let (store, _dir) = make_store();
        store.set("ns1", "k", b"v1".to_vec()).await.unwrap();
        store.set("ns1", "k", b"v2".to_vec()).await.unwrap();
        let val = store.get("ns1", "k").await.unwrap();
        assert_eq!(val, Some(b"v2".to_vec()));
    }

    #[tokio::test]
    async fn test_surreal_delete() {
        let (store, _dir) = make_store();
        store.set("ns1", "k", b"v".to_vec()).await.unwrap();
        assert!(store.delete("ns1", "k").await.unwrap());
        assert!(!store.delete("ns1", "k").await.unwrap());
        assert!(store.get("ns1", "k").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_surreal_exists() {
        let (store, _dir) = make_store();
        assert!(!store.exists("ns1", "k").await.unwrap());
        store.set("ns1", "k", b"v".to_vec()).await.unwrap();
        assert!(store.exists("ns1", "k").await.unwrap());
    }

    #[tokio::test]
    async fn test_surreal_namespace_isolation() {
        let (store, _dir) = make_store();
        store.set("ns1", "k", b"v1".to_vec()).await.unwrap();
        store.set("ns2", "k", b"v2".to_vec()).await.unwrap();
        assert_eq!(store.get("ns1", "k").await.unwrap(), Some(b"v1".to_vec()));
        assert_eq!(store.get("ns2", "k").await.unwrap(), Some(b"v2".to_vec()));
    }

    #[tokio::test]
    async fn test_surreal_list_keys() {
        let (store, _dir) = make_store();
        store.set("ns1", "a", b"1".to_vec()).await.unwrap();
        store.set("ns1", "b", b"2".to_vec()).await.unwrap();
        store.set("ns2", "c", b"3".to_vec()).await.unwrap();
        let mut keys = store.list_keys("ns1").await.unwrap();
        keys.sort();
        assert_eq!(keys, vec!["a", "b"]);
    }

    #[tokio::test]
    async fn test_surreal_clear_namespace() {
        let (store, _dir) = make_store();
        store.set("ns1", "a", b"1".to_vec()).await.unwrap();
        store.set("ns1", "b", b"2".to_vec()).await.unwrap();
        store.set("ns2", "c", b"3".to_vec()).await.unwrap();
        let cleared = store.clear_namespace("ns1").await.unwrap();
        assert_eq!(cleared, 2);
        assert!(store.list_keys("ns1").await.unwrap().is_empty());
        assert_eq!(store.list_keys("ns2").await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_surreal_clear_prefix_basic() {
        let (store, _dir) = make_store();
        store.set("ns1", "pfx.a", b"1".to_vec()).await.unwrap();
        store.set("ns1", "pfx.b", b"2".to_vec()).await.unwrap();
        store.set("ns1", "other", b"3".to_vec()).await.unwrap();
        store.set("ns2", "pfx.c", b"4".to_vec()).await.unwrap();

        let cleared = store.clear_prefix("ns1", "pfx.").await.unwrap();
        assert_eq!(cleared, 2);
        // "other" in ns1 untouched
        assert_eq!(
            store.get("ns1", "other").await.unwrap(),
            Some(b"3".to_vec())
        );
        // ns2 untouched
        assert_eq!(
            store.get("ns2", "pfx.c").await.unwrap(),
            Some(b"4".to_vec())
        );
    }

    #[tokio::test]
    async fn test_surreal_clear_prefix_no_matches() {
        let (store, _dir) = make_store();
        store.set("ns1", "key", b"v".to_vec()).await.unwrap();
        let cleared = store.clear_prefix("ns1", "nope.").await.unwrap();
        assert_eq!(cleared, 0);
        // Original key untouched
        assert!(store.exists("ns1", "key").await.unwrap());
    }

    #[tokio::test]
    async fn test_surreal_clear_prefix_empty_clears_all() {
        let (store, _dir) = make_store();
        store.set("ns1", "a", b"1".to_vec()).await.unwrap();
        store.set("ns1", "b", b"2".to_vec()).await.unwrap();
        store.set("ns2", "c", b"3".to_vec()).await.unwrap();

        let cleared = store.clear_prefix("ns1", "").await.unwrap();
        assert_eq!(cleared, 2);
        assert!(store.list_keys("ns1").await.unwrap().is_empty());
        // ns2 untouched
        assert_eq!(store.list_keys("ns2").await.unwrap().len(), 1);
    }

    // -- compare_and_swap --

    #[tokio::test]
    async fn surreal_cas_insert_if_absent_succeeds_when_missing() {
        let (store, _dir) = make_store();
        let ok = store
            .compare_and_swap("ns", "k", None, b"v1".to_vec())
            .await
            .unwrap();
        assert!(ok);
        assert_eq!(store.get("ns", "k").await.unwrap(), Some(b"v1".to_vec()));
    }

    #[tokio::test]
    async fn surreal_cas_insert_if_absent_fails_when_present() {
        let (store, _dir) = make_store();
        store.set("ns", "k", b"existing".to_vec()).await.unwrap();
        let ok = store
            .compare_and_swap("ns", "k", None, b"v1".to_vec())
            .await
            .unwrap();
        assert!(!ok);
        assert_eq!(
            store.get("ns", "k").await.unwrap(),
            Some(b"existing".to_vec())
        );
    }

    #[tokio::test]
    async fn surreal_cas_replace_when_expected_matches() {
        let (store, _dir) = make_store();
        store.set("ns", "k", b"v1".to_vec()).await.unwrap();
        let ok = store
            .compare_and_swap("ns", "k", Some(b"v1"), b"v2".to_vec())
            .await
            .unwrap();
        assert!(ok);
        assert_eq!(store.get("ns", "k").await.unwrap(), Some(b"v2".to_vec()));
    }

    #[tokio::test]
    async fn surreal_cas_replace_rejects_when_expected_differs() {
        let (store, _dir) = make_store();
        store.set("ns", "k", b"actual".to_vec()).await.unwrap();
        let ok = store
            .compare_and_swap("ns", "k", Some(b"wrong"), b"v2".to_vec())
            .await
            .unwrap();
        assert!(!ok);
        assert_eq!(
            store.get("ns", "k").await.unwrap(),
            Some(b"actual".to_vec())
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn surreal_cas_concurrent_only_one_winner() {
        // SurrealKV's MVCC plus the `is_transaction_conflict` mapping
        // means at most one of the concurrent CAS attempts ever
        // returns Ok(true) for the same (expected → new) transition.
        //
        // Prefix the per-task value so a task can never accidentally
        // write back the initial "0" and let a follower also win.
        let (store, _dir) = make_store();
        let store = Arc::new(store);
        store.set("ns", "k", b"0".to_vec()).await.unwrap();

        const TASKS: usize = 16;
        let mut handles = Vec::with_capacity(TASKS);
        for i in 0..TASKS {
            let s = Arc::clone(&store);
            handles.push(tokio::spawn(async move {
                s.compare_and_swap("ns", "k", Some(b"0"), format!("winner-{i}").into_bytes())
                    .await
                    .unwrap()
            }));
        }
        let mut wins = 0u32;
        for h in handles {
            if h.await.unwrap() {
                wins += 1;
            }
        }
        assert_eq!(wins, 1, "exactly one CAS must win the race");
    }
}
