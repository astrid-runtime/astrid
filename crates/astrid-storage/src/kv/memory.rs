//! In-memory `KvStore` implementation backed by a single `RwLock<HashMap>`.
//!
//! Suitable for tests and ephemeral data. All operations serialize through
//! the same lock, so `compare_and_swap` is trivially atomic across capsules
//! sharing this store.

use async_trait::async_trait;

use super::{KvStore, validate_prefix};
use crate::error::{StorageError, StorageResult};

/// In-memory key-value store for tests and ephemeral data.
///
/// Keys are stored as `"{namespace}\0{key}"` in a `HashMap`.
#[derive(Debug, Default)]
pub struct MemoryKvStore {
    data: std::sync::RwLock<std::collections::HashMap<String, Vec<u8>>>,
}

impl MemoryKvStore {
    /// Create a new empty in-memory KV store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn full_key(namespace: &str, key: &str) -> String {
        format!("{namespace}\0{key}")
    }
}

#[async_trait]
impl KvStore for MemoryKvStore {
    async fn get(&self, namespace: &str, key: &str) -> StorageResult<Option<Vec<u8>>> {
        let data = self
            .data
            .read()
            .map_err(|e| StorageError::Internal(e.to_string()))?;
        Ok(data.get(&Self::full_key(namespace, key)).cloned())
    }

    async fn set(&self, namespace: &str, key: &str, value: Vec<u8>) -> StorageResult<()> {
        let mut data = self
            .data
            .write()
            .map_err(|e| StorageError::Internal(e.to_string()))?;
        data.insert(Self::full_key(namespace, key), value);
        Ok(())
    }

    async fn delete(&self, namespace: &str, key: &str) -> StorageResult<bool> {
        let mut data = self
            .data
            .write()
            .map_err(|e| StorageError::Internal(e.to_string()))?;
        Ok(data.remove(&Self::full_key(namespace, key)).is_some())
    }

    async fn exists(&self, namespace: &str, key: &str) -> StorageResult<bool> {
        let data = self
            .data
            .read()
            .map_err(|e| StorageError::Internal(e.to_string()))?;
        Ok(data.contains_key(&Self::full_key(namespace, key)))
    }

    async fn list_keys(&self, namespace: &str) -> StorageResult<Vec<String>> {
        let data = self
            .data
            .read()
            .map_err(|e| StorageError::Internal(e.to_string()))?;
        let ns_prefix = format!("{namespace}\0");
        Ok(data
            .keys()
            .filter_map(|k| k.strip_prefix(&ns_prefix).map(String::from))
            .collect())
    }

    async fn list_keys_with_prefix(
        &self,
        namespace: &str,
        prefix: &str,
    ) -> StorageResult<Vec<String>> {
        let data = self
            .data
            .read()
            .map_err(|e| StorageError::Internal(e.to_string()))?;
        let full_prefix = format!("{namespace}\0{prefix}");
        let ns_prefix_len = namespace.len().saturating_add(1);
        Ok(data
            .keys()
            .filter(|k| k.starts_with(&full_prefix))
            .filter_map(|k| k.get(ns_prefix_len..).map(String::from))
            .collect())
    }

    async fn compare_and_swap(
        &self,
        namespace: &str,
        key: &str,
        expected: Option<&[u8]>,
        new: Vec<u8>,
    ) -> StorageResult<bool> {
        // Single write lock covers read + conditional write. Other
        // capsules calling `set` / `compare_and_swap` block until this
        // returns, so the compare cannot race a concurrent mutation.
        let mut data = self
            .data
            .write()
            .map_err(|e| StorageError::Internal(e.to_string()))?;
        let full = Self::full_key(namespace, key);
        let current = data.get(&full).map(Vec::as_slice);
        if current == expected {
            data.insert(full, new);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn clear_namespace(&self, namespace: &str) -> StorageResult<u64> {
        let mut data = self
            .data
            .write()
            .map_err(|e| StorageError::Internal(e.to_string()))?;
        let prefix = format!("{namespace}\0");
        let keys: Vec<String> = data
            .keys()
            .filter(|k| k.starts_with(&prefix))
            .cloned()
            .collect();
        let count = keys.len() as u64;
        for key in keys {
            data.remove(&key);
        }
        Ok(count)
    }

    async fn clear_prefix(&self, namespace: &str, prefix: &str) -> StorageResult<u64> {
        validate_prefix(prefix)?;
        let mut data = self
            .data
            .write()
            .map_err(|e| StorageError::Internal(e.to_string()))?;
        let full_prefix = format!("{namespace}\0{prefix}");
        let keys: Vec<String> = data
            .keys()
            .filter(|k| k.starts_with(&full_prefix))
            .cloned()
            .collect();
        let count = u64::try_from(keys.len()).unwrap_or(u64::MAX);
        for key in keys {
            data.remove(&key);
        }
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    #[tokio::test]
    async fn test_memory_get_set() {
        let store = MemoryKvStore::new();
        store.set("ns1", "key1", b"hello".to_vec()).await.unwrap();
        let val = store.get("ns1", "key1").await.unwrap();
        assert_eq!(val, Some(b"hello".to_vec()));
    }

    #[tokio::test]
    async fn test_memory_get_missing() {
        let store = MemoryKvStore::new();
        let val = store.get("ns1", "missing").await.unwrap();
        assert!(val.is_none());
    }

    #[tokio::test]
    async fn test_memory_overwrite() {
        let store = MemoryKvStore::new();
        store.set("ns1", "k", b"v1".to_vec()).await.unwrap();
        store.set("ns1", "k", b"v2".to_vec()).await.unwrap();
        let val = store.get("ns1", "k").await.unwrap();
        assert_eq!(val, Some(b"v2".to_vec()));
    }

    #[tokio::test]
    async fn test_memory_delete() {
        let store = MemoryKvStore::new();
        store.set("ns1", "k", b"v".to_vec()).await.unwrap();
        assert!(store.delete("ns1", "k").await.unwrap());
        assert!(!store.delete("ns1", "k").await.unwrap());
        assert!(store.get("ns1", "k").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_memory_exists() {
        let store = MemoryKvStore::new();
        assert!(!store.exists("ns1", "k").await.unwrap());
        store.set("ns1", "k", b"v".to_vec()).await.unwrap();
        assert!(store.exists("ns1", "k").await.unwrap());
    }

    #[tokio::test]
    async fn test_memory_namespace_isolation() {
        let store = MemoryKvStore::new();
        store.set("ns1", "k", b"v1".to_vec()).await.unwrap();
        store.set("ns2", "k", b"v2".to_vec()).await.unwrap();
        assert_eq!(store.get("ns1", "k").await.unwrap(), Some(b"v1".to_vec()));
        assert_eq!(store.get("ns2", "k").await.unwrap(), Some(b"v2".to_vec()));
    }

    #[tokio::test]
    async fn test_memory_list_keys() {
        let store = MemoryKvStore::new();
        store.set("ns1", "a", b"1".to_vec()).await.unwrap();
        store.set("ns1", "b", b"2".to_vec()).await.unwrap();
        store.set("ns2", "c", b"3".to_vec()).await.unwrap();
        let mut keys = store.list_keys("ns1").await.unwrap();
        keys.sort();
        assert_eq!(keys, vec!["a", "b"]);
    }

    #[tokio::test]
    async fn test_memory_clear_namespace() {
        let store = MemoryKvStore::new();
        store.set("ns1", "a", b"1".to_vec()).await.unwrap();
        store.set("ns1", "b", b"2".to_vec()).await.unwrap();
        store.set("ns2", "c", b"3".to_vec()).await.unwrap();
        let cleared = store.clear_namespace("ns1").await.unwrap();
        assert_eq!(cleared, 2);
        assert!(store.list_keys("ns1").await.unwrap().is_empty());
        assert_eq!(store.list_keys("ns2").await.unwrap().len(), 1);
    }

    // -- compare_and_swap --

    #[tokio::test]
    async fn cas_insert_if_absent_succeeds_when_missing() {
        let store = MemoryKvStore::new();
        let ok = store
            .compare_and_swap("ns", "k", None, b"v1".to_vec())
            .await
            .unwrap();
        assert!(ok);
        assert_eq!(store.get("ns", "k").await.unwrap(), Some(b"v1".to_vec()));
    }

    #[tokio::test]
    async fn cas_insert_if_absent_fails_when_present() {
        let store = MemoryKvStore::new();
        store.set("ns", "k", b"existing".to_vec()).await.unwrap();
        let ok = store
            .compare_and_swap("ns", "k", None, b"v1".to_vec())
            .await
            .unwrap();
        assert!(!ok);
        // Value untouched.
        assert_eq!(
            store.get("ns", "k").await.unwrap(),
            Some(b"existing".to_vec())
        );
    }

    #[tokio::test]
    async fn cas_replace_when_expected_matches() {
        let store = MemoryKvStore::new();
        store.set("ns", "k", b"v1".to_vec()).await.unwrap();
        let ok = store
            .compare_and_swap("ns", "k", Some(b"v1"), b"v2".to_vec())
            .await
            .unwrap();
        assert!(ok);
        assert_eq!(store.get("ns", "k").await.unwrap(), Some(b"v2".to_vec()));
    }

    #[tokio::test]
    async fn cas_replace_rejects_when_expected_differs() {
        let store = MemoryKvStore::new();
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

    #[tokio::test]
    async fn cas_replace_rejects_when_key_missing() {
        let store = MemoryKvStore::new();
        let ok = store
            .compare_and_swap("ns", "k", Some(b"anything"), b"v".to_vec())
            .await
            .unwrap();
        assert!(!ok);
        assert!(store.get("ns", "k").await.unwrap().is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn cas_concurrent_only_one_winner() {
        // Hammer the same key from many tasks; exactly one CAS must
        // succeed at each (expected → new) transition. Reproduces the
        // race the previous get-then-set host-side emulation lost.
        //
        // Each task's `new` value is prefixed so it can never collide
        // with the initial `"0"`; otherwise a task that happens to
        // write back `"0"` would let a follower observe the original
        // state and falsely "win".
        let store = Arc::new(MemoryKvStore::new());
        store.set("ns", "k", b"0".to_vec()).await.unwrap();

        const TASKS: usize = 32;
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
        // The stored value must equal whichever task won.
        let stored = store.get("ns", "k").await.unwrap().unwrap();
        assert!(
            stored.starts_with(b"winner-"),
            "winner's value must replace the initial; got {stored:?}"
        );
    }
}
