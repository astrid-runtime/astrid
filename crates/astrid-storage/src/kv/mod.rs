//! Raw key-value store trait and implementations.
//!
//! The [`KvStore`] trait provides byte-level `get`/`set`/`delete` operations
//! with namespaced keys. Implementations:
//!
//! - **In-memory** (always available): For tests and ephemeral data
//! - **`SurrealKV`** (behind `kv` feature): Persistent, versioned, ACID-compliant
//!
//! # Namespacing
//!
//! All operations are scoped to a namespace. WASM guests receive a namespace
//! like `wasm:{plugin_id}` and cannot access keys outside their namespace.
//! The runtime uses `system:*` namespaces for internal state.
//!
//! # Ergonomic Access
//!
//! Use [`ScopedKvStore`] to pre-bind a namespace. This is the primary API
//! for WASM guests — they receive a scoped store and never handle namespaces
//! directly. It also provides typed [`get_json`](ScopedKvStore::get_json) /
//! [`set_json`](ScopedKvStore::set_json) convenience methods.

use async_trait::async_trait;

use crate::error::{StorageError, StorageResult};

mod memory;
mod scoped;
#[cfg(feature = "kv")]
mod surreal;

pub use memory::MemoryKvStore;
pub use scoped::ScopedKvStore;
#[cfg(feature = "kv")]
pub use surreal::SurrealKvStore;

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Validate that a namespace is safe for use as a key prefix.
///
/// Namespaces must be non-empty and must not contain the null byte
/// (used internally as the namespace/key separator).
pub(super) fn validate_namespace(namespace: &str) -> StorageResult<()> {
    if namespace.is_empty() {
        return Err(StorageError::InvalidKey(
            "namespace must not be empty".into(),
        ));
    }
    if namespace.contains('\0') {
        return Err(StorageError::InvalidKey(
            "namespace must not contain null bytes".into(),
        ));
    }
    Ok(())
}

/// Validate that a prefix is safe for range operations.
///
/// Prefixes may be empty (clears all keys) but must not contain the null byte.
pub(super) fn validate_prefix(prefix: &str) -> StorageResult<()> {
    if prefix.contains('\0') {
        return Err(StorageError::InvalidKey(
            "prefix must not contain null bytes".into(),
        ));
    }
    Ok(())
}

/// Validate that a key is safe for storage.
///
/// Keys must be non-empty and must not contain the null byte.
pub(super) fn validate_key(key: &str) -> StorageResult<()> {
    if key.is_empty() {
        return Err(StorageError::InvalidKey("key must not be empty".into()));
    }
    if key.contains('\0') {
        return Err(StorageError::InvalidKey(
            "key must not contain null bytes".into(),
        ));
    }
    Ok(())
}

/// Build the composite key `"{namespace}\0{key}"` as bytes.
#[cfg(feature = "kv")]
pub(super) fn composite_key(namespace: &str, key: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(namespace.len().saturating_add(1).saturating_add(key.len()));
    buf.extend_from_slice(namespace.as_bytes());
    buf.push(0);
    buf.extend_from_slice(key.as_bytes());
    buf
}

/// Build the start of the namespace range (inclusive): `"{namespace}\0"`.
#[cfg(feature = "kv")]
pub(super) fn namespace_range_start(namespace: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(namespace.len().saturating_add(1));
    buf.extend_from_slice(namespace.as_bytes());
    buf.push(0);
    buf
}

/// Build the end of the namespace range (exclusive): `"{namespace}\x01"`.
///
/// Since `\0` is the separator, any key in the namespace has the form
/// `"{namespace}\0{key}"`. The byte `\x01` immediately follows `\0`,
/// so the range `["{namespace}\0", "{namespace}\x01")` captures exactly
/// all keys in the namespace.
#[cfg(feature = "kv")]
pub(super) fn namespace_range_end(namespace: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(namespace.len().saturating_add(1));
    buf.extend_from_slice(namespace.as_bytes());
    buf.push(1);
    buf
}

/// Build the exclusive upper bound for a prefix range scan within a namespace.
///
/// For prefix "foo" in namespace "ns", this returns the key just after all
/// keys starting with "ns\0foo". Works by incrementing the last byte of
/// the prefix. If the prefix is empty, falls back to the full namespace
/// range end.
#[cfg(feature = "kv")]
pub(super) fn prefix_range_end(namespace: &str, prefix: &str) -> Vec<u8> {
    if prefix.is_empty() {
        return namespace_range_end(namespace);
    }
    let mut buf = composite_key(namespace, prefix);
    // Increment the last byte to form the exclusive upper bound.
    // If the last byte is 0xFF, pop and try the next one up.
    while let Some(&last) = buf.last() {
        if let Some(next) = last.checked_add(1) {
            // Safety: we just confirmed `buf.last()` is `Some`.
            if let Some(slot) = buf.last_mut() {
                *slot = next;
            }
            return buf;
        }
        buf.pop();
    }
    // All bytes were 0xFF - fall back to namespace end.
    namespace_range_end(namespace)
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A key-value entry with its namespace and key.
#[derive(Debug, Clone)]
pub struct KvEntry {
    /// The namespace this entry belongs to.
    pub namespace: String,
    /// The key within the namespace.
    pub key: String,
    /// The raw value bytes.
    pub value: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// Raw key-value store trait.
///
/// Provides namespaced byte-level storage. All operations are scoped
/// to a namespace for isolation.
#[async_trait]
pub trait KvStore: Send + Sync {
    /// Get a value by namespace and key.
    ///
    /// Returns `None` if the key does not exist.
    async fn get(&self, namespace: &str, key: &str) -> StorageResult<Option<Vec<u8>>>;

    /// Set a value for a namespace and key.
    ///
    /// Overwrites any existing value.
    async fn set(&self, namespace: &str, key: &str, value: Vec<u8>) -> StorageResult<()>;

    /// Delete a key from a namespace.
    ///
    /// Returns `true` if the key existed and was deleted.
    async fn delete(&self, namespace: &str, key: &str) -> StorageResult<bool>;

    /// Check if a key exists in a namespace.
    async fn exists(&self, namespace: &str, key: &str) -> StorageResult<bool>;

    /// List all keys in a namespace.
    async fn list_keys(&self, namespace: &str) -> StorageResult<Vec<String>>;

    /// List keys matching a prefix within a namespace.
    ///
    /// Default implementation filters `list_keys` output. Backends
    /// should override with a native range scan when available.
    async fn list_keys_with_prefix(
        &self,
        namespace: &str,
        prefix: &str,
    ) -> StorageResult<Vec<String>> {
        let all = self.list_keys(namespace).await?;
        Ok(all.into_iter().filter(|k| k.starts_with(prefix)).collect())
    }

    /// Atomically replace `key` with `new` iff its current value
    /// matches `expected`.
    ///
    /// Semantics:
    /// - Returns `Ok(true)` if the swap happened (current matched
    ///   `expected` and `new` is now stored).
    /// - Returns `Ok(false)` if the swap was skipped because current
    ///   did not match `expected` (or — for transactional backends —
    ///   a concurrent commit invalidated the comparison).
    /// - Returns `Err(...)` only for I/O / validation failures, not
    ///   for the normal "compare failed" case.
    ///
    /// `expected = None` means "the key must currently be missing"
    /// (the typical insert-if-absent CAS).
    ///
    /// Backends must guarantee atomicity across concurrent capsules.
    /// The kernel does not retry on its own — capsules implementing
    /// optimistic-concurrency loops re-issue the call themselves.
    async fn compare_and_swap(
        &self,
        namespace: &str,
        key: &str,
        expected: Option<&[u8]>,
        new: Vec<u8>,
    ) -> StorageResult<bool>;

    /// Delete all keys in a namespace.
    async fn clear_namespace(&self, namespace: &str) -> StorageResult<u64>;

    /// Delete all keys matching a prefix within a namespace.
    ///
    /// Returns the number of keys that matched the prefix.
    ///
    /// Default implementation lists then deletes one-by-one (non-atomic).
    /// On error, some keys may already have been deleted. Backends should
    /// override with an atomic implementation.
    async fn clear_prefix(&self, namespace: &str, prefix: &str) -> StorageResult<u64> {
        validate_prefix(prefix)?;
        let keys = self.list_keys_with_prefix(namespace, prefix).await?;
        let count = u64::try_from(keys.len()).unwrap_or(u64::MAX);
        for key in &keys {
            self.delete(namespace, key).await?;
        }
        Ok(count)
    }
}

// ---------------------------------------------------------------------------
// Tests for validators (impl-level tests live with their submodules)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_namespace_rejects_empty() {
        assert!(validate_namespace("").is_err());
    }

    #[test]
    fn test_validate_namespace_rejects_null_byte() {
        assert!(validate_namespace("ns\0bad").is_err());
    }

    #[test]
    fn test_validate_key_rejects_empty() {
        assert!(validate_key("").is_err());
    }

    #[test]
    fn test_validate_key_rejects_null_byte() {
        assert!(validate_key("k\0bad").is_err());
    }
}
