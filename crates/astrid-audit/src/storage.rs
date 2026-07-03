//! Audit log storage trait and SurrealKV-based implementation.

use astrid_capabilities::AuditEntryId;
use astrid_core::SessionId;
use astrid_storage::{KvStore, MemoryKvStore, SurrealKvStore};
use std::path::Path;
use std::sync::Arc;

use crate::entry::AuditEntry;
use crate::error::{AuditError, AuditResult};

/// Storage backend for audit logs.
///
/// Implementations must be thread-safe and support:
/// - Storing and retrieving individual entries
/// - Session-scoped queries
/// - Chain head tracking (latest entry per session)
pub(crate) trait AuditStorage: Send + Sync {
    /// Store an audit entry.
    ///
    /// # Errors
    ///
    /// Returns an error if the entry cannot be persisted.
    fn store(&self, entry: &AuditEntry) -> AuditResult<()>;

    /// Get an entry by ID.
    ///
    /// # Errors
    ///
    /// Returns an error if retrieval or deserialization fails.
    fn get(&self, id: &AuditEntryId) -> AuditResult<Option<AuditEntry>>;

    /// Get the chain head (latest entry ID) for a session+principal chain.
    ///
    /// `principal = None` returns the system chain head. `Some(pid)` returns
    /// the principal-specific chain head.
    ///
    /// # Errors
    ///
    /// Returns an error if retrieval or parsing fails.
    fn get_chain_head(
        &self,
        session_id: &SessionId,
        principal: Option<&astrid_core::PrincipalId>,
    ) -> AuditResult<Option<AuditEntryId>>;

    /// Get all entries for a session, in insertion order.
    ///
    /// # Errors
    ///
    /// Returns an error if retrieval or deserialization fails.
    fn get_session_entries(&self, session_id: &SessionId) -> AuditResult<Vec<AuditEntry>>;

    /// Count total entries.
    ///
    /// # Errors
    ///
    /// Returns an error if the storage backend fails.
    fn count(&self) -> AuditResult<usize>;

    /// Count entries for a session.
    ///
    /// # Errors
    ///
    /// Returns an error if retrieval or deserialization fails.
    fn count_session(&self, session_id: &SessionId) -> AuditResult<usize>;

    /// List all session IDs.
    ///
    /// # Errors
    ///
    /// Returns an error if retrieval or parsing fails.
    fn list_sessions(&self) -> AuditResult<Vec<SessionId>>;

    /// Flush pending writes to durable storage.
    ///
    /// # Errors
    ///
    /// Returns an error if the storage backend fails to flush.
    fn flush(&self) -> AuditResult<()>;
}

// -- Namespace constants (crate-internal) --

const NS_ENTRIES: &str = "audit:entries";
const NS_SESSION_INDEX: &str = "audit:session_index";
const NS_CHAIN_HEADS: &str = "audit:chain_heads";

/// Run an async future synchronously, bridging the sync [`AuditStorage`] trait
/// to the async [`KvStore`](astrid_storage::kv::KvStore) trait.
///
/// `SurrealKV` operations are fast in-process (no network), so blocking is safe.
///
/// Handles three runtime contexts:
/// - **Multi-threaded tokio runtime** (production): uses `block_in_place` to
///   avoid O(N) OS thread churn when `verify_all()` or concurrent writes hit
///   this path repeatedly.
/// - **Single-threaded tokio runtime** (unit tests): uses a scoped thread
///   because `block_in_place` panics on `current_thread` runtimes.
/// - **No runtime** (sync `#[test]` functions): creates a temporary runtime.
///
/// # Panics
///
/// Panics if the temporary runtime cannot be created (no-runtime path) or if
/// the scoped thread panics (single-threaded runtime path).
fn block_on<F>(f: F) -> F::Output
where
    F: std::future::Future + Send,
    F::Output: Send,
{
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => {
            // Multi-threaded runtime (production): block_in_place yields the
            // worker thread to the runtime scheduler instead of spawning a new
            // OS thread per storage operation. Nested block_in_place calls
            // (e.g. WASM host -> interceptor -> audit append) are safe: tokio
            // detects the thread is already in a blocking context and skips
            // worker-thread migration, running the closure directly.
            // `block_in_place` requires the `rt-multi-thread` feature, which is
            // native-only (no multi-threaded runtime exists on wasm), so this
            // branch is compiled out on wasm — where the flavor is never
            // MultiThread anyway.
            #[cfg(not(target_family = "wasm"))]
            if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread {
                return tokio::task::block_in_place(|| handle.block_on(f));
            }
            // Single-threaded runtime (tests), and every wasm target:
            // block_in_place panics on current_thread runtimes, so fall back to
            // a scoped thread.
            std::thread::scope(|s| {
                s.spawn(|| handle.block_on(f))
                    .join()
                    .expect("async thread panicked")
            })
        },
        Err(_) => {
            // No runtime (sync tests) - create a temporary one.
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("failed to create tokio runtime")
                .block_on(f)
        },
    }
}

/// Build the storage key for a chain head.
///
/// System chain (no principal): `"{session_uuid}"`
/// Principal chain: `"{session_uuid}:{principal}"`
///
/// Unambiguous because session UUIDs contain no colons and principal IDs
/// are validated to contain only alphanumeric, hyphens, and underscores.
fn chain_head_key(session_id: &SessionId, principal: Option<&astrid_core::PrincipalId>) -> String {
    match principal {
        Some(p) => format!("{}:{}", session_id.0, p),
        None => session_id.0.to_string(),
    }
}

/// SurrealKV-based storage backend for audit logs.
pub(crate) struct SurrealKvAuditStorage {
    store: Arc<dyn KvStore>,
}

impl SurrealKvAuditStorage {
    /// Open or create audit storage at the given path.
    ///
    /// # Errors
    ///
    /// Returns an error if the `SurrealKV` store fails to open.
    pub(crate) fn open(path: impl AsRef<Path>) -> AuditResult<Self> {
        let store =
            SurrealKvStore::open(path).map_err(|e| AuditError::StorageError(e.to_string()))?;
        Ok(Self {
            store: Arc::new(store),
        })
    }

    /// Create an in-memory storage (for testing).
    #[must_use]
    pub(crate) fn in_memory() -> Self {
        Self {
            store: Arc::new(MemoryKvStore::new()),
        }
    }

    /// Get all entry IDs for a session (from the session index).
    fn get_session_entry_ids(&self, session_id: &SessionId) -> AuditResult<Vec<AuditEntryId>> {
        let key = session_id.0.to_string();

        let data = block_on(self.store.get(NS_SESSION_INDEX, &key))
            .map_err(|e| AuditError::StorageError(e.to_string()))?;

        match data {
            Some(bytes) => {
                let ids: Vec<AuditEntryId> = serde_json::from_slice(&bytes)
                    .map_err(|e| AuditError::SerializationError(e.to_string()))?;
                Ok(ids)
            },
            None => Ok(Vec::new()),
        }
    }
}

impl AuditStorage for SurrealKvAuditStorage {
    fn store(&self, entry: &AuditEntry) -> AuditResult<()> {
        let entry_key = entry.id.0.to_string();
        let session_key = entry.session_id.0.to_string();

        // Serialize entry.
        let entry_data =
            serde_json::to_vec(entry).map_err(|e| AuditError::SerializationError(e.to_string()))?;

        // Store entry.
        block_on(self.store.set(NS_ENTRIES, &entry_key, entry_data))
            .map_err(|e| AuditError::StorageError(e.to_string()))?;

        // Update session index (append entry ID to the list).
        let mut entry_ids = self.get_session_entry_ids(&entry.session_id)?;
        entry_ids.push(entry.id.clone());
        let index_data = serde_json::to_vec(&entry_ids)
            .map_err(|e| AuditError::SerializationError(e.to_string()))?;
        block_on(self.store.set(NS_SESSION_INDEX, &session_key, index_data))
            .map_err(|e| AuditError::StorageError(e.to_string()))?;

        // Update chain head for the entry's chain (system or principal).
        let chain_key = chain_head_key(&entry.session_id, entry.principal.as_ref());
        block_on(
            self.store
                .set(NS_CHAIN_HEADS, &chain_key, entry_key.into_bytes()),
        )
        .map_err(|e| AuditError::StorageError(e.to_string()))?;

        Ok(())
    }

    fn get(&self, id: &AuditEntryId) -> AuditResult<Option<AuditEntry>> {
        let key = id.0.to_string();

        let data = block_on(self.store.get(NS_ENTRIES, &key))
            .map_err(|e| AuditError::StorageError(e.to_string()))?;

        match data {
            Some(bytes) => {
                let entry = serde_json::from_slice(&bytes)
                    .map_err(|e| AuditError::SerializationError(e.to_string()))?;
                Ok(Some(entry))
            },
            None => Ok(None),
        }
    }

    fn get_chain_head(
        &self,
        session_id: &SessionId,
        principal: Option<&astrid_core::PrincipalId>,
    ) -> AuditResult<Option<AuditEntryId>> {
        let key = chain_head_key(session_id, principal);

        let data = block_on(self.store.get(NS_CHAIN_HEADS, &key))
            .map_err(|e| AuditError::StorageError(e.to_string()))?;

        match data {
            Some(bytes) => {
                let id_str = std::str::from_utf8(&bytes)
                    .map_err(|e| AuditError::StorageError(e.to_string()))?;
                let uuid = uuid::Uuid::parse_str(id_str)
                    .map_err(|e| AuditError::StorageError(e.to_string()))?;
                Ok(Some(AuditEntryId(uuid)))
            },
            None => Ok(None),
        }
    }

    fn get_session_entries(&self, session_id: &SessionId) -> AuditResult<Vec<AuditEntry>> {
        let ids = self.get_session_entry_ids(session_id)?;
        let mut entries = Vec::with_capacity(ids.len());

        for id in ids {
            if let Some(entry) = self.get(&id)? {
                entries.push(entry);
            }
        }

        Ok(entries)
    }

    fn count(&self) -> AuditResult<usize> {
        let keys = block_on(self.store.list_keys(NS_ENTRIES))
            .map_err(|e| AuditError::StorageError(e.to_string()))?;
        Ok(keys.len())
    }

    fn count_session(&self, session_id: &SessionId) -> AuditResult<usize> {
        Ok(self.get_session_entry_ids(session_id)?.len())
    }

    fn list_sessions(&self) -> AuditResult<Vec<SessionId>> {
        let keys = block_on(self.store.list_keys(NS_SESSION_INDEX))
            .map_err(|e| AuditError::StorageError(e.to_string()))?;

        let mut sessions = Vec::new();
        for key in keys {
            if let Ok(uuid) = uuid::Uuid::parse_str(&key) {
                sessions.push(SessionId::from_uuid(uuid));
            }
        }

        Ok(sessions)
    }

    fn flush(&self) -> AuditResult<()> {
        // KvStore commits on every set(), no explicit flush needed.
        Ok(())
    }
}

impl std::fmt::Debug for SurrealKvAuditStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SurrealKvAuditStorage")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::{AuditAction, AuditOutcome, AuthorizationProof};
    use astrid_crypto::{ContentHash, KeyPair};

    fn test_keypair() -> KeyPair {
        KeyPair::generate()
    }

    #[tokio::test]
    async fn test_store_and_retrieve() {
        let storage = SurrealKvAuditStorage::in_memory();
        let keypair = test_keypair();
        let session_id = SessionId::new();

        let entry = AuditEntry::create(
            session_id.clone(),
            AuditAction::SessionStarted {
                user_id: keypair.key_id(),
                platform: "cli".to_string(),
            },
            AuthorizationProof::System {
                reason: "test".to_string(),
            },
            AuditOutcome::success(),
            ContentHash::zero(),
            &keypair,
        );

        let entry_id = entry.id.clone();

        storage.store(&entry).unwrap();

        let retrieved = storage.get(&entry_id).unwrap().unwrap();
        assert_eq!(retrieved.id, entry_id);
    }

    #[tokio::test]
    async fn test_session_index() {
        let storage = SurrealKvAuditStorage::in_memory();
        let keypair = test_keypair();
        let session_id = SessionId::new();

        // Create multiple entries
        let mut prev_hash = ContentHash::zero();
        for i in 0..3 {
            let entry = AuditEntry::create(
                session_id.clone(),
                AuditAction::McpToolCall {
                    server: "test".to_string(),
                    tool: format!("tool_{i}"),
                    args_hash: ContentHash::zero(),
                },
                AuthorizationProof::NotRequired {
                    reason: "test".to_string(),
                },
                AuditOutcome::success(),
                prev_hash,
                &keypair,
            );
            prev_hash = entry.content_hash();
            storage.store(&entry).unwrap();
        }

        let entries = storage.get_session_entries(&session_id).unwrap();
        assert_eq!(entries.len(), 3);
    }

    #[tokio::test]
    async fn test_chain_head() {
        let storage = SurrealKvAuditStorage::in_memory();
        let keypair = test_keypair();
        let session_id = SessionId::new();

        let entry1 = AuditEntry::create(
            session_id.clone(),
            AuditAction::SessionStarted {
                user_id: keypair.key_id(),
                platform: "cli".to_string(),
            },
            AuthorizationProof::System {
                reason: "test".to_string(),
            },
            AuditOutcome::success(),
            ContentHash::zero(),
            &keypair,
        );

        storage.store(&entry1).unwrap();

        let entry2 = AuditEntry::create(
            session_id.clone(),
            AuditAction::SessionEnded {
                reason: "done".to_string(),
                duration_secs: 100,
            },
            AuthorizationProof::System {
                reason: "test".to_string(),
            },
            AuditOutcome::success(),
            entry1.content_hash(),
            &keypair,
        );

        storage.store(&entry2).unwrap();

        let head = storage.get_chain_head(&session_id, None).unwrap().unwrap();
        assert_eq!(head, entry2.id);
    }

    /// Exercises the `block_in_place` branch that only fires under a
    /// multi-threaded runtime (the production path fixed by #305).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_store_and_retrieve_multi_thread() {
        let storage = SurrealKvAuditStorage::in_memory();
        let keypair = test_keypair();
        let session_id = SessionId::new();

        let entry = AuditEntry::create(
            session_id.clone(),
            AuditAction::SessionStarted {
                user_id: keypair.key_id(),
                platform: "cli".to_string(),
            },
            AuthorizationProof::System {
                reason: "test".to_string(),
            },
            AuditOutcome::success(),
            ContentHash::zero(),
            &keypair,
        );

        let entry_id = entry.id.clone();
        storage.store(&entry).unwrap();

        let retrieved = storage.get(&entry_id).unwrap().unwrap();
        assert_eq!(retrieved.id, entry_id);

        // Also verify session queries work through block_in_place.
        let entries = storage.get_session_entries(&session_id).unwrap();
        assert_eq!(entries.len(), 1);

        let head = storage.get_chain_head(&session_id, None).unwrap().unwrap();
        assert_eq!(head, entry_id);
    }

    /// Concurrent stores from multiple tasks under a multi-threaded runtime.
    /// Exercises the `block_in_place` path under the load pattern from #305.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_concurrent_stores_multi_thread() {
        let storage = std::sync::Arc::new(SurrealKvAuditStorage::in_memory());
        let mut handles = Vec::new();

        for _ in 0..8 {
            let s = std::sync::Arc::clone(&storage);
            handles.push(tokio::task::spawn(async move {
                let keypair = test_keypair();
                let session_id = SessionId::new();
                let entry = AuditEntry::create(
                    session_id,
                    AuditAction::SessionStarted {
                        user_id: keypair.key_id(),
                        platform: "cli".to_string(),
                    },
                    AuthorizationProof::System {
                        reason: "test".to_string(),
                    },
                    AuditOutcome::success(),
                    ContentHash::zero(),
                    &keypair,
                );
                s.store(&entry).unwrap();
                entry.id
            }));
        }

        for h in handles {
            let id = h.await.unwrap();
            assert!(storage.get(&id).unwrap().is_some());
        }

        // All 8 sessions should be visible.
        let sessions = storage.list_sessions().unwrap();
        assert_eq!(sessions.len(), 8);
    }
}
