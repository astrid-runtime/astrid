//! Audit log storage trait and SurrealKV-based implementation.

use astrid_capabilities::AuditEntryId;
use astrid_core::SessionId;
use astrid_storage::{KvStore, MemoryKvStore, SurrealKvStore};
use async_trait::async_trait;
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
///
/// The methods are genuinely `async` (bridged with [`async_trait`]): they
/// `await` the underlying async [`KvStore`](astrid_storage::kv::KvStore)
/// directly rather than driving it through a sync-over-async `block_on`. That
/// bridge parked a temporary tokio runtime whose time driver reads
/// [`std::time::Instant`] — an instant panic on `wasm32-unknown-unknown` — so
/// the whole surface is async end-to-end to boot on the browser profile.
#[async_trait]
pub(crate) trait AuditStorage: Send + Sync {
    /// Store an audit entry.
    ///
    /// # Errors
    ///
    /// Returns an error if the entry cannot be persisted.
    async fn store(&self, entry: &AuditEntry) -> AuditResult<()>;

    /// Get an entry by ID.
    ///
    /// # Errors
    ///
    /// Returns an error if retrieval or deserialization fails.
    async fn get(&self, id: &AuditEntryId) -> AuditResult<Option<AuditEntry>>;

    /// Get the chain head (latest entry ID) for a session+principal chain.
    ///
    /// `principal = None` returns the system chain head. `Some(pid)` returns
    /// the principal-specific chain head.
    ///
    /// # Errors
    ///
    /// Returns an error if retrieval or parsing fails.
    async fn get_chain_head(
        &self,
        session_id: &SessionId,
        principal: Option<&astrid_core::PrincipalId>,
    ) -> AuditResult<Option<AuditEntryId>>;

    /// Get all entries for a session, in insertion order.
    ///
    /// # Errors
    ///
    /// Returns an error if retrieval or deserialization fails.
    async fn get_session_entries(&self, session_id: &SessionId) -> AuditResult<Vec<AuditEntry>>;

    /// Count total entries.
    ///
    /// # Errors
    ///
    /// Returns an error if the storage backend fails.
    async fn count(&self) -> AuditResult<usize>;

    /// Count entries for a session.
    ///
    /// # Errors
    ///
    /// Returns an error if retrieval or deserialization fails.
    async fn count_session(&self, session_id: &SessionId) -> AuditResult<usize>;

    /// List all session IDs.
    ///
    /// # Errors
    ///
    /// Returns an error if retrieval or parsing fails.
    async fn list_sessions(&self) -> AuditResult<Vec<SessionId>>;

    /// Flush pending writes to durable storage.
    ///
    /// # Errors
    ///
    /// Returns an error if the storage backend fails to flush.
    async fn flush(&self) -> AuditResult<()>;

    /// Flush and close the underlying store, releasing any OS-level file lock
    /// it holds.
    ///
    /// Persistent backends (surrealkv) hold an exclusive `LOCK` on the store
    /// directory for their whole lifetime; without an explicit close it is
    /// released only when the process dies. Closing here lets a graceful
    /// shutdown release it deterministically. Works through `&self` because the
    /// backend closes through its shared `Arc<dyn KvStore>` handle.
    ///
    /// # Errors
    ///
    /// Returns an error if the storage backend fails to close.
    async fn close(&self) -> AuditResult<()>;
}

// -- Namespace constants (crate-internal) --

const NS_ENTRIES: &str = "audit:entries";
const NS_SESSION_INDEX: &str = "audit:session_index";
const NS_CHAIN_HEADS: &str = "audit:chain_heads";

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
    async fn get_session_entry_ids(
        &self,
        session_id: &SessionId,
    ) -> AuditResult<Vec<AuditEntryId>> {
        let key = session_id.0.to_string();

        let data = self
            .store
            .get(NS_SESSION_INDEX, &key)
            .await
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

#[async_trait]
impl AuditStorage for SurrealKvAuditStorage {
    async fn store(&self, entry: &AuditEntry) -> AuditResult<()> {
        let entry_key = entry.id.0.to_string();
        let session_key = entry.session_id.0.to_string();

        // Serialize entry.
        let entry_data =
            serde_json::to_vec(entry).map_err(|e| AuditError::SerializationError(e.to_string()))?;

        // Store entry.
        self.store
            .set(NS_ENTRIES, &entry_key, entry_data)
            .await
            .map_err(|e| AuditError::StorageError(e.to_string()))?;

        // Update session index (append entry ID to the list).
        let mut entry_ids = self.get_session_entry_ids(&entry.session_id).await?;
        entry_ids.push(entry.id.clone());
        let index_data = serde_json::to_vec(&entry_ids)
            .map_err(|e| AuditError::SerializationError(e.to_string()))?;
        self.store
            .set(NS_SESSION_INDEX, &session_key, index_data)
            .await
            .map_err(|e| AuditError::StorageError(e.to_string()))?;

        // Update chain head for the entry's chain (system or principal).
        let chain_key = chain_head_key(&entry.session_id, entry.principal.as_ref());
        self.store
            .set(NS_CHAIN_HEADS, &chain_key, entry_key.into_bytes())
            .await
            .map_err(|e| AuditError::StorageError(e.to_string()))?;

        Ok(())
    }

    async fn get(&self, id: &AuditEntryId) -> AuditResult<Option<AuditEntry>> {
        let key = id.0.to_string();

        let data = self
            .store
            .get(NS_ENTRIES, &key)
            .await
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

    async fn get_chain_head(
        &self,
        session_id: &SessionId,
        principal: Option<&astrid_core::PrincipalId>,
    ) -> AuditResult<Option<AuditEntryId>> {
        let key = chain_head_key(session_id, principal);

        let data = self
            .store
            .get(NS_CHAIN_HEADS, &key)
            .await
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

    async fn get_session_entries(&self, session_id: &SessionId) -> AuditResult<Vec<AuditEntry>> {
        let ids = self.get_session_entry_ids(session_id).await?;
        let mut entries = Vec::with_capacity(ids.len());

        for id in ids {
            if let Some(entry) = self.get(&id).await? {
                entries.push(entry);
            }
        }

        Ok(entries)
    }

    async fn count(&self) -> AuditResult<usize> {
        let keys = self
            .store
            .list_keys(NS_ENTRIES)
            .await
            .map_err(|e| AuditError::StorageError(e.to_string()))?;
        Ok(keys.len())
    }

    async fn count_session(&self, session_id: &SessionId) -> AuditResult<usize> {
        Ok(self.get_session_entry_ids(session_id).await?.len())
    }

    async fn list_sessions(&self) -> AuditResult<Vec<SessionId>> {
        let keys = self
            .store
            .list_keys(NS_SESSION_INDEX)
            .await
            .map_err(|e| AuditError::StorageError(e.to_string()))?;

        let mut sessions = Vec::new();
        for key in keys {
            if let Ok(uuid) = uuid::Uuid::parse_str(&key) {
                sessions.push(SessionId::from_uuid(uuid));
            }
        }

        Ok(sessions)
    }

    async fn flush(&self) -> AuditResult<()> {
        // KvStore commits on every set(), no explicit flush needed.
        Ok(())
    }

    async fn close(&self) -> AuditResult<()> {
        // Delegates to the shared `Arc<dyn KvStore>`; for surrealkv this closes
        // the underlying tree and releases its `LOCK`. The in-memory backend's
        // default `close` is a harmless no-op.
        self.store
            .close()
            .await
            .map_err(|e| AuditError::StorageError(e.to_string()))
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

        storage.store(&entry).await.unwrap();

        let retrieved = storage.get(&entry_id).await.unwrap().unwrap();
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
            storage.store(&entry).await.unwrap();
        }

        let entries = storage.get_session_entries(&session_id).await.unwrap();
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

        storage.store(&entry1).await.unwrap();

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

        storage.store(&entry2).await.unwrap();

        let head = storage
            .get_chain_head(&session_id, None)
            .await
            .unwrap()
            .unwrap();
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
        storage.store(&entry).await.unwrap();

        let retrieved = storage.get(&entry_id).await.unwrap().unwrap();
        assert_eq!(retrieved.id, entry_id);

        // Also verify session queries work under a multi-threaded runtime.
        let entries = storage.get_session_entries(&session_id).await.unwrap();
        assert_eq!(entries.len(), 1);

        let head = storage
            .get_chain_head(&session_id, None)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(head, entry_id);
    }

    /// Concurrent stores from multiple tasks under a multi-threaded runtime.
    /// Exercises the async persist path under the load pattern from #305.
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
                s.store(&entry).await.unwrap();
                entry.id
            }));
        }

        for h in handles {
            let id = h.await.unwrap();
            assert!(storage.get(&id).await.unwrap().is_some());
        }

        // All 8 sessions should be visible.
        let sessions = storage.list_sessions().await.unwrap();
        assert_eq!(sessions.len(), 8);
    }
}
