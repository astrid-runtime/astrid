//! Audit log storage trait and SurrealKV-based implementation.

use astrid_capabilities::AuditEntryId;
use astrid_core::SessionId;
use astrid_storage::{KvStore, MemoryKvStore, SurrealKvStore};
use async_trait::async_trait;
use std::collections::HashSet;
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
const NS_SESSION_ENTRIES: &str = "audit:session_entries";
const NS_SESSION_SEQUENCE: &str = "audit:session_sequence";
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

    async fn get_legacy_session_entry_ids(
        &self,
        session_id: &SessionId,
    ) -> AuditResult<Vec<AuditEntryId>> {
        let session_key = session_id.0.to_string();
        let data = self
            .store
            .get(NS_SESSION_INDEX, &session_key)
            .await
            .map_err(|e| AuditError::StorageError(e.to_string()))?;
        match data {
            Some(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| AuditError::SerializationError(e.to_string())),
            None => Ok(Vec::new()),
        }
    }

    /// Get all committed append-only entry IDs for a session in insertion order.
    async fn get_committed_session_entry_ids(
        &self,
        session_id: &SessionId,
    ) -> AuditResult<Vec<AuditEntryId>> {
        let session_key = session_id.0.to_string();
        let prefix = format!("{session_key}:");
        let mut keys = self
            .store
            .list_keys_with_prefix(NS_SESSION_ENTRIES, &prefix)
            .await
            .map_err(|e| AuditError::StorageError(e.to_string()))?;
        keys.sort_unstable();

        let mut ids = Vec::with_capacity(keys.len());
        for key in keys {
            let (_, encoded_id) = key.rsplit_once(':').ok_or_else(|| {
                AuditError::StorageError(format!("invalid audit session index key: {key}"))
            })?;
            let id = uuid::Uuid::parse_str(encoded_id)
                .map_err(|e| AuditError::StorageError(e.to_string()))?;
            ids.push(AuditEntryId(id));
        }
        Ok(ids)
    }

    /// Get all entry IDs for a session in insertion order.
    ///
    /// The original index is a JSON array stored under one session key. New
    /// entries use individually keyed, monotonically sequenced records so an
    /// append never rewrites history. During migration the legacy array is the
    /// historical prefix; append-only records follow it. IDs are deduplicated
    /// defensively so a partially migrated store cannot return an entry twice.
    async fn get_session_entry_ids(
        &self,
        session_id: &SessionId,
    ) -> AuditResult<Vec<AuditEntryId>> {
        let mut ids = self.get_legacy_session_entry_ids(session_id).await?;
        let mut seen: HashSet<_> = ids.iter().cloned().collect();
        for id in self.get_committed_session_entry_ids(session_id).await? {
            if seen.insert(id.clone()) {
                ids.push(id);
            }
        }

        Ok(ids)
    }

    /// Atomically reserve the next per-session insertion sequence.
    async fn reserve_session_sequence(&self, session_id: &SessionId) -> AuditResult<u64> {
        let key = session_id.0.to_string();
        loop {
            let current = self
                .store
                .get(NS_SESSION_SEQUENCE, &key)
                .await
                .map_err(|e| AuditError::StorageError(e.to_string()))?;
            let sequence = current.as_deref().map_or(Ok(0), parse_sequence)?;
            let next = sequence.checked_add(1).ok_or_else(|| {
                AuditError::StorageError(format!("session index sequence exhausted for {key}"))
            })?;
            if self
                .store
                .compare_and_swap(
                    NS_SESSION_SEQUENCE,
                    &key,
                    current.as_deref(),
                    next.to_be_bytes().to_vec(),
                )
                .await
                .map_err(|e| AuditError::StorageError(e.to_string()))?
            {
                return Ok(sequence);
            }
        }
    }
}

fn parse_sequence(bytes: &[u8]) -> AuditResult<u64> {
    let encoded: [u8; 8] = bytes.try_into().map_err(|_| {
        AuditError::StorageError("invalid audit session sequence encoding".to_string())
    })?;
    Ok(u64::from_be_bytes(encoded))
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

        // Reserve insertion order, then publish one fixed-size session
        // record as the durable commit point. If either earlier write fails,
        // the direct entry is unreachable (its random ID was not returned) and
        // a sequence gap is harmless. Once this final set succeeds, queries and
        // restart chain recovery see only a fully stored signed entry.
        let sequence = self.reserve_session_sequence(&entry.session_id).await?;
        let index_key = format!("{session_key}:{sequence:020}:{entry_key}");
        self.store
            .set(NS_SESSION_ENTRIES, &index_key, vec![1])
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
        for id in self
            .get_committed_session_entry_ids(session_id)
            .await?
            .into_iter()
            .rev()
        {
            if self
                .get(&id)
                .await?
                .is_some_and(|entry| entry.principal.as_ref() == principal)
            {
                return Ok(Some(id));
            }
        }

        // Legacy stores tracked their head separately from the growing array.
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
        let legacy_ids = self.get_legacy_session_entry_ids(session_id).await?;
        let mut entries = Vec::with_capacity(legacy_ids.len());
        let mut seen = HashSet::with_capacity(legacy_ids.len());
        for id in legacy_ids {
            if let Some(entry) = self.get(&id).await? {
                seen.insert(id);
                entries.push(entry);
            }
        }
        for id in self.get_committed_session_entry_ids(session_id).await? {
            if seen.insert(id.clone())
                && let Some(entry) = self.get(&id).await?
            {
                entries.push(entry);
            }
        }

        Ok(entries)
    }

    async fn count(&self) -> AuditResult<usize> {
        let mut count = 0usize;
        for session in self.list_sessions().await? {
            count = count.saturating_add(self.count_session(&session).await?);
        }
        Ok(count)
    }

    async fn count_session(&self, session_id: &SessionId) -> AuditResult<usize> {
        Ok(self.get_session_entry_ids(session_id).await?.len())
    }

    async fn list_sessions(&self) -> AuditResult<Vec<SessionId>> {
        let legacy_keys = self
            .store
            .list_keys(NS_SESSION_INDEX)
            .await
            .map_err(|e| AuditError::StorageError(e.to_string()))?;

        let new_keys = self
            .store
            .list_keys(NS_SESSION_ENTRIES)
            .await
            .map_err(|e| AuditError::StorageError(e.to_string()))?;

        let mut sessions = HashSet::new();
        for key in legacy_keys {
            if let Ok(uuid) = uuid::Uuid::parse_str(&key) {
                sessions.insert(SessionId::from_uuid(uuid));
            }
        }
        for key in new_keys {
            if let Some(session) = key.split(':').next()
                && let Ok(uuid) = uuid::Uuid::parse_str(session)
            {
                sessions.insert(SessionId::from_uuid(uuid));
            }
        }

        let mut sessions: Vec<_> = sessions.into_iter().collect();
        sessions.sort_by_key(|session| session.0);
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
#[path = "storage_tests.rs"]
mod tests;
