//! Audit log storage trait and SurrealKV-based implementation.

use crate::entry::AuditEntry;
use crate::error::{AuditError, AuditResult};
use astrid_capabilities::AuditEntryId;
use astrid_core::SessionId;
use astrid_storage::{KvStore, MemoryKvStore, SurrealKvStore};
use async_trait::async_trait;
use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
mod append;
mod append_batch;
mod global;
mod helpers;
mod metadata;
mod migration_cas;
mod migration_marker;
mod paging_all;
mod paging_chains;
mod paging_principal;
mod paging_session;
mod prune_chain;
mod prune_finish;
mod system;
use global::GlobalMetadata;
#[cfg(test)]
pub(crate) use global::GlobalMetadata as TestGlobalMetadata;
use helpers::{chain_head_key, parse_sequence};
use metadata::ChainMetadata;
#[cfg(test)]
pub(crate) use metadata::ChainMetadata as TestChainMetadata;
use system::AuditSystemNamespace;
#[async_trait]
pub(crate) trait AuditStorage: Send + Sync {
    async fn store(&self, entry: &AuditEntry) -> AuditResult<()>;

    async fn append_if_head(
        &self,
        entry: &AuditEntry,
        _expected: Option<&AuditEntryId>,
    ) -> AuditResult<bool> {
        self.store(entry).await?;
        Ok(true)
    }

    async fn append_batch_if_heads(
        &self,
        entries: &[(&AuditEntry, Option<&AuditEntryId>)],
    ) -> AuditResult<Vec<bool>> {
        let mut results = Vec::with_capacity(entries.len());
        for (entry, expected) in entries {
            results.push(self.append_if_head(entry, *expected).await?);
        }
        Ok(results)
    }

    async fn seal_chain(
        &self,
        _session_id: &SessionId,
        _principal: Option<&astrid_core::PrincipalId>,
    ) -> AuditResult<()> {
        Err(AuditError::StorageError(
            "audit backend does not support segment sealing".to_owned(),
        ))
    }

    async fn chain_metadata(
        &self,
        _session_id: &SessionId,
        _principal: Option<&astrid_core::PrincipalId>,
    ) -> AuditResult<Option<ChainMetadata>> {
        Ok(None)
    }

    async fn global_metadata(&self) -> AuditResult<GlobalMetadata> {
        Ok(GlobalMetadata::default())
    }

    async fn set_global_caps(&self, _entries: u64, _bytes: u64) -> AuditResult<()> {
        Err(AuditError::StorageError(
            "audit backend does not support retention caps".to_owned(),
        ))
    }

    async fn oldest_sealed_segment(
        &self,
    ) -> AuditResult<Option<(SessionId, Option<astrid_core::PrincipalId>, ChainMetadata)>> {
        Ok(None)
    }

    async fn prune_chain(
        &self,
        _session_id: &SessionId,
        _principal: Option<&astrid_core::PrincipalId>,
        _keep_entries: usize,
        _receipt: Vec<u8>,
    ) -> AuditResult<()> {
        Err(AuditError::StorageError(
            "audit backend does not support archive pruning".to_owned(),
        ))
    }

    async fn prune_receipt(
        &self,
        _session_id: &SessionId,
        _principal: Option<&astrid_core::PrincipalId>,
    ) -> AuditResult<Option<Vec<u8>>> {
        Ok(None)
    }

    async fn migration_marker(&self) -> AuditResult<Option<Vec<u8>>> {
        Ok(None)
    }

    async fn compare_and_swap_migration_marker(
        &self,
        expected: Option<&[u8]>,
        marker: Vec<u8>,
    ) -> AuditResult<bool> {
        let _ = (expected, marker);
        Err(AuditError::StorageError(
            "audit backend does not support migration receipts".to_owned(),
        ))
    }

    async fn get(&self, id: &AuditEntryId) -> AuditResult<Option<AuditEntry>>;

    async fn get_chain_head(
        &self,
        session_id: &SessionId,
        principal: Option<&astrid_core::PrincipalId>,
    ) -> AuditResult<Option<AuditEntryId>>;

    async fn get_session_entries(&self, session_id: &SessionId) -> AuditResult<Vec<AuditEntry>>;

    async fn get_session_entries_page(
        &self,
        session_id: &SessionId,
        after: Option<&str>,
        limit: usize,
    ) -> AuditResult<Vec<(String, AuditEntry)>> {
        let entries = self.get_session_entries(session_id).await?;
        Ok(entries
            .into_iter()
            .enumerate()
            .map(|(index, entry)| (format!("legacy:{index:020}"), entry))
            .filter(|(cursor, _)| after.is_none_or(|previous| cursor.as_str() > previous))
            .take(limit)
            .collect())
    }

    async fn all_entries_page(
        &self,
        after: Option<&str>,
        limit: usize,
    ) -> AuditResult<Vec<(String, AuditEntry)>> {
        let mut sessions = self.list_sessions().await?;
        sessions.sort_by_key(|session| session.0);
        let mut result = Vec::new();
        for session in sessions {
            let remaining = limit.saturating_sub(result.len());
            if remaining == 0 {
                break;
            }
            result.extend(
                self.get_session_entries_page(&session, after, remaining)
                    .await?,
            );
        }
        Ok(result)
    }

    async fn session_chains_page(
        &self,
        _session_id: &SessionId,
        _after: Option<&str>,
        _limit: usize,
    ) -> AuditResult<Vec<(String, Option<astrid_core::PrincipalId>)>> {
        Err(AuditError::UnsupportedOperation {
            operation: "bounded chain enumeration",
        })
    }

    async fn principal_entries_page(
        &self,
        _session_id: &SessionId,
        _principal: Option<&astrid_core::PrincipalId>,
        _after: Option<&str>,
        _limit: usize,
    ) -> AuditResult<Vec<(String, AuditEntry)>> {
        Err(AuditError::UnsupportedOperation {
            operation: "bounded principal-chain verification",
        })
    }

    async fn is_entry_committed(&self, _id: &AuditEntryId) -> AuditResult<bool> {
        Ok(false)
    }

    async fn clear_migration_temp(&self) -> AuditResult<()> {
        Err(AuditError::StorageError(
            "audit backend does not support migration scratch state".to_owned(),
        ))
    }

    async fn migration_temp_get(&self, _key: &str) -> AuditResult<Option<Vec<u8>>> {
        Ok(None)
    }

    async fn migration_temp_put(&self, _key: &str, _value: Vec<u8>) -> AuditResult<()> {
        Err(AuditError::StorageError(
            "audit backend does not support migration scratch state".to_owned(),
        ))
    }

    async fn migration_temp_cas(
        &self,
        _key: &str,
        _expected: Option<&[u8]>,
        _value: Vec<u8>,
    ) -> AuditResult<bool> {
        Err(AuditError::StorageError(
            "audit backend does not support migration scratch state".to_owned(),
        ))
    }

    async fn migration_temp_keys_page(
        &self,
        _prefix: &str,
        _after: Option<&str>,
        _limit: usize,
    ) -> AuditResult<Vec<String>> {
        Err(AuditError::StorageError(
            "audit backend does not support migration scratch state".to_owned(),
        ))
    }

    async fn count(&self) -> AuditResult<usize>;

    async fn count_session(&self, session_id: &SessionId) -> AuditResult<usize>;

    async fn list_sessions(&self) -> AuditResult<Vec<SessionId>>;

    async fn flush(&self) -> AuditResult<()>;

    async fn close(&self) -> AuditResult<()>;
}

const NS_ENTRIES: &str = "audit:entries";
const NS_SESSION_INDEX: &str = "audit:session_index";
const NS_SESSION_ENTRIES: &str = "audit:session_entries";
const NS_SESSION_SEQUENCE: &str = "audit:session_sequence";
const NS_CHAIN_HEADS: &str = "audit:chain_heads";
const NS_CHAIN_METADATA: &str = "audit:chain_metadata";
const NS_COMMITTED_ENTRIES: &str = "audit:committed_entries";
const NS_APPEND_INTENTS: &str = "audit:append_intents";
const NS_MIGRATION: &str = "audit:migrations";
const LEGACY_MIGRATION_KEY: &str = "legacy-principal-home-v1";
const NS_PRUNE_RECEIPTS: &str = "audit:prune_receipts";
const NS_PRUNE_PLANS: &str = "audit:prune_plans";
const NS_GLOBAL_METADATA: &str = "audit:global_metadata";
const NS_SEGMENT_INDEX: &str = "audit:segment_index";
pub(crate) const DEFAULT_SEGMENT_MAX_ENTRIES: u64 = 1_024;
pub(crate) const DEFAULT_SEGMENT_MAX_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct PrunePlan {
    receipt: Vec<u8>,
    keep_entries: usize,
    after: Option<String>,
    complete: bool,
    #[serde(default)]
    segment_key: Option<String>,
    #[serde(default)]
    segment_accounted: bool,
}

static DURABLE_APPEND_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

pub(crate) struct KvAuditStorage {
    store: Arc<dyn KvStore>,
}

impl KvAuditStorage {
    pub(crate) fn open_legacy_source(path: impl AsRef<Path>) -> AuditResult<Self> {
        let store =
            SurrealKvStore::open(path).map_err(|e| AuditError::StorageError(e.to_string()))?;
        Ok(Self {
            store: Arc::new(store),
        })
    }

    #[must_use]
    pub(crate) fn in_memory() -> Self {
        Self {
            store: Arc::new(MemoryKvStore::new()),
        }
    }

    #[cfg(test)]
    pub(crate) fn from_test_store(store: Arc<dyn KvStore>) -> Self {
        Self { store }
    }

    pub(crate) fn from_kv_store(store: Arc<dyn KvStore>) -> AuditResult<Self> {
        Ok(Self {
            store: Arc::new(AuditSystemNamespace::new(store)?),
        })
    }

    #[cfg(test)]
    pub(crate) async fn test_set_legacy_session_index(
        &self,
        session_id: &SessionId,
        bytes: Vec<u8>,
    ) -> AuditResult<()> {
        self.store
            .set(NS_SESSION_INDEX, &session_id.0.to_string(), bytes)
            .await
            .map_err(|error| AuditError::StorageError(error.to_string()))
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

    async fn load_chain_metadata(
        &self,
        session_id: &SessionId,
        principal: Option<&astrid_core::PrincipalId>,
    ) -> AuditResult<(Option<Vec<u8>>, Option<ChainMetadata>)> {
        let key = chain_head_key(session_id, principal);
        let bytes = self
            .store
            .get(NS_CHAIN_METADATA, &key)
            .await
            .map_err(|e| AuditError::StorageError(e.to_string()))?;
        let metadata = bytes
            .as_deref()
            .map(serde_json::from_slice)
            .transpose()
            .map_err(|e| AuditError::SerializationError(e.to_string()))?;
        Ok((bytes, metadata))
    }

    async fn persist_chain_metadata(
        &self,
        session_id: &SessionId,
        principal: Option<&astrid_core::PrincipalId>,
        expected: Option<&[u8]>,
        metadata: &ChainMetadata,
    ) -> AuditResult<bool> {
        let key = chain_head_key(session_id, principal);
        let bytes = serde_json::to_vec(metadata)
            .map_err(|e| AuditError::SerializationError(e.to_string()))?;
        self.store
            .compare_and_swap(NS_CHAIN_METADATA, &key, expected, bytes)
            .await
            .map_err(|e| AuditError::StorageError(e.to_string()))
    }

    async fn load_global_metadata(&self) -> AuditResult<(Option<Vec<u8>>, GlobalMetadata)> {
        let bytes = self
            .store
            .get(NS_GLOBAL_METADATA, "current")
            .await
            .map_err(|e| AuditError::StorageError(e.to_string()))?;
        let metadata = bytes
            .as_deref()
            .map(serde_json::from_slice)
            .transpose()
            .map_err(|e| AuditError::SerializationError(e.to_string()))?
            .unwrap_or_default();
        Ok((bytes, metadata))
    }

    async fn persist_global_metadata(
        &self,
        expected: Option<&[u8]>,
        metadata: &GlobalMetadata,
    ) -> AuditResult<bool> {
        let bytes = serde_json::to_vec(metadata)
            .map_err(|e| AuditError::SerializationError(e.to_string()))?;
        self.store
            .compare_and_swap(NS_GLOBAL_METADATA, "current", expected, bytes)
            .await
            .map_err(|e| AuditError::StorageError(e.to_string()))
    }
}

#[async_trait]
impl AuditStorage for KvAuditStorage {
    async fn clear_migration_temp(&self) -> AuditResult<()> {
        self.store
            .clear_prefix(NS_MIGRATION, "tmp:")
            .await
            .map_err(|e| AuditError::StorageError(e.to_string()))
            .map(|_| ())
    }

    async fn migration_temp_get(&self, key: &str) -> AuditResult<Option<Vec<u8>>> {
        self.store
            .get(NS_MIGRATION, &format!("tmp:{key}"))
            .await
            .map_err(|e| AuditError::StorageError(e.to_string()))
    }

    async fn migration_temp_put(&self, key: &str, value: Vec<u8>) -> AuditResult<()> {
        let key = format!("tmp:{key}");
        let existing = self
            .store
            .get(NS_MIGRATION, &key)
            .await
            .map_err(|e| AuditError::StorageError(e.to_string()))?;
        if let Some(existing) = existing {
            if existing != value {
                return Err(AuditError::StorageError(
                    "legacy audit migration scratch-index collision".to_owned(),
                ));
            }
            return Ok(());
        }
        self.store
            .compare_and_swap(NS_MIGRATION, &key, None, value)
            .await
            .map_err(|e| AuditError::StorageError(e.to_string()))?
            .then_some(())
            .ok_or_else(|| AuditError::StorageError("migration scratch CAS lost".to_owned()))
    }

    async fn migration_temp_cas(
        &self,
        key: &str,
        expected: Option<&[u8]>,
        value: Vec<u8>,
    ) -> AuditResult<bool> {
        self.store
            .compare_and_swap(NS_MIGRATION, &format!("tmp:{key}"), expected, value)
            .await
            .map_err(|e| AuditError::StorageError(e.to_string()))
    }

    async fn migration_temp_keys_page(
        &self,
        prefix: &str,
        after: Option<&str>,
        limit: usize,
    ) -> AuditResult<Vec<String>> {
        let keys = self
            .store
            .list_keys_with_prefix_page(
                NS_MIGRATION,
                &format!("tmp:{prefix}"),
                after.map(|cursor| format!("tmp:{cursor}")).as_deref(),
                limit,
            )
            .await
            .map_err(|e| AuditError::StorageError(e.to_string()))?;
        Ok(keys
            .into_iter()
            .filter_map(|key| key.strip_prefix("tmp:").map(ToOwned::to_owned))
            .collect())
    }

    async fn all_entries_page(
        &self,
        after: Option<&str>,
        limit: usize,
    ) -> AuditResult<Vec<(String, AuditEntry)>> {
        self.load_all_entries_page(after, limit).await
    }

    async fn session_chains_page(
        &self,
        session_id: &SessionId,
        after: Option<&str>,
        limit: usize,
    ) -> AuditResult<Vec<(String, Option<astrid_core::PrincipalId>)>> {
        self.load_session_chains_page(session_id, after, limit)
            .await
    }

    async fn principal_entries_page(
        &self,
        session_id: &SessionId,
        principal: Option<&astrid_core::PrincipalId>,
        after: Option<&str>,
        limit: usize,
    ) -> AuditResult<Vec<(String, AuditEntry)>> {
        self.load_principal_entries_page(session_id, principal, after, limit)
            .await
    }

    async fn is_entry_committed(&self, id: &AuditEntryId) -> AuditResult<bool> {
        if self
            .store
            .exists(NS_COMMITTED_ENTRIES, &id.0.to_string())
            .await
            .map_err(|e| AuditError::StorageError(e.to_string()))?
        {
            return Ok(true);
        }
        if let Some(entry) = self.get(id).await?
            && self
                .store
                .exists(NS_SESSION_SEQUENCE, &entry.session_id.0.to_string())
                .await
                .map_err(|e| AuditError::StorageError(e.to_string()))?
        {
            return Ok(false);
        }
        for session in self.list_sessions().await? {
            if self
                .get_session_entries(&session)
                .await?
                .into_iter()
                .any(|entry| entry.id == *id)
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    async fn get_session_entries_page(
        &self,
        session_id: &SessionId,
        after: Option<&str>,
        limit: usize,
    ) -> AuditResult<Vec<(String, AuditEntry)>> {
        self.load_session_entries_page(session_id, after, limit)
            .await
    }

    async fn migration_marker(&self) -> AuditResult<Option<Vec<u8>>> {
        self.load_migration_marker().await
    }

    async fn compare_and_swap_migration_marker(
        &self,
        expected: Option<&[u8]>,
        marker: Vec<u8>,
    ) -> AuditResult<bool> {
        self.compare_and_swap_stored_migration_marker(expected, marker)
            .await
    }

    async fn append_if_head(
        &self,
        entry: &AuditEntry,
        expected: Option<&AuditEntryId>,
    ) -> AuditResult<bool> {
        self.append_if_head_durable(entry, expected).await
    }

    async fn append_batch_if_heads(
        &self,
        entries: &[(&AuditEntry, Option<&AuditEntryId>)],
    ) -> AuditResult<Vec<bool>> {
        self.append_batch_if_heads_durable(entries).await
    }

    async fn seal_chain(
        &self,
        session_id: &SessionId,
        principal: Option<&astrid_core::PrincipalId>,
    ) -> AuditResult<()> {
        let _guard = DURABLE_APPEND_LOCK.lock().await;
        let (expected, Some(mut metadata)) =
            self.load_chain_metadata(session_id, principal).await?
        else {
            return Err(AuditError::StorageError(
                "cannot seal an untracked audit chain".to_owned(),
            ));
        };
        if metadata.sealed {
            return Ok(());
        }
        metadata.sealed = true;
        if self
            .persist_chain_metadata(session_id, principal, expected.as_deref(), &metadata)
            .await?
        {
            Ok(())
        } else {
            Err(AuditError::StorageError(
                "audit chain metadata changed while sealing".to_owned(),
            ))
        }
    }

    async fn chain_metadata(
        &self,
        session_id: &SessionId,
        principal: Option<&astrid_core::PrincipalId>,
    ) -> AuditResult<Option<ChainMetadata>> {
        self.load_chain_metadata(session_id, principal)
            .await
            .map(|(_, metadata)| metadata)
    }

    async fn global_metadata(&self) -> AuditResult<GlobalMetadata> {
        self.load_global_metadata()
            .await
            .map(|(_, metadata)| metadata)
    }

    async fn set_global_caps(&self, entries: u64, bytes: u64) -> AuditResult<()> {
        if entries == 0 || bytes == 0 {
            return Err(AuditError::StorageError(
                "audit retention caps must be positive".to_owned(),
            ));
        }
        let _guard = DURABLE_APPEND_LOCK.lock().await;
        let (expected, mut metadata) = self.load_global_metadata().await?;
        metadata.cap_entries = entries;
        metadata.cap_bytes = bytes;
        metadata.degraded = metadata.total_count > entries || metadata.total_bytes > bytes;
        metadata.last_error = metadata.degraded.then(|| {
            "system audit retention cap is below current usage; prune sealed segments".to_owned()
        });
        if self
            .persist_global_metadata(expected.as_deref(), &metadata)
            .await?
        {
            Ok(())
        } else {
            Err(AuditError::StorageError(
                "audit global retention caps changed concurrently".to_owned(),
            ))
        }
    }

    async fn oldest_sealed_segment(
        &self,
    ) -> AuditResult<Option<(SessionId, Option<astrid_core::PrincipalId>, ChainMetadata)>> {
        let keys = self
            .store
            .list_keys_with_prefix_page(NS_SEGMENT_INDEX, "", None, 1)
            .await
            .map_err(|error| AuditError::StorageError(error.to_string()))?;
        let Some(index_key) = keys.into_iter().next() else {
            return Ok(None);
        };
        let descriptor = self
            .store
            .get(NS_SEGMENT_INDEX, &index_key)
            .await
            .map_err(|error| AuditError::StorageError(error.to_string()))?
            .ok_or_else(|| {
                AuditError::StorageError("audit segment descriptor disappeared".to_owned())
            })?;
        let metadata: ChainMetadata = serde_json::from_slice(&descriptor)
            .map_err(|error| AuditError::SerializationError(error.to_string()))?;
        let (_, chain_with_segment) = index_key.split_once(':').ok_or_else(|| {
            AuditError::StorageError("invalid audit segment index key".to_owned())
        })?;
        let (chain, _) = chain_with_segment.rsplit_once(':').ok_or_else(|| {
            AuditError::StorageError("invalid audit segment index key".to_owned())
        })?;
        let (session, principal) = chain
            .split_once(':')
            .map_or((chain, None), |(session, principal)| {
                (session, Some(principal))
            });
        let session = uuid::Uuid::parse_str(session)
            .map_err(|error| AuditError::StorageError(error.to_string()))?;
        let principal = principal
            .map(astrid_core::PrincipalId::new)
            .transpose()
            .map_err(|error| AuditError::StorageError(error.to_string()))?;
        Ok(Some((SessionId::from_uuid(session), principal, metadata)))
    }

    async fn prune_chain(
        &self,
        session_id: &SessionId,
        principal: Option<&astrid_core::PrincipalId>,
        keep_entries: usize,
        receipt: Vec<u8>,
    ) -> AuditResult<()> {
        self.prune_chain_durable(session_id, principal, keep_entries, receipt)
            .await
    }

    async fn prune_receipt(
        &self,
        session_id: &SessionId,
        principal: Option<&astrid_core::PrincipalId>,
    ) -> AuditResult<Option<Vec<u8>>> {
        self.store
            .get(NS_PRUNE_RECEIPTS, &chain_head_key(session_id, principal))
            .await
            .map_err(|e| AuditError::StorageError(e.to_string()))
    }

    async fn store(&self, entry: &AuditEntry) -> AuditResult<()> {
        let entry_key = entry.id.0.to_string();
        let session_key = entry.session_id.0.to_string();

        let entry_data =
            serde_json::to_vec(entry).map_err(|e| AuditError::SerializationError(e.to_string()))?;

        self.store
            .set(NS_ENTRIES, &entry_key, entry_data)
            .await
            .map_err(|e| AuditError::StorageError(e.to_string()))?;

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
        if let (_, Some(metadata)) = self.load_chain_metadata(session_id, principal).await?
            && let Some(head) = metadata.head
            && self.get(&head).await?.is_some_and(|entry| {
                &entry.session_id == session_id && entry.principal.as_ref() == principal
            })
        {
            return Ok(Some(head));
        }

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
        let session_key = session_id.0.to_string();
        let mut keys = self
            .store
            .list_keys_with_prefix(NS_CHAIN_METADATA, &format!("{session_key}:"))
            .await
            .map_err(|e| AuditError::StorageError(e.to_string()))?;
        if self
            .store
            .exists(NS_CHAIN_METADATA, &session_key)
            .await
            .map_err(|e| AuditError::StorageError(e.to_string()))?
        {
            keys.push(session_key);
        }
        if keys.is_empty() {
            return Ok(self.get_session_entry_ids(session_id).await?.len());
        }
        let mut total = 0usize;
        for key in keys {
            let bytes = self
                .store
                .get(NS_CHAIN_METADATA, &key)
                .await
                .map_err(|e| AuditError::StorageError(e.to_string()))?
                .ok_or_else(|| {
                    AuditError::StorageError("audit chain metadata disappeared".into())
                })?;
            let metadata: ChainMetadata = serde_json::from_slice(&bytes)
                .map_err(|e| AuditError::SerializationError(e.to_string()))?;
            total = total.saturating_add(usize::try_from(metadata.count).unwrap_or(usize::MAX));
        }
        Ok(total)
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
        Ok(())
    }

    async fn close(&self) -> AuditResult<()> {
        self.store
            .close()
            .await
            .map_err(|e| AuditError::StorageError(e.to_string()))
    }
}

impl std::fmt::Debug for KvAuditStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KvAuditStorage").finish_non_exhaustive()
    }
}

#[cfg(test)]
#[path = "storage_tests.rs"]
mod tests;
