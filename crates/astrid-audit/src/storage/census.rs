//! Entry/session census over the audit KV projection.

use super::metadata::ChainMetadata;
use super::{
    KvAuditStorage, NS_CHAIN_HEADS, NS_CHAIN_METADATA, NS_COMMITTED_ENTRIES, NS_ENTRIES,
    NS_SESSION_ENTRIES, NS_SESSION_INDEX,
};
use crate::error::{AuditError, AuditResult};
use astrid_core::SessionId;
use std::collections::HashSet;

impl KvAuditStorage {
    pub(super) async fn record_count(&self) -> AuditResult<usize> {
        let committed = self
            .store
            .list_keys(NS_COMMITTED_ENTRIES)
            .await
            .map_err(|e| AuditError::StorageError(e.to_string()))?;
        if !committed.is_empty() {
            return Ok(committed.len());
        }
        self.store
            .list_keys(NS_ENTRIES)
            .await
            .map(|keys| keys.len())
            .map_err(|e| AuditError::StorageError(e.to_string()))
    }

    pub(super) async fn session_record_count(&self, session_id: &SessionId) -> AuditResult<usize> {
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

    pub(super) async fn session_ids(&self) -> AuditResult<Vec<SessionId>> {
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
        let head_keys = self
            .store
            .list_keys(NS_CHAIN_HEADS)
            .await
            .map_err(|e| AuditError::StorageError(e.to_string()))?;

        let mut sessions = HashSet::new();
        for key in legacy_keys.into_iter().chain(new_keys).chain(head_keys) {
            let session = key.split(':').next().unwrap_or(key.as_str());
            if let Ok(uuid) = uuid::Uuid::parse_str(session) {
                sessions.insert(SessionId::from_uuid(uuid));
            }
        }

        let mut sessions: Vec<_> = sessions.into_iter().collect();
        sessions.sort_by_key(|session| session.0);
        Ok(sessions)
    }
}
