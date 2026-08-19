use super::{
    AuditEntry, AuditEntryId, AuditError, AuditResult, AuditStorage, KvAuditStorage,
    NS_SESSION_ENTRIES,
};
use astrid_core::{PrincipalId, SessionId};

impl KvAuditStorage {
    pub(super) async fn load_principal_entries_page(
        &self,
        session_id: &SessionId,
        principal: Option<&PrincipalId>,
        after: Option<&str>,
        limit: usize,
    ) -> AuditResult<Vec<(String, AuditEntry)>> {
        let session_key = session_id.0.to_string();
        let prefix = format!("{session_key}:");
        let mut cursor = after.map(ToOwned::to_owned);
        let mut result = Vec::with_capacity(limit.min(256));
        while result.len() < limit {
            let page_limit = limit.saturating_sub(result.len()).clamp(1, 256);
            let keys = self
                .store
                .list_keys_with_prefix_page(
                    NS_SESSION_ENTRIES,
                    &prefix,
                    cursor.as_deref(),
                    page_limit,
                )
                .await
                .map_err(|error| AuditError::StorageError(error.to_string()))?;
            let Some(last) = keys.last().cloned() else {
                break;
            };
            for key in &keys {
                let (_, encoded_id) = key.rsplit_once(':').ok_or_else(|| {
                    AuditError::StorageError(format!("invalid audit session index key: {key}"))
                })?;
                let id = AuditEntryId(
                    uuid::Uuid::parse_str(encoded_id)
                        .map_err(|error| AuditError::StorageError(error.to_string()))?,
                );
                let entry = self.get(&id).await?.ok_or_else(|| {
                    AuditError::StorageError(format!("audit page points to missing entry {id}"))
                })?;
                if entry.principal.as_ref() == principal {
                    result.push((key.clone(), entry));
                    if result.len() == limit {
                        break;
                    }
                }
            }
            cursor = Some(last);
            if keys.len() < page_limit {
                break;
            }
        }
        Ok(result)
    }
}
