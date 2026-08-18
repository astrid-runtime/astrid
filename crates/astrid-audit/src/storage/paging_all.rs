use super::{AuditEntry, AuditEntryId, AuditError, AuditResult, KvAuditStorage, NS_ENTRIES};

impl KvAuditStorage {
    pub(super) async fn load_all_entries_page(
        &self,
        after: Option<&str>,
        limit: usize,
    ) -> AuditResult<Vec<(String, AuditEntry)>> {
        let keys = self
            .store
            .list_keys_with_prefix_page(NS_ENTRIES, "", after, limit)
            .await
            .map_err(|error| AuditError::StorageError(error.to_string()))?;
        let mut entries = Vec::with_capacity(keys.len());
        for key in keys {
            let id = uuid::Uuid::parse_str(&key)
                .map_err(|error| AuditError::StorageError(error.to_string()))?;
            let raw = self
                .store
                .get(NS_ENTRIES, &key)
                .await
                .map_err(|error| AuditError::StorageError(error.to_string()))?
                .ok_or_else(|| {
                    AuditError::StorageError(format!("audit entry page points to missing {key}"))
                })?;
            let entry: AuditEntry = serde_json::from_slice(&raw)
                .map_err(|error| AuditError::SerializationError(error.to_string()))?;
            let canonical = serde_json::to_vec(&entry)
                .map_err(|error| AuditError::SerializationError(error.to_string()))?;
            if canonical != raw || entry.id != AuditEntryId(id) {
                return Err(AuditError::StorageError(format!(
                    "audit entry {key} is not byte-canonical"
                )));
            }
            entries.push((key, entry));
        }
        Ok(entries)
    }
}
