{
let keys = self
    .store
    .list_keys_with_prefix_page(NS_ENTRIES, "", after, limit)
    .await
    .map_err(|e| AuditError::StorageError(e.to_string()))?;
let mut entries = Vec::with_capacity(keys.len());
for key in keys {
    let id =
        uuid::Uuid::parse_str(&key).map_err(|e| AuditError::StorageError(e.to_string()))?;
    let raw = self
        .store
        .get(NS_ENTRIES, &key)
        .await
        .map_err(|e| AuditError::StorageError(e.to_string()))?
        .ok_or_else(|| {
            AuditError::StorageError(format!("audit entry page points to missing {key}"))
        })?;
    let entry: AuditEntry = serde_json::from_slice(&raw)
        .map_err(|e| AuditError::SerializationError(e.to_string()))?;
    let canonical = serde_json::to_vec(&entry)
        .map_err(|e| AuditError::SerializationError(e.to_string()))?;
    if canonical != raw || entry.id != AuditEntryId(id) {
        return Err(AuditError::StorageError(format!(
            "audit entry {key} is not byte-canonical"
        )));
    }
    entries.push((key, entry));
}
Ok(entries)
}
