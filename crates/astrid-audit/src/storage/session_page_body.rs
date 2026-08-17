{
let session_key = session_id.0.to_string();
let prefix = format!("{session_key}:");
let keys = self
    .store
    .list_keys_with_prefix_page(NS_SESSION_ENTRIES, &prefix, after, limit)
    .await
    .map_err(|e| AuditError::StorageError(e.to_string()))?;
if !keys.is_empty() {
    let mut page = Vec::with_capacity(keys.len());
    for key in keys {
        let (_, encoded_id) = key.rsplit_once(':').ok_or_else(|| {
            AuditError::StorageError(format!("invalid audit session index key: {key}"))
        })?;
        let id = uuid::Uuid::parse_str(encoded_id)
            .map_err(|e| AuditError::StorageError(e.to_string()))?;
        let id = AuditEntryId(id);
        let entry = self.get(&id).await?.ok_or_else(|| {
            AuditError::StorageError(format!("audit page points to missing entry {id}"))
        })?;
        page.push((key, entry));
    }
    return Ok(page);
}
if after.is_some() {
    return Ok(Vec::new());
}
// Released pre-page stores kept one JSON index array. This fallback is
// intentionally isolated; new stores always use per-sequence records.
let ids = self.get_legacy_session_entry_ids(session_id).await?;
let mut page = Vec::with_capacity(ids.len().min(limit));
for (index, id) in ids.into_iter().enumerate().take(limit) {
    if let Some(entry) = self.get(&id).await? {
        page.push((format!("legacy:{index:020}"), entry));
    }
}
Ok(page)
}
