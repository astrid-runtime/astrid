{
let session_key = session_id.0.to_string();
let prefix = format!("{session_key}:");
let key_limit = if after.is_none() { limit.saturating_sub(1) } else { limit };
let keys = self
    .store
    .list_keys_with_prefix_page(NS_CHAIN_METADATA, &prefix, after, key_limit)
    .await
    .map_err(|error| AuditError::StorageError(error.to_string()))?;
let mut result = Vec::with_capacity(keys.len());
for key in keys {
    let principal = key
        .strip_prefix(&prefix)
        .ok_or_else(|| AuditError::StorageError("invalid chain metadata key".to_owned()))?;
    let principal = astrid_core::PrincipalId::new(principal)
        .map_err(|error| AuditError::StorageError(error.to_string()))?;
    result.push((key, Some(principal)));
}
if after.is_none()
    && result.len() < limit
    && self.store.exists(NS_CHAIN_METADATA, &session_key).await
        .map_err(|error| AuditError::StorageError(error.to_string()))?
{
    result.insert(0, (session_key, None));
    result.truncate(limit);
}
Ok(result)
}
