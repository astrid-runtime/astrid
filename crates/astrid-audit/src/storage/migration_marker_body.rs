{
self.store
    .get(NS_MIGRATION, LEGACY_MIGRATION_KEY)
    .await
    .map_err(|e| AuditError::StorageError(e.to_string()))
}
