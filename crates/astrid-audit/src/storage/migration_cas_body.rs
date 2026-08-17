{
self.store
    .compare_and_swap(NS_MIGRATION, LEGACY_MIGRATION_KEY, expected, marker)
    .await
    .map_err(|e| AuditError::StorageError(e.to_string()))
}
