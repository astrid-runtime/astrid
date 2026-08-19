use super::{AuditError, AuditResult, KvAuditStorage, LEGACY_MIGRATION_KEY, NS_MIGRATION};

impl KvAuditStorage {
    pub(super) async fn load_migration_marker(&self) -> AuditResult<Option<Vec<u8>>> {
        self.store
            .get(NS_MIGRATION, LEGACY_MIGRATION_KEY)
            .await
            .map_err(|error| AuditError::StorageError(error.to_string()))
    }
}
