use super::{AuditError, AuditResult, KvAuditStorage, LEGACY_MIGRATION_KEY, NS_MIGRATION};

impl KvAuditStorage {
    pub(super) async fn compare_and_swap_stored_migration_marker(
        &self,
        expected: Option<&[u8]>,
        marker: Vec<u8>,
    ) -> AuditResult<bool> {
        self.store
            .compare_and_swap(NS_MIGRATION, LEGACY_MIGRATION_KEY, expected, marker)
            .await
            .map_err(|error| AuditError::StorageError(error.to_string()))
    }
}
