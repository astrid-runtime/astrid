//! Native bulk move of a legacy `SurrealKV` audit tree into [`AuditLog`].

use super::migration::{
    decode_receipt, digest_legacy_source, digest_storage, import_legacy_graph, index_legacy_source,
    payload_matches, validate_destination, validate_legacy_source_path,
};
use super::{
    AuditError, AuditLog, AuditResult, AuditStorage, KvAuditStorage, LegacyAuditImportReport,
};
use std::path::Path;

impl AuditLog {
    pub(super) async fn import_legacy_audit_impl(
        &self,
        legacy_path: impl AsRef<Path>,
        destination_identity: &str,
    ) -> AuditResult<LegacyAuditImportReport> {
        let legacy_path = legacy_path.as_ref().to_path_buf();
        let marker_before = self.storage.migration_marker().await?;

        if !validate_legacy_source_path(&legacy_path)? {
            return self
                .report_missing_legacy_source(marker_before, destination_identity)
                .await;
        }

        let source = KvAuditStorage::open_legacy_source(&legacy_path)?;
        let (receipt, graph) = index_legacy_source(&source, destination_identity).await?;
        self.ensure_migration_capacity(&receipt)?;
        if let Some(existing) = marker_before.as_deref() {
            let prior = decode_receipt(existing)?;
            if !payload_matches(&prior, &receipt) {
                return Err(AuditError::StorageError(
                    "legacy audit migration receipt conflicts with source or destination"
                        .to_owned(),
                ));
            }
        }

        let imported_entries = import_legacy_graph(self, &source, &graph).await?;
        let source_after = digest_legacy_source(&source, destination_identity).await?;
        if !payload_matches(&receipt, &source_after) {
            return Err(AuditError::StorageError(
                "legacy audit source changed during native volume move".to_owned(),
            ));
        }
        let destination = digest_storage(self.storage.as_ref(), destination_identity).await?;
        if !payload_matches(&receipt, &destination) {
            return Err(AuditError::StorageError(
                "native audit reconstruction does not match the source payload digest".to_owned(),
            ));
        }
        source.close().await?;
        self.storage.clear_migration_temp().await?;
        validate_destination(&receipt, destination_identity)?;
        let marker = serde_json::to_vec(&receipt)
            .map_err(|error| AuditError::SerializationError(error.to_string()))?;
        let marker_installed = self
            .install_migration_marker(marker_before.as_deref(), marker)
            .await?;
        Ok(LegacyAuditImportReport {
            source_entries: receipt.source_entries,
            imported_entries,
            marker_installed,
            source_digest: receipt.source_digest,
        })
    }

    async fn report_missing_legacy_source(
        &self,
        marker: Option<Vec<u8>>,
        destination_identity: &str,
    ) -> AuditResult<LegacyAuditImportReport> {
        let Some(marker_bytes) = marker else {
            return Ok(LegacyAuditImportReport {
                source_entries: 0,
                imported_entries: 0,
                marker_installed: false,
                source_digest: String::new(),
            });
        };
        let receipt = decode_receipt(&marker_bytes)?;
        validate_destination(&receipt, destination_identity)?;
        let destination = digest_storage(self.storage.as_ref(), destination_identity).await?;
        if !payload_matches(&receipt, &destination) {
            return Err(AuditError::StorageError(
                "native audit reconstruction does not match the stored migration receipt"
                    .to_owned(),
            ));
        }
        Ok(LegacyAuditImportReport {
            source_entries: receipt.source_entries,
            imported_entries: 0,
            marker_installed: false,
            source_digest: receipt.source_digest,
        })
    }

    async fn install_migration_marker(
        &self,
        marker_before: Option<&[u8]>,
        marker: Vec<u8>,
    ) -> AuditResult<bool> {
        if marker_before.is_some() {
            return Ok(false);
        }
        if self
            .storage
            .compare_and_swap_migration_marker(None, marker.clone())
            .await?
        {
            return Ok(true);
        }
        let Some(existing) = self.storage.migration_marker().await? else {
            return Err(AuditError::StorageError(
                "audit migration marker CAS failed without a durable marker".to_owned(),
            ));
        };
        if existing != marker {
            return Err(AuditError::StorageError(
                "audit migration marker conflict".to_owned(),
            ));
        }
        Ok(false)
    }
}
