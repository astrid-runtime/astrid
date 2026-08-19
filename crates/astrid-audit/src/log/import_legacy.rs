//! Legacy native audit import implementation.

use super::migration::{
    LegacyAuditReceipt, decode_receipt, digest_legacy_source, import_legacy_chains,
    scan_legacy_source, validate_destination, validate_legacy_source_path,
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
        // Estimate capacity before creating migration scratch keys. The source
        // remains authoritative until all digest/read-back checks complete.
        let source_estimate = digest_legacy_source(&source, destination_identity).await?;
        self.ensure_migration_capacity(&source_estimate)?;
        let receipt =
            scan_legacy_source(&source, self.storage.as_ref(), destination_identity).await?;
        let marker = serde_json::to_vec(&receipt)
            .map_err(|error| AuditError::SerializationError(error.to_string()))?;
        if marker_before
            .as_deref()
            .is_some_and(|existing| existing != marker)
        {
            return Err(AuditError::StorageError(
                "legacy audit migration receipt conflicts with source or destination".to_owned(),
            ));
        }

        let second_receipt = digest_legacy_source(&source, destination_identity).await?;
        require_matching_receipt(
            &receipt,
            &second_receipt,
            "legacy audit source changed during streaming import",
        )?;
        let imported_entries = import_legacy_chains(self, &source).await?;
        let final_receipt = digest_legacy_source(&source, destination_identity).await?;
        require_matching_receipt(
            &receipt,
            &final_receipt,
            "legacy audit source changed during forward import",
        )?;
        source.close().await?;
        self.storage.clear_migration_temp().await?;

        self.verify_receipted_destination(&receipt).await?;
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
        self.verify_receipted_destination(&receipt).await?;
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

fn require_matching_receipt(
    expected: &LegacyAuditReceipt,
    actual: &LegacyAuditReceipt,
    error: &str,
) -> AuditResult<()> {
    if actual.schema != expected.schema
        || actual.destination != expected.destination
        || actual.source_entries != expected.source_entries
        || actual.source_bytes != expected.source_bytes
        || actual.source_digest != expected.source_digest
    {
        return Err(AuditError::StorageError(error.to_owned()));
    }
    Ok(())
}
