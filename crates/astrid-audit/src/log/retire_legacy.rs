//! Retirement phases live in the existing durable audit MOVE receipt.

use super::migration::{
    CompletedRetirement, LegacyAuditReceipt, LegacyRetirementRecord, StagedRetirement,
    decode_receipt, validate_destination, validate_legacy_source_path,
};
use super::{AuditError, AuditLog, AuditResult};
use astrid_storage::{LegacyRetirementIntent, LegacySource, LegacySourceKind};
use std::path::Path;

impl AuditLog {
    /// Retire a verified source, or resume its previously authorized retirement.
    ///
    /// Database sources MOVE to a generation stage, persist Staged, then
    /// delete only that stage. Empty sources retire in place on first live
    /// capture; a later Authorized empty original is refused. Restart never
    /// deletes a name after Staged: a restored occupant is not the stage.
    ///
    /// # Errors
    ///
    /// Returns an error on a missing/conflicting MOVE receipt, changed source,
    /// empty Authorized retry while the original remains, failed flush, or
    /// ambiguous/replaced retirement stage.
    pub async fn retire_legacy_audit(
        &self,
        legacy_path: impl AsRef<Path>,
        staging_root: impl AsRef<Path>,
        destination_identity: &str,
    ) -> AuditResult<()> {
        let legacy_path = legacy_path.as_ref();
        let staging_root = staging_root.as_ref();
        let marker = self.storage.migration_marker().await?;
        if !validate_legacy_source_path(legacy_path)? {
            return self
                .retire_absent_original(marker, staging_root, destination_identity)
                .await;
        }
        let marker = marker.ok_or_else(|| {
            AuditError::StorageError("legacy retirement requires a durable MOVE receipt".to_owned())
        })?;
        let receipt = decode_receipt(&marker)?;
        validate_destination(&receipt, destination_identity)?;
        match receipt.retirement.clone() {
            Some(LegacyRetirementRecord::Completed(_)) => Ok(()),
            Some(LegacyRetirementRecord::Staged(staged)) => {
                self.finish_staged(staging_root, &marker, receipt, staged.staged)
                    .await
            },
            Some(LegacyRetirementRecord::Authorized(intent)) => {
                self.retire_authorized_present(
                    legacy_path,
                    staging_root,
                    destination_identity,
                    marker,
                    receipt,
                    intent,
                )
                .await
            },
            None => {
                self.retire_fresh_present(
                    legacy_path,
                    staging_root,
                    destination_identity,
                    marker,
                    receipt,
                )
                .await
            },
        }
    }

    async fn retire_absent_original(
        &self,
        marker: Option<Vec<u8>>,
        staging_root: &Path,
        destination_identity: &str,
    ) -> AuditResult<()> {
        let Some(marker) = marker else {
            return Ok(());
        };
        let receipt = decode_receipt(&marker)?;
        validate_destination(&receipt, destination_identity)?;
        match receipt.retirement.clone() {
            None | Some(LegacyRetirementRecord::Completed(_)) => Ok(()),
            Some(LegacyRetirementRecord::Staged(staged)) => {
                self.finish_staged(staging_root, &marker, receipt, staged.staged)
                    .await
            },
            Some(LegacyRetirementRecord::Authorized(intent))
                if intent.kind() == LegacySourceKind::LockedDatabase =>
            {
                // The original name is gone, so MOVE may already have happened
                // before Staged was durable. Publish Staged first so a later
                // occupant of that name cannot be adopted as the stage.
                let staged_receipt = with_phase(
                    receipt,
                    LegacyRetirementRecord::Staged(StagedRetirement {
                        staged: intent.clone(),
                    }),
                );
                let staged_marker = self.persist_phase(&marker, &staged_receipt).await?;
                astrid_storage::resume_staged_legacy_retirement(staging_root, &intent)
                    .await
                    .map_err(storage_error)?;
                self.complete_phase(&staged_marker, staged_receipt, intent)
                    .await
            },
            Some(LegacyRetirementRecord::Authorized(intent)) => {
                self.complete_phase(&marker, receipt, intent).await
            },
        }
    }

    async fn retire_authorized_present(
        &self,
        legacy_path: &Path,
        staging_root: &Path,
        destination_identity: &str,
        marker: Vec<u8>,
        receipt: LegacyAuditReceipt,
        intent: LegacyRetirementIntent,
    ) -> AuditResult<()> {
        let expected_digest = receipt.source_digest.clone();
        self.with_verified_legacy_source(
            legacy_path,
            destination_identity,
            &expected_digest,
            async |source| {
                self.prove_reopened_destination(destination_identity, &receipt)
                    .await?;
                match source.kind() {
                    LegacySourceKind::EmptyDirectory => Err(AuditError::StorageError(
                        "legacy empty source retirement already authorized; refusing to delete a present original"
                            .to_owned(),
                    )),
                    LegacySourceKind::LockedDatabase
                        if source.matches_retirement_intent(&intent) =>
                    {
                        // Earlier writer may have CAS'd Authorized without a
                        // durability fence. Flush before MOVE.
                        let current = self.persist_phase(&marker, &receipt).await?;
                        self.stage_then_complete(source, staging_root, &current, receipt, intent)
                            .await
                    },
                    LegacySourceKind::LockedDatabase => Err(AuditError::StorageError(
                        "legacy retirement source identity conflicts with MOVE receipt"
                            .to_owned(),
                    )),
                }
            },
        )
        .await
    }

    async fn retire_fresh_present(
        &self,
        legacy_path: &Path,
        staging_root: &Path,
        destination_identity: &str,
        marker: Vec<u8>,
        receipt: LegacyAuditReceipt,
    ) -> AuditResult<()> {
        let expected_digest = receipt.source_digest.clone();
        self.with_verified_legacy_source(
            legacy_path,
            destination_identity,
            &expected_digest,
            async |source| {
                self.prove_reopened_destination(destination_identity, &receipt)
                    .await?;
                let intent = source.retirement_intent();
                let authorized =
                    with_phase(receipt, LegacyRetirementRecord::Authorized(intent.clone()));
                let authorized_marker = self.persist_phase(&marker, &authorized).await?;
                match source.kind() {
                    LegacySourceKind::EmptyDirectory => {
                        source
                            .retire(&intent, staging_root)
                            .await
                            .map_err(storage_error)?;
                        self.complete_phase(&authorized_marker, authorized, intent)
                            .await
                    },
                    LegacySourceKind::LockedDatabase => {
                        self.stage_then_complete(
                            source,
                            staging_root,
                            &authorized_marker,
                            authorized,
                            intent,
                        )
                        .await
                    },
                }
            },
        )
        .await
    }

    async fn stage_then_complete(
        &self,
        source: LegacySource,
        staging_root: &Path,
        current_marker: &[u8],
        current_receipt: LegacyAuditReceipt,
        intent: LegacyRetirementIntent,
    ) -> AuditResult<()> {
        let stage = source
            .stage_retirement(&intent, staging_root)
            .await
            .map_err(storage_error)?;
        let staged_receipt = with_phase(
            current_receipt,
            LegacyRetirementRecord::Staged(StagedRetirement {
                staged: intent.clone(),
            }),
        );
        let staged_marker = self.persist_phase(current_marker, &staged_receipt).await?;
        stage.retire().await.map_err(storage_error)?;
        self.complete_phase(&staged_marker, staged_receipt, intent)
            .await
    }

    async fn finish_staged(
        &self,
        staging_root: &Path,
        marker: &[u8],
        receipt: LegacyAuditReceipt,
        intent: LegacyRetirementIntent,
    ) -> AuditResult<()> {
        // Earlier writer may have CAS'd Staged without a durability fence.
        let current = self.persist_phase(marker, &receipt).await?;
        astrid_storage::resume_staged_legacy_retirement(staging_root, &intent)
            .await
            .map_err(storage_error)?;
        self.complete_phase(&current, receipt, intent).await
    }

    async fn complete_phase(
        &self,
        expected: &[u8],
        receipt: LegacyAuditReceipt,
        intent: LegacyRetirementIntent,
    ) -> AuditResult<()> {
        let completed = with_phase(
            receipt,
            LegacyRetirementRecord::Completed(CompletedRetirement { completed: intent }),
        );
        self.persist_phase(expected, &completed).await?;
        Ok(())
    }

    /// CAS a new phase, or flush an already-read phase, then fence durability.
    async fn persist_phase(
        &self,
        expected: &[u8],
        receipt: &LegacyAuditReceipt,
    ) -> AuditResult<Vec<u8>> {
        let encoded = serde_json::to_vec(receipt)
            .map_err(|error| AuditError::SerializationError(error.to_string()))?;
        if encoded != expected
            && !self
                .storage
                .compare_and_swap_migration_marker(Some(expected), encoded.clone())
                .await?
        {
            return Err(AuditError::StorageError(
                "legacy retirement authorization conflicts with MOVE receipt".to_owned(),
            ));
        }
        self.storage.flush().await?;
        Ok(encoded)
    }
}

fn with_phase(
    mut receipt: LegacyAuditReceipt,
    retirement: LegacyRetirementRecord,
) -> LegacyAuditReceipt {
    receipt.retirement = Some(retirement);
    receipt
}

fn storage_error(error: astrid_storage::StorageError) -> AuditError {
    AuditError::StorageError(error.to_string())
}
