//! Retryable signed summaries, separate from custody of complete GC evidence.

use astrid_audit::{
    AuditAction, AuditEntry, AuditError, AuditLog, AuditOutcome, AuthorizationProof,
};
use astrid_capabilities::AuditEntryId;
use astrid_core::SessionId;
use astrid_storage::RuntimePrincipalStore;
use astrid_storage::engine::{CompactionEvidenceBundle, CompactionReport};

pub(super) async fn record_summary(
    audit: &AuditLog,
    store: &RuntimePrincipalStore,
    session: &SessionId,
    bundle: &CompactionEvidenceBundle,
    report: &CompactionReport,
) -> Result<(), AuditError> {
    let records = [
        bundle.fact_snapshot(),
        bundle.retention_policy(),
        bundle.tensor_logic_proof(),
        bundle.plan(),
        bundle.placement_before(),
        bundle.placement_after(),
        bundle.execution_measurements(),
        bundle.commit(),
    ];
    let digest = super::bundle_digest(&records);
    let commit = bundle.commit_id().object_id();
    let summaries = store
        .system_control_kv("audit")
        .map_err(|error| storage_error(&error))?;
    let key = format!("gc-summary:{}", hex::encode(commit.as_bytes()));
    if let Some(id) = summaries
        .get_json::<AuditEntryId>(&key)
        .await
        .map_err(|error| storage_error(&error))?
        && let Some(entry) = audit.get(&id).await?
    {
        return if matches_summary(&entry, commit.as_bytes(), &digest) {
            Ok(())
        } else {
            Err(AuditError::StorageError(
                "checkpointed compaction summary failed verification".to_owned(),
            ))
        };
    }

    let mut params = serde_json::json!({
        "gc_commit": commit.as_bytes().to_vec(),
        "evidence_digest": digest,
    });
    // An older bundle may be retrying its first summary after a failed append.
    // Its measurements are in its retained evidence, not in this newer report.
    if bundle.commit_id() == report.gc_commit() {
        params["objects_reclaimed"] = report.objects_reclaimed().into();
        params["arena_bytes_before"] = report.arena_bytes_before().into();
        params["arena_bytes_after"] = report.arena_bytes_after().into();
    }
    let id = audit
        .append(
            session.clone(),
            AuditAction::AdminRequest {
                method: "AuditPhysicalCompaction".to_owned(),
                required_capability: "audit:prune".to_owned(),
                target_principal: None,
                params: Some(params),
                device_key_id: None,
            },
            AuthorizationProof::System {
                reason: "audit prune physical compaction summary".to_owned(),
            },
            AuditOutcome::success(),
        )
        .await?;
    let entry = audit.get(&id).await?.ok_or_else(|| {
        AuditError::StorageError("compaction summary read-back is missing".to_owned())
    })?;
    if !matches_summary(&entry, commit.as_bytes(), &digest) {
        return Err(AuditError::StorageError(
            "compaction summary read-back failed verification".to_owned(),
        ));
    }
    // A crash before this durable marker can repeat a summary, but cannot lose
    // the bundle. A marker never authorizes deleting the complete evidence.
    summaries
        .set_json(&key, &id)
        .await
        .map_err(|error| storage_error(&error))
}

fn matches_summary(entry: &AuditEntry, commit: &[u8; 32], digest: &[u8]) -> bool {
    entry.verify_signature().is_ok()
        && matches!(
            &entry.action,
            AuditAction::AdminRequest { method, params: Some(value), .. }
                if method == "AuditPhysicalCompaction"
                    && value.get("gc_commit") == Some(&serde_json::json!(commit))
                    && value.get("evidence_digest") == Some(&serde_json::json!(digest))
        )
}

fn storage_error(error: &astrid_storage::StorageError) -> AuditError {
    AuditError::StorageError(format!("compaction summary checkpoint: {error}"))
}
