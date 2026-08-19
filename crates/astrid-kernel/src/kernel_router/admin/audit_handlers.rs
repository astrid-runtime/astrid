//! Operator-only audit accounting, retention, and ingestion-health handlers.
//!
//! These handlers never open a native audit directory and never expose entry
//! payloads. They operate on the kernel's system-owned [`AuditLog`] handle and
//! return bounded metadata or a signed archive-receipt summary.

use std::sync::Arc;

use astrid_audit::{AuditAction, AuditLog, AuditOutcome, AuditRetentionPolicy, AuthorizationProof};
use astrid_core::SessionId;
use astrid_core::kernel_api::{AdminResponseBody, AuditHealth, AuditPruneResult, AuditStats};

use crate::Kernel;

/// Return O(1) system-wide audit accounting and retention state.
pub(super) async fn stats(kernel: &Arc<Kernel>) -> AdminResponseBody {
    match kernel.audit_log.global_stats().await {
        Ok(stats) => AdminResponseBody::AuditStats(AuditStats {
            total_count: stats.total_count,
            total_bytes: stats.total_bytes,
            sealed_segments: stats.sealed_segments,
            segments: stats.segments,
            eligible_segments: stats.eligible_segments,
            cap_entries: stats.cap_entries,
            cap_bytes: stats.cap_bytes,
            degraded: stats.degraded,
            last_error: stats.last_error,
        }),
        Err(error) => AdminResponseBody::Error(format!("audit stats unavailable: {error}")),
    }
}

/// Prune the oldest eligible sealed segment and return its signed receipt
/// summary. The byte/count minima are deliberately validated here, before
/// invoking the retention planner, so a CLI typo cannot request delete-all.
pub(super) async fn prune(
    kernel: &Arc<Kernel>,
    retain_entries: u64,
    retain_bytes: Option<u64>,
) -> AdminResponseBody {
    if retain_entries == 0 {
        return AdminResponseBody::Error("audit prune requires retain_entries >= 1".to_owned());
    }
    if retain_bytes == Some(0) {
        return AdminResponseBody::Error("audit prune retain_bytes must be > 0".to_owned());
    }
    let Ok(retain_entries) = usize::try_from(retain_entries) else {
        return AdminResponseBody::Error("audit prune retain_entries is too large".to_owned());
    };
    let policy = AuditRetentionPolicy {
        retain_entries,
        retain_bytes,
    };
    let receipt = match kernel.audit_log.prune_oldest(policy).await {
        Ok(Some(receipt)) => receipt,
        Ok(None) => {
            return AdminResponseBody::Error(
                "audit prune found no eligible sealed segment".to_owned(),
            );
        },
        Err(error) => return AdminResponseBody::Error(format!("audit prune failed: {error}")),
    };
    let encoded = match serde_json::to_vec(&receipt) {
        Ok(encoded) => encoded,
        Err(error) => {
            return AdminResponseBody::Error(format!("audit receipt encoding failed: {error}"));
        },
    };
    let logical_reclaimed_count = receipt.omitted_count;
    let logical_reclaimed_bytes = receipt.omitted_bytes;
    let (physical_reclaimed_bytes, physical_reclaim_pending) =
        compact_after_prune(kernel, &encoded, retain_entries, retain_bytes).await;
    AdminResponseBody::AuditPruned(Box::new(AuditPruneResult {
        generation: receipt.generation,
        receipt_hash: blake3::hash(&encoded).to_hex().to_string(),
        session: receipt.session,
        principal: receipt.principal,
        segment: receipt.segment,
        seal_ordinal: receipt.seal_ordinal,
        omitted_count: receipt.omitted_count,
        omitted_bytes: receipt.omitted_bytes,
        retained_count: receipt.retained_count,
        retained_bytes: receipt.retained_bytes,
        logical_reclaimed_count,
        logical_reclaimed_bytes,
        physical_reclaimed_bytes,
        physical_reclaim_pending,
    }))
}

#[cfg(not(target_family = "wasm"))]
async fn compact_after_prune(
    kernel: &Arc<Kernel>,
    receipt: &[u8],
    retain_entries: usize,
    retain_bytes: Option<u64>,
) -> (u64, bool) {
    use astrid_storage::storage_model::{
        ObjectClass, ObjectFormatVersion, ObjectId, ObjectKind, ObjectRecord,
    };

    let Some(store) = kernel.principal_store.as_ref() else {
        return (0, true);
    };
    let operation_contract = ObjectId::new(*blake3::hash(receipt).as_bytes());
    let Ok(policy_bytes) = serde_json::to_vec(&(retain_entries, retain_bytes)) else {
        return (0, true);
    };
    let Ok(policy) = ObjectRecord::new(
        ObjectKind::Evidence,
        ObjectFormatVersion::V1,
        policy_bytes,
        Vec::new(),
        0,
        ObjectClass::Metadata,
    ) else {
        return (0, true);
    };
    let report = match store
        .compact_with_deterministic_proof(operation_contract, policy, Vec::new())
        .await
    {
        Ok(report) => report,
        Err(error) => {
            tracing::warn!(error = %error, "audit prune physical compaction is pending");
            return (0, true);
        },
    };
    deliver_compaction_evidence(
        kernel.audit_log.as_ref(),
        store,
        &kernel.session_id,
        &report,
    )
    .await
}

#[cfg(not(target_family = "wasm"))]
async fn deliver_compaction_evidence(
    audit_log: &AuditLog,
    store: &astrid_storage::RuntimePrincipalStore,
    session_id: &SessionId,
    report: &astrid_storage::engine::CompactionReport,
) -> (u64, bool) {
    let reclaimed_bytes = report
        .arena_bytes_before()
        .saturating_sub(report.arena_bytes_after());
    let pending = match store.pending_compaction_evidence() {
        Ok(pending) => pending,
        Err(error) => {
            tracing::warn!(error = %error, "audit compaction evidence is unavailable");
            return (reclaimed_bytes, true);
        },
    };
    for bundle in pending {
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
        let evidence_digest = bundle_digest(&records);
        let expected_digest = evidence_digest.clone();
        let params = serde_json::json!({
            "gc_commit": bundle.commit_id().object_id().as_bytes().to_vec(),
            "evidence_digest": evidence_digest,
            "objects_reclaimed": report.objects_reclaimed(),
            "arena_bytes_before": report.arena_bytes_before(),
            "arena_bytes_after": report.arena_bytes_after(),
        });
        let event_id = match audit_log
            .append(
                session_id.clone(),
                AuditAction::AdminRequest {
                    method: "AuditPhysicalCompaction".to_owned(),
                    required_capability: "audit:prune".to_owned(),
                    target_principal: None,
                    params: Some(params),
                    device_key_id: None,
                },
                AuthorizationProof::System {
                    reason: "audit prune physical compaction receipt".to_owned(),
                },
                AuditOutcome::success(),
            )
            .await
        {
            Ok(id) => id,
            Err(error) => {
                tracing::warn!(error = %error, "audit compaction receipt persistence failed");
                return (reclaimed_bytes, true);
            },
        };
        let Some(persisted) = audit_log.get(&event_id).await.ok().flatten() else {
            tracing::warn!("audit compaction receipt read-back is missing");
            return (reclaimed_bytes, true);
        };
        let readback_ok = match &persisted.action {
            AuditAction::AdminRequest {
                params: Some(value),
                ..
            } => value.get("evidence_digest") == Some(&serde_json::json!(expected_digest)),
            _ => false,
        };
        if persisted.verify_signature().is_err() || !readback_ok {
            tracing::warn!("audit compaction receipt read-back failed verification");
            return (reclaimed_bytes, true);
        }
        if let Err(error) = store.acknowledge_compaction_evidence(bundle.commit_id()) {
            tracing::warn!(error = %error, "audit compaction receipt acknowledgement failed");
            return (reclaimed_bytes, true);
        }
    }
    (reclaimed_bytes, false)
}

#[cfg(not(target_family = "wasm"))]
fn bundle_digest(records: &[&astrid_storage::storage_model::ObjectRecord; 8]) -> Vec<u8> {
    let mut digest = blake3::Hasher::new_derive_key("astrid audit compaction evidence v1");
    for record in records {
        digest.update(&record.kind().code().to_be_bytes());
        digest.update(&record.format_version().get().to_be_bytes());
        digest.update(&[record.class().code()]);
        digest.update(&record.logical_bytes().to_be_bytes());
        digest.update(
            &u64::try_from(record.canonical_bytes().len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        digest.update(record.canonical_bytes());
        digest.update(
            &u64::try_from(record.references().len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        for reference in record.references() {
            digest.update(
                &u64::try_from(reference.label().as_bytes().len())
                    .unwrap_or(u64::MAX)
                    .to_be_bytes(),
            );
            digest.update(reference.label().as_bytes());
            digest.update(reference.target().as_bytes());
            digest.update(&[reference.kind().code()]);
        }
    }
    digest.finalize().as_bytes().to_vec()
}

#[cfg(target_family = "wasm")]
async fn compact_after_prune(
    _kernel: &Arc<Kernel>,
    _receipt: &[u8],
    _retain_entries: usize,
    _retain_bytes: Option<u64>,
) -> (u64, bool) {
    (0, true)
}

/// Return bounded queue and writer health for the shared system audit sink.
pub(super) fn health(kernel: &Arc<Kernel>) -> AdminResponseBody {
    let health = kernel.audit_sink.health();
    AdminResponseBody::AuditHealth(AuditHealth {
        accepted: health.accepted,
        persisted: health.persisted,
        failed: health.failed,
        queue_full: health.queue_full,
        queue_depth: health.queue_depth,
        worker_alive: health.worker_alive,
        degraded: health.degraded,
        last_error: health.last_error,
    })
}
