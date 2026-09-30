//! Operator-only audit accounting, retention, ingestion-health and anchoring
//! handlers.
//!
//! These handlers never open a native audit directory. They operate on the
//! kernel's system-owned [`AuditLog`] handle and return bounded metadata, a
//! signed archive-receipt summary, a runtime-key-signed chain-head snapshot,
//! or one bounded page of a chain's raw signed entries for external anchoring.

use std::sync::Arc;

use astrid_audit::{
    AuditAction, AuditChainHead, AuditChainPruneState, AuditEntry, AuditError, AuditLog,
    AuditOutcome, AuditRetentionPolicy, AuthorizationProof,
};
use astrid_core::kernel_api::{
    AUDIT_OMITTED_TOTAL_UNKNOWN, AdminRequestKind, AdminResponseBody, AuditExportEntry,
    AuditExportPage, AuditExportReceipt, AuditExportRequest, AuditHeadsChain, AuditHeadsPrune,
    AuditHeadsSnapshot, AuditHealth, AuditPruneResult, AuditStats,
};
use astrid_core::{PrincipalId, SessionId, Timestamp};

use crate::Kernel;

/// Default entries per `audit.export` page.
const EXPORT_DEFAULT_LIMIT: u32 = 500;
/// Hard cap on entries per `audit.export` page.
const EXPORT_MAX_LIMIT: u32 = 1_000;
/// Budget in bytes for the serialized entries of one export page. Admin
/// responses cross the event bus and the native uplink, whose per-client
/// egress queue holds four times this budget, so a page ends early when its
/// entries are large.
const EXPORT_PAGE_BYTES: usize = 1024 * 1024;
/// Largest serialized entry an export page returns. An entry above the page
/// budget is returned alone so the chain can be read past it, up to this
/// ceiling, which leaves room for the page envelope inside one native uplink
/// frame (twice the page budget). A larger entry fails the page with an
/// error that names it.
const EXPORT_ENTRY_MAX_BYTES: usize = EXPORT_PAGE_BYTES * 3 / 2;
/// Entries read per storage call. A single entry can be nearly as large as
/// the page budget, so this bounds what an export holds in memory while it
/// skips to a `from` index or fills a page up to the byte budget.
const EXPORT_READ_BATCH: usize = 32;
/// Largest unpaged heads snapshot (roughly 600 bytes of JSON per chain).
const HEADS_MAX_CHAINS: usize = 4_096;
/// Most prune receipts in one export page (each about 2,500 bytes).
const EXPORT_MAX_RECEIPTS: usize = 32;

/// Whether an authorized admin request skips the generic success audit row.
///
/// The anchoring service polls `audit.heads` and `audit.export` every few
/// seconds and marks what it anchored with `audit.anchor_mark`. A success
/// row per call would grow the log being anchored by tens of thousands of
/// entries a day, and each mark would leave a new unanchored entry behind.
/// Denied requests are still recorded before dispatch, and an authorized
/// request that fails (an unknown chain, a rejected cursor or mark, a
/// storage error) is recorded after it; see [`skipped_row_failure`].
pub(super) fn omit_success_admin_audit(request: &AdminRequestKind) -> bool {
    matches!(
        request,
        AdminRequestKind::AuditHeads
            | AdminRequestKind::AuditExport(_)
            | AdminRequestKind::AuditAnchorMark(_)
    )
}

/// The failure to record for a request whose success row is skipped: the
/// handler's error, or the chains an anchor mark rejected.
pub(super) fn skipped_row_failure(body: &AdminResponseBody) -> Option<String> {
    match body {
        AdminResponseBody::Error(error) => Some(error.clone()),
        other => super::audit_anchor_handlers::rejected_marks(other),
    }
}

/// Return a runtime-key-signed snapshot of every audit chain head.
///
/// The runtime Ed25519 key signs the raw bytes of
/// [`AuditHeadsSnapshot::signed_bytes_v1`] directly, with no pre-hash.
pub(super) async fn heads(kernel: &Arc<Kernel>) -> AdminResponseBody {
    let records = match kernel.audit_log.heads_snapshot().await {
        Ok(records) => records,
        Err(error) => {
            return AdminResponseBody::Error(format!("audit heads unavailable: {error}"));
        },
    };
    if records.len() > HEADS_MAX_CHAINS {
        return AdminResponseBody::Error(format!(
            "audit heads: {} chains exceed the unpaged snapshot limit of {HEADS_MAX_CHAINS}",
            records.len()
        ));
    }
    let mut chains: Vec<AuditHeadsChain> = records.iter().map(heads_chain).collect();
    chains.sort_by(|left, right| chain_order(left).cmp(&chain_order(right)));
    let snapshot_time_ns = Timestamp::now()
        .0
        .timestamp_nanos_opt()
        .and_then(|nanos| u64::try_from(nanos).ok())
        .unwrap_or(0);
    let mut snapshot = AuditHeadsSnapshot {
        signed_bytes_hex: String::new(),
        signature_hex: String::new(),
        runtime_public_key_hex: kernel.runtime_key.export_public_key().to_hex(),
        snapshot_time_ns,
        chains,
    };
    let signed_bytes = match snapshot.signed_bytes_v1() {
        Ok(bytes) => bytes,
        Err(error) => {
            return AdminResponseBody::Error(format!("audit heads encoding failed: {error}"));
        },
    };
    snapshot.signature_hex = kernel.runtime_key.sign(&signed_bytes).to_hex();
    snapshot.signed_bytes_hex = hex::encode(&signed_bytes);
    AdminResponseBody::AuditHeads(Box::new(snapshot))
}

fn chain_order(chain: &AuditHeadsChain) -> (&str, Option<&str>) {
    (
        chain.session.as_str(),
        chain.principal.as_ref().map(PrincipalId::as_str),
    )
}

fn heads_chain(record: &AuditChainHead) -> AuditHeadsChain {
    AuditHeadsChain {
        session: record.session_id.0.to_string(),
        principal: record.principal.clone(),
        count: record.count,
        omitted_total: record.omitted_total.unwrap_or(AUDIT_OMITTED_TOTAL_UNKNOWN),
        head_hash_hex: record.head_hash.to_hex(),
        head_id: record.head.as_ref().map(|id| id.0.to_string()),
        last_timestamp: record.last_timestamp.map(rfc3339),
        prune: record.prune.as_ref().map(|state| AuditHeadsPrune {
            generation: state.receipt.generation,
            omitted_count: state.receipt.omitted_count,
            omitted_terminal_hash_hex: state.receipt.omitted_terminal_hash.clone(),
            receipt_hash_hex: state.receipt_hash.to_hex(),
        }),
    }
}

fn rfc3339(timestamp: Timestamp) -> String {
    timestamp
        .0
        .to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true)
}

/// Return one bounded page of a chain's raw signed entries in chain order.
pub(super) async fn export(kernel: &Arc<Kernel>, request: AuditExportRequest) -> AdminResponseBody {
    match export_page(kernel.audit_log.as_ref(), request).await {
        Ok(page) => AdminResponseBody::AuditExport(Box::new(page)),
        Err(error) => AdminResponseBody::Error(format!("audit export failed: {error}")),
    }
}

async fn export_page(
    log: &AuditLog,
    request: AuditExportRequest,
) -> Result<AuditExportPage, String> {
    let AuditExportRequest {
        session,
        principal,
        from,
        cursor,
        limit,
        receipts_from,
    } = request;
    let principal = principal.as_ref();
    let limit = usize::try_from(
        limit
            .unwrap_or(EXPORT_DEFAULT_LIMIT)
            .clamp(1, EXPORT_MAX_LIMIT),
    )
    .map_err(|error| error.to_string())?;
    let prune_before = settled_prune_state(log, &session, principal).await?;
    let chain = log
        .chain_stats(&session, principal)
        .await
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "audit chain not found".to_owned())?;
    let (from, after) = match cursor {
        Some(cursor) => {
            let (index, key) = resume_export_cursor(log, &session, principal, &cursor).await?;
            if index > chain.count {
                return Err(
                    "audit export cursor is past the retained chain; restart from an index"
                        .to_owned(),
                );
            }
            (index, Some(key))
        },
        None => skip_to_index(log, &session, principal, from).await?,
    };
    let ExportedEntries {
        entries,
        after,
        complete,
    } = read_export_entries(log, &session, principal, from, after, limit).await?;
    let next_index = from.saturating_add(u64::try_from(entries.len()).unwrap_or(u64::MAX));
    let (prune_receipts, next_receipts_from) = match receipts_from {
        Some(from_generation) => export_receipts(log, &session, principal, from_generation).await?,
        None => (Vec::new(), None),
    };
    let prune = settled_prune_state(log, &session, principal).await?;
    if prune.as_ref().map(|state| state.receipt_hash)
        != prune_before.as_ref().map(|state| state.receipt_hash)
    {
        return Err("audit chain was pruned during the export; retry".to_owned());
    }
    let receipt = ExportedReceipt::new(prune)?;
    Ok(AuditExportPage {
        session: session.0.to_string(),
        principal: principal.cloned(),
        from,
        entries,
        next_index,
        next_cursor: after.map(|key| format!("{next_index}:{key}")),
        complete,
        chain_count: chain.count,
        chain_head_hash_hex: chain.head_hash.to_hex(),
        prune_receipt: receipt.receipt,
        prune_receipt_hash_hex: receipt.hash_hex,
        prune_receipt_signing_data_hex: receipt.signing_data_hex,
        prune_receipts,
        next_receipts_from,
    })
}

/// A bounded run of a chain's prune receipts from `from_generation` on, and
/// the generation that continues it when the run is full.
async fn export_receipts(
    log: &AuditLog,
    session: &SessionId,
    principal: Option<&PrincipalId>,
    from_generation: u64,
) -> Result<(Vec<AuditExportReceipt>, Option<u64>), String> {
    let states = log
        .prune_receipts(session, principal, from_generation, EXPORT_MAX_RECEIPTS)
        .await
        .map_err(|error| error.to_string())?;
    let next = if states.len() == EXPORT_MAX_RECEIPTS {
        states
            .last()
            .map(|state| state.receipt.generation.saturating_add(1))
    } else {
        None
    };
    let receipts = states
        .into_iter()
        .map(|state| {
            let exported = ExportedReceipt::new(Some(state.clone()))?;
            Ok(AuditExportReceipt {
                generation: state.receipt.generation,
                receipt: exported.receipt.unwrap_or_default(),
                receipt_hash_hex: exported.hash_hex.unwrap_or_default(),
                signing_data_hex: exported.signing_data_hex.unwrap_or_default(),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok((receipts, next))
}

/// The entries of one export page and where the next page resumes.
struct ExportedEntries {
    entries: Vec<AuditExportEntry>,
    /// Storage cursor of the last exported entry, or the starting cursor
    /// when the page is empty.
    after: Option<String>,
    /// Whether no further entry existed when the page was read.
    complete: bool,
}

/// Read up to `limit` entries after `after`, numbered from `from`, stopping
/// at the page byte budget.
///
/// Entries are read [`EXPORT_READ_BATCH`] at a time, one more than the page
/// still needs when that fits, so reading stops as soon as the page is full
/// and a following entry, if any, shows the page is not complete.
async fn read_export_entries(
    log: &AuditLog,
    session: &SessionId,
    principal: Option<&PrincipalId>,
    from: u64,
    mut after: Option<String>,
    limit: usize,
) -> Result<ExportedEntries, String> {
    let mut entries = Vec::new();
    let mut page_bytes = 0_usize;
    loop {
        let want = limit
            .saturating_sub(entries.len())
            .saturating_add(1)
            .min(EXPORT_READ_BATCH);
        let batch = log
            .chain_entries_page(session, principal, after.as_deref(), want)
            .await
            .map_err(|error| error.to_string())?;
        let exhausted = batch.len() < want;
        for (key, entry) in batch {
            if entries.len() == limit {
                return Ok(ExportedEntries {
                    entries,
                    after,
                    complete: false,
                });
            }
            let index = from.saturating_add(u64::try_from(entries.len()).unwrap_or(u64::MAX));
            let exported = export_entry(index, &entry)?;
            let size = serde_json::to_vec(&exported)
                .map_err(|error| error.to_string())?
                .len();
            if !entries.is_empty() && page_bytes.saturating_add(size) > EXPORT_PAGE_BYTES {
                return Ok(ExportedEntries {
                    entries,
                    after,
                    complete: false,
                });
            }
            if size > EXPORT_ENTRY_MAX_BYTES {
                return Err(format!(
                    "audit entry {} at index {index} exports as {size} bytes, above the \
                     {EXPORT_ENTRY_MAX_BYTES}-byte limit",
                    exported.id
                ));
            }
            page_bytes = page_bytes.saturating_add(size);
            after = Some(key);
            entries.push(exported);
        }
        if exhausted {
            return Ok(ExportedEntries {
                entries,
                after,
                complete: true,
            });
        }
    }
}

/// A chain's latest prune receipt as an export page carries it.
#[derive(Default)]
struct ExportedReceipt {
    /// The receipt as stored.
    receipt: Option<serde_json::Value>,
    /// Hex BLAKE3 of the stored receipt bytes.
    hash_hex: Option<String>,
    /// Hex of the bytes the receipt signature covers.
    signing_data_hex: Option<String>,
}

impl ExportedReceipt {
    fn new(prune: Option<AuditChainPruneState>) -> Result<Self, String> {
        let Some(state) = prune else {
            return Ok(Self::default());
        };
        let signing_data = state
            .receipt
            .signing_data()
            .map_err(|error| error.to_string())?;
        Ok(Self {
            receipt: Some(
                serde_json::from_slice(&state.stored_bytes).map_err(|error| error.to_string())?,
            ),
            hash_hex: Some(state.receipt_hash.to_hex()),
            signing_data_hex: Some(hex::encode(signing_data)),
        })
    }
}

/// Read a chain's latest prune receipt, failing while a prune is in progress.
///
/// A prune deletes entries only while it is in progress and installs a new
/// receipt when it finishes. The export reads this before and after its
/// metadata, cursor and entry reads and requires the same receipt, so a page
/// never mixes states from before and after a prune. The in-progress check
/// precedes the receipt read, so a prune that starts between the two cannot
/// have deleted an entry the page already read. An interrupted prune stays
/// in progress until the next prune of the chain resumes and finishes it.
async fn settled_prune_state(
    log: &AuditLog,
    session: &SessionId,
    principal: Option<&PrincipalId>,
) -> Result<Option<AuditChainPruneState>, String> {
    if log
        .prune_in_progress(session, principal)
        .await
        .map_err(|error| error.to_string())?
    {
        return Err("audit chain has a prune in progress; retry once it finishes".to_owned());
    }
    log.prune_state(session, principal)
        .await
        .map_err(|error| error.to_string())
}

/// Split an export cursor `"<next index>:<storage cursor>"` and check that
/// the storage cursor is a stored index key of an entry of the requested
/// chain.
///
/// The storage cursor is a session-index key `"<session>:<sequence>:<entry
/// id>"` shared by every chain of the session and compared lexically when
/// paging, so a cursor taken from another principal's export, or one with an
/// altered sequence, would silently skip entries of this chain. The index is
/// carried by the caller and is not authenticated; entry hashes and links
/// are what a verifier relies on.
async fn resume_export_cursor(
    log: &AuditLog,
    session: &SessionId,
    principal: Option<&PrincipalId>,
    cursor: &str,
) -> Result<(u64, String), String> {
    let malformed = || "malformed audit export cursor".to_owned();
    let (index, key) = cursor.split_once(':').ok_or_else(malformed)?;
    let index = index.parse::<u64>().map_err(|_| malformed())?;
    if !key.starts_with(&format!("{}:", session.0)) {
        return Err("audit export cursor does not belong to this session".to_owned());
    }
    let entry = log
        .chain_cursor_entry(key)
        .await
        .map_err(|error| error.to_string())?
        .ok_or_else(|| {
            "audit export cursor names no retained entry; restart from an index".to_owned()
        })?;
    if &entry.session_id != session || entry.principal.as_ref() != principal {
        return Err("audit export cursor belongs to another chain".to_owned());
    }
    Ok((index, key.to_owned()))
}

/// Walk the chain to retained index `from` and return the reached index with
/// the storage cursor of the entry before it. A chain shorter than `from`
/// stops at its end.
async fn skip_to_index(
    log: &AuditLog,
    session: &SessionId,
    principal: Option<&PrincipalId>,
    from: u64,
) -> Result<(u64, Option<String>), String> {
    let mut reached = 0_u64;
    let mut after: Option<String> = None;
    while reached < from {
        let want = usize::try_from(from.saturating_sub(reached))
            .unwrap_or(usize::MAX)
            .min(EXPORT_READ_BATCH);
        let page = log
            .chain_entries_page(session, principal, after.as_deref(), want)
            .await
            .map_err(|error| error.to_string())?;
        let Some((last, _)) = page.last() else {
            break;
        };
        after = Some(last.clone());
        reached = reached.saturating_add(u64::try_from(page.len()).unwrap_or(u64::MAX));
        if page.len() < want {
            break;
        }
    }
    Ok((reached, after))
}

fn export_entry(index: u64, entry: &AuditEntry) -> Result<AuditExportEntry, String> {
    let signing_data = entry.signing_data();
    Ok(AuditExportEntry {
        index,
        id: entry.id.0.to_string(),
        timestamp: rfc3339(entry.timestamp),
        previous_hash_hex: entry.previous_hash.to_hex(),
        content_hash_hex: entry.content_hash().to_hex(),
        signature_hex: entry.signature.to_hex(),
        public_key_hex: entry.runtime_key.to_hex(),
        signing_data_hex: hex::encode(&signing_data),
        entry: serde_json::to_value(entry).map_err(|error| error.to_string())?,
    })
}

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
            retention_hold: stats.retention_hold,
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
        Err(AuditError::UnanchoredPrune(reason)) => {
            return AdminResponseBody::Error(format!("audit prune refused: {reason}"));
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
