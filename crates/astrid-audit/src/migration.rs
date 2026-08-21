// Bounded, chain-aware import of legacy principal-home audit records.

use crate::entry::AuditEntry;
use crate::error::{AuditError, AuditResult};
use crate::log::AuditLog;
use crate::storage::{AuditStorage, KvAuditStorage};
use astrid_capabilities::AuditEntryId;
use astrid_core::{PrincipalId, SessionId};
use std::path::Path;

/// Validate the legacy source boundary without following a redirected root.
///
/// The kernel performs a stronger recursive tree/device/mount validation before
/// retirement.  Keeping this small no-follow check in the audit crate closes
/// the earlier open-before-preflight window for callers that use the migration
/// API directly.
pub(crate) fn validate_legacy_source_path(path: &Path) -> AuditResult<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            Err(AuditError::StorageError(format!(
                "legacy audit source is redirected or not a directory: {}",
                path.display()
            )))
        },
        Ok(_) => {
            astrid_core::platform_fs::verify_no_redirects(path)
                .map_err(|error| AuditError::StorageError(error.to_string()))?;
            Ok(true)
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(AuditError::StorageError(error.to_string())),
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub(crate) struct LegacyAuditChainReceipt {
    pub(crate) session: String,
    pub(crate) principal: Option<String>,
    pub(crate) count: u64,
    pub(crate) terminal_hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub(crate) struct LegacyAuditReceipt {
    pub(crate) schema: u8,
    pub(crate) destination: String,
    pub(crate) source_entries: u64,
    pub(crate) source_bytes: u64,
    pub(crate) source_digest: String,
    /// Number of verified source chains, retained as O(1) metadata.
    #[serde(default)]
    pub(crate) chain_count: u64,
    /// Digest over canonical, key-ordered chain receipt fragments.
    #[serde(default)]
    pub(crate) chain_digest: String,
    /// Legacy compatibility field. New receipts never serialize this vector;
    /// chain fragments live in disposable paged scratch keys while migrating.
    #[serde(default, skip_serializing)]
    pub(crate) chains: Vec<LegacyAuditChainReceipt>,
}

pub(crate) struct ReceiptAccumulator {
    digest: [u8; 32],
    pub(crate) source_entries: u64,
    source_bytes: u64,
}

/// Maximum migration-receipt bytes accepted from a previous interrupted run.
///
/// Older receipts could embed one JSON chain fragment per session. The current
/// format stores only a count and digest, but a bounded decoder is still needed
/// when reopening a receipt written by an older release; reject oversized bytes
/// before `serde_json` can allocate a large compatibility vector.
pub(crate) const MAX_LEGACY_RECEIPT_BYTES: usize = 8 * 1024 * 1024;

/// Fixed scratch/receipt overhead reserved before a legacy import mutates the
/// destination projection. This covers migration state, chain fragments, and
/// receipt publication without depending on the number of sessions.
pub(crate) const LEGACY_MIGRATION_FIXED_OVERHEAD_BYTES: u64 = 4 * 1024 * 1024;
/// Per-entry index and transaction overhead reserved for the destination
/// entry, committed/session indexes, and bounded scratch markers.
pub(crate) const LEGACY_MIGRATION_ENTRY_OVERHEAD_BYTES: u64 = 768;

/// Estimate destination bytes required while the native source remains
/// present. The estimate is deliberately conservative and overflow-safe:
/// failure to represent it is a capacity refusal, never permission to write.
pub(crate) fn estimated_migration_bytes(source_bytes: u64, source_entries: u64) -> Option<u64> {
    source_bytes
        .checked_add(source_entries.checked_mul(LEGACY_MIGRATION_ENTRY_OVERHEAD_BYTES)?)?
        .checked_add(LEGACY_MIGRATION_FIXED_OVERHEAD_BYTES)
}

impl ReceiptAccumulator {
    pub(crate) fn new() -> Self {
        Self {
            digest: [0; 32],
            source_entries: 0,
            source_bytes: 0,
        }
    }

    pub(crate) fn add(&mut self, entry: &AuditEntry, bytes: &[u8]) {
        let mut page = blake3::Hasher::new_derive_key("astrid audit legacy import v1");
        page.update(&self.digest);
        page.update(entry.session_id.0.as_bytes());
        page.update(&u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
        page.update(bytes);
        self.digest = *page.finalize().as_bytes();
        self.source_entries = self.source_entries.saturating_add(1);
        self.source_bytes = self
            .source_bytes
            .saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
    }

    pub(crate) fn finish(
        self,
        destination_identity: &str,
        chain_count: u64,
        chain_digest: String,
    ) -> LegacyAuditReceipt {
        LegacyAuditReceipt {
            schema: 1,
            destination: destination_identity.to_owned(),
            source_entries: self.source_entries,
            source_bytes: self.source_bytes,
            source_digest: blake3::Hash::from_bytes(self.digest).to_hex().to_string(),
            chain_count,
            chain_digest,
            chains: Vec::new(),
        }
    }
}

/// Must stay at or below the durable `append_batch` atomic entry ceiling.
/// Larger batches fall back to per-row CAS, which is the cutover failure mode.
const LEGACY_MOVE_BATCH_ENTRIES: usize = 128;

pub(crate) struct LegacySourceGraph {
    successor: std::collections::HashMap<astrid_crypto::ContentHash, AuditEntryId>,
    geneses: Vec<AuditEntryId>,
}

fn chain_identity_key(session: &SessionId, principal: Option<&PrincipalId>) -> String {
    format!(
        "{}:{}",
        session,
        principal.map_or("<system>", PrincipalId::as_str)
    )
}

/// Hash canonical stored entry bytes. Cutover does not recertify Ed25519.
pub(crate) async fn digest_legacy_source(
    source: &KvAuditStorage,
    destination_identity: &str,
) -> AuditResult<LegacyAuditReceipt> {
    digest_storage(source, destination_identity).await
}

pub(crate) async fn digest_storage(
    storage: &dyn AuditStorage,
    destination_identity: &str,
) -> AuditResult<LegacyAuditReceipt> {
    let mut accumulator = ReceiptAccumulator::new();
    let mut after = None;
    loop {
        let page = storage.all_entries_page(after.as_deref(), 256).await?;
        if page.is_empty() {
            break;
        }
        let next_after = page.last().map(|(cursor, _)| cursor.clone());
        for (_, entry) in page {
            let bytes = serde_json::to_vec(&entry)
                .map_err(|error| AuditError::SerializationError(error.to_string()))?;
            accumulator.add(&entry, &bytes);
        }
        after = next_after;
    }
    Ok(accumulator.finish(destination_identity, 0, String::new()))
}

pub(crate) fn decode_receipt(bytes: &[u8]) -> AuditResult<LegacyAuditReceipt> {
    if bytes.len() > MAX_LEGACY_RECEIPT_BYTES {
        return Err(AuditError::StorageError(format!(
            "legacy audit migration receipt exceeds bounded size ({MAX_LEGACY_RECEIPT_BYTES} bytes)"
        )));
    }
    serde_json::from_slice(bytes).map_err(|e| AuditError::SerializationError(e.to_string()))
}

pub(crate) fn validate_destination(
    receipt: &LegacyAuditReceipt,
    destination_identity: &str,
) -> AuditResult<()> {
    if receipt.schema != 1 || receipt.destination != destination_identity {
        return Err(AuditError::StorageError(
            "legacy audit migration destination identity changed".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) fn payload_matches(expected: &LegacyAuditReceipt, actual: &LegacyAuditReceipt) -> bool {
    actual.schema == expected.schema
        && actual.destination == expected.destination
        && actual.source_entries == expected.source_entries
        && actual.source_bytes == expected.source_bytes
        && actual.source_digest == expected.source_digest
}

pub(crate) async fn index_legacy_source(
    source: &KvAuditStorage,
    destination_identity: &str,
) -> AuditResult<(LegacyAuditReceipt, LegacySourceGraph)> {
    let mut accumulator = ReceiptAccumulator::new();
    let mut successor = std::collections::HashMap::new();
    let mut geneses = Vec::new();
    let mut genesis_identity = std::collections::HashMap::new();
    let mut after = None;
    loop {
        let page = source.all_entries_page(after.as_deref(), 256).await?;
        if page.is_empty() {
            break;
        }
        let next_after = page.last().map(|(cursor, _)| cursor.clone());
        for (_, entry) in page {
            let bytes = serde_json::to_vec(&entry)
                .map_err(|error| AuditError::SerializationError(error.to_string()))?;
            accumulator.add(&entry, &bytes);
            if entry.previous_hash.is_zero() {
                let identity = chain_identity_key(&entry.session_id, entry.principal.as_ref());
                if let Some(existing) = genesis_identity.insert(identity, entry.id.clone()) {
                    return Err(AuditError::IntegrityViolation {
                        entry_id: entry.id.to_string(),
                        reason: format!(
                            "multiple genesis entries for one legacy chain ({existing})"
                        ),
                    });
                }
                geneses.push(entry.id.clone());
            } else if let Some(existing) = successor.insert(entry.previous_hash, entry.id.clone()) {
                return Err(AuditError::IntegrityViolation {
                    entry_id: entry.id.to_string(),
                    reason: format!("multiple successors for one legacy predecessor ({existing})"),
                });
            }
        }
        after = next_after;
    }
    let chain_count = u64::try_from(geneses.len()).unwrap_or(u64::MAX);
    Ok((
        accumulator.finish(destination_identity, chain_count, String::new()),
        LegacySourceGraph { successor, geneses },
    ))
}

pub(crate) async fn import_legacy_graph(
    log: &AuditLog,
    source: &KvAuditStorage,
    graph: &LegacySourceGraph,
) -> AuditResult<u64> {
    let mut imported = 0_u64;
    let mut visited = std::collections::HashSet::new();
    for genesis_id in &graph.geneses {
        imported = imported
            .saturating_add(import_one_chain(log, source, graph, genesis_id, &mut visited).await?);
    }
    let mut after = None;
    loop {
        let page = source.all_entries_page(after.as_deref(), 256).await?;
        if page.is_empty() {
            break;
        }
        let next_after = page.last().map(|(cursor, _)| cursor.clone());
        for (_, entry) in page {
            if !visited.contains(&entry.id) {
                return Err(AuditError::IntegrityViolation {
                    entry_id: entry.id.to_string(),
                    reason: "legacy audit entry is not reachable from genesis".to_owned(),
                });
            }
        }
        after = next_after;
    }
    Ok(imported)
}

async fn import_one_chain(
    log: &AuditLog,
    source: &KvAuditStorage,
    graph: &LegacySourceGraph,
    genesis_id: &AuditEntryId,
    visited: &mut std::collections::HashSet<AuditEntryId>,
) -> AuditResult<u64> {
    let genesis = source
        .get(genesis_id)
        .await?
        .ok_or_else(|| AuditError::StorageError("legacy genesis disappeared".to_owned()))?;
    let session = genesis.session_id.clone();
    let principal = genesis.principal.clone();
    let dest_head = log
        .storage()
        .get_chain_head(&session, principal.as_ref())
        .await?;
    let mut current = genesis;
    let mut passed_dest_head = dest_head.is_none();
    let mut batch = Vec::new();
    let mut batch_expected = dest_head.clone();
    let mut imported = 0_u64;
    loop {
        if !visited.insert(current.id.clone()) {
            return Err(AuditError::IntegrityViolation {
                entry_id: current.id.to_string(),
                reason: "legacy audit chain contains a cycle or duplicate entry".to_owned(),
            });
        }
        if current.session_id != session || current.principal != principal {
            return Err(AuditError::IntegrityViolation {
                entry_id: current.id.to_string(),
                reason: "legacy chain identity changed across successor".to_owned(),
            });
        }
        let committed = log.storage().is_entry_committed(&current.id).await?;
        if dest_head.as_ref() == Some(&current.id) {
            passed_dest_head = true;
        }
        if !committed {
            if !passed_dest_head {
                return Err(AuditError::IntegrityViolation {
                    entry_id: current.id.to_string(),
                    reason: "legacy destination is a torn prefix of the source chain".to_owned(),
                });
            }
            batch.push(current.clone());
            if batch.len() >= LEGACY_MOVE_BATCH_ENTRIES {
                imported = imported
                    .saturating_add(flush_move_batch(log, &batch, batch_expected.as_ref()).await?);
                batch_expected = batch.last().map(|entry| entry.id.clone());
                batch.clear();
            }
        }
        let Some(child_id) = graph.successor.get(&current.content_hash()) else {
            break;
        };
        current = source
            .get(child_id)
            .await?
            .ok_or_else(|| AuditError::StorageError("legacy successor disappeared".to_owned()))?;
    }
    if !batch.is_empty() {
        imported =
            imported.saturating_add(flush_move_batch(log, &batch, batch_expected.as_ref()).await?);
    }
    Ok(imported)
}

async fn flush_move_batch(
    log: &AuditLog,
    batch: &[AuditEntry],
    first_expected: Option<&AuditEntryId>,
) -> AuditResult<u64> {
    let expecteds: Vec<Option<AuditEntryId>> = std::iter::once(first_expected.cloned())
        .chain(batch.iter().map(|entry| Some(entry.id.clone())))
        .take(batch.len())
        .collect();
    let requests: Vec<(&AuditEntry, Option<&AuditEntryId>)> = batch
        .iter()
        .zip(expecteds.iter())
        .map(|(entry, expected)| (entry, expected.as_ref()))
        .collect();
    let results = log.storage().append_batch_if_heads(&requests).await?;
    if results.iter().any(|applied| !applied) {
        return Err(AuditError::StorageError(
            "legacy audit import lost a destination batch CAS".to_owned(),
        ));
    }
    u64::try_from(batch.len()).map_err(|_| {
        AuditError::StorageError("legacy audit import batch length overflowed".to_owned())
    })
}
