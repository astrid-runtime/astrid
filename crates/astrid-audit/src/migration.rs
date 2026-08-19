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

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
struct ScanState {
    cursor: Option<String>,
    source_entries: u64,
    source_bytes: u64,
    digest: [u8; 32],
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
struct MigrationState {
    phase: u8,
    cursor: Option<String>,
}

const PHASE_TAIL: u8 = 1;
const PHASE_REACHABILITY: u8 = 2;
const PHASE_READY: u8 = 3;
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

    fn from_state(state: &ScanState) -> Self {
        Self {
            digest: state.digest,
            source_entries: state.source_entries,
            source_bytes: state.source_bytes,
        }
    }

    fn state(&self, cursor: Option<String>) -> ScanState {
        ScanState {
            cursor,
            source_entries: self.source_entries,
            source_bytes: self.source_bytes,
            digest: self.digest,
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

async fn migration_state(destination: &dyn AuditStorage) -> AuditResult<Option<MigrationState>> {
    destination
        .migration_temp_get("migration-state")
        .await?
        .map(|bytes| {
            serde_json::from_slice(&bytes)
                .map_err(|error| AuditError::SerializationError(error.to_string()))
        })
        .transpose()
}

async fn persist_migration_state(
    destination: &dyn AuditStorage,
    state: &MigrationState,
) -> AuditResult<()> {
    let bytes = serde_json::to_vec(state)
        .map_err(|error| AuditError::SerializationError(error.to_string()))?;
    let previous = destination.migration_temp_get("migration-state").await?;
    if destination
        .migration_temp_cas("migration-state", previous.as_deref(), bytes)
        .await?
    {
        Ok(())
    } else {
        Err(AuditError::StorageError(
            "legacy audit migration phase changed concurrently".to_owned(),
        ))
    }
}

pub(crate) async fn chain_fragment_summary(
    destination: &dyn AuditStorage,
    prefix: &str,
) -> AuditResult<(u64, String)> {
    let mut count = 0_u64;
    let mut digest = blake3::Hasher::new_derive_key("astrid audit legacy chains v1");
    let mut after = None;
    loop {
        let keys = destination
            .migration_temp_keys_page(prefix, after.as_deref(), 256)
            .await?;
        if keys.is_empty() {
            break;
        }
        let next_after = keys.last().cloned();
        for key in keys {
            let value = destination.migration_temp_get(&key).await?.ok_or_else(|| {
                AuditError::StorageError("legacy chain fragment disappeared".to_owned())
            })?;
            digest.update(&(u64::try_from(key.len()).unwrap_or(u64::MAX)).to_be_bytes());
            digest.update(key.as_bytes());
            digest.update(&(u64::try_from(value.len()).unwrap_or(u64::MAX)).to_be_bytes());
            digest.update(&value);
            count = count.saturating_add(1);
        }
        after = next_after;
    }
    let digest = if count == 0 {
        String::new()
    } else {
        digest.finalize().to_hex().to_string()
    };
    Ok((count, digest))
}

pub(crate) async fn finalize_chain_fragments(
    destination: &dyn AuditStorage,
    prefix: &str,
) -> AuditResult<()> {
    let mut after = None;
    loop {
        let keys = destination
            .migration_temp_keys_page(prefix, after.as_deref(), 256)
            .await?;
        if keys.is_empty() {
            break;
        }
        let next_after = keys.last().cloned();
        for key in keys {
            let Some(raw) = destination.migration_temp_get(&key).await? else {
                return Err(AuditError::StorageError(
                    "legacy chain fragment disappeared".to_owned(),
                ));
            };
            let mut fragment: LegacyAuditChainReceipt = serde_json::from_slice(&raw)
                .map_err(|e| AuditError::SerializationError(e.to_string()))?;
            let encoded_key = key
                .strip_prefix(prefix)
                .ok_or_else(|| AuditError::StorageError("invalid chain fragment key".to_owned()))?;
            let session_text = encoded_key.strip_prefix("session:").ok_or_else(|| {
                AuditError::StorageError("invalid chain fragment session".to_owned())
            })?;
            let (session_uuid_text, principal_text) =
                session_text.split_once(':').ok_or_else(|| {
                    AuditError::StorageError("invalid chain fragment identity".to_owned())
                })?;
            let session_uuid = uuid::Uuid::parse_str(session_uuid_text).map_err(|_| {
                AuditError::StorageError("invalid chain fragment session".to_owned())
            })?;
            let session = SessionId::from_uuid(session_uuid);
            let principal = if principal_text == "<system>" {
                None
            } else {
                Some(PrincipalId::new(principal_text.to_owned()).map_err(|e| {
                    AuditError::StorageError(format!("invalid chain fragment principal: {e}"))
                })?)
            };
            let head_id = destination
                .get_chain_head(&session, principal.as_ref())
                .await?
                .ok_or_else(|| {
                    AuditError::StorageError("chain fragment has no destination head".to_owned())
                })?;
            let head = destination.get(&head_id).await?.ok_or_else(|| {
                AuditError::StorageError("destination chain head is missing".to_owned())
            })?;
            fragment.terminal_hash = head.content_hash().to_hex();
            let encoded = serde_json::to_vec(&fragment)
                .map_err(|e| AuditError::SerializationError(e.to_string()))?;
            if !destination
                .migration_temp_cas(&key, Some(&raw), encoded)
                .await?
            {
                return Err(AuditError::StorageError(
                    "chain fragment changed during destination verification".to_owned(),
                ));
            }
        }
        after = next_after;
    }
    Ok(())
}

#[expect(
    clippy::too_many_lines,
    reason = "streaming migration keeps bounded passes together"
)]
pub(crate) async fn scan_legacy_source(
    source: &KvAuditStorage,
    destination: &dyn AuditStorage,
    destination_identity: &str,
) -> AuditResult<LegacyAuditReceipt> {
    let state = migration_state(destination).await?;
    let scan_state = destination.migration_temp_get("scan-state").await?;
    let (mut accumulator, mut after) = if let Some(scan_state) = scan_state {
        let scan_state: ScanState = serde_json::from_slice(&scan_state)
            .map_err(|e| AuditError::SerializationError(e.to_string()))?;
        (
            ReceiptAccumulator::from_state(&scan_state),
            scan_state.cursor,
        )
    } else {
        if state.is_some() {
            return Err(AuditError::StorageError(
                "legacy audit migration checkpoint is missing its scan state".to_owned(),
            ));
        }
        destination.clear_migration_temp().await?;
        (ReceiptAccumulator::new(), None)
    };
    let phase = state.as_ref().map_or(0, |state| state.phase);
    if phase == 0 {
        loop {
            let page = source.all_entries_page(after.as_deref(), 256).await?;
            if page.is_empty() {
                break;
            }
            let next_after = page.last().map(|(cursor, _)| cursor.clone());
            for (_, entry) in page {
                entry.verify_signature()?;
                let bytes = serde_json::to_vec(&entry)
                    .map_err(|e| AuditError::SerializationError(e.to_string()))?;
                destination
                    .migration_temp_put(
                        &format!("hash:{}", entry.content_hash()),
                        entry.id.0.as_bytes().to_vec(),
                    )
                    .await?;
                if !entry.previous_hash.is_zero() {
                    destination
                        .migration_temp_put(
                            &format!("ref:{}", entry.previous_hash),
                            entry.id.0.as_bytes().to_vec(),
                        )
                        .await?;
                }
                accumulator.add(&entry, &bytes);
            }
            after = next_after;
            let state = serde_json::to_vec(&accumulator.state(after.clone()))
                .map_err(|e| AuditError::SerializationError(e.to_string()))?;
            let previous_state = destination.migration_temp_get("scan-state").await?;
            if !destination
                .migration_temp_cas("scan-state", previous_state.as_deref(), state)
                .await?
            {
                return Err(AuditError::StorageError(
                    "legacy audit migration scan cursor changed concurrently".to_owned(),
                ));
            }
        }
    }
    if accumulator.source_entries == 0 {
        destination.clear_migration_temp().await?;
        return Ok(accumulator.finish(destination_identity, 0, String::new()));
    }

    if phase >= PHASE_READY {
        let (chain_count, chain_digest) = chain_fragment_summary(destination, "chain:").await?;
        return Ok(accumulator.finish(destination_identity, chain_count, chain_digest));
    }

    let mut phase_cursor = if phase == PHASE_TAIL {
        state.and_then(|state| state.cursor)
    } else {
        None
    };
    if phase == 0 {
        persist_migration_state(
            destination,
            &MigrationState {
                phase: PHASE_TAIL,
                cursor: None,
            },
        )
        .await?;
    }

    // Walk every unreferenced tail backwards through the disposable
    // content-hash index. This recovers terminal counts without ever loading
    // the legacy session-index array or retaining all entry IDs in memory.
    let mut after = phase_cursor.take();
    loop {
        let page = source.all_entries_page(after.as_deref(), 256).await?;
        if page.is_empty() {
            break;
        }
        let next_after = page.last().map(|(cursor, _)| cursor.clone());
        for (_, tail) in page {
            if destination
                .migration_temp_get(&format!("ref:{}", tail.content_hash()))
                .await?
                .is_some()
            {
                continue;
            }
            let chain_session = tail.session_id.to_string();
            let chain_principal = tail
                .principal
                .as_ref()
                .map_or_else(|| "<system>".to_owned(), ToString::to_string);
            let chain_key = format!("chain:{chain_session}:{chain_principal}");
            if let Some(existing) = destination.migration_temp_get(&chain_key).await? {
                let existing: LegacyAuditChainReceipt = serde_json::from_slice(&existing)
                    .map_err(|e| AuditError::SerializationError(e.to_string()))?;
                if existing.terminal_hash != tail.content_hash().to_hex() {
                    return Err(AuditError::IntegrityViolation {
                        entry_id: tail.id.to_string(),
                        reason: "multiple terminal entries for one legacy chain".to_owned(),
                    });
                }
                continue;
            }
            let tail_session = tail.session_id.clone();
            let tail_principal = tail.principal.clone();
            let tail_hash = tail.content_hash();
            let mut current = tail;
            let mut count = 0_u64;
            loop {
                let seen_key = format!("seen:{}", current.id);
                if destination.migration_temp_get(&seen_key).await?.is_some() {
                    return Err(AuditError::IntegrityViolation {
                        entry_id: current.id.to_string(),
                        reason: "legacy audit chain contains a cycle or duplicate entry".to_owned(),
                    });
                }
                destination.migration_temp_put(&seen_key, vec![1]).await?;
                count = count.saturating_add(1);
                if current.previous_hash.is_zero() {
                    break;
                }
                let Some(previous_id) = destination
                    .migration_temp_get(&format!("hash:{}", current.previous_hash))
                    .await?
                else {
                    return Err(AuditError::IntegrityViolation {
                        entry_id: current.id.to_string(),
                        reason: "legacy audit predecessor is missing".to_owned(),
                    });
                };
                let previous_id = uuid::Uuid::from_slice(&previous_id).map_err(|_| {
                    AuditError::StorageError("invalid legacy audit scratch entry id".to_owned())
                })?;
                current = source
                    .get(&AuditEntryId(previous_id))
                    .await?
                    .ok_or_else(|| {
                        AuditError::StorageError("legacy predecessor disappeared".into())
                    })?;
                if current.session_id != tail_session
                    || current.principal.as_ref() != tail_principal.as_ref()
                {
                    return Err(AuditError::IntegrityViolation {
                        entry_id: current.id.to_string(),
                        reason: "legacy chain identity changed across predecessor".to_owned(),
                    });
                }
            }
            let fragment = LegacyAuditChainReceipt {
                session: chain_session,
                principal: tail_principal.map(|principal| principal.to_string()),
                count,
                terminal_hash: tail_hash.to_hex(),
            };
            let bytes = serde_json::to_vec(&fragment)
                .map_err(|e| AuditError::SerializationError(e.to_string()))?;
            destination.migration_temp_put(&chain_key, bytes).await?;
        }
        after = next_after;
        persist_migration_state(
            destination,
            &MigrationState {
                phase: PHASE_TAIL,
                cursor: after.clone(),
            },
        )
        .await?;
    }

    persist_migration_state(
        destination,
        &MigrationState {
            phase: PHASE_REACHABILITY,
            cursor: None,
        },
    )
    .await?;

    // Every scanned entry must be reachable from exactly one terminal walk.
    let mut after = migration_state(destination)
        .await?
        .and_then(|state| state.cursor);
    loop {
        let page = source.all_entries_page(after.as_deref(), 256).await?;
        if page.is_empty() {
            break;
        }
        let next_after = page.last().map(|(cursor, _)| cursor.clone());
        for (_, entry) in page {
            if destination
                .migration_temp_get(&format!("seen:{}", entry.id))
                .await?
                .is_none()
            {
                return Err(AuditError::IntegrityViolation {
                    entry_id: entry.id.to_string(),
                    reason: "legacy audit entry is unreachable from a chain head".to_owned(),
                });
            }
        }
        after = next_after;
        persist_migration_state(
            destination,
            &MigrationState {
                phase: PHASE_REACHABILITY,
                cursor: after.clone(),
            },
        )
        .await?;
    }
    persist_migration_state(
        destination,
        &MigrationState {
            phase: PHASE_READY,
            cursor: None,
        },
    )
    .await?;
    let (chain_count, chain_digest) = chain_fragment_summary(destination, "chain:").await?;
    Ok(accumulator.finish(destination_identity, chain_count, chain_digest))
}

pub(crate) fn decode_receipt(bytes: &[u8]) -> AuditResult<LegacyAuditReceipt> {
    if bytes.len() > MAX_LEGACY_RECEIPT_BYTES {
        return Err(AuditError::StorageError(format!(
            "legacy audit migration receipt exceeds bounded size ({MAX_LEGACY_RECEIPT_BYTES} bytes)"
        )));
    }
    serde_json::from_slice(bytes).map_err(|e| AuditError::SerializationError(e.to_string()))
}

/// Recompute the canonical source digest in bounded pages immediately before
/// a migration receipt is published. The caller may run this before and after
/// forward import to detect source mutation during a long copy.
pub(crate) async fn digest_legacy_source(
    source: &KvAuditStorage,
    destination_identity: &str,
) -> AuditResult<LegacyAuditReceipt> {
    let mut accumulator = ReceiptAccumulator::new();
    let mut after = None;
    loop {
        let page = source.all_entries_page(after.as_deref(), 256).await?;
        if page.is_empty() {
            break;
        }
        let next_after = page.last().map(|(cursor, _)| cursor.clone());
        for (_, entry) in page {
            entry.verify_signature()?;
            let bytes = serde_json::to_vec(&entry)
                .map_err(|error| AuditError::SerializationError(error.to_string()))?;
            accumulator.add(&entry, &bytes);
        }
        after = next_after;
    }
    Ok(accumulator.finish(destination_identity, 0, String::new()))
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

#[expect(clippy::too_many_lines, reason = "bounded resumable forward migration")]
pub(crate) async fn import_legacy_chains(
    log: &AuditLog,
    source: &KvAuditStorage,
) -> AuditResult<u64> {
    let mut imported_entries = 0_u64;
    let import_state = log.storage().migration_temp_get("import-state").await?;
    if import_state.as_deref() == Some(b"done") {
        return Ok(0);
    }
    let mut after = import_state.and_then(|bytes| String::from_utf8(bytes).ok());
    loop {
        let page = source.all_entries_page(after.as_deref(), 256).await?;
        if page.is_empty() {
            break;
        }
        let next_after = page.last().map(|(cursor, _)| cursor.clone());
        for (_, genesis) in page {
            if !genesis.previous_hash.is_zero() {
                continue;
            }
            let mut current = genesis;
            loop {
                let imported_key = format!("imported:{}", current.id);
                let already_imported = log
                    .storage()
                    .migration_temp_get(&imported_key)
                    .await?
                    .is_some();
                if !already_imported {
                    log.storage()
                        .migration_temp_put(&imported_key, vec![1])
                        .await?;
                }
                if append_legacy_entry(log, &current).await? {
                    imported_entries = imported_entries.saturating_add(1);
                }

                let Some(child_id_bytes) = log
                    .storage()
                    .migration_temp_get(&format!("ref:{}", current.content_hash()))
                    .await?
                else {
                    break;
                };
                let child_uuid = uuid::Uuid::from_slice(&child_id_bytes).map_err(|_| {
                    AuditError::StorageError("invalid legacy audit scratch entry id".to_owned())
                })?;
                let child = source
                    .get(&AuditEntryId(child_uuid))
                    .await?
                    .ok_or_else(|| {
                        AuditError::StorageError("legacy successor disappeared".to_owned())
                    })?;
                if child.session_id != current.session_id
                    || child.principal != current.principal
                    || child.previous_hash != current.content_hash()
                {
                    return Err(AuditError::IntegrityViolation {
                        entry_id: child.id.to_string(),
                        reason: "legacy successor does not follow its predecessor".to_owned(),
                    });
                }
                current = child;
            }
        }
        after = next_after;
        let state = after.clone().unwrap_or_else(|| "done".to_owned());
        let previous = log.storage().migration_temp_get("import-state").await?;
        if !log
            .storage()
            .migration_temp_cas("import-state", previous.as_deref(), state.into_bytes())
            .await?
        {
            return Err(AuditError::StorageError(
                "legacy audit import cursor changed concurrently".to_owned(),
            ));
        }
    }

    let previous = log.storage().migration_temp_get("import-state").await?;
    if previous.as_deref() != Some(b"done")
        && !log
            .storage()
            .migration_temp_cas("import-state", previous.as_deref(), b"done".to_vec())
            .await?
    {
        return Err(AuditError::StorageError(
            "legacy audit import completion changed concurrently".to_owned(),
        ));
    }

    // A chain walk must account for every record admitted by the first pass.
    // This catches disconnected entries without retaining a global set of IDs.
    let mut after = None;
    loop {
        let page = source.all_entries_page(after.as_deref(), 256).await?;
        if page.is_empty() {
            break;
        }
        let next_after = page.last().map(|(cursor, _)| cursor.clone());
        for (_, entry) in page {
            if log
                .storage()
                .migration_temp_get(&format!("imported:{}", entry.id))
                .await?
                .is_none()
            {
                return Err(AuditError::IntegrityViolation {
                    entry_id: entry.id.to_string(),
                    reason: "legacy audit entry is not reachable from genesis".to_owned(),
                });
            }
        }
        after = next_after;
    }
    Ok(imported_entries)
}

async fn append_legacy_entry(log: &AuditLog, entry: &AuditEntry) -> AuditResult<bool> {
    let storage = log.storage();
    let raw =
        serde_json::to_vec(entry).map_err(|e| AuditError::SerializationError(e.to_string()))?;
    if let Some(existing) = storage.get(&entry.id).await? {
        let canonical = serde_json::to_vec(&existing)
            .map_err(|e| AuditError::SerializationError(e.to_string()))?;
        if canonical != raw {
            return Err(AuditError::StorageError(format!(
                "system audit entry {} conflicts byte-for-byte",
                entry.id
            )));
        }
    }
    if storage.is_entry_committed(&entry.id).await? {
        return Ok(false);
    }
    let expected = storage
        .get_chain_head(&entry.session_id, entry.principal.as_ref())
        .await?;
    // A crash can leave this exact entry indexed before the head CAS (or after
    // the CAS but before its committed marker). Re-run the durable append to
    // repair the marker/head without creating a second logical record.
    if expected.as_ref() == Some(&entry.id) {
        if !storage.append_if_head(entry, expected.as_ref()).await? {
            return Err(AuditError::StorageError(
                "legacy audit recovery lost a destination head CAS".to_owned(),
            ));
        }
        return Ok(false);
    }
    if let Some(previous_id) = expected.as_ref() {
        let previous = storage.get(previous_id).await?.ok_or_else(|| {
            AuditError::StorageError(format!("system audit chain head {previous_id} is missing"))
        })?;
        if entry.previous_hash != previous.content_hash() {
            return Err(AuditError::IntegrityViolation {
                entry_id: entry.id.to_string(),
                reason: "legacy entry does not follow destination chain head".to_owned(),
            });
        }
    } else if !entry.previous_hash.is_zero() {
        return Err(AuditError::IntegrityViolation {
            entry_id: entry.id.to_string(),
            reason: "legacy entry has a non-genesis predecessor in an empty destination".to_owned(),
        });
    }
    if !storage.append_if_head(entry, expected.as_ref()).await? {
        return Err(AuditError::StorageError(
            "legacy audit import lost a destination head CAS".to_owned(),
        ));
    }
    Ok(true)
}
