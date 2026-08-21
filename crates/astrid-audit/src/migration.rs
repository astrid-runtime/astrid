// Blind payload MOVE of a legacy principal-home audit projection.

use crate::error::{AuditError, AuditResult};
use crate::storage::{AuditStorage, KvAuditStorage};
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

    pub(crate) fn add_record(&mut self, namespace: &str, key: &str, bytes: &[u8]) {
        let mut page = blake3::Hasher::new_derive_key("astrid audit legacy blind-move v1");
        page.update(&self.digest);
        page.update(namespace.as_bytes());
        page.update(&[0]);
        page.update(key.as_bytes());
        page.update(&u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
        page.update(bytes);
        self.digest = *page.finalize().as_bytes();
        if namespace == "audit:entries" {
            self.source_entries = self.source_entries.saturating_add(1);
            self.source_bytes = self
                .source_bytes
                .saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        }
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
    let Some(kv) = storage.as_kv_audit_storage() else {
        return Err(AuditError::StorageError(
            "native audit destination cannot be reopened".to_owned(),
        ));
    };
    let store = kv.kv_store();
    let mut accumulator = ReceiptAccumulator::new();
    // Payload identity is the stored entry bytes. Dest may seal committed
    // markers and global totals after the copy; those must not enter the digest.
    let mut keys = store
        .list_keys("audit:entries")
        .await
        .map_err(|error| AuditError::StorageError(error.to_string()))?;
    keys.sort();
    for key in keys {
        let Some(value) = store
            .get("audit:entries", &key)
            .await
            .map_err(|error| AuditError::StorageError(error.to_string()))?
        else {
            return Err(AuditError::StorageError(format!(
                "audit key disappeared while hashing audit:entries/{key}"
            )));
        };
        accumulator.add_record("audit:entries", &key, &value);
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

pub(crate) async fn copy_legacy_projection(
    source: &KvAuditStorage,
    destination: &KvAuditStorage,
) -> AuditResult<u64> {
    crate::storage::blind_move::copy_projection(source, destination).await
}
