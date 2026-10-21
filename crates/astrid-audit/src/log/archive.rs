//! Archive-then-drop: hand a prune's entries to an archiver before any of
//! them is deleted.

use astrid_core::{PrincipalId, SessionId};
use async_trait::async_trait;

use super::{AuditError, AuditLog, AuditPruneReceipt, AuditResult};
use crate::entry::AuditEntry;

/// Entries read per storage call while archiving.
const ARCHIVE_READ_BATCH: usize = 64;

/// Receives the entries a prune removes, before the prune deletes any.
///
/// Set with [`AuditLog::set_prune_archiver`]. A prune that removes entries
/// opens one archive, writes the removed entries to it in chain order and
/// commits it; deletion starts only after the commit succeeds, and an error
/// at any step aborts the prune with nothing deleted. A prune that resumes an
/// interrupted plan does not archive again: whoever started the plan archived
/// its entries.
#[async_trait]
pub trait AuditArchiver: Send + Sync {
    /// Open the archive of the prune that `receipt` describes.
    /// `receipt_bytes` are the signed receipt exactly as it will be stored.
    ///
    /// # Errors
    ///
    /// Returns an error when the archive cannot be opened; the prune is then
    /// abandoned.
    async fn begin(
        &self,
        receipt: &AuditPruneReceipt,
        receipt_bytes: &[u8],
    ) -> AuditResult<Box<dyn AuditArchiveWriter>>;
}

/// One archive being written.
#[async_trait]
pub trait AuditArchiveWriter: Send {
    /// Append entries, in chain order.
    ///
    /// # Errors
    ///
    /// Returns an error when the entries cannot be written.
    async fn write(&mut self, entries: &[AuditEntry]) -> AuditResult<()>;

    /// Make the archive durable. The prune deletes nothing before this
    /// returns `Ok`.
    ///
    /// # Errors
    ///
    /// Returns an error when the archive cannot be made durable.
    async fn commit(self: Box<Self>) -> AuditResult<()>;
}

/// Archive the entries `receipt` omits, when an archiver is set and no
/// earlier prune plan of the chain is pending.
///
/// The archived entries are checked against the receipt: their count, the
/// digest over their canonical bytes and the hash of the last one must all
/// match, so the archive holds exactly what the prune deletes.
pub(super) async fn archive_pruned(
    log: &AuditLog,
    session_id: &SessionId,
    principal: Option<&PrincipalId>,
    receipt: &AuditPruneReceipt,
    receipt_bytes: &[u8],
) -> AuditResult<()> {
    if receipt.omitted_count == 0 {
        return Ok(());
    }
    let Some(archiver) = log.prune_archiver() else {
        return Ok(());
    };
    if log.prune_in_progress(session_id, principal).await? {
        return Ok(());
    }
    let cutoff = receipt.cutoff_cursor.as_deref().ok_or_else(|| {
        AuditError::StorageError("audit prune receipt omits entries but has no cutoff".to_owned())
    })?;
    let mut writer = archiver.begin(receipt, receipt_bytes).await?;
    let mut digest = blake3::Hasher::new_derive_key("astrid audit archive prefix v1");
    let mut written = 0_u64;
    let mut last_hash = None;
    let mut after: Option<String> = None;
    let mut reached = false;
    while !reached {
        let page = log
            .storage()
            .principal_entries_page(session_id, principal, after.as_deref(), ARCHIVE_READ_BATCH)
            .await?;
        if page.is_empty() {
            break;
        }
        let mut batch = Vec::with_capacity(page.len());
        for (cursor, entry) in page {
            if cursor.as_str() > cutoff {
                reached = true;
                break;
            }
            let encoded = serde_json::to_vec(&entry)
                .map_err(|error| AuditError::SerializationError(error.to_string()))?;
            digest.update(&encoded);
            written = written.saturating_add(1);
            last_hash = Some(entry.content_hash().to_hex());
            reached = cursor == cutoff;
            after = Some(cursor);
            batch.push(entry);
            if reached {
                break;
            }
        }
        writer.write(&batch).await?;
    }
    if written != receipt.omitted_count
        || digest.finalize().to_hex().as_str() != receipt.omitted_digest
        || last_hash.as_deref() != Some(receipt.omitted_terminal_hash.as_str())
    {
        return Err(AuditError::StorageError(format!(
            "audit archive read {written} entries that do not match the {} the prune removes; \
             the chain changed, retry",
            receipt.omitted_count
        )));
    }
    writer.commit().await
}

#[cfg(test)]
#[path = "archive_tests.rs"]
mod tests;
