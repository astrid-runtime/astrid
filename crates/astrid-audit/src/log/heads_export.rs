//! Read-only chain-head snapshot and raw chain paging for external anchoring.
//!
//! Neither read holds the process-wide durable append lock across chains. A
//! chain's `(count, omitted_total, head, head_hash)` comes from its single
//! chain-metadata record, which appends and prunes replace with one
//! compare-and-swap each, so every head reported here is a committed state
//! of its own chain. The snapshot reads a chain's metadata and prune state
//! together under that lock, for just those reads. Different chains may be
//! read at slightly different instants; each head is an independent claim.

use astrid_capabilities::AuditEntryId;
use astrid_core::{PrincipalId, SessionId, Timestamp};
use astrid_crypto::ContentHash;

use super::{AuditLog, AuditPruneReceipt};
use crate::entry::AuditEntry;
use crate::error::{AuditError, AuditResult};

/// Chain-metadata keys read per storage page while enumerating heads.
const HEADS_PAGE_SIZE: usize = 256;

/// Committed head of one audit chain, as read by [`AuditLog::heads_snapshot`].
#[derive(Clone, Debug)]
pub struct AuditChainHead {
    /// Session that owns the chain.
    pub session_id: SessionId,
    /// Principal alias of the chain, or `None` for the session's system chain.
    pub principal: Option<PrincipalId>,
    /// Retained entries in the chain. Pruning lowers this.
    pub count: u64,
    /// Entries removed from the front of the chain by every prune, read
    /// from the same committed metadata as [`count`](Self::count). A known
    /// total never decreases. `None` when the total cannot be known, as for
    /// a chain pruned more than once before Astrid recorded the total: only
    /// the latest prune receipt is kept.
    pub omitted_total: Option<u64>,
    /// Newest committed entry, if the chain has entries.
    pub head: Option<AuditEntryId>,
    /// Content hash of [`head`](Self::head), or zero for an empty chain.
    pub head_hash: ContentHash,
    /// Stored timestamp of the head entry.
    pub last_timestamp: Option<Timestamp>,
    /// Latest signed prune receipt, if the chain was ever pruned.
    pub prune: Option<AuditChainPruneState>,
}

/// Latest prune receipt of one chain.
#[derive(Clone, Debug)]
pub struct AuditChainPruneState {
    /// The decoded receipt.
    pub receipt: AuditPruneReceipt,
    /// BLAKE3 of the receipt bytes exactly as stored. This matches the
    /// `receipt_hash` reported by an operator prune.
    pub receipt_hash: ContentHash,
    /// The receipt bytes exactly as stored.
    pub stored_bytes: Vec<u8>,
}

impl AuditLog {
    /// Read the committed head of every audit chain in the log.
    ///
    /// Chains are returned in storage-key order. Each head entry is read back
    /// and must hash to the head hash recorded in its chain metadata.
    ///
    /// # Errors
    ///
    /// Returns an error when the backend cannot enumerate chains, chain
    /// metadata or a prune receipt cannot be decoded, or a recorded head is
    /// missing or does not match its metadata. A prune that runs between a
    /// chain's metadata read and its head read can remove that head; the
    /// error is transient and the caller retries.
    pub async fn heads_snapshot(&self) -> AuditResult<Vec<AuditChainHead>> {
        let Some(storage) = self.storage.as_kv_audit_storage() else {
            return Err(AuditError::UnsupportedOperation {
                operation: "audit heads snapshot",
            });
        };
        let mut heads = Vec::new();
        let mut after: Option<String> = None;
        loop {
            let page = storage
                .chain_metadata_page(after.as_deref(), HEADS_PAGE_SIZE)
                .await?;
            for record in page.records {
                let metadata = record.metadata;
                let last_timestamp = self
                    .verified_head_timestamp(
                        &record.session,
                        record.principal.as_ref(),
                        metadata.head.as_ref(),
                        &metadata.head_hash,
                    )
                    .await?;
                let prune = record.prune_receipt.map(decode_prune_state).transpose()?;
                heads.push(AuditChainHead {
                    session_id: record.session,
                    principal: record.principal,
                    count: metadata.count,
                    omitted_total: record.omitted_total,
                    head: metadata.head,
                    head_hash: metadata.head_hash,
                    last_timestamp,
                    prune,
                });
            }
            match page.next_after {
                Some(next) => after = Some(next),
                None => break,
            }
        }
        Ok(heads)
    }

    async fn verified_head_timestamp(
        &self,
        session_id: &SessionId,
        principal: Option<&PrincipalId>,
        head: Option<&AuditEntryId>,
        head_hash: &ContentHash,
    ) -> AuditResult<Option<Timestamp>> {
        let Some(head) = head else {
            return Ok(None);
        };
        let entry = self.storage.get(head).await?.ok_or_else(|| {
            AuditError::StorageError(format!("audit chain head {head} is missing"))
        })?;
        if &entry.session_id != session_id
            || entry.principal.as_ref() != principal
            || entry.content_hash() != *head_hash
        {
            return Err(AuditError::StorageError(format!(
                "audit chain head {head} does not match its chain metadata"
            )));
        }
        Ok(Some(entry.timestamp))
    }

    /// Read the latest prune receipt of one chain, if the chain was pruned.
    ///
    /// # Errors
    ///
    /// Returns an error when the receipt cannot be read or decoded.
    pub async fn prune_state(
        &self,
        session_id: &SessionId,
        principal: Option<&PrincipalId>,
    ) -> AuditResult<Option<AuditChainPruneState>> {
        self.storage
            .prune_receipt(session_id, principal)
            .await?
            .map(decode_prune_state)
            .transpose()
    }

    /// Whether a prune of one chain has started and not yet finished.
    ///
    /// A prune deletes entries only while it is in progress and installs a
    /// new receipt when it finishes. A reader that finds no prune in progress
    /// and then the same receipt, both before and after a series of reads,
    /// read no state that a prune changed in between.
    ///
    /// # Errors
    ///
    /// Returns an error when the prune state cannot be read.
    pub async fn prune_in_progress(
        &self,
        session_id: &SessionId,
        principal: Option<&PrincipalId>,
    ) -> AuditResult<bool> {
        match self.storage.as_kv_audit_storage() {
            Some(storage) => storage.prune_plan_pending(session_id, principal).await,
            None => Ok(false),
        }
    }

    /// Read up to `limit` retained entries of one chain in chain order.
    ///
    /// Every entry is returned with its durable cursor. Passing the last
    /// cursor back as `after` continues with the next entry, including
    /// entries appended after the previous call. Pass `None` as `principal`
    /// for the session's system chain.
    ///
    /// # Errors
    ///
    /// Returns an error when the backend cannot page the chain or an indexed
    /// entry is missing (for example while a concurrent prune deletes it).
    pub async fn chain_entries_page(
        &self,
        session_id: &SessionId,
        principal: Option<&PrincipalId>,
        after: Option<&str>,
        limit: usize,
    ) -> AuditResult<Vec<(String, AuditEntry)>> {
        self.storage
            .principal_entries_page(session_id, principal, after, limit)
            .await
    }
}

fn decode_prune_state(stored_bytes: Vec<u8>) -> AuditResult<AuditChainPruneState> {
    let receipt = serde_json::from_slice(&stored_bytes)
        .map_err(|error| AuditError::SerializationError(error.to_string()))?;
    Ok(AuditChainPruneState {
        receipt,
        receipt_hash: ContentHash::hash(&stored_bytes),
        stored_bytes,
    })
}

#[cfg(test)]
#[path = "heads_export_tests.rs"]
mod tests;
