//! Anchored watermarks: an external anchoring service records how far each
//! chain has been certified, and retention never prunes past that point.
//!
//! Positions count entries from a chain's genesis, pruned ones included: a
//! chain whose `audit.heads` record shows `omitted_total` O and `count` C has
//! entries at positions `0..O+C`, and anchoring its head certifies position
//! `O+C`, whose head hash is that of the entry at `O+C-1`.

use astrid_capabilities::AuditEntryId;
use astrid_core::{PrincipalId, SessionId, Timestamp};
use astrid_crypto::ContentHash;
use tracing::warn;

use super::retention_guard::chain_label;
use super::{AuditError, AuditLog, AuditPruneReceipt, AuditResult};
use crate::storage::{AnchorMark, ChainPositions, KvAuditStorage, MarkInstall};

/// Largest accepted evidence, as serialized JSON.
const MAX_EVIDENCE_BYTES: usize = 4_096;
/// Entries read per storage call while locating a position.
const WALK_PAGE: usize = 256;
/// Chain-metadata keys read per storage page while listing anchor status.
const STATUS_PAGE: usize = 256;

/// A chain's anchored watermark.
#[derive(Clone, Debug, PartialEq)]
pub struct AuditAnchorWatermark {
    /// Entries anchored, counted from the chain's genesis, pruned ones
    /// included.
    pub position: u64,
    /// Content hash of the entry at `position - 1`.
    pub head_hash: ContentHash,
    /// Id of that entry, when known.
    pub head: Option<AuditEntryId>,
    /// Evidence supplied with the mark, stored as given.
    pub evidence: serde_json::Value,
    /// When the mark was recorded.
    pub recorded_at: Timestamp,
}

impl From<AnchorMark> for AuditAnchorWatermark {
    fn from(mark: AnchorMark) -> Self {
        Self {
            position: mark.position,
            head_hash: mark.head_hash,
            head: mark.head,
            evidence: mark.evidence,
            recorded_at: mark.recorded_at,
        }
    }
}

/// Result of [`AuditLog::mark_anchored`].
#[derive(Clone, Debug, PartialEq)]
pub struct AuditAnchorMarkResult {
    /// Whether the call raised the watermark. `false` when it already stood
    /// at the requested position with the same head hash.
    pub advanced: bool,
    /// The chain's watermark after the call.
    pub watermark: AuditAnchorWatermark,
}

/// One chain's anchoring state, as listed by [`AuditLog::anchor_status`].
#[derive(Clone, Debug)]
pub struct AuditChainAnchorStatus {
    /// Session that owns the chain.
    pub session_id: SessionId,
    /// Principal of the chain, or `None` for the session's system chain.
    pub principal: Option<PrincipalId>,
    /// Retained entries.
    pub count: u64,
    /// Entries pruned from the chain's start, or `None` when unknown.
    pub omitted_total: Option<u64>,
    /// The chain's watermark, if one was recorded.
    pub watermark: Option<AuditAnchorWatermark>,
}

/// Where a position was found: the hash, id and session-index key of the
/// entry just before it.
struct Located {
    hash: ContentHash,
    id: Option<AuditEntryId>,
    cursor: Option<String>,
}

impl AuditLog {
    /// Record that an external anchoring service certified one chain through
    /// `position` entries, the last of which hashes to `head_hash`.
    ///
    /// The kernel checks the claim against its own chain before accepting
    /// it: the entry at `position - 1` must hash to `head_hash`. For a
    /// position at the pruned boundary, the chain's latest prune receipt
    /// supplies that hash. Verification reads onward from the previous
    /// watermark, or from the start of the retained chain for a chain's
    /// first mark. The watermark never decreases: a lower position is
    /// rejected, and the current position with the same hash succeeds
    /// without change. `evidence` must be a JSON object of at most 4,096
    /// bytes; it is stored as given and not interpreted.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError::AnchorRejected`] when the chain does not exist,
    /// its pruned total is unknown, the position is zero, past the head,
    /// below the watermark or inside pruned history, the hash does not
    /// match, or a prune ran during verification (retry). Returns a storage
    /// error when the chain cannot be read or the mark cannot be written.
    pub async fn mark_anchored(
        &self,
        session_id: &SessionId,
        principal: Option<&PrincipalId>,
        position: u64,
        head_hash: ContentHash,
        evidence: serde_json::Value,
    ) -> AuditResult<AuditAnchorMarkResult> {
        let storage = self.anchor_storage()?;
        let chain = chain_label(session_id, principal);
        let reject =
            |reason: String| AuditError::AnchorRejected(format!("chain {chain}: {reason}"));
        check_evidence(&evidence).map_err(reject)?;
        if position == 0 {
            return Err(reject("position 0 anchors no entries".to_owned()));
        }
        let before = storage
            .chain_positions(session_id, principal)
            .await?
            .ok_or_else(|| reject("no such audit chain".to_owned()))?;
        if before.prune_pending {
            return Err(reject(
                "a prune is in progress; retry once it finishes".to_owned(),
            ));
        }
        let omitted = before.omitted_total.ok_or_else(|| {
            reject("the number of pruned entries is unknown, so positions cannot be checked".into())
        })?;
        let end = omitted.saturating_add(before.count);
        if position > end {
            return Err(reject(format!(
                "position {position} is past the chain head at position {end}"
            )));
        }
        let (current_bytes, current) = storage.anchor_mark(session_id, principal).await?;
        if let Some(unchanged) =
            compare_with_watermark(current.as_ref(), position, &head_hash).map_err(reject)?
        {
            return Ok(unchanged);
        }
        let located = self
            .locate_position(
                session_id,
                principal,
                &before,
                omitted,
                current.as_ref(),
                position,
            )
            .await
            .map_err(|error| match error {
                AuditError::AnchorRejected(reason) => reject(reason),
                other => other,
            })?;
        if located.hash != head_hash {
            return Err(reject(format!(
                "head hash {} does not match the entry at position {}, which hashes to {}",
                head_hash.to_hex(),
                position.saturating_sub(1),
                located.hash.to_hex()
            )));
        }
        let mark = AnchorMark {
            schema: 1,
            position,
            head_hash,
            head: located.id,
            cursor: located.cursor,
            evidence,
            recorded_at: Timestamp::now(),
        };
        // Installed only if no prune started or finished since `before`, so
        // the verified position still names the same entry.
        let installed = storage
            .install_anchor_mark(
                session_id,
                principal,
                current_bytes.as_deref(),
                before.receipt.as_deref(),
                &mark,
            )
            .await?;
        match installed {
            MarkInstall::Installed => {},
            MarkInstall::Pruned => {
                return Err(reject(
                    "the chain was pruned during verification; retry".into(),
                ));
            },
            MarkInstall::MarkChanged => {
                return Err(reject("the watermark changed concurrently; retry".into()));
            },
        }
        // The next append at the cap retries pruning with the new watermark.
        if let Err(error) = storage.set_retention_hold(None).await {
            warn!(error = %error, "failed to clear the audit retention hold");
        }
        Ok(AuditAnchorMarkResult {
            advanced: true,
            watermark: mark.into(),
        })
    }

    /// Read one chain's anchored watermark.
    ///
    /// # Errors
    ///
    /// Returns an error when the backend records no watermarks or the
    /// record cannot be read.
    pub async fn anchor_watermark(
        &self,
        session_id: &SessionId,
        principal: Option<&PrincipalId>,
    ) -> AuditResult<Option<AuditAnchorWatermark>> {
        let (_, mark) = self
            .anchor_storage()?
            .anchor_mark(session_id, principal)
            .await?;
        Ok(mark.map(Into::into))
    }

    /// List every chain's retained count, pruned total and watermark, in
    /// storage-key order.
    ///
    /// # Errors
    ///
    /// Returns an error when the backend cannot enumerate chains or a record
    /// cannot be decoded.
    pub async fn anchor_status(&self) -> AuditResult<Vec<AuditChainAnchorStatus>> {
        let storage = self.anchor_storage()?;
        let mut chains = Vec::new();
        let mut after: Option<String> = None;
        loop {
            let page = storage
                .chain_metadata_page(after.as_deref(), STATUS_PAGE)
                .await?;
            for record in page.records {
                let (_, mark) = storage
                    .anchor_mark(&record.session, record.principal.as_ref())
                    .await?;
                chains.push(AuditChainAnchorStatus {
                    session_id: record.session,
                    principal: record.principal,
                    count: record.metadata.count,
                    omitted_total: record.omitted_total,
                    watermark: mark.map(Into::into),
                });
            }
            match page.next_after {
                Some(next) => after = Some(next),
                None => break,
            }
        }
        Ok(chains)
    }

    fn anchor_storage(&self) -> AuditResult<&KvAuditStorage> {
        self.storage
            .as_kv_audit_storage()
            .ok_or(AuditError::UnsupportedOperation {
                operation: "audit anchor watermarks",
            })
    }

    /// Find the entry at `position - 1` of a chain with `omitted` pruned
    /// entries, reading onward from `current`'s cursor when the watermark
    /// is not behind the pruned boundary, else from the retained start.
    ///
    /// Prunes never remove entries at or past a watermark, so every entry
    /// after the watermark's cursor is still retained and positions counted
    /// from it are exact.
    async fn locate_position(
        &self,
        session_id: &SessionId,
        principal: Option<&PrincipalId>,
        before: &ChainPositions,
        omitted: u64,
        current: Option<&AnchorMark>,
        position: u64,
    ) -> AuditResult<Located> {
        if position < omitted {
            return Err(AuditError::AnchorRejected(format!(
                "position {position} is inside pruned history (the first {omitted} entries \
                 were pruned)"
            )));
        }
        if position == omitted {
            return pruned_boundary(before.receipt.as_deref());
        }
        let target = position.saturating_sub(1);
        let (mut next, mut after) = match current {
            Some(mark) if mark.position >= omitted && mark.cursor.is_some() => {
                (mark.position, mark.cursor.clone())
            },
            _ => (omitted, None),
        };
        loop {
            let page = self
                .storage
                .principal_entries_page(session_id, principal, after.as_deref(), WALK_PAGE)
                .await?;
            if page.is_empty() {
                return Err(AuditError::AnchorRejected(format!(
                    "the chain ended at position {next} before position {position}; retry"
                )));
            }
            for (cursor, entry) in page {
                if next == target {
                    return Ok(Located {
                        hash: entry.content_hash(),
                        id: Some(entry.id),
                        cursor: Some(cursor),
                    });
                }
                next = next.saturating_add(1);
                after = Some(cursor);
            }
        }
    }
}

/// Check a mark against the chain's current watermark: `Ok(Some(_))` when
/// it already stands at `position` with `head_hash`, `Ok(None)` when the
/// mark would raise it, and the reason otherwise.
fn compare_with_watermark(
    current: Option<&AnchorMark>,
    position: u64,
    head_hash: &ContentHash,
) -> Result<Option<AuditAnchorMarkResult>, String> {
    let Some(current) = current else {
        return Ok(None);
    };
    if position < current.position {
        return Err(format!(
            "position {position} is below the anchored watermark {}",
            current.position
        ));
    }
    if position > current.position {
        return Ok(None);
    }
    if &current.head_hash != head_hash {
        return Err(format!(
            "head hash differs from the hash anchored at position {position}"
        ));
    }
    Ok(Some(AuditAnchorMarkResult {
        advanced: false,
        watermark: current.clone().into(),
    }))
}

/// The last pruned entry, as the chain's latest prune receipt records it.
fn pruned_boundary(receipt: Option<&[u8]>) -> AuditResult<Located> {
    let receipt = receipt.ok_or_else(|| {
        AuditError::AnchorRejected("the chain has pruned entries but no prune receipt".to_owned())
    })?;
    let receipt: AuditPruneReceipt = serde_json::from_slice(receipt)
        .map_err(|error| AuditError::SerializationError(error.to_string()))?;
    receipt.verify()?;
    let hash = ContentHash::from_hex(&receipt.omitted_terminal_hash).map_err(|error| {
        AuditError::StorageError(format!("audit prune receipt terminal hash: {error}"))
    })?;
    let id = receipt
        .cutoff_cursor
        .as_deref()
        .and_then(|cursor| cursor.rsplit_once(':'))
        .and_then(|(_, id)| uuid::Uuid::parse_str(id).ok())
        .map(AuditEntryId);
    Ok(Located {
        hash,
        id,
        cursor: receipt.cutoff_cursor,
    })
}

fn check_evidence(evidence: &serde_json::Value) -> Result<(), String> {
    if !evidence.is_object() {
        return Err("anchor evidence must be a JSON object".to_owned());
    }
    let size = serde_json::to_vec(evidence)
        .map_err(|error| error.to_string())?
        .len();
    if size > MAX_EVIDENCE_BYTES {
        return Err(format!(
            "anchor evidence is {size} bytes, above the {MAX_EVIDENCE_BYTES}-byte limit"
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "anchor_tests.rs"]
mod tests;
