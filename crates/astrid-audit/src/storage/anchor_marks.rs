//! Per-chain anchored watermarks and the consistent chain positions they are
//! checked against.
//!
//! A watermark records that an external anchoring service certified a chain
//! up to an absolute position: a number of entries counted from the chain's
//! genesis, pruned ones included. Pruning never removes an entry at or beyond
//! it. Each chain has at most one record, replaced by compare-and-swap, and a
//! replacement never lowers the position.

use astrid_capabilities::AuditEntryId;
use astrid_core::{PrincipalId, SessionId, Timestamp};
use astrid_crypto::ContentHash;

use super::metadata::PruneGeneration;
use super::{
    AuditError, AuditResult, DURABLE_APPEND_LOCK, KvAuditStorage, NS_PRUNE_PLANS,
    NS_PRUNE_RECEIPTS, PrunePlan, chain_head_key,
};

pub(super) const NS_ANCHOR_MARKS: &str = "audit:anchor_marks";

/// Stored watermark of one chain.
#[derive(Clone, Debug, PartialEq, serde::Deserialize, serde::Serialize)]
pub(crate) struct AnchorMark {
    pub(crate) schema: u8,
    /// Entries anchored, counted from the chain's genesis.
    pub(crate) position: u64,
    /// Content hash of the entry at `position - 1`.
    pub(crate) head_hash: ContentHash,
    /// Id of that entry.
    pub(crate) head: Option<AuditEntryId>,
    /// Session-index key of that entry. The next mark of the chain verifies
    /// onward from it instead of from the start of the retained chain.
    pub(crate) cursor: Option<String>,
    /// Evidence supplied by the anchoring service, stored as given.
    pub(crate) evidence: serde_json::Value,
    /// When the mark was recorded.
    pub(crate) recorded_at: Timestamp,
}

/// Outcome of [`KvAuditStorage::install_anchor_mark`].
pub(crate) enum MarkInstall {
    /// The watermark was installed.
    Installed,
    /// A prune started or finished since the position was verified.
    Pruned,
    /// Another mark replaced the watermark since it was read.
    MarkChanged,
}

/// A chain's retained count, pruned total and prune state, read together.
pub(crate) struct ChainPositions {
    /// Retained entries.
    pub(crate) count: u64,
    /// Entries pruned from the chain's start, or `None` when unknown.
    pub(crate) omitted_total: Option<u64>,
    /// Latest prune receipt exactly as stored.
    pub(crate) receipt: Option<Vec<u8>>,
    /// Whether a prune of the chain has started and not finished.
    pub(crate) prune_pending: bool,
}

impl KvAuditStorage {
    /// Read a chain's watermark with its stored bytes for a later
    /// compare-and-swap.
    pub(crate) async fn anchor_mark(
        &self,
        session_id: &SessionId,
        principal: Option<&PrincipalId>,
    ) -> AuditResult<(Option<Vec<u8>>, Option<AnchorMark>)> {
        let bytes = self
            .store
            .get(NS_ANCHOR_MARKS, &chain_head_key(session_id, principal))
            .await
            .map_err(|error| AuditError::StorageError(error.to_string()))?;
        let mark = bytes
            .as_deref()
            .map(serde_json::from_slice)
            .transpose()
            .map_err(|error| AuditError::SerializationError(error.to_string()))?;
        Ok((bytes, mark))
    }

    /// Install a chain's watermark if the chain is in the prune state its
    /// position was verified in: no prune plan exists and the installed
    /// receipt still equals `expected_receipt`. The watermark record itself
    /// must still equal `expected_mark`.
    ///
    /// Runs under the durable append lock, as prune plans are created, so a
    /// prune whose plan is created after this returns sees the watermark
    /// (see [`Self::check_plan_against_watermark`]), and one created before
    /// makes this refuse.
    pub(crate) async fn install_anchor_mark(
        &self,
        session_id: &SessionId,
        principal: Option<&PrincipalId>,
        expected_mark: Option<&[u8]>,
        expected_receipt: Option<&[u8]>,
        mark: &AnchorMark,
    ) -> AuditResult<MarkInstall> {
        let key = chain_head_key(session_id, principal);
        let bytes = serde_json::to_vec(mark)
            .map_err(|error| AuditError::SerializationError(error.to_string()))?;
        let _guard = DURABLE_APPEND_LOCK.lock().await;
        let plan_pending = self
            .store
            .exists(NS_PRUNE_PLANS, &key)
            .await
            .map_err(|error| AuditError::StorageError(error.to_string()))?;
        let receipt = self
            .store
            .get(NS_PRUNE_RECEIPTS, &key)
            .await
            .map_err(|error| AuditError::StorageError(error.to_string()))?;
        if plan_pending || receipt.as_deref() != expected_receipt {
            return Ok(MarkInstall::Pruned);
        }
        let installed = self
            .store
            .compare_and_swap(NS_ANCHOR_MARKS, &key, expected_mark, bytes)
            .await
            .map_err(|error| AuditError::StorageError(error.to_string()))?;
        Ok(if installed {
            MarkInstall::Installed
        } else {
            MarkInstall::MarkChanged
        })
    }

    /// Refuse a new prune plan whose receipt removes entries at or past the
    /// chain's watermark.
    ///
    /// The log checks every prune against the watermark before signing its
    /// receipt, but a chain's first watermark can be installed after that
    /// check. Plans are created, and watermarks installed, under the durable
    /// append lock, so this check at plan creation sees every watermark a
    /// prune could delete past. The plan's receipt links to the installed
    /// receipt, so the removal starts at the pruned total read here.
    pub(super) async fn check_plan_against_watermark(
        &self,
        session_id: &SessionId,
        principal: Option<&PrincipalId>,
        omitted_count: u64,
    ) -> AuditResult<()> {
        if omitted_count == 0 {
            return Ok(());
        }
        let (_, Some(mark)) = self.anchor_mark(session_id, principal).await? else {
            return Ok(());
        };
        let key = chain_head_key(session_id, principal);
        let (_, metadata) = self.load_chain_metadata(session_id, principal).await?;
        let latest = self
            .store
            .get(NS_PRUNE_RECEIPTS, &key)
            .await
            .map_err(|error| AuditError::StorageError(error.to_string()))?
            .as_deref()
            .map(PruneGeneration::parse)
            .transpose()?;
        let omitted_before = metadata.map_or(Some(0), |metadata| {
            metadata.resolved_omitted_total(latest, false)
        });
        match omitted_before {
            Some(before) if before.saturating_add(omitted_count) <= mark.position => Ok(()),
            _ => Err(AuditError::UnanchoredPrune(format!(
                "chain {} {} is anchored through its first {} entries, and the prune would \
                 remove entries past them",
                session_id.0,
                principal.map_or("(system)", PrincipalId::as_str),
                mark.position
            ))),
        }
    }

    /// Read a chain's metadata, latest prune receipt and prune plan under
    /// the durable append lock, so the pruned total, the retained count and
    /// the receipt come from one committed state. `None` when the chain has
    /// no metadata.
    pub(crate) async fn chain_positions(
        &self,
        session_id: &SessionId,
        principal: Option<&PrincipalId>,
    ) -> AuditResult<Option<ChainPositions>> {
        let key = chain_head_key(session_id, principal);
        let guard = DURABLE_APPEND_LOCK.lock().await;
        let (_, metadata) = self.load_chain_metadata(session_id, principal).await?;
        let receipt = self
            .store
            .get(NS_PRUNE_RECEIPTS, &key)
            .await
            .map_err(|error| AuditError::StorageError(error.to_string()))?;
        let plan = self
            .store
            .get(NS_PRUNE_PLANS, &key)
            .await
            .map_err(|error| AuditError::StorageError(error.to_string()))?;
        drop(guard);
        let Some(metadata) = metadata else {
            return Ok(None);
        };
        let prune_finishing = plan
            .as_deref()
            .map(serde_json::from_slice::<PrunePlan>)
            .transpose()
            .map_err(|error| AuditError::SerializationError(error.to_string()))?
            .is_some_and(|plan| plan.complete);
        let latest = receipt.as_deref().map(PruneGeneration::parse).transpose()?;
        Ok(Some(ChainPositions {
            count: metadata.count,
            omitted_total: metadata.resolved_omitted_total(latest, prune_finishing),
            receipt,
            prune_pending: plan.is_some(),
        }))
    }
}
