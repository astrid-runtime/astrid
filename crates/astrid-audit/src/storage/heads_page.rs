//! Paged enumeration of every chain-metadata record across all sessions.

use super::metadata::PruneGeneration;
use super::{
    AuditError, AuditResult, ChainMetadata, DURABLE_APPEND_LOCK, KvAuditStorage, NS_CHAIN_METADATA,
    NS_PRUNE_PLANS, NS_PRUNE_RECEIPTS, PrunePlan, chain_head_key,
};
use astrid_core::{PrincipalId, SessionId};

/// One chain's metadata and latest prune receipt, read together.
pub(crate) struct ChainHeadRecord {
    pub(crate) session: SessionId,
    pub(crate) principal: Option<PrincipalId>,
    pub(crate) metadata: ChainMetadata,
    /// Entries pruned from the front of the chain, or `None` when unknown.
    pub(crate) omitted_total: Option<u64>,
    /// Latest prune receipt bytes exactly as stored, if the chain was pruned.
    pub(crate) prune_receipt: Option<Vec<u8>>,
}

/// One page of chain records in storage-key order.
pub(crate) struct ChainMetadataPage {
    /// Every listed chain that still has metadata.
    pub(crate) records: Vec<ChainHeadRecord>,
    /// Cursor for the next page, or `None` when the listing is exhausted.
    pub(crate) next_after: Option<String>,
}

impl KvAuditStorage {
    /// List chain records after `after`, at most `limit` keys.
    ///
    /// Keys are `"<session uuid>"` for a session's system chain and
    /// `"<session uuid>:<principal>"` for a principal chain. A record removed
    /// between the key listing and its read is skipped; the cursor still
    /// advances past it.
    ///
    /// A prune finalizes while holding the durable append lock: one
    /// compare-and-swap lowers the chain's retained count and raises its
    /// omitted total, and the receipt is installed after it. Each chain's
    /// reads take that lock briefly, so the count and omitted total of a
    /// record always come from the same committed state. The lock is not
    /// held across chains.
    pub(crate) async fn chain_metadata_page(
        &self,
        after: Option<&str>,
        limit: usize,
    ) -> AuditResult<ChainMetadataPage> {
        let keys = self
            .store
            .list_keys_with_prefix_page(NS_CHAIN_METADATA, "", after, limit)
            .await
            .map_err(|error| AuditError::StorageError(error.to_string()))?;
        let next_after = (keys.len() >= limit)
            .then(|| keys.last().cloned())
            .flatten();
        let mut records = Vec::with_capacity(keys.len());
        for key in keys {
            let (session, principal) = key
                .split_once(':')
                .map_or((key.as_str(), None), |(session, principal)| {
                    (session, Some(principal))
                });
            let session = uuid::Uuid::parse_str(session)
                .map(SessionId::from_uuid)
                .map_err(|error| AuditError::StorageError(error.to_string()))?;
            let principal = principal
                .map(PrincipalId::new)
                .transpose()
                .map_err(|error| AuditError::StorageError(error.to_string()))?;
            let guard = DURABLE_APPEND_LOCK.lock().await;
            let (_, metadata) = self
                .load_chain_metadata(&session, principal.as_ref())
                .await?;
            let prune_receipt = self
                .store
                .get(NS_PRUNE_RECEIPTS, &key)
                .await
                .map_err(|error| AuditError::StorageError(error.to_string()))?;
            let prune_finishing = match &metadata {
                Some(metadata) if metadata.omitted_total.is_none() => {
                    self.prune_plan_finishing(&key).await?
                },
                _ => false,
            };
            drop(guard);
            let Some(metadata) = metadata else {
                continue;
            };
            let latest = prune_receipt
                .as_deref()
                .map(PruneGeneration::parse)
                .transpose()?;
            records.push(ChainHeadRecord {
                session,
                principal,
                omitted_total: metadata.resolved_omitted_total(latest, prune_finishing),
                metadata,
                prune_receipt,
            });
        }
        Ok(ChainMetadataPage {
            records,
            next_after,
        })
    }

    /// Whether the chain has a prune plan: a prune has started and not yet
    /// finished. Entries are deleted only while a plan exists.
    pub(crate) async fn prune_plan_pending(
        &self,
        session_id: &SessionId,
        principal: Option<&PrincipalId>,
    ) -> AuditResult<bool> {
        self.store
            .exists(NS_PRUNE_PLANS, &chain_head_key(session_id, principal))
            .await
            .map_err(|error| AuditError::StorageError(error.to_string()))
    }

    /// Whether the chain has a prune plan that finished deleting entries but
    /// was not yet finalized.
    async fn prune_plan_finishing(&self, chain_key: &str) -> AuditResult<bool> {
        let Some(bytes) = self
            .store
            .get(NS_PRUNE_PLANS, chain_key)
            .await
            .map_err(|error| AuditError::StorageError(error.to_string()))?
        else {
            return Ok(false);
        };
        let plan: PrunePlan = serde_json::from_slice(&bytes)
            .map_err(|error| AuditError::SerializationError(error.to_string()))?;
        Ok(plan.complete)
    }
}
