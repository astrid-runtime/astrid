//! Every prune receipt of every chain, kept by generation.
//!
//! The chain's installed receipt (`audit:prune_receipts`) is only the latest
//! one. A verifier connecting retained entries to history it anchored earlier
//! needs each generation between the two, so every receipt is also kept here
//! under `"<chain key>/<generation:020>"`, before it is installed. A chain
//! pruned before this history existed has only its installed receipt, which
//! is copied here by the chain's next prune.

use astrid_core::{PrincipalId, SessionId};

use super::metadata::PruneGeneration;
use super::{AuditError, AuditResult, KvAuditStorage, chain_head_key};

pub(super) const NS_RECEIPT_HISTORY: &str = "audit:receipt_history";

fn history_key(chain_key: &str, generation: u64) -> String {
    format!("{chain_key}/{generation:020}")
}

impl KvAuditStorage {
    /// Keep one receipt of `chain_key` in its history. Recording the same
    /// bytes again is a no-op; a different receipt for a recorded
    /// generation is an error.
    pub(super) async fn record_receipt_history(
        &self,
        chain_key: &str,
        receipt: &[u8],
    ) -> AuditResult<()> {
        let generation = PruneGeneration::parse(receipt)?.generation;
        let key = history_key(chain_key, generation);
        let stored = self
            .store
            .get(NS_RECEIPT_HISTORY, &key)
            .await
            .map_err(|error| AuditError::StorageError(error.to_string()))?;
        match stored {
            Some(stored) if stored == receipt => Ok(()),
            Some(_) => Err(AuditError::StorageError(format!(
                "audit prune receipt history already holds a different receipt for \
                 generation {generation}"
            ))),
            None => self
                .store
                .set(NS_RECEIPT_HISTORY, &key, receipt.to_vec())
                .await
                .map_err(|error| AuditError::StorageError(error.to_string())),
        }
    }

    /// Up to `limit` recorded receipts of one chain with generation at
    /// least `from`, oldest first, exactly as stored.
    pub(crate) async fn receipt_history_page(
        &self,
        session_id: &SessionId,
        principal: Option<&PrincipalId>,
        from: u64,
        limit: usize,
    ) -> AuditResult<Vec<Vec<u8>>> {
        let chain_key = chain_head_key(session_id, principal);
        let after = from
            .checked_sub(1)
            .map(|previous| history_key(&chain_key, previous));
        let keys = self
            .store
            .list_keys_with_prefix_page(
                NS_RECEIPT_HISTORY,
                &format!("{chain_key}/"),
                after.as_deref(),
                limit,
            )
            .await
            .map_err(|error| AuditError::StorageError(error.to_string()))?;
        let mut receipts = Vec::with_capacity(keys.len());
        for key in keys {
            let receipt = self
                .store
                .get(NS_RECEIPT_HISTORY, &key)
                .await
                .map_err(|error| AuditError::StorageError(error.to_string()))?
                .ok_or_else(|| {
                    AuditError::StorageError(format!("audit receipt history {key} disappeared"))
                })?;
            receipts.push(receipt);
        }
        Ok(receipts)
    }

    /// Drop a chain's receipt history, as for a chain pruned before the
    /// history existed.
    #[cfg(test)]
    pub(crate) async fn test_forget_receipt_history(
        &self,
        session_id: &SessionId,
        principal: Option<&PrincipalId>,
    ) -> AuditResult<()> {
        self.store
            .clear_prefix(
                NS_RECEIPT_HISTORY,
                &format!("{}/", chain_head_key(session_id, principal)),
            )
            .await
            .map(|_| ())
            .map_err(|error| AuditError::StorageError(error.to_string()))
    }
}
