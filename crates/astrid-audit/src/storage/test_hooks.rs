//! Test-only hooks that corrupt or rewrite audit projections directly.

use super::helpers::chain_head_key;
use super::{KvAuditStorage, NS_CHAIN_HEADS, NS_CHAIN_METADATA, NS_SESSION_INDEX};
use crate::error::{AuditError, AuditResult};
use astrid_core::SessionId;

impl KvAuditStorage {
    /// Accept a prune plan as a prune does, without deleting anything yet.
    pub(crate) async fn test_accept_prune_plan(
        &self,
        session_id: &SessionId,
        principal: Option<&astrid_core::PrincipalId>,
        keep_entries: usize,
        receipt: Vec<u8>,
    ) -> AuditResult<()> {
        let _guard = super::DURABLE_APPEND_LOCK.lock().await;
        self.load_or_create_prune_plan(
            session_id,
            principal,
            &chain_head_key(session_id, principal),
            keep_entries,
            receipt,
        )
        .await
        .map(|_| ())
    }

    pub(crate) async fn test_set_legacy_session_index(
        &self,
        session_id: &SessionId,
        bytes: Vec<u8>,
    ) -> AuditResult<()> {
        self.store
            .set(NS_SESSION_INDEX, &session_id.0.to_string(), bytes)
            .await
            .map_err(|error| AuditError::StorageError(error.to_string()))
    }

    pub(crate) async fn test_drop_chain_head(
        &self,
        session_id: &SessionId,
        principal: Option<&astrid_core::PrincipalId>,
    ) -> AuditResult<()> {
        self.store
            .delete(NS_CHAIN_HEADS, &chain_head_key(session_id, principal))
            .await
            .map_err(|error| AuditError::StorageError(error.to_string()))
            .map(|_| ())
    }

    pub(crate) async fn test_set_chain_head(
        &self,
        session_id: &SessionId,
        principal: Option<&astrid_core::PrincipalId>,
        bytes: Vec<u8>,
    ) -> AuditResult<()> {
        self.store
            .set(
                NS_CHAIN_HEADS,
                &chain_head_key(session_id, principal),
                bytes,
            )
            .await
            .map_err(|error| AuditError::StorageError(error.to_string()))
    }

    pub(crate) async fn test_drop_chain_metadata(
        &self,
        session_id: &SessionId,
        principal: Option<&astrid_core::PrincipalId>,
    ) -> AuditResult<()> {
        self.store
            .delete(NS_CHAIN_METADATA, &chain_head_key(session_id, principal))
            .await
            .map_err(|error| AuditError::StorageError(error.to_string()))
            .map(|_| ())
    }
}
