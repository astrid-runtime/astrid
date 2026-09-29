//! Reading the global sealed-segment index in seal order.
//!
//! Index keys are `"<seal ordinal:020>:<chain key>:<segment:020>"`, where the
//! chain key is `"<session>"` for a session's system chain and
//! `"<session>:<principal>"` for a principal chain.

use astrid_core::{PrincipalId, SessionId};

use super::{AuditError, AuditResult, ChainMetadata, KvAuditStorage, NS_SEGMENT_INDEX};

/// The chain a sealed-segment index key belongs to.
pub(crate) struct SegmentChain {
    pub(crate) session: SessionId,
    pub(crate) principal: Option<PrincipalId>,
    /// `"<session>"` or `"<session>:<principal>"`.
    pub(crate) chain_key: String,
}

/// One sealed segment as its descriptor recorded it when it was sealed.
pub(crate) struct SealedSegment {
    /// Entries in the segment.
    pub(crate) segment_count: u64,
    /// Segment number within its chain.
    pub(crate) segment: u64,
    /// Global seal ordinal.
    pub(crate) seal_ordinal: Option<u64>,
}

/// Parse the chain out of a sealed-segment index key.
pub(crate) fn segment_chain(index_key: &str) -> AuditResult<SegmentChain> {
    let invalid = || AuditError::StorageError("invalid audit segment index key".to_owned());
    let (_, chain_with_segment) = index_key.split_once(':').ok_or_else(invalid)?;
    let (chain_key, _) = chain_with_segment.rsplit_once(':').ok_or_else(invalid)?;
    let (session, principal) = chain_key
        .split_once(':')
        .map_or((chain_key, None), |(session, principal)| {
            (session, Some(principal))
        });
    let session = uuid::Uuid::parse_str(session)
        .map(SessionId::from_uuid)
        .map_err(|error| AuditError::StorageError(error.to_string()))?;
    let principal = principal
        .map(PrincipalId::new)
        .transpose()
        .map_err(|error| AuditError::StorageError(error.to_string()))?;
    Ok(SegmentChain {
        session,
        principal,
        chain_key: chain_key.to_owned(),
    })
}

impl KvAuditStorage {
    /// Up to `limit` sealed-segment index keys after `after`, in seal order.
    pub(crate) async fn sealed_segment_keys(
        &self,
        after: Option<&str>,
        limit: usize,
    ) -> AuditResult<Vec<String>> {
        self.store
            .list_keys_with_prefix_page(NS_SEGMENT_INDEX, "", after, limit)
            .await
            .map_err(|error| AuditError::StorageError(error.to_string()))
    }

    /// The descriptor stored under one index key, or `None` when a prune
    /// removed it after the key was listed.
    pub(crate) async fn sealed_segment(
        &self,
        index_key: &str,
    ) -> AuditResult<Option<SealedSegment>> {
        let Some(bytes) = self
            .store
            .get(NS_SEGMENT_INDEX, index_key)
            .await
            .map_err(|error| AuditError::StorageError(error.to_string()))?
        else {
            return Ok(None);
        };
        let descriptor: ChainMetadata = serde_json::from_slice(&bytes)
            .map_err(|error| AuditError::SerializationError(error.to_string()))?;
        Ok(Some(SealedSegment {
            segment_count: descriptor.segment_count,
            segment: descriptor.segment,
            seal_ordinal: descriptor.seal_ordinal,
        }))
    }
}
