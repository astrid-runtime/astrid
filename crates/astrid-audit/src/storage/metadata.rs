use astrid_capabilities::AuditEntryId;
use astrid_crypto::ContentHash;

use crate::error::{AuditError, AuditResult};

/// Stored [`ChainMetadata::omitted_total`] of a chain whose pruned history
/// cannot be counted: it was pruned more than once before the counter
/// existed, and only the latest prune receipt is kept. Saturating addition
/// keeps the value absorbing.
pub(crate) const OMITTED_TOTAL_UNKNOWN: u64 = u64::MAX;

/// Recoverable O(1) accounting for one signed chain segment.
#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize)]
pub(crate) struct ChainMetadata {
    pub(crate) schema: u8,
    pub(crate) segment: u64,
    pub(crate) sealed: bool,
    pub(crate) count: u64,
    pub(crate) bytes: u64,
    pub(crate) head: Option<AuditEntryId>,
    pub(crate) head_hash: ContentHash,
    /// Entries in the current segment (chain totals remain in `count`).
    #[serde(default)]
    pub(crate) segment_count: u64,
    /// Canonical bytes in the current segment.
    #[serde(default)]
    pub(crate) segment_bytes: u64,
    /// First entry in the current segment.
    #[serde(default)]
    pub(crate) segment_first: Option<AuditEntryId>,
    /// Durable global seal ordinal for the current segment.
    #[serde(default)]
    pub(crate) seal_ordinal: Option<u64>,
    /// Entries removed from the front of the chain by every counted prune.
    ///
    /// A prune raises it in the same compare-and-swap that lowers `count`,
    /// so it never decreases. `None` until the chain's first prune under
    /// this field, including metadata written before it existed; readers
    /// then derive the total from the latest prune receipt. Absent fields
    /// are not serialized, so re-encoding such metadata reproduces its
    /// stored bytes, which append-intent recovery compares exactly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) omitted_total: Option<u64>,
    /// Generation of the latest prune receipt counted in `omitted_total`.
    /// A resumed prune finalization uses it to count its receipt once.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) omitted_generation: Option<u64>,
}

/// Generation and per-generation omitted count of one prune receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PruneGeneration {
    pub(crate) generation: u64,
    pub(crate) omitted_count: u64,
}

impl PruneGeneration {
    /// Read both fields from receipt bytes as stored.
    pub(crate) fn parse(receipt: &[u8]) -> AuditResult<Self> {
        let value: serde_json::Value = serde_json::from_slice(receipt)
            .map_err(|error| AuditError::SerializationError(error.to_string()))?;
        Self::from_value(&value)
    }

    pub(crate) fn from_value(receipt: &serde_json::Value) -> AuditResult<Self> {
        let field = |name: &str| {
            receipt
                .get(name)
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| {
                    AuditError::StorageError(format!("audit prune receipt lacks {name}"))
                })
        };
        Ok(Self {
            generation: field("generation")?,
            omitted_count: field("omitted_count")?,
        })
    }
}

impl ChainMetadata {
    /// Count one finished prune generation into `omitted_total`.
    ///
    /// `installed` is the chain's prune receipt as currently stored; it is
    /// consulted only while `omitted_total` is still `None`. Counting a
    /// generation that is already counted leaves the metadata unchanged, so
    /// a resumed finalization cannot count its receipt twice.
    pub(crate) fn count_prune(
        &mut self,
        pruned: PruneGeneration,
        installed: Option<PruneGeneration>,
    ) {
        if self.omitted_generation == Some(pruned.generation) {
            return;
        }
        let before = match self.omitted_total {
            Some(total) if self.omitted_generation == pruned.generation.checked_sub(1) => total,
            // A generation was skipped, so the counted total is incomplete.
            Some(_) => OMITTED_TOTAL_UNKNOWN,
            None => uncounted_total_before(pruned.generation, installed),
        };
        self.omitted_total = Some(before.saturating_add(pruned.omitted_count));
        self.omitted_generation = Some(pruned.generation);
    }

    /// Entries removed from the front of the chain by pruning, or `None`
    /// when that total cannot be known.
    ///
    /// `latest` is the chain's installed prune receipt. `prune_finishing` is
    /// whether a prune plan has finished deleting but is still pending, in
    /// which case an interrupted finalization may already have lowered
    /// `count` without recording the total. Both matter only while
    /// `omitted_total` is `None`.
    pub(crate) fn resolved_omitted_total(
        &self,
        latest: Option<PruneGeneration>,
        prune_finishing: bool,
    ) -> Option<u64> {
        let total = match (self.omitted_total, latest) {
            (Some(total), _) => total,
            (None, _) if prune_finishing => OMITTED_TOTAL_UNKNOWN,
            (None, None) => 0,
            (
                None,
                Some(PruneGeneration {
                    generation: 0,
                    omitted_count,
                }),
            ) => omitted_count,
            (None, Some(_)) => OMITTED_TOTAL_UNKNOWN,
        };
        (total != OMITTED_TOTAL_UNKNOWN).then_some(total)
    }
}

/// Entries omitted before prune `generation` of a chain that has not counted
/// any prune: none before generation 0, and the generation-0 receipt's count
/// before generation 1 while that receipt is still installed. Earlier
/// receipts are replaced by later ones, so any other total is unknown.
fn uncounted_total_before(generation: u64, installed: Option<PruneGeneration>) -> u64 {
    match (generation, installed) {
        (0, _) => 0,
        (
            1,
            Some(PruneGeneration {
                generation: 0,
                omitted_count,
            }),
        ) => omitted_count,
        _ => OMITTED_TOTAL_UNKNOWN,
    }
}

#[cfg(test)]
impl super::KvAuditStorage {
    /// Rewrite a chain's metadata as stored before `omitted_total` existed.
    pub(crate) async fn test_forget_omitted_total(
        &self,
        session_id: &astrid_core::SessionId,
        principal: Option<&astrid_core::PrincipalId>,
    ) -> AuditResult<()> {
        let (_, metadata) = self.load_chain_metadata(session_id, principal).await?;
        let mut metadata = metadata.ok_or_else(|| {
            AuditError::StorageError("missing chain metadata to rewrite".to_owned())
        })?;
        metadata.omitted_total = None;
        metadata.omitted_generation = None;
        let bytes = serde_json::to_vec(&metadata)
            .map_err(|error| AuditError::SerializationError(error.to_string()))?;
        self.store
            .set(
                super::NS_CHAIN_METADATA,
                &super::chain_head_key(session_id, principal),
                bytes,
            )
            .await
            .map_err(|error| AuditError::StorageError(error.to_string()))
    }

    /// Leave a prune plan for `receipt` that finished deleting but was not
    /// finalized, as a process that died during finalization does.
    pub(crate) async fn test_stage_finished_prune_plan(
        &self,
        session_id: &astrid_core::SessionId,
        principal: Option<&astrid_core::PrincipalId>,
        receipt: Vec<u8>,
    ) -> AuditResult<()> {
        let plan = super::PrunePlan {
            receipt,
            keep_entries: 1,
            after: None,
            complete: true,
            segment_key: None,
            segment_accounted: false,
        };
        let bytes = serde_json::to_vec(&plan)
            .map_err(|error| AuditError::SerializationError(error.to_string()))?;
        self.store
            .set(
                super::NS_PRUNE_PLANS,
                &super::chain_head_key(session_id, principal),
                bytes,
            )
            .await
            .map_err(|error| AuditError::StorageError(error.to_string()))
    }
}

#[cfg(test)]
#[path = "metadata_tests.rs"]
mod tests;
