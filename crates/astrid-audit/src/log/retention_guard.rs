//! Retention that never removes history which is not anchored.
//!
//! A chain's anchored watermark (see [`AuditLog::mark_anchored`]) is the
//! number of entries, counted from the chain's genesis, that an external
//! anchoring service has certified. A prune of the chain may remove only
//! entries before it. A chain without a watermark is pruned as before, unless
//! the operator requires anchoring before any prune.
//!
//! Every prune is checked after its retention scan, against the chain's
//! pruned total read after the prior receipt the new receipt links to. A
//! prune that finishes in between moves that receipt on, and the new
//! receipt's generation link then fails when its plan is installed, so the
//! check always sees the pruned total the removal starts from, or a larger
//! one.
//!
//! When the global cap is reached, the append path prunes the oldest sealed
//! segment that can be removed. When every candidate would remove unanchored
//! history, it sets the retention hold instead: entries are kept over the
//! cap, the global state reports degraded, and an error is logged. The hold
//! is cleared when a watermark advances, a prune finishes, a new segment is
//! sealed or the caps change, and the next append at the cap tries again.

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};

use astrid_core::{PrincipalId, SessionId};
use tracing::error;

use super::{
    AuditArchiver, AuditError, AuditLog, AuditResult, AuditRetentionPolicy,
    DEFAULT_AUTO_RETENTION_ENTRIES,
};
use crate::storage::{KvAuditStorage, SegmentChain, segment_chain};

/// Sealed-segment index keys read per page while choosing a segment.
const SEGMENT_KEY_PAGE: usize = 256;

/// Operator retention controls, set once the kernel has read its config.
#[derive(Default)]
pub(super) struct RetentionControls {
    require_anchor: AtomicBool,
    archiver: RwLock<Option<Arc<dyn AuditArchiver>>>,
}

/// How far a prune of one chain may reach.
pub(super) struct PruneLimit {
    chain: String,
    /// Entries pruned from the chain's start before this prune.
    omitted_before: u64,
    /// The chain's watermark, or `None` when it has none.
    anchored: Option<u64>,
}

impl PruneLimit {
    /// Most entries the prune may remove.
    fn max_omitted(&self) -> u64 {
        self.anchored
            .unwrap_or(0)
            .saturating_sub(self.omitted_before)
    }

    fn check(&self, remove: u64) -> AuditResult<()> {
        if remove <= self.max_omitted() {
            return Ok(());
        }
        let reach = self.omitted_before.saturating_add(remove);
        let chain = &self.chain;
        Err(AuditError::UnanchoredPrune(match self.anchored {
            Some(anchored) => format!(
                "chain {chain} is anchored through its first {anchored} entries, but the prune \
                 would remove its first {reach}"
            ),
            None => format!(
                "chain {chain} has no anchored watermark, and pruning requires one (the prune \
                 would remove its first {reach} entries)"
            ),
        }))
    }
}

/// A sealed segment chosen for pruning, and the retention that removes it.
pub(super) struct PrunableSegment {
    pub(super) session: SessionId,
    pub(super) principal: Option<PrincipalId>,
    pub(super) segment: u64,
    pub(super) seal_ordinal: Option<u64>,
    pub(super) retain_entries: usize,
}

/// `"<session> (system)"` or `"<session> <principal>"`.
pub(super) fn chain_label(session_id: &SessionId, principal: Option<&PrincipalId>) -> String {
    match principal {
        Some(principal) => format!("{} {principal}", session_id.0),
        None => format!("{} (system)", session_id.0),
    }
}

impl AuditLog {
    /// Require an anchored watermark before any chain is pruned.
    ///
    /// Off by default: a chain without a watermark is then pruned as before,
    /// and only chains with a watermark are limited by it. When on, a chain
    /// without one cannot be pruned, and the global cap holds instead of
    /// pruning it.
    pub fn set_require_anchor_before_prune(&self, required: bool) {
        self.retention
            .require_anchor
            .store(required, Ordering::SeqCst);
    }

    /// Whether pruning requires an anchored watermark (see
    /// [`Self::set_require_anchor_before_prune`]).
    #[must_use]
    pub fn require_anchor_before_prune(&self) -> bool {
        self.retention.require_anchor.load(Ordering::SeqCst)
    }

    /// Hand every pruned segment to `archiver` before deleting it, or stop
    /// archiving with `None`. See [`AuditArchiver`].
    pub fn set_prune_archiver(&self, archiver: Option<Arc<dyn AuditArchiver>>) {
        *self
            .retention
            .archiver
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = archiver;
    }

    pub(super) fn prune_archiver(&self) -> Option<Arc<dyn AuditArchiver>> {
        self.retention
            .archiver
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Refuse a prune of one chain that would remove `remove` entries past
    /// its watermark, or any entry of a chain without one while anchoring is
    /// required.
    pub(super) async fn check_prune_reach(
        &self,
        session_id: &SessionId,
        principal: Option<&PrincipalId>,
        remove: u64,
    ) -> AuditResult<()> {
        if remove == 0 {
            return Ok(());
        }
        let Some(storage) = self.storage.as_kv_audit_storage() else {
            if self.require_anchor_before_prune() {
                return Err(AuditError::UnanchoredPrune(
                    "this audit backend records no anchored watermarks".to_owned(),
                ));
            }
            return Ok(());
        };
        let omitted_before = storage
            .chain_positions(session_id, principal)
            .await?
            .map_or(Some(0), |positions| positions.omitted_total);
        match self
            .prune_limit(storage, session_id, principal, omitted_before)
            .await?
        {
            Some(limit) => limit.check(remove),
            None => Ok(()),
        }
    }

    async fn prune_limit(
        &self,
        storage: &KvAuditStorage,
        session_id: &SessionId,
        principal: Option<&PrincipalId>,
        omitted_before: Option<u64>,
    ) -> AuditResult<Option<PruneLimit>> {
        let (_, mark) = storage.anchor_mark(session_id, principal).await?;
        let anchored = mark.map(|mark| mark.position);
        if anchored.is_none() && !self.require_anchor_before_prune() {
            return Ok(None);
        }
        let chain = chain_label(session_id, principal);
        let Some(omitted_before) = omitted_before else {
            return Err(AuditError::UnanchoredPrune(format!(
                "chain {chain}: the number of entries already pruned is unknown, so the prune \
                 cannot be checked against its anchored history"
            )));
        };
        Ok(Some(PruneLimit {
            chain,
            omitted_before,
            anchored,
        }))
    }

    /// Choose the oldest sealed segment, in global seal order, whose prune
    /// removes no unanchored history, and the retention that removes it.
    ///
    /// `Ok(None)` means no sealed segment exists. When segments exist but
    /// none can be pruned, the refusal for the oldest one is returned.
    ///
    /// The whole index is read when nothing earlier can be pruned, so a
    /// refusal means no sealed segment can be. That costs one page of keys
    /// per 256 segments and a few reads per chain: a chain whose oldest
    /// segment is refused has every later segment refused too, so those are
    /// skipped without being read. With the retention hold set, appends at
    /// the cap do not search again until a watermark advances, a prune
    /// finishes, a segment is sealed or the caps change.
    pub(super) async fn select_prunable_segment(
        &self,
        policy: AuditRetentionPolicy,
    ) -> AuditResult<Option<PrunableSegment>> {
        let Some(storage) = self.storage.as_kv_audit_storage() else {
            return self.oldest_segment_unchecked(policy).await;
        };
        let mut blocked = HashSet::new();
        let mut refusal = None;
        let mut after: Option<String> = None;
        loop {
            let keys = storage
                .sealed_segment_keys(after.as_deref(), SEGMENT_KEY_PAGE)
                .await?;
            for key in &keys {
                let chain = segment_chain(key)?;
                if blocked.contains(&chain.chain_key) {
                    continue;
                }
                let Some(segment) = storage.sealed_segment(key).await? else {
                    continue;
                };
                match self
                    .segment_prune(storage, &chain, segment.segment_count, policy)
                    .await
                {
                    Ok(retain_entries) => {
                        return Ok(Some(PrunableSegment {
                            session: chain.session,
                            principal: chain.principal,
                            segment: segment.segment,
                            seal_ordinal: segment.seal_ordinal,
                            retain_entries,
                        }));
                    },
                    Err(error @ AuditError::UnanchoredPrune(_)) => {
                        blocked.insert(chain.chain_key);
                        refusal.get_or_insert(error);
                    },
                    Err(error) => return Err(error),
                }
            }
            if keys.len() < SEGMENT_KEY_PAGE {
                break;
            }
            after = keys.last().cloned();
        }
        refusal.map_or(Ok(None), Err)
    }

    /// The retention that removes one chain's oldest sealed segment of
    /// `segment_count` entries, if that removes no unanchored history.
    async fn segment_prune(
        &self,
        storage: &KvAuditStorage,
        chain: &SegmentChain,
        segment_count: u64,
        policy: AuditRetentionPolicy,
    ) -> AuditResult<usize> {
        let positions = storage
            .chain_positions(&chain.session, chain.principal.as_ref())
            .await?
            .ok_or_else(|| {
                AuditError::StorageError("oldest sealed segment has no chain metadata".to_owned())
            })?;
        let suffix = positions.count.saturating_sub(segment_count);
        let retain_entries = policy
            .retain_entries
            .max(usize::try_from(suffix).unwrap_or(usize::MAX));
        let remove = positions
            .count
            .saturating_sub(u64::try_from(retain_entries).unwrap_or(u64::MAX));
        if remove > 0
            && let Some(limit) = self
                .prune_limit(
                    storage,
                    &chain.session,
                    chain.principal.as_ref(),
                    positions.omitted_total,
                )
                .await?
        {
            limit.check(remove)?;
        }
        Ok(retain_entries)
    }

    /// The globally oldest sealed segment, for backends without anchored
    /// watermarks.
    async fn oldest_segment_unchecked(
        &self,
        policy: AuditRetentionPolicy,
    ) -> AuditResult<Option<PrunableSegment>> {
        let Some((session, principal, segment)) = self.storage.oldest_sealed_segment().await?
        else {
            return Ok(None);
        };
        let chain = self
            .storage
            .chain_metadata(&session, principal.as_ref())
            .await?
            .ok_or_else(|| {
                AuditError::StorageError("oldest sealed segment has no chain metadata".to_owned())
            })?;
        let suffix = chain.count.saturating_sub(segment.segment_count);
        Ok(Some(PrunableSegment {
            session,
            principal,
            segment: segment.segment,
            seal_ordinal: segment.seal_ordinal,
            retain_entries: policy
                .retain_entries
                .max(usize::try_from(suffix).unwrap_or(usize::MAX)),
        }))
    }

    /// Make room for an append that reached the global cap.
    ///
    /// Prunes the oldest sealed segment that can be pruned and returns
    /// `true`. When every candidate would remove unanchored history, sets the
    /// retention hold, so the retried append is admitted over the cap, and
    /// returns `true`. Returns `false` when no sealed segment exists.
    pub(super) async fn relieve_retention_cap(&self) -> AuditResult<bool> {
        let policy = AuditRetentionPolicy {
            retain_entries: DEFAULT_AUTO_RETENTION_ENTRIES,
            retain_bytes: None,
        };
        match self.prune_oldest(policy).await {
            Ok(pruned) => Ok(pruned.is_some()),
            Err(AuditError::UnanchoredPrune(reason)) => {
                let Some(storage) = self.storage.as_kv_audit_storage() else {
                    return Err(AuditError::UnanchoredPrune(reason));
                };
                let hold = format!(
                    "system audit retention cap reached; entries are kept over the cap because \
                     pruning would remove unanchored history: {reason}"
                );
                if storage.set_retention_hold(Some(hold)).await? {
                    error!(
                        security_event = true,
                        reason = %reason,
                        "Audit retention cap reached, but every prunable segment holds \
                         unanchored history; keeping entries over the cap"
                    );
                }
                Ok(true)
            },
            Err(error) => Err(error),
        }
    }
}

#[cfg(test)]
#[path = "retention_guard_tests.rs"]
mod tests;
