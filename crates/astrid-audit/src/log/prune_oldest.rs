use super::{AuditLog, AuditPruneReceipt, AuditResult, AuditRetentionPolicy, prune};

impl AuditLog {
    /// Prune the oldest sealed segment, in global seal order, whose removal
    /// keeps every unanchored entry (see `retention_guard`).
    pub(super) async fn prune_oldest_impl(
        &self,
        policy: AuditRetentionPolicy,
    ) -> AuditResult<Option<AuditPruneReceipt>> {
        let Some(selected) = self.select_prunable_segment(policy).await? else {
            return Ok(None);
        };
        let bounded_policy = AuditRetentionPolicy {
            retain_entries: selected.retain_entries,
            retain_bytes: policy.retain_bytes,
        };
        prune::prune_chain_segment(
            self,
            &selected.session,
            selected.principal.as_ref(),
            bounded_policy,
            Some((selected.segment, selected.seal_ordinal)),
        )
        .await
        .map(Some)
    }
}
