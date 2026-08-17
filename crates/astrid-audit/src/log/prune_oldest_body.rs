{
let Some((session, principal, segment)) = self.storage.oldest_sealed_segment().await? else {
    return Ok(None);
};
let chain = self
    .storage
    .chain_metadata(&session, principal.as_ref())
    .await?;
let Some(chain) = chain else {
    return Err(AuditError::StorageError(
        "oldest sealed segment has no chain metadata".to_owned(),
    ));
};
let suffix = chain.count.saturating_sub(segment.segment_count);
let retain_entries = policy
    .retain_entries
    .max(usize::try_from(suffix).unwrap_or(usize::MAX));
let bounded_policy = AuditRetentionPolicy {
    retain_entries,
    retain_bytes: policy.retain_bytes,
};
prune::prune_chain_segment(
    self,
    &session,
    principal.as_ref(),
    bounded_policy,
    Some((segment.segment, segment.seal_ordinal)),
)
    .await
    .map(Some)
}
