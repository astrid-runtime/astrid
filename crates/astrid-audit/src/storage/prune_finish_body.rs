{
let value: serde_json::Value = serde_json::from_slice(&plan.receipt)
    .map_err(|e| AuditError::SerializationError(e.to_string()))?;
let retained_count = value
    .get("retained_count")
    .and_then(serde_json::Value::as_u64)
    .unwrap_or(0);
let retained_bytes = value
    .get("retained_bytes")
    .and_then(serde_json::Value::as_u64)
    .unwrap_or(0);
let omitted_count = value
    .get("omitted_count")
    .and_then(serde_json::Value::as_u64)
    .unwrap_or(0);
let omitted_bytes = value
    .get("omitted_bytes")
    .and_then(serde_json::Value::as_u64)
    .unwrap_or(0);
let retained_head = value
    .get("retained_head")
    .and_then(serde_json::Value::as_str)
    .map(str::parse::<uuid::Uuid>)
    .transpose()
    .map_err(|e| AuditError::StorageError(e.to_string()))?
    .map(AuditEntryId);
let head_hash = if let Some(head) = retained_head.as_ref() {
    match self.get(head).await? {
        Some(entry) => entry.content_hash(),
        None => astrid_crypto::ContentHash::zero(),
    }
} else {
    astrid_crypto::ContentHash::zero()
};
if let (metadata_bytes, Some(mut metadata)) =
    self.load_chain_metadata(session_id, principal).await?
{
    metadata.count = retained_count;
    metadata.bytes = retained_bytes;
    metadata.head = retained_head;
    metadata.head_hash = head_hash;
    metadata.sealed = true;
    if !self
        .persist_chain_metadata(session_id, principal, metadata_bytes.as_deref(), &metadata)
        .await?
    {
        return Err(AuditError::StorageError(
            "audit chain metadata changed while pruning".to_owned(),
        ));
    }
}
let (global_bytes, mut global) = self.load_global_metadata().await?;
global.total_count = global.total_count.saturating_sub(omitted_count);
global.total_bytes = global.total_bytes.saturating_sub(omitted_bytes);
if plan.segment_key.is_some() && !plan.segment_accounted {
    global.sealed_segments = global.sealed_segments.saturating_sub(1);
    global.eligible_segments = global.eligible_segments.saturating_sub(1);
    global.segments = global.segments.saturating_sub(1);
}
global.degraded = global.total_count > global.cap_entries
    || global.total_bytes > global.cap_bytes;
let mut next_plan = plan.clone();
next_plan.segment_accounted = true;
let plan_current = self
    .store
    .get(NS_PRUNE_PLANS, plan_key)
    .await
    .map_err(|e| AuditError::StorageError(e.to_string()))?;
let next_plan_bytes = serde_json::to_vec(&next_plan)
    .map_err(|e| AuditError::SerializationError(e.to_string()))?;
if self.store.supports_atomic_batch() {
    let plan_key = astrid_storage::KvEntryKey::new(NS_PRUNE_PLANS, plan_key)
        .map_err(|e| AuditError::StorageError(e.to_string()))?;
    let global_key = astrid_storage::KvEntryKey::new(NS_GLOBAL_METADATA, "current")
        .map_err(|e| AuditError::StorageError(e.to_string()))?;
    let batch = astrid_storage::KvMutationBatch::new(
        [
            astrid_storage::KvBatchCondition::ValueEquals {
                key: plan_key.clone(),
                expected: plan_current.clone(),
            },
            astrid_storage::KvBatchCondition::ValueEquals {
                key: global_key.clone(),
                expected: global_bytes.clone(),
            },
        ],
        [
            astrid_storage::KvBatchMutation::Set {
                key: plan_key,
                value: next_plan_bytes,
            },
            astrid_storage::KvBatchMutation::Set {
                key: global_key,
                value: serde_json::to_vec(&global)
                    .map_err(|e| AuditError::SerializationError(e.to_string()))?,
            },
        ],
    )
    .map_err(|e| AuditError::StorageError(e.to_string()))?;
    if !self
        .store
        .apply_batch(&batch)
        .await
        .map_err(|e| AuditError::StorageError(e.to_string()))?
        .applied
    {
        return Err(AuditError::StorageError(
            "audit prune plan or global metadata changed".to_owned(),
        ));
    }
} else {
    if !self
        .persist_global_metadata(global_bytes.as_deref(), &global)
        .await?
    {
        return Err(AuditError::StorageError(
            "audit global metadata changed while pruning".to_owned(),
        ));
    }
    if !self
        .store
        .compare_and_swap(
            NS_PRUNE_PLANS,
            plan_key,
            plan_current.as_deref(),
            next_plan_bytes,
        )
        .await
        .map_err(|e| AuditError::StorageError(e.to_string()))?
    {
        return Err(AuditError::StorageError(
            "audit prune plan changed while accounting".to_owned(),
        ));
    }
}
if let Some(segment_key) = plan.segment_key.as_deref() {
    self.store
        .delete(NS_SEGMENT_INDEX, segment_key)
        .await
        .map_err(|e| AuditError::StorageError(e.to_string()))?;
}
let receipt_key = chain_head_key(session_id, principal);
let current = self
    .store
    .get(NS_PRUNE_RECEIPTS, &receipt_key)
    .await
    .map_err(|e| AuditError::StorageError(e.to_string()))?;
if current.as_deref() != Some(plan.receipt.as_slice())
    && !self
        .store
        .compare_and_swap(
            NS_PRUNE_RECEIPTS,
            &receipt_key,
            current.as_deref(),
            plan.receipt.clone(),
        )
        .await
        .map_err(|e| AuditError::StorageError(e.to_string()))?
{
    return Err(AuditError::StorageError(
        "audit prune receipt pointer changed during finalization".to_owned(),
    ));
}
self.store
    .delete(NS_PRUNE_PLANS, plan_key)
    .await
    .map_err(|e| AuditError::StorageError(e.to_string()))
    .map(|_| ())
}
