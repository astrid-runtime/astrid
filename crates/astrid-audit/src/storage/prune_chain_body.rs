{
let _guard = DURABLE_APPEND_LOCK.lock().await;
// Never fall back to the legacy giant session-index array. Migration
// must first create bounded per-entry sequence records.
if !self
    .store
    .exists(NS_SESSION_SEQUENCE, &session_id.0.to_string())
    .await
    .map_err(|e| AuditError::StorageError(e.to_string()))?
{
    return Err(AuditError::StorageError(
        "audit prune requires a paged session projection".to_owned(),
    ));
}

let plan_key = chain_head_key(session_id, principal);
let plan_bytes = self
    .store
    .get(NS_PRUNE_PLANS, &plan_key)
    .await
    .map_err(|e| AuditError::StorageError(e.to_string()))?;
let mut plan = if let Some(bytes) = plan_bytes.clone() {
    serde_json::from_slice::<PrunePlan>(&bytes)
        .map_err(|e| AuditError::SerializationError(e.to_string()))?
} else {
    // Validate receipt generations before journalling the deletion plan. A
    // replacement must explicitly hash-link to the current anchor.
    let current = self
        .store
        .get(NS_PRUNE_RECEIPTS, &plan_key)
        .await
        .map_err(|e| AuditError::StorageError(e.to_string()))?;
    if let Some(current) = current.as_deref() {
        let old: serde_json::Value = serde_json::from_slice(current)
            .map_err(|e| AuditError::SerializationError(e.to_string()))?;
        let next: serde_json::Value = serde_json::from_slice(&receipt)
            .map_err(|e| AuditError::SerializationError(e.to_string()))?;
        let old_generation = old
            .get("generation")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| {
                AuditError::StorageError("archive receipt lacks generation".to_owned())
            })?;
        let next_generation = next
            .get("generation")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| {
                AuditError::StorageError("archive receipt lacks generation".to_owned())
            })?;
        let prior = next
            .get("prior_receipt_hash")
            .and_then(serde_json::Value::as_str);
        let expected_prior = blake3::hash(current).to_hex().to_string();
        if next_generation != old_generation.saturating_add(1)
            || prior != Some(expected_prior.as_str())
        {
            return Err(AuditError::StorageError(
                "audit prune receipt generation is not linked to the current anchor"
                    .to_owned(),
            ));
        }
    }
    let receipt_value: serde_json::Value = serde_json::from_slice(&receipt)
        .map_err(|e| AuditError::SerializationError(e.to_string()))?;
    let omitted_count = receipt_value
        .get("omitted_count")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let omitted_bytes = receipt_value
        .get("omitted_bytes")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let omitted_terminal_hash = receipt_value
        .get("omitted_terminal_hash")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let chain_marker = format!(":{}:", chain_head_key(session_id, principal));
    let mut segment_key = None;
    if omitted_count > 0 {
        let mut after_segment = None;
        loop {
            let page = self
                .store
                .list_keys_with_prefix_page(
                    NS_SEGMENT_INDEX,
                    "",
                    after_segment.as_deref(),
                    256,
                )
                .await
                .map_err(|e| AuditError::StorageError(e.to_string()))?;
            if page.is_empty() {
                break;
            }
            let next_after = page.last().cloned();
            for candidate_key in &page {
                if !candidate_key.contains(&chain_marker) {
                    continue;
                }
                let Some(bytes) = self
                    .store
                    .get(NS_SEGMENT_INDEX, candidate_key)
                    .await
                    .map_err(|e| AuditError::StorageError(e.to_string()))?
                else {
                    continue;
                };
                let metadata: ChainMetadata = serde_json::from_slice(&bytes)
                    .map_err(|e| AuditError::SerializationError(e.to_string()))?;
                if metadata.sealed
                    && metadata.segment_count == omitted_count
                    && metadata.segment_bytes == omitted_bytes
                    && metadata.head_hash.to_hex() == omitted_terminal_hash
                {
                    segment_key = Some(candidate_key.clone());
                    break;
                }
            }
            if segment_key.is_some() {
                break;
            }
            after_segment = next_after;
        }
    }
    let candidate = PrunePlan {
        receipt,
        keep_entries,
        after: None,
        complete: false,
        segment_key,
        segment_count: omitted_count,
        segment_bytes: omitted_bytes,
        segment_accounted: false,
    };
    let bytes = serde_json::to_vec(&candidate)
        .map_err(|e| AuditError::SerializationError(e.to_string()))?;
    if !self
        .store
        .compare_and_swap(NS_PRUNE_PLANS, &plan_key, None, bytes)
        .await
        .map_err(|e| AuditError::StorageError(e.to_string()))?
    {
        return Err(AuditError::StorageError(
            "audit prune plan was concurrently installed; retry".to_owned(),
        ));
    }
    candidate
};

if plan.complete {
    return self
        .finish_prune_plan(session_id, principal, &plan_key, &plan)
        .await;
}

let receipt_value: serde_json::Value = serde_json::from_slice(&plan.receipt)
    .map_err(|e| AuditError::SerializationError(e.to_string()))?;
let cutoff = receipt_value
    .get("cutoff_cursor")
    .and_then(serde_json::Value::as_str)
    .map(str::to_owned);

// Nothing was omitted: install the receipt/metadata without deleting records.
if cutoff.is_none() {
    plan.complete = true;
    let current_plan = self
        .store
        .get(NS_PRUNE_PLANS, &plan_key)
        .await
        .map_err(|e| AuditError::StorageError(e.to_string()))?;
    let next_bytes = serde_json::to_vec(&plan)
        .map_err(|e| AuditError::SerializationError(e.to_string()))?;
    if !self
        .store
        .compare_and_swap(
            NS_PRUNE_PLANS,
            &plan_key,
            current_plan.as_deref(),
            next_bytes,
        )
        .await
        .map_err(|e| AuditError::StorageError(e.to_string()))?
    {
        return Err(AuditError::StorageError(
            "audit prune plan changed during finalization".to_owned(),
        ));
    }
    return self
        .finish_prune_plan(session_id, principal, &plan_key, &plan)
        .await;
}

// Apply at most one bounded page per durable progress update. A crash after
// any individual delete is safe: the plan cursor advances only after a page
// has been replayed, and deletes are idempotent on retry.
let page = self
    .get_session_entries_page(session_id, plan.after.as_deref(), 256)
    .await?;
let page_empty = page.is_empty();
let mut reached_cutoff = false;
let mut last_cursor = plan.after.clone();
for (cursor, entry) in page {
    if cutoff
        .as_deref()
        .is_some_and(|limit| cursor.as_str() > limit)
    {
        reached_cutoff = true;
        break;
    }
    last_cursor = Some(cursor.clone());
    if entry.principal.as_ref() != principal {
        continue;
    }
    self.store
        .delete(NS_ENTRIES, &entry.id.0.to_string())
        .await
        .map_err(|e| AuditError::StorageError(e.to_string()))?;
    self.store
        .delete(NS_COMMITTED_ENTRIES, &entry.id.0.to_string())
        .await
        .map_err(|e| AuditError::StorageError(e.to_string()))?;
    self.store
        .delete(NS_SESSION_ENTRIES, &cursor)
        .await
        .map_err(|e| AuditError::StorageError(e.to_string()))?;
    if cutoff.as_deref().is_some_and(|limit| cursor == limit) {
        reached_cutoff = true;
        break;
    }
}
if page_empty {
    reached_cutoff = true;
}
plan.after = last_cursor;
plan.complete = reached_cutoff;
let next_bytes =
    serde_json::to_vec(&plan).map_err(|e| AuditError::SerializationError(e.to_string()))?;
let expected_plan = self
    .store
    .get(NS_PRUNE_PLANS, &plan_key)
    .await
    .map_err(|e| AuditError::StorageError(e.to_string()))?;
if !self
    .store
    .compare_and_swap(
        NS_PRUNE_PLANS,
        &plan_key,
        expected_plan.as_deref(),
        next_bytes,
    )
    .await
    .map_err(|e| AuditError::StorageError(e.to_string()))?
{
    return Err(AuditError::StorageError(
        "audit prune plan changed during bounded deletion".to_owned(),
    ));
}
if plan.complete {
    self.finish_prune_plan(session_id, principal, &plan_key, &plan)
        .await
} else {
    Ok(())
}
}
