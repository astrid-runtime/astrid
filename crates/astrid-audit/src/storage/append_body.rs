{
let _guard = DURABLE_APPEND_LOCK.lock().await;
let current = self
    .get_chain_head(&entry.session_id, entry.principal.as_ref())
    .await?;
if current.as_ref() != expected {
    return Ok(false);
}
let head_key = chain_head_key(&entry.session_id, entry.principal.as_ref());
let stored_head = self
    .store
    .get(NS_CHAIN_HEADS, &head_key)
    .await
    .map_err(|e| AuditError::StorageError(e.to_string()))?;
let (metadata_bytes, metadata) = self
    .load_chain_metadata(&entry.session_id, entry.principal.as_ref())
    .await?;
if let Some(metadata_head) = metadata
    .as_ref()
    .and_then(|metadata| metadata.head.as_ref())
    && Some(metadata_head) != expected
{
    return Ok(false);
}
let expected_bytes = expected.map(|id| id.0.to_string().into_bytes());
if stored_head != expected_bytes {
    let Some(expected_bytes) = expected_bytes.as_ref() else {
        return Ok(false);
    };
    if !self
        .store
        .compare_and_swap(
            NS_CHAIN_HEADS,
            &head_key,
            stored_head.as_deref(),
            expected_bytes.clone(),
        )
        .await
        .map_err(|e| AuditError::StorageError(e.to_string()))?
    {
        return Ok(false);
    }
}
let encoded_len = serde_json::to_vec(entry)
    .map_err(|e| AuditError::SerializationError(e.to_string()))?
    .len();
let (global_bytes, mut global) = self.load_global_metadata().await?;
let entry_bytes = u64::try_from(encoded_len).unwrap_or(u64::MAX);
if global.total_count >= global.cap_entries
    || global.total_bytes.saturating_add(entry_bytes) > global.cap_bytes
{
    global.degraded = true;
    global.last_error = Some("system audit retention cap reached; prune sealed segments".to_owned());
    let _ = self
        .persist_global_metadata(global_bytes.as_deref(), &global)
        .await?;
    return Err(AuditError::RetentionCapReached);
}
self.store(entry).await?;
let new_head = entry.id.0.to_string().into_bytes();
if !self
    .store
    .compare_and_swap(
        NS_CHAIN_HEADS,
        &head_key,
        expected_bytes.as_deref(),
        new_head,
    )
    .await
    .map_err(|e| AuditError::StorageError(e.to_string()))?
{
    return Err(AuditError::StorageError(
        "audit chain head CAS lost after entry commit".to_owned(),
    ));
}
self.store
    .set(NS_COMMITTED_ENTRIES, &entry.id.0.to_string(), vec![1])
    .await
    .map_err(|e| AuditError::StorageError(e.to_string()))?;
let prior = metadata.unwrap_or_default();
let next_count = prior.count.saturating_add(1);
let next_bytes = prior.bytes.saturating_add(entry_bytes);
let prior_segment_count = if prior.segment_count == 0 && prior.count > 0 {
    prior.count
} else {
    prior.segment_count
};
let prior_segment_bytes = if prior.segment_bytes == 0 && prior.bytes > 0 {
    prior.bytes
} else {
    prior.segment_bytes
};
let starts_new_segment = prior.sealed;
let segment_count = if starts_new_segment {
    1
} else {
    prior_segment_count.saturating_add(1)
};
let segment_bytes = if starts_new_segment {
    entry_bytes
} else {
    prior_segment_bytes.saturating_add(entry_bytes)
};
let next_sealed = segment_count >= DEFAULT_SEGMENT_MAX_ENTRIES
    || segment_bytes >= DEFAULT_SEGMENT_MAX_BYTES;
if next_sealed {
    global.next_seal_ordinal = global.next_seal_ordinal.saturating_add(1);
}
let next = ChainMetadata {
    schema: 1,
    segment: if prior.sealed { prior.segment.saturating_add(1) } else { prior.segment },
    sealed: next_sealed,
    count: next_count,
    bytes: next_bytes,
    head: Some(entry.id.clone()),
    head_hash: entry.content_hash(),
    segment_count,
    segment_bytes,
    segment_first: if starts_new_segment {
        Some(entry.id.clone())
    } else {
        prior.segment_first.or_else(|| Some(entry.id.clone()))
    },
    seal_ordinal: if next_sealed {
        Some(global.next_seal_ordinal)
    } else if starts_new_segment {
        None
    } else {
        prior.seal_ordinal
    },
};
if !self
    .persist_chain_metadata(
        &entry.session_id,
        entry.principal.as_ref(),
        metadata_bytes.as_deref(),
        &next,
    )
    .await?
{
    return Err(AuditError::StorageError(
        "audit chain metadata CAS lost after head commit".to_owned(),
    ));
}
if next_sealed {
    let segment_key = format!("{:020}:{}:{:020}", global.next_seal_ordinal, head_key, next.segment);
    let segment_bytes = serde_json::to_vec(&next)
        .map_err(|e| AuditError::SerializationError(e.to_string()))?;
    self.store
        .set(NS_SEGMENT_INDEX, &segment_key, segment_bytes)
        .await
        .map_err(|e| AuditError::StorageError(e.to_string()))?;
}
global.total_count = global.total_count.saturating_add(1);
global.total_bytes = global.total_bytes.saturating_add(entry_bytes);
if prior.count == 0 || prior.sealed {
    global.segments = global.segments.saturating_add(1);
}
if next_sealed && !prior.sealed {
    global.sealed_segments = global.sealed_segments.saturating_add(1);
    global.eligible_segments = global.eligible_segments.saturating_add(1);
}
global.degraded = global.total_count > global.cap_entries || global.total_bytes > global.cap_bytes;
if !global.degraded {
    global.last_error = None;
}
if !self
    .persist_global_metadata(global_bytes.as_deref(), &global)
    .await?
{
    return Err(AuditError::StorageError(
        "audit global metadata CAS lost after append".to_owned(),
    ));
}
Ok(true)
}
