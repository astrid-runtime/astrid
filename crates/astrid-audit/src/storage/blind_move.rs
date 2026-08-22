//! Blind payload MOVE of a legacy `KvAuditStorage` projection.
//!
//! Copies stored namespace/key/value bytes. Does not decode audit JSON, walk
//! chains, or replay live append. Destination must be an empty audit
//! projection. Torn live-writer namespaces stay behind.

use super::global::GlobalMetadata;
use super::{
    KvAuditStorage, NS_CHAIN_HEADS, NS_CHAIN_METADATA, NS_COMMITTED_ENTRIES, NS_ENTRIES,
    NS_GLOBAL_METADATA, NS_PRUNE_PLANS, NS_PRUNE_RECEIPTS, NS_SEGMENT_INDEX, NS_SESSION_ENTRIES,
    NS_SESSION_INDEX, NS_SESSION_SEQUENCE,
};
use crate::error::{AuditError, AuditResult};
use astrid_storage::{
    KvBatchMutation, KvEntryKey, KvMutationBatch, KvStore, MAX_KV_BATCH_OPERATIONS,
    MAX_KV_BATCH_PAYLOAD_BYTES,
};
use std::sync::Arc;

/// Namespaces copied as opaque KV pairs. Append intents and migration scratch
/// stay source-local so a torn live writer cannot replay onto dest.
fn copy_namespaces() -> [&'static str; 11] {
    [
        NS_ENTRIES,
        NS_SESSION_INDEX,
        NS_SESSION_ENTRIES,
        NS_SESSION_SEQUENCE,
        NS_CHAIN_HEADS,
        NS_CHAIN_METADATA,
        NS_COMMITTED_ENTRIES,
        NS_PRUNE_RECEIPTS,
        NS_PRUNE_PLANS,
        NS_GLOBAL_METADATA,
        NS_SEGMENT_INDEX,
    ]
}

/// Copy every MOVE namespace from `source` onto an empty `destination`.
pub(crate) async fn copy_projection(
    source: &KvAuditStorage,
    destination: &KvAuditStorage,
) -> AuditResult<u64> {
    refuse_nonempty_destination(destination).await?;
    let mut imported_entries = 0_u64;
    let mut imported_bytes = 0_u64;
    for namespace in copy_namespaces() {
        let (entries, bytes) = copy_namespace(
            source.kv_store().as_ref(),
            destination.kv_store(),
            namespace,
        )
        .await?;
        imported_entries = imported_entries.saturating_add(entries);
        imported_bytes = imported_bytes.saturating_add(bytes);
    }
    seed_global_metadata(destination.kv_store(), imported_entries, imported_bytes).await?;
    ensure_committed_index(destination.kv_store()).await?;
    Ok(imported_entries)
}

async fn refuse_nonempty_destination(destination: &KvAuditStorage) -> AuditResult<()> {
    let occupied = destination
        .kv_store()
        .list_keys_with_prefix_page(NS_ENTRIES, "", None, 1)
        .await
        .map_err(|error| AuditError::StorageError(error.to_string()))?;
    if occupied.is_empty() {
        let heads = destination
            .kv_store()
            .list_keys_with_prefix_page(NS_CHAIN_HEADS, "", None, 1)
            .await
            .map_err(|error| AuditError::StorageError(error.to_string()))?;
        if heads.is_empty() {
            return Ok(());
        }
    }
    Err(AuditError::StorageError(
        "native audit destination is not empty; refusing blind MOVE".to_owned(),
    ))
}

pub(crate) async fn ensure_committed_index(destination: &Arc<dyn KvStore>) -> AuditResult<()> {
    let entries = destination
        .list_keys(NS_ENTRIES)
        .await
        .map_err(|error| AuditError::StorageError(error.to_string()))?;
    let committed = destination
        .list_keys(NS_COMMITTED_ENTRIES)
        .await
        .map_err(|error| AuditError::StorageError(error.to_string()))?;
    if committed.len() >= entries.len() {
        return Ok(());
    }
    let existing: std::collections::HashSet<_> = committed.into_iter().collect();
    let mut mutations = Vec::new();
    for key in entries {
        if existing.contains(&key) {
            continue;
        }
        if mutations.len() >= MAX_KV_BATCH_OPERATIONS {
            flush_sets(destination, std::mem::take(&mut mutations)).await?;
        }
        mutations.push(KvBatchMutation::Set {
            key: KvEntryKey::new(NS_COMMITTED_ENTRIES, key)
                .map_err(|error| AuditError::StorageError(error.to_string()))?,
            value: vec![1],
        });
    }
    flush_sets(destination, mutations).await
}

async fn seed_global_metadata(
    destination: &Arc<dyn KvStore>,
    entries: u64,
    bytes: u64,
) -> AuditResult<()> {
    if entries == 0 {
        return Ok(());
    }
    if destination
        .get(NS_GLOBAL_METADATA, "current")
        .await
        .map_err(|error| AuditError::StorageError(error.to_string()))?
        .is_some()
    {
        return Ok(());
    }
    let metadata = GlobalMetadata {
        total_count: entries,
        total_bytes: bytes,
        ..GlobalMetadata::default()
    };
    let encoded = serde_json::to_vec(&metadata)
        .map_err(|error| AuditError::SerializationError(error.to_string()))?;
    destination
        .set(NS_GLOBAL_METADATA, "current", encoded)
        .await
        .map_err(|error| AuditError::StorageError(error.to_string()))
}

async fn copy_namespace(
    source: &dyn KvStore,
    destination: &Arc<dyn KvStore>,
    namespace: &str,
) -> AuditResult<(u64, u64)> {
    let mut after = None;
    let mut copied_entries = 0_u64;
    let mut copied_bytes = 0_u64;
    loop {
        let keys = source
            .list_keys_with_prefix_page(namespace, "", after.as_deref(), MAX_KV_BATCH_OPERATIONS)
            .await
            .map_err(|error| AuditError::StorageError(error.to_string()))?;
        if keys.is_empty() {
            return Ok((copied_entries, copied_bytes));
        }
        after = keys.last().cloned();
        let mut mutations = Vec::new();
        let mut payload = 0_usize;
        for key in keys {
            let Some(value) = source
                .get(namespace, &key)
                .await
                .map_err(|error| AuditError::StorageError(error.to_string()))?
            else {
                return Err(AuditError::StorageError(format!(
                    "legacy audit key disappeared while copying {namespace}/{key}"
                )));
            };
            let pair_bytes = namespace
                .len()
                .saturating_add(key.len())
                .saturating_add(value.len());
            if !mutations.is_empty()
                && (mutations.len() >= MAX_KV_BATCH_OPERATIONS
                    || payload.saturating_add(pair_bytes) > MAX_KV_BATCH_PAYLOAD_BYTES)
            {
                flush_sets(destination, std::mem::take(&mut mutations)).await?;
                payload = 0;
            }
            payload = payload.saturating_add(pair_bytes);
            if namespace == NS_ENTRIES {
                copied_entries = copied_entries.saturating_add(1);
                copied_bytes =
                    copied_bytes.saturating_add(u64::try_from(value.len()).unwrap_or(u64::MAX));
            }
            mutations.push(KvBatchMutation::Set {
                key: KvEntryKey::new(namespace, key)
                    .map_err(|error| AuditError::StorageError(error.to_string()))?,
                value,
            });
        }
        flush_sets(destination, mutations).await?;
    }
}

async fn flush_sets(
    destination: &Arc<dyn KvStore>,
    mutations: Vec<KvBatchMutation>,
) -> AuditResult<()> {
    if mutations.is_empty() {
        return Ok(());
    }
    if !destination.supports_atomic_batch() {
        for mutation in mutations {
            let KvBatchMutation::Set { key, value } = mutation else {
                return Err(AuditError::StorageError(
                    "blind MOVE produced a non-set mutation".to_owned(),
                ));
            };
            destination
                .set(key.namespace(), key.key(), value)
                .await
                .map_err(|error| AuditError::StorageError(error.to_string()))?;
        }
        return Ok(());
    }
    let batch = KvMutationBatch::new(std::iter::empty(), mutations)
        .map_err(|error| AuditError::StorageError(error.to_string()))?;
    let outcome = destination
        .apply_batch(&batch)
        .await
        .map_err(|error| AuditError::StorageError(error.to_string()))?;
    if !outcome.applied {
        return Err(AuditError::StorageError(
            "legacy audit blind MOVE lost a destination batch CAS".to_owned(),
        ));
    }
    Ok(())
}
