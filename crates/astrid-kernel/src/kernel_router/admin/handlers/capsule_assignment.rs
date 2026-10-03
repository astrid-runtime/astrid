//! Materialize inherited installs without replacing principal-owned configuration.

use std::sync::Arc;

use astrid_core::PrincipalId;

use astrid_core::identity::PrincipalUid;
use astrid_storage::env::{env_key, principal_capsule_namespace, principal_env_store, read_env};
use astrid_storage::{
    KvBatchCondition, KvBatchMutation, KvEntryKey, KvMutationBatch, KvStore,
    MAX_KV_BATCH_OPERATIONS, MAX_KV_BATCH_PAYLOAD_BYTES,
};

pub(super) async fn materialize_added_capsule_installs(
    kernel: &Arc<crate::Kernel>,
    principal: &PrincipalId,
    add_capsules: &[String],
) -> Result<(), String> {
    if add_capsules.is_empty() {
        return Ok(());
    }
    // The caller holds admin_write_lock. Never wait for this fence: an install
    // can already own it while waiting to stage environment under that lock.
    let _install_fence = Arc::clone(&kernel.env_install_fence)
        .try_write_owned()
        .map_err(|_| "capsule install in progress; retry the grant".to_owned())?;
    let store = kernel
        .principal_store
        .as_ref()
        .ok_or_else(|| "authoritative principal store is unavailable".to_owned())?;
    let source_uid = kernel
        .principal_directory
        .uid_for(&PrincipalId::default())
        .map_err(|error| format!("resolve default principal UID: {error}"))?;
    let target_uid = kernel
        .principal_directory
        .uid_for(principal)
        .map_err(|error| format!("resolve target principal UID: {error}"))?;
    let source_owner = astrid_storage::StateOwner::Principal(source_uid);
    let target_owner = astrid_storage::StateOwner::Principal(target_uid);
    for capsule in add_capsules {
        if store
            .capsules()
            .get_snapshot(&target_owner, capsule)
            .map_err(|error| format!("read target capsule '{capsule}': {error}"))?
            .is_some()
        {
            // Granting access to an explicit install does not opt that principal
            // into the default principal's tenant, identity or other settings.
            continue;
        }
        let Some(snapshot) = store
            .capsules()
            .get_snapshot(&source_owner, capsule)
            .map_err(|error| format!("read default capsule '{capsule}': {error}"))?
        else {
            continue;
        };
        // Copy before publishing the inherited install. A failed copy must not
        // leave a snapshot that a retry mistakes for a configured local install.
        // The existing strict copy keeps conflicts and secrets fail-closed.
        inherit_and_publish(kernel, source_uid, target_uid, capsule, || {
            store
                .capsules()
                .install(
                    &target_owner,
                    capsule,
                    snapshot.package(),
                    astrid_storage::CapsuleInstallExpectation::Absent,
                )
                .map(|_| ())
                .map_err(|error| {
                    format!("copy durable capsule '{capsule}' for {principal}: {error}")
                })
        })
        .await?;
    }
    Ok(())
}

/// Caller holds the admin lock and install fence through publication and rollback.
async fn inherit_and_publish(
    kernel: &crate::Kernel,
    source: PrincipalUid,
    target: PrincipalUid,
    capsule: &str,
    publish: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    let source_scope = principal_env_store(Arc::clone(&kernel.kv), source, capsule)
        .map_err(|error| error.to_string())?;
    let values = read_env(&source_scope)
        .await
        .map_err(|error| error.to_string())?;
    let namespace = principal_capsule_namespace(target, capsule);
    let mut inserted = Vec::new();
    for (field, value) in values {
        let key = env_key(&field);
        let previous = kernel
            .kv
            .get(&namespace, &key)
            .await
            .map_err(|error| error.to_string())?;
        let value = value.into_bytes();
        if previous.as_ref().is_some_and(|previous| *previous != value) {
            return Err(format!(
                "destination environment field {field:?} already has a different value"
            ));
        }
        let key = KvEntryKey::new(namespace.clone(), key).map_err(|error| error.to_string())?;
        if previous.is_none() {
            inserted.push((key, value));
        }
    }
    let batches = inheritance_batches(inserted)?;
    apply_inheritance(kernel.kv.as_ref(), &batches, publish).await
}

/// Partition by the storage contract, not by an independent environment cap.
/// Construct every batch before writing so invalid individual entries cannot
/// leave a partial copy. The caller's locks exclude control-namespace writers;
/// guests cannot access this namespace, and the install stays unpublished until
/// every batch succeeds. This is staged publication, not a multi-batch KV transaction.
fn inheritance_batches(
    entries: Vec<(KvEntryKey, Vec<u8>)>,
) -> Result<Vec<KvMutationBatch>, String> {
    let mut batches = Vec::new();
    let mut conditions = Vec::new();
    let mut mutations = Vec::new();
    let mut payload = 0_usize;
    for (key, value) in entries {
        let entry = KvMutationBatch::new(
            [KvBatchCondition::ValueEquals {
                key: key.clone(),
                expected: None,
            }],
            [KvBatchMutation::Set { key, value }],
        )
        .map_err(|error| error.to_string())?;
        if conditions
            .len()
            .strict_add(mutations.len())
            .strict_add(entry.operation_count())
            > MAX_KV_BATCH_OPERATIONS
            || payload.strict_add(entry.payload_bytes()) > MAX_KV_BATCH_PAYLOAD_BYTES
        {
            batches.push(
                KvMutationBatch::new(
                    std::mem::take(&mut conditions),
                    std::mem::take(&mut mutations),
                )
                .map_err(|error| error.to_string())?,
            );
            payload = 0;
        }
        payload = payload.strict_add(entry.payload_bytes());
        conditions.extend_from_slice(entry.conditions());
        mutations.extend_from_slice(entry.mutations());
    }
    if !mutations.is_empty() {
        batches
            .push(KvMutationBatch::new(conditions, mutations).map_err(|error| error.to_string())?);
    }
    Ok(batches)
}

async fn apply_inheritance(
    kv: &dyn KvStore,
    batches: &[KvMutationBatch],
    publish: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    for (index, batch) in batches.iter().enumerate() {
        let result = match kv.apply_batch(batch).await {
            Ok(outcome) if outcome.applied => continue,
            Ok(_) => "destination environment changed during inheritance; retry the grant".into(),
            Err(error) => format!("copy inherited environment: {error}"),
        };
        rollback_inheritance(kv, &batches[..index])
            .await
            .map_err(|rollback| format!("{result}; {rollback}"))?;
        return Err(result);
    }
    if let Err(error) = publish() {
        rollback_inheritance(kv, batches)
            .await
            .map_err(|rollback| format!("{error}; {rollback}"))?;
        return Err(error);
    }
    Ok(())
}

async fn rollback_inheritance(kv: &dyn KvStore, batches: &[KvMutationBatch]) -> Result<(), String> {
    // Delete only bytes introduced by successful batches, never pre-existing or
    // subsequently changed values. Attempt every cleanup even if one fails.
    let mut errors = Vec::new();
    for batch in batches {
        for mutation in batch.mutations() {
            let KvBatchMutation::Set { key, value } = mutation else {
                continue;
            };
            let rollback = KvMutationBatch::new(
                vec![KvBatchCondition::ValueEquals {
                    key: key.clone(),
                    expected: Some(value.clone()),
                }],
                vec![KvBatchMutation::Delete { key: key.clone() }],
            )
            .map_err(|error| format!("construct environment rollback: {error}"))?;
            if let Err(error) = kv.apply_batch(&rollback).await {
                errors.push(error.to_string());
            }
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "environment rollback failed: {}",
            errors.join("; ")
        ))
    }
}

#[cfg(test)]
#[path = "capsule_assignment_tests.rs"]
mod tests;
