//! Mutation-free owner admission for interrupted directory-store recovery.

use std::path::Path;

use crate::engine::durable::{
    OwnerObservations, PersistentObjectIdentity, RecoveryLimits,
    inspect_native_root_history_without_repair, inspect_native_wal_owners_without_repair,
};
use crate::error::{StorageError, StorageResult};

use super::{Blake3ObjectIdentityV1, StateOwner, StateOwnerCodecV2};

/// Reject every canonical User owner in a directory store before recovery can
/// repair roots, replay WAL, rebuild an index, or promote compaction evidence.
pub(super) fn directory_store_owners(store: &Path) -> StorageResult<()> {
    let mut user = false;
    let mut incomplete: Option<StorageError> = None;
    let roots = [
        "roots.journal",
        "roots.journal.compacting",
        "roots.journal.previous",
        "roots.principal-uid.replacement",
        "roots.alias.previous",
    ];
    for name in roots {
        let path = store.join(name);
        if !path.exists() {
            continue;
        }
        let observations: OwnerObservations<StateOwner> =
            inspect_native_root_history_without_repair(
                &path,
                Blake3ObjectIdentityV1.scheme(),
                &StateOwnerCodecV2,
                RecoveryLimits::process_addressable(),
            )
            .map_err(|error| {
                StorageError::Connection(format!(
                    "directory-store owner preflight failed for {}: {error}",
                    path.display()
                ))
            })?;
        user |= observations
            .owners
            .iter()
            .any(|owner| matches!(owner, StateOwner::User(_)));
        if incomplete.is_none()
            && let Some(error) = observations.scan_error
        {
            incomplete = Some(StorageError::Connection(format!(
                "directory-store owner preflight could not prove complete coverage for {}: {error}",
                path.display()
            )));
        }
    }
    let wal = store.join("transactions.wal");
    if wal.exists() {
        let observations = inspect_native_wal_owners_without_repair(
            &wal,
            Blake3ObjectIdentityV1,
            &StateOwnerCodecV2,
            RecoveryLimits::process_addressable(),
        )
        .map_err(|error| {
            StorageError::Connection(format!(
                "directory-store WAL owner preflight failed for {}: {error}",
                wal.display()
            ))
        })?;
        user |= observations
            .owners
            .iter()
            .any(|owner| matches!(owner, StateOwner::User(_)));
        if incomplete.is_none()
            && let Some(error) = observations.scan_error
        {
            incomplete = Some(StorageError::Connection(format!(
                "directory-store WAL owner preflight could not prove complete coverage for {}: {error}",
                wal.display()
            )));
        }
    }
    if user {
        return Err(StorageError::Connection(
            "directory store contains an explicit user StateOwner; recovery mutation is refused"
                .to_owned(),
        ));
    }
    if let Some(error) = incomplete {
        return Err(error);
    }
    Ok(())
}
