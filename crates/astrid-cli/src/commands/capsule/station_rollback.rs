//! Conditional ownership-preserving Station lock recovery.

use anyhow::Context;
use astrid_core::PrincipalId;
use astrid_core::kernel_api::StationLock;

use super::station;

pub(crate) fn station_lock_clear_ready() -> bool {
    #[cfg(test)]
    if station::test_lock_backend_active() {
        return true;
    }
    crate::socket_client::readiness_path().exists()
}

/// Restore the lock from one completed transaction only if it still wins CAS.
///
/// `just_written` is the exact typed value this process persisted immediately
/// before installation. Its digest is the sole authorization for restoring or
/// deleting the current slot; no fresh GET is used to authorize the write.
pub(crate) async fn restore_station_lock(
    principal: &PrincipalId,
    capsule: &str,
    previous: Option<&StationLock>,
    just_written: &StationLock,
) -> anyhow::Result<()> {
    let mut written = just_written.clone();
    station::canonicalize_lock(&mut written)?;
    let expected_hash = station::station_lock_digest(&written)
        .with_context(|| format!("digest just-written {capsule} Station lock"))?;

    let restored = match previous {
        Some(previous) => {
            let mut previous = previous.clone();
            station::canonicalize_lock(&mut previous)?;
            station::store_lock_at_expected_hash(principal, capsule, previous, Some(expected_hash))
                .await
        },
        None => station::delete_lock_at_expected_hash(principal, capsule, expected_hash).await,
    };
    restored.with_context(|| format!("conditionally restore {capsule} Station lock"))
}

/// Keep an installer failure visible while surfacing a failed restoration.
pub(crate) fn combine_install_and_restore_errors(
    install_error: anyhow::Error,
    restore_result: anyhow::Result<()>,
) -> anyhow::Error {
    match restore_result {
        Ok(()) => install_error,
        Err(restore_error) => {
            install_error.context(format!("Station lock rollback failed: {restore_error:#}"))
        },
    }
}
