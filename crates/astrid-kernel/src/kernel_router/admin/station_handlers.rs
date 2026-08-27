//! UID-scoped Station lock control-plane handlers.
//!
//! Station locks are independent of capsule packages and Astrid's CAS.  The
//! kernel stores one strict `station-lock-v2` JSON record per owner/capsule
//! key under the principal's control namespace. Every mutating path holds the
//! owner/capsule [`Kernel::lock_capsule_view`] guard first so a Station-bound
//! install and an external set/delete cannot interleave their critical
//! sections.

use std::sync::Arc;

use astrid_core::kernel_api::{AdminResponseBody, StationLock};
use astrid_core::principal::PrincipalId;

use super::station_store;
use crate::Kernel;

/// Owner/capsule guard plus opened control store, held across one whole
/// mutating critical section.
struct StationStoreLease {
    _view: crate::CapsuleViewGuard,
    store: astrid_storage::kv::ScopedKvStore,
}

/// Parse one control key into its capsule identity and hold the same
/// owner/capsule guard used by Station-bound installs.
async fn guarded_store(
    kernel: &Arc<Kernel>,
    principal: &PrincipalId,
    capsule: &str,
) -> Result<StationStoreLease, String> {
    let capsule_id = station_store::parse_capsule_id(capsule)?;
    let view_guard = kernel.lock_capsule_view(principal, &capsule_id).await;
    let store = station_store::principal_control_store(kernel, principal)?;
    Ok(StationStoreLease {
        _view: view_guard,
        store,
    })
}

/// Read one owner's Station lock for a capsule.
pub(crate) async fn get(
    kernel: &Arc<Kernel>,
    principal: &PrincipalId,
    capsule: &str,
) -> AdminResponseBody {
    if let Err(error) = station_store::validate_capsule(capsule) {
        return AdminResponseBody::Error(error);
    }
    match station_store::read_raw(kernel, principal, capsule).await {
        Ok(Some(raw)) => match serde_json::from_slice::<StationLock>(&raw) {
            Ok(lock) => {
                if let Err(error) = station_store::validate_station_lock(&lock) {
                    return AdminResponseBody::Error(error);
                }
                AdminResponseBody::StationLock(Box::new(Some(lock)))
            },
            Err(error) => AdminResponseBody::Error(format!("decode Station lock: {error}")),
        },
        Ok(None) => AdminResponseBody::StationLock(Box::new(None)),
        Err(error) => AdminResponseBody::Error(error),
    }
}

/// Atomically replace one owner's Station lock for a capsule.
pub(crate) async fn set(
    kernel: &Arc<Kernel>,
    principal: &PrincipalId,
    capsule: &str,
    lock: StationLock,
    expected_hash: Option<String>,
) -> AdminResponseBody {
    if let Err(error) = station_store::validate_capsule(capsule)
        .and_then(|()| station_store::validate_station_lock(&lock))
    {
        return AdminResponseBody::Error(error);
    }
    if let Some(expected_hash) = &expected_hash
        && !station_store::is_blake3_digest(expected_hash)
    {
        return AdminResponseBody::Error(
            "expected_hash must be a canonical blake3:<64-hex> digest".to_owned(),
        );
    }
    let encoded = match station_store::encode_lock(&lock) {
        Ok(encoded) => encoded,
        Err(error) => return AdminResponseBody::Error(error),
    };
    let lease = match guarded_store(kernel, principal, capsule).await {
        Ok(store) => store,
        Err(error) => return AdminResponseBody::Error(error),
    };
    let store = &lease.store;
    let _admin_guard = kernel.admin_write_lock.lock().await;
    let previous_physical = match station_store::read_physical(store, capsule).await {
        Ok(previous) => previous,
        Err(error) => return AdminResponseBody::Error(error),
    };
    if station_store::logical_state(previous_physical.as_ref()) != expected_hash {
        return AdminResponseBody::Error(
            "Station lock changed; retry with a fresh expected_hash".to_owned(),
        );
    }
    let stored_hash = station_store::digest_bytes(&encoded);
    match station_store::compare_and_swap_write(
        store,
        capsule,
        previous_physical.as_deref(),
        encoded,
    )
    .await
    {
        Ok(true) => AdminResponseBody::Success(serde_json::json!({
            "principal": principal.as_str(),
            "capsule": capsule,
            "stored": true,
            "digest": stored_hash,
        })),
        Ok(false) => AdminResponseBody::Error(
            "Station lock changed concurrently; retry with a fresh expected_hash".to_owned(),
        ),
        Err(error) => AdminResponseBody::Error(error),
    }
}

/// Atomically clear one owner's Station lock. An absent lock is a successful
/// no-op; when `expected_hash` is present it must match the current JSON lock.
pub(super) async fn delete(
    kernel: &Arc<Kernel>,
    principal: &PrincipalId,
    capsule: &str,
    expected_hash: Option<String>,
) -> AdminResponseBody {
    if let Err(error) = station_store::validate_capsule(capsule) {
        return AdminResponseBody::Error(error);
    }
    if let Some(expected_hash) = &expected_hash
        && !station_store::is_blake3_digest(expected_hash)
    {
        return AdminResponseBody::Error(
            "expected_hash must be a canonical blake3:<64-hex> digest".to_owned(),
        );
    }
    let lease = match guarded_store(kernel, principal, capsule).await {
        Ok(store) => store,
        Err(error) => return AdminResponseBody::Error(error),
    };
    let store = &lease.store;
    let _admin_guard = kernel.admin_write_lock.lock().await;
    let previous_physical = match station_store::read_physical(store, capsule).await {
        Ok(previous) => previous,
        Err(error) => return AdminResponseBody::Error(error),
    };
    let previous_hash = station_store::logical_state(previous_physical.as_ref());
    if expected_hash.is_some() && previous_hash != expected_hash {
        return AdminResponseBody::Error(
            "Station lock changed; retry with a fresh expected_hash".to_owned(),
        );
    }
    match station_store::compare_and_swap_write(
        store,
        capsule,
        previous_physical.as_deref(),
        station_store::deleted_marker(),
    )
    .await
    {
        Ok(true) => AdminResponseBody::Success(serde_json::json!({
            "principal": principal.as_str(),
            "capsule": capsule,
            "deleted": previous_hash.is_some(),
        })),
        Ok(false) => AdminResponseBody::Error(
            "Station lock changed concurrently; retry with a fresh expected_hash".to_owned(),
        ),
        Err(error) => AdminResponseBody::Error(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use astrid_core::dirs::AstridHome;
    use astrid_core::kernel_api::{AdminRequestKind, StationCoordinate};
    use tempfile::TempDir;

    use super::station_store::{LOCK_SCHEMA_V2, digest_bytes};

    pub(super) fn digest_byte(prefix: &str, byte: u8) -> String {
        format!("{prefix}{}", hex::encode([byte; 32]))
    }

    pub(super) fn valid_lock() -> StationLock {
        StationLock {
            schema: LOCK_SCHEMA_V2.to_owned(),
            station_id: "official".to_owned(),
            trust_root: digest_byte("sha256:", 1),
            coordinate: StationCoordinate {
                namespace: "official".to_owned(),
                name: "demo".to_owned(),
            },
            version: "1.0.0".to_owned(),
            publication_digest: digest_byte("blake3:", 2),
            artifact_size: 0,
            artifact_media_type: "application/vnd.astrid.capsule".to_owned(),
            artifact_sha256: digest_byte("sha256:", 3),
            artifact_blake3: digest_byte("blake3:", 4),
            manifest_digest: digest_byte("blake3:", 5),
            capsule_content_digest: digest_byte("blake3:", 6),
            package_digest: digest_byte("blake3:", 7),
            component_count: 0,
            component_digest: digest_byte("blake3:", 8),
            wit_digest: digest_byte("blake3:", 9),
            capability_digest: digest_byte("blake3:", 10),
            ipc_digest: digest_byte("blake3:", 11),
            runtime_abi_digest: digest_byte("blake3:", 12),
            dependency_digest: digest_byte("blake3:", 13),
            provenance_digest: digest_byte("blake3:", 14),
            source_digest: digest_byte("blake3:", 15),
        }
    }

    async fn fixture() -> (TempDir, Arc<Kernel>, PrincipalId) {
        let dir = tempfile::tempdir().expect("tempdir");
        let kernel = crate::test_kernel_with_home(AstridHome::from_path(dir.path())).await;
        (dir, kernel, PrincipalId::default())
    }

    #[tokio::test]
    async fn direct_get_set_delete_round_trip_and_cas() {
        let (_dir, kernel, principal) = fixture().await;
        let empty = get(&kernel, &principal, "demo").await;
        assert!(matches!(empty, AdminResponseBody::StationLock(ref lock) if lock.is_none()));

        let lock = valid_lock();
        let stored = set(&kernel, &principal, "demo", lock.clone(), None).await;
        assert!(matches!(stored, AdminResponseBody::Success(_)));

        let encoded = serde_json::to_vec(&lock).expect("encode lock");
        let expected_hash = digest_bytes(&encoded);
        let read = get(&kernel, &principal, "demo").await;
        assert!(
            matches!(read, AdminResponseBody::StationLock(lock) if lock.as_ref().as_ref() == Some(&valid_lock()))
        );

        let conflict = set(
            &kernel,
            &principal,
            "demo",
            valid_lock(),
            Some(digest_byte("blake3:", 0xff)),
        )
        .await;
        assert!(
            matches!(conflict, AdminResponseBody::Error(message) if message.contains("changed"))
        );

        let delete_conflict = delete(
            &kernel,
            &principal,
            "demo",
            Some(digest_byte("blake3:", 0xff)),
        )
        .await;
        assert!(
            matches!(delete_conflict, AdminResponseBody::Error(message) if message.contains("changed"))
        );

        let deleted = delete(&kernel, &principal, "demo", Some(expected_hash)).await;
        assert!(matches!(deleted, AdminResponseBody::Success(_)));
        let missing = delete(&kernel, &principal, "demo", None).await;
        assert!(matches!(missing, AdminResponseBody::Success(_)));
        let after = get(&kernel, &principal, "demo").await;
        assert!(matches!(after, AdminResponseBody::StationLock(lock) if lock.is_none()));
    }

    #[tokio::test]
    async fn malformed_and_bare_digests_fail_before_persist() {
        let (_dir, kernel, principal) = fixture().await;
        let mut bare = valid_lock();
        bare.publication_digest = "a".repeat(64);
        let response = set(&kernel, &principal, "demo", bare, None).await;
        assert!(
            matches!(response, AdminResponseBody::Error(message) if message.contains("canonical"))
        );

        let mut malformed = valid_lock();
        malformed.publication_digest = "sha256:".to_owned() + &"a".repeat(64);
        let response = set(&kernel, &principal, "demo", malformed, None).await;
        assert!(
            matches!(response, AdminResponseBody::Error(message) if message.contains("blake3"))
        );
        let after_reject = get(&kernel, &principal, "demo").await;
        assert!(matches!(after_reject, AdminResponseBody::StationLock(ref lock) if lock.is_none()));
    }

    #[test]
    fn station_lock_requests_are_self_scoped_for_the_owner() {
        let principal = PrincipalId::default();
        let request = AdminRequestKind::StationLockDelete {
            principal: principal.clone(),
            capsule: "demo".to_owned(),
            expected_hash: None,
        };
        assert_eq!(
            super::super::resolve_admin_scope(&request, &principal),
            crate::kernel_router::AuthorityScope::Self_
        );
    }
}
