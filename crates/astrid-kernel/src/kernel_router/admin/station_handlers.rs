//! UID-scoped Station lock control-plane handlers.
//!
//! Station locks are independent of capsule packages and Astrid's CAS.  The
//! kernel stores one strict `station-lock-v2` JSON record per owner/capsule
//! key under the principal's control namespace.

use std::sync::Arc;

use astrid_core::kernel_api::{AdminResponseBody, StationLock};
use astrid_core::principal::PrincipalId;

use crate::Kernel;

const NAMESPACE: &str = "station";
const MAX_BYTES: usize = 64 * 1024;
const MAX_TEXT_BYTES: usize = 4096;
const MAX_CAPSULE_BYTES: usize = 256;
const MAX_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;
const LOCK_SCHEMA_V2: &str = "station-lock-v2";
// Scoped KV does not expose a compare-and-swap delete. An empty value is not
// valid Station JSON, so it is a durable tombstone that preserves atomic CAS
// semantics while all typed reads continue to observe the key as absent.
const DELETED_MARKER: &[u8] = b"";

/// Read one owner's Station lock for a capsule.
pub(super) async fn get(
    kernel: &Arc<Kernel>,
    principal: &PrincipalId,
    capsule: &str,
) -> AdminResponseBody {
    if let Err(error) = validate_capsule(capsule) {
        return AdminResponseBody::Error(error);
    }
    let store = match principal_store(kernel, principal) {
        Ok(store) => store,
        Err(error) => return AdminResponseBody::Error(error),
    };
    let value = match store.get(capsule).await {
        Ok(value) => value,
        Err(error) => return AdminResponseBody::Error(format!("read Station lock: {error}")),
    };
    let Some(value) = value else {
        return AdminResponseBody::StationLock(Box::new(None));
    };
    if value.is_empty() {
        return AdminResponseBody::StationLock(Box::new(None));
    }
    if value.len() > MAX_BYTES {
        return AdminResponseBody::Error("Station lock exceeds size limit".to_owned());
    }
    match serde_json::from_slice(&value) {
        Ok(lock) => match validate_lock(&lock) {
            Ok(()) => AdminResponseBody::StationLock(Box::new(Some(lock))),
            Err(error) => AdminResponseBody::Error(error),
        },
        Err(error) => AdminResponseBody::Error(format!("decode Station lock: {error}")),
    }
}

/// Atomically replace one owner's Station lock for a capsule.
pub(super) async fn set(
    kernel: &Arc<Kernel>,
    principal: &PrincipalId,
    capsule: &str,
    lock: StationLock,
    expected_hash: Option<String>,
) -> AdminResponseBody {
    if let Err(error) = validate_capsule(capsule).and_then(|()| validate_lock(&lock)) {
        return AdminResponseBody::Error(error);
    }
    if let Some(expected_hash) = &expected_hash
        && !is_blake3_digest(expected_hash)
    {
        return AdminResponseBody::Error(
            "expected_hash must be a canonical blake3:<64-hex> digest".to_owned(),
        );
    }
    let encoded = match serde_json::to_vec(&lock) {
        Ok(encoded) => encoded,
        Err(error) => return AdminResponseBody::Error(format!("encode Station lock: {error}")),
    };
    if encoded.len() > MAX_BYTES {
        return AdminResponseBody::Error("Station lock exceeds size limit".to_owned());
    }
    let _guard = kernel.admin_write_lock.lock().await;
    let store = match principal_store(kernel, principal) {
        Ok(store) => store,
        Err(error) => return AdminResponseBody::Error(error),
    };
    let previous = match store.get(capsule).await {
        Ok(previous) => previous,
        Err(error) => return AdminResponseBody::Error(format!("read Station lock: {error}")),
    };
    let previous_hash = previous
        .as_deref()
        .filter(|value| !value.is_empty())
        .map(digest);
    if previous_hash != expected_hash {
        return AdminResponseBody::Error(
            "Station lock changed; retry with a fresh expected_hash".to_owned(),
        );
    }
    let stored_hash = digest(&encoded);
    match store
        .compare_and_swap(capsule, previous.as_deref(), encoded)
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
        Err(error) => AdminResponseBody::Error(format!("write Station lock: {error}")),
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
    if let Err(error) = validate_capsule(capsule) {
        return AdminResponseBody::Error(error);
    }
    if let Some(expected_hash) = &expected_hash
        && !is_blake3_digest(expected_hash)
    {
        return AdminResponseBody::Error(
            "expected_hash must be a canonical blake3:<64-hex> digest".to_owned(),
        );
    }
    let _guard = kernel.admin_write_lock.lock().await;
    let store = match principal_store(kernel, principal) {
        Ok(store) => store,
        Err(error) => return AdminResponseBody::Error(error),
    };
    let previous = match store.get(capsule).await {
        Ok(previous) => previous,
        Err(error) => return AdminResponseBody::Error(format!("read Station lock: {error}")),
    };
    let previous_hash = previous
        .as_deref()
        .filter(|value| !value.is_empty())
        .map(digest);
    if expected_hash.is_some() && previous_hash != expected_hash {
        return AdminResponseBody::Error(
            "Station lock changed; retry with a fresh expected_hash".to_owned(),
        );
    }
    match store
        .compare_and_swap(capsule, previous.as_deref(), DELETED_MARKER.to_vec())
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
        Err(error) => AdminResponseBody::Error(format!("delete Station lock: {error}")),
    }
}

fn principal_store(
    kernel: &Arc<Kernel>,
    principal: &PrincipalId,
) -> Result<astrid_storage::kv::ScopedKvStore, String> {
    let store = kernel
        .principal_store
        .as_ref()
        .ok_or_else(|| "authoritative principal store is unavailable".to_owned())?;
    let uid = kernel
        .principal_directory
        .uid_for(principal)
        .map_err(|error| format!("resolve principal UID: {error}"))?;
    store
        .principal_control_kv(uid, NAMESPACE)
        .map_err(|error| format!("open principal Station control namespace: {error}"))
}

fn validate_capsule(capsule: &str) -> Result<(), String> {
    if capsule.is_empty() || capsule.len() > MAX_CAPSULE_BYTES {
        return Err("Station lock capsule key is empty or too long".to_owned());
    }
    if !capsule.bytes().enumerate().all(|(index, byte)| {
        byte.is_ascii_lowercase()
            || byte.is_ascii_digit()
            || byte == b'-'
            || (index > 0 && byte == b'_')
    }) || capsule.starts_with('-')
        || capsule.ends_with('-')
    {
        return Err("Station lock capsule key is not canonical".to_owned());
    }
    Ok(())
}

fn validate_lock(lock: &StationLock) -> Result<(), String> {
    if lock.schema != LOCK_SCHEMA_V2 {
        return Err("Station lock schema must be station-lock-v2".to_owned());
    }
    validate_station_id(&lock.station_id)?;
    validate_digest("trust_root", &lock.trust_root, "sha256:")?;
    validate_coordinate(&lock.coordinate.namespace, "coordinate.namespace")?;
    validate_coordinate(&lock.coordinate.name, "coordinate.name")?;
    bounded_text("version", &lock.version)?;
    validate_digest("publication_digest", &lock.publication_digest, "blake3:")?;
    if lock.artifact_size > MAX_ARTIFACT_BYTES {
        return Err("Station artifact exceeds size limit".to_owned());
    }
    bounded_text("artifact_media_type", &lock.artifact_media_type)?;
    validate_digest("artifact_sha256", &lock.artifact_sha256, "sha256:")?;
    validate_digest("artifact_blake3", &lock.artifact_blake3, "blake3:")?;
    for (field, value) in [
        ("manifest_digest", &lock.manifest_digest),
        ("capsule_content_digest", &lock.capsule_content_digest),
        ("package_digest", &lock.package_digest),
        ("component_digest", &lock.component_digest),
        ("wit_digest", &lock.wit_digest),
        ("capability_digest", &lock.capability_digest),
        ("ipc_digest", &lock.ipc_digest),
        ("runtime_abi_digest", &lock.runtime_abi_digest),
        ("dependency_digest", &lock.dependency_digest),
        ("provenance_digest", &lock.provenance_digest),
        ("source_digest", &lock.source_digest),
    ] {
        validate_digest(field, value, "blake3:")?;
    }
    if lock.component_count > 4096 {
        return Err("Station component count exceeds size limit".to_owned());
    }
    Ok(())
}

fn validate_coordinate(value: &str, field: &str) -> Result<(), String> {
    bounded_text(field, value)?;
    if value.len() > 63
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        || !value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        || value.ends_with('-')
    {
        return Err(format!("{field} is not a canonical identifier"));
    }
    Ok(())
}

fn validate_station_id(value: &str) -> Result<(), String> {
    bounded_text("station_id", value)?;
    if value == "."
        || value == ".."
        || !value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        || !value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
    {
        return Err("station_id is not a canonical identifier".to_owned());
    }
    Ok(())
}

fn bounded_text(field: &str, value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > MAX_TEXT_BYTES || value.bytes().any(|byte| byte == 0) {
        return Err(format!("{field} is empty or exceeds size limit"));
    }
    Ok(())
}

fn validate_digest(field: &str, value: &str, prefix: &str) -> Result<(), String> {
    if prefix.len().checked_add(64) != Some(value.len())
        || !value.starts_with(prefix)
        || !value[prefix.len()..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(format!(
            "{field} must be a canonical {prefix}<64-hex> digest"
        ));
    }
    Ok(())
}

fn is_blake3_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("blake3:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn digest(value: &[u8]) -> String {
    format!("blake3:{}", blake3::hash(value).to_hex())
}

#[cfg(test)]
mod tests {
    use super::*;
    use astrid_core::dirs::AstridHome;
    use astrid_core::kernel_api::{AdminRequestKind, StationCoordinate};
    use tempfile::TempDir;

    fn digest_byte(prefix: &str, byte: u8) -> String {
        format!("{prefix}{}", hex::encode([byte; 32]))
    }

    fn valid_lock() -> StationLock {
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
        let expected_hash = digest(&encoded);
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
