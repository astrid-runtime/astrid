//! Shared owner-scoped Station lock storage primitives.
//!
//! Admin Station lock handlers and the `InstallCapsule` Station binding use
//! the same namespace, encoding, digesting, and compare-and-swap helpers so a
//! lock write from either path observes the same canonical bytes and the same
//! owner/capsule critical section.

use std::sync::Arc;

use astrid_core::kernel_api::StationLock;
use astrid_core::principal::PrincipalId;
use astrid_storage::kv::ScopedKvStore;

use crate::Kernel;

pub(crate) const NAMESPACE: &str = "station";
pub(crate) const MAX_BYTES: usize = 64 * 1024;
pub(crate) const MAX_TEXT_BYTES: usize = 4096;
pub(crate) const MAX_CAPSULE_BYTES: usize = 256;
pub(crate) const MAX_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;
pub(crate) const LOCK_SCHEMA_V2: &str = "station-lock-v2";

/// Scoped KV has no compare-and-swap delete. An empty value is not valid
/// Station JSON, so it is a durable tombstone that keeps atomic CAS semantics
/// while every typed read treats the key as absent.
const DELETED_MARKER: &[u8] = b"";

pub(crate) fn principal_control_store(
    kernel: &Arc<Kernel>,
    principal: &PrincipalId,
) -> Result<ScopedKvStore, String> {
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

pub(crate) fn validate_capsule(capsule: &str) -> Result<(), String> {
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

/// Typed control-key identity backing every per-owner/capsule critical
/// section (external admin writes and Station-bound installs alike).
pub(crate) fn parse_capsule_id(capsule: &str) -> Result<astrid_capsule_types::CapsuleId, String> {
    validate_capsule(capsule)?;
    astrid_capsule_types::CapsuleId::new(capsule.to_owned())
        .map_err(|error| format!("Station lock capsule key is not a valid capsule id: {error}"))
}

/// Canonical stored bytes for one validated lock.
pub(crate) fn encode_lock(lock: &StationLock) -> Result<Vec<u8>, String> {
    let encoded =
        serde_json::to_vec(lock).map_err(|error| format!("encode Station lock: {error}"))?;
    if encoded.len() > MAX_BYTES {
        return Err("Station lock exceeds size limit".to_owned());
    }
    Ok(encoded)
}

/// Logical reads treat the deletion tombstone as absence.
pub(crate) async fn read_raw(
    kernel: &Arc<Kernel>,
    principal: &PrincipalId,
    capsule: &str,
) -> Result<Option<Vec<u8>>, String> {
    let store = principal_control_store(kernel, principal)?;
    let raw = store
        .get(capsule)
        .await
        .map_err(|error| format!("read Station lock: {error}"))?;
    Ok(raw.filter(|value| !value.is_empty()))
}

/// Read the exact physical slot bytes so compare-and-swap expectations stay
/// faithful across tombstones.
pub(crate) async fn read_physical(
    store: &ScopedKvStore,
    capsule: &str,
) -> Result<Option<Vec<u8>>, String> {
    store
        .get(capsule)
        .await
        .map_err(|error| format!("read Station lock: {error}"))
}

pub(crate) async fn compare_and_swap_write(
    store: &ScopedKvStore,
    capsule: &str,
    previous_physical: Option<&[u8]>,
    replacement: Vec<u8>,
) -> Result<bool, String> {
    store
        .compare_and_swap(capsule, previous_physical, replacement)
        .await
        .map_err(|error| format!("write Station lock: {error}"))
}

pub(crate) fn deleted_marker() -> Vec<u8> {
    DELETED_MARKER.to_vec()
}

pub(crate) fn digest_bytes(value: &[u8]) -> String {
    format!("blake3:{}", blake3::hash(value).to_hex())
}

pub(crate) fn logical_state(raw: Option<&Vec<u8>>) -> Option<String> {
    match raw {
        Some(value) if !value.is_empty() => Some(digest_bytes(value)),
        _ => None,
    }
}

pub(crate) fn validate_station_lock(lock: &StationLock) -> Result<(), String> {
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

pub(crate) fn is_blake3_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("blake3:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}
