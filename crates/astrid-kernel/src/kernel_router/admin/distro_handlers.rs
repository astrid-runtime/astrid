//! UID-scoped distro provenance control-plane handlers.

use std::collections::HashSet;
use std::sync::Arc;

use astrid_core::kernel_api::{AdminResponseBody, DistroProvenance};
use astrid_core::principal::PrincipalId;
use astrid_core::profile::{CapsuleGrant, PrincipalProfile};

use crate::Kernel;

const KEY: &str = "provenance";
const MAX_BYTES: usize = 512 * 1024;
const MAX_CAPSULES: usize = 4096;
const MAX_ID_BYTES: usize = 256;
const MAX_SOURCE_BYTES: usize = 4096;

/// Read one principal's durable distro record.
pub(super) async fn get(kernel: &Arc<Kernel>, principal: &PrincipalId) -> AdminResponseBody {
    let store = match principal_store(kernel, principal) {
        Ok(store) => store,
        Err(error) => return AdminResponseBody::Error(error),
    };
    let value = match store.get(KEY).await {
        Ok(value) => value,
        Err(error) => return AdminResponseBody::Error(format!("read distro provenance: {error}")),
    };
    let Some(value) = value else {
        return AdminResponseBody::DistroLock(Box::new(None));
    };
    if value.len() > MAX_BYTES {
        return AdminResponseBody::Error("distro provenance exceeds size limit".to_owned());
    }
    match serde_json::from_slice(&value) {
        Ok(lock) => AdminResponseBody::DistroLock(Box::new(Some(lock))),
        Err(error) => AdminResponseBody::Error(format!("decode distro provenance: {error}")),
    }
}

/// Replace one principal's durable distro record.
pub(super) async fn set(
    kernel: &Arc<Kernel>,
    principal: &PrincipalId,
    lock: DistroProvenance,
    expected_hash: Option<String>,
) -> AdminResponseBody {
    let _guard = kernel.admin_write_lock.lock().await;
    if let Err(error) = validate(&lock) {
        return AdminResponseBody::Error(error);
    }
    let encoded = match serde_json::to_vec(&lock) {
        Ok(encoded) => encoded,
        Err(error) => {
            return AdminResponseBody::Error(format!("encode distro provenance: {error}"));
        },
    };
    if encoded.len() > MAX_BYTES {
        return AdminResponseBody::Error("distro provenance exceeds size limit".to_owned());
    }
    if let Some(expected_hash) = &expected_hash
        && !is_digest(expected_hash)
    {
        return AdminResponseBody::Error(
            "expected_hash must be a canonical blake3:<64-hex> digest".to_owned(),
        );
    }
    let store = match principal_store(kernel, principal) {
        Ok(store) => store,
        Err(error) => return AdminResponseBody::Error(error),
    };
    let previous = match store.get(KEY).await {
        Ok(previous) => previous,
        Err(error) => return AdminResponseBody::Error(format!("read distro provenance: {error}")),
    };
    let previous_hash = previous.as_deref().map(digest);
    if previous_hash != expected_hash {
        return AdminResponseBody::Error(
            "distro provenance changed; retry with a fresh expected_hash".to_owned(),
        );
    }
    let stored_hash = digest(&encoded);
    match store
        .compare_and_swap(KEY, previous.as_deref(), encoded)
        .await
    {
        Ok(true) => AdminResponseBody::Success(serde_json::json!({
            "principal": principal.as_str(),
            "stored": true,
            "digest": stored_hash,
        })),
        Ok(false) => AdminResponseBody::Error(
            "distro provenance changed concurrently; retry with a fresh expected_hash".to_owned(),
        ),
        Err(error) => AdminResponseBody::Error(format!("write distro provenance: {error}")),
    }
}

/// Grant the caller exactly its admitted Distro lock's capsule identities.
///
/// The caller is the only target and the kernel-owned lock is the only
/// source of names. The digest is captured, then rechecked under the same
/// admin write lock used by `DistroLockSet`, so a concurrent lock change
/// cannot authorize a stale member set.
pub(super) async fn self_grant(kernel: &Arc<Kernel>, caller: &PrincipalId) -> AdminResponseBody {
    let observed = match load_lock(kernel, caller).await {
        Ok(Some(lock)) => lock,
        Ok(None) => return AdminResponseBody::Error("no admitted Distro lock".to_owned()),
        Err(error) => return AdminResponseBody::Error(error),
    };
    if let Err(error) = validate(&observed) {
        return AdminResponseBody::Error(error);
    }
    if observed.capsules.is_empty() {
        return AdminResponseBody::Error("admitted Distro lock has no capsules".to_owned());
    }
    let Some(manifest_hash) = observed.manifest_hash.as_ref() else {
        return AdminResponseBody::Error(
            "admitted Distro lock has no manifest_hash binding".to_owned(),
        );
    };
    let observed_digest = match lock_digest(&observed) {
        Ok(digest) => digest,
        Err(error) => return AdminResponseBody::Error(error),
    };
    let capsule_names: Vec<String> = observed
        .capsules
        .iter()
        .map(|capsule| capsule.name.clone())
        .collect();

    let _guard = kernel.admin_write_lock.lock().await;
    let current = match load_lock(kernel, caller).await {
        Ok(Some(lock)) => lock,
        Ok(None) => {
            return AdminResponseBody::Error("Distro lock was removed concurrently".to_owned());
        },
        Err(error) => return AdminResponseBody::Error(error),
    };
    let current_digest = match lock_digest(&current) {
        Ok(digest) => digest,
        Err(error) => return AdminResponseBody::Error(error),
    };
    if current_digest != observed_digest {
        return AdminResponseBody::Error(
            "Distro lock changed concurrently; retry with the fresh admitted lock".to_owned(),
        );
    }
    if current.manifest_hash.as_ref() != Some(manifest_hash) {
        return AdminResponseBody::Error(
            "Distro manifest_hash changed concurrently; retry with the fresh admitted lock"
                .to_owned(),
        );
    }

    let profile_path = super::handlers::principal_profile_path(kernel, caller);
    if let Err(error) = super::handlers::require_principal_exists(caller, &profile_path) {
        return AdminResponseBody::Error(error);
    }
    let mut profile = match PrincipalProfile::load_from_path(&profile_path) {
        Ok(profile) => profile,
        Err(error) => {
            return AdminResponseBody::Error(format!("load principal profile: {error}"));
        },
    };
    let changed = match super::handlers::apply_set_delta::<CapsuleGrant>(
        &mut profile.capsules,
        &capsule_names,
        &[],
    ) {
        Ok(changed) => changed,
        Err(error) => {
            return AdminResponseBody::Error(format!("capsule grant delta rejected: {error}"));
        },
    };
    if changed {
        if let Err(error) = profile.validate() {
            return AdminResponseBody::Error(format!("principal profile rejected: {error}"));
        }
        if let Err(error) = profile.save_to_path(&profile_path) {
            return AdminResponseBody::Error(format!("save principal profile: {error}"));
        }
    }
    kernel.profile_cache.invalidate(caller);
    AdminResponseBody::Success(serde_json::json!({
        "principal": caller.as_str(),
        "capsules": profile.capsules,
        "manifest_hash": manifest_hash,
        "lock_digest": observed_digest,
        "changed": changed,
    }))
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
        .principal_control_kv(uid, "distro")
        .map_err(|error| format!("open principal distro control namespace: {error}"))
}

async fn load_lock(
    kernel: &Arc<Kernel>,
    principal: &PrincipalId,
) -> Result<Option<DistroProvenance>, String> {
    let store = principal_store(kernel, principal)?;
    let value = store
        .get(KEY)
        .await
        .map_err(|error| format!("read distro provenance: {error}"))?;
    let Some(value) = value else {
        return Ok(None);
    };
    if value.len() > MAX_BYTES {
        return Err("distro provenance exceeds size limit".to_owned());
    }
    serde_json::from_slice(&value)
        .map(Some)
        .map_err(|error| format!("decode distro provenance: {error}"))
}

fn lock_digest(lock: &DistroProvenance) -> Result<String, String> {
    serde_json::to_vec(lock)
        .map(|encoded| digest(&encoded))
        .map_err(|error| format!("encode distro provenance: {error}"))
}

fn validate(lock: &DistroProvenance) -> Result<(), String> {
    if lock.schema_version == 0 {
        return Err("distro provenance schema_version must be non-zero".to_owned());
    }
    bounded_identifier("distro_id", &lock.distro_id)?;
    bounded_nonempty("distro_version", &lock.distro_version, MAX_ID_BYTES)?;
    bounded_nonempty("resolved_at", &lock.resolved_at, MAX_ID_BYTES)?;
    if lock.capsules.len() > MAX_CAPSULES {
        return Err("distro provenance contains too many capsules".to_owned());
    }
    if let Some(hash) = &lock.manifest_hash {
        validate_hash("manifest_hash", hash)?;
    }
    let mut names = HashSet::with_capacity(lock.capsules.len());
    for capsule in &lock.capsules {
        bounded_identifier("capsule.name", &capsule.name)?;
        bounded_nonempty("capsule.version", &capsule.version, MAX_ID_BYTES)?;
        bounded_nonempty("capsule.source", &capsule.source, MAX_SOURCE_BYTES)?;
        validate_hash("capsule.hash", &capsule.hash)?;
        if let Some(resolved_ref) = &capsule.resolved_ref {
            bounded_nonempty("capsule.resolved_ref", resolved_ref, MAX_ID_BYTES)?;
        }
        if !names.insert(&capsule.name) {
            return Err(format!("duplicate capsule name: {}", capsule.name));
        }
    }
    Ok(())
}

fn bounded_identifier(field: &str, value: &str) -> Result<(), String> {
    bounded_nonempty(field, value, MAX_ID_BYTES)?;
    if !value.bytes().enumerate().all(|(index, byte)| {
        byte.is_ascii_lowercase()
            || byte.is_ascii_digit()
            || byte == b'-'
            || (index > 0 && byte == b'_')
    }) || value.starts_with('-')
        || value.ends_with('-')
    {
        return Err(format!("{field} has a non-canonical identifier"));
    }
    Ok(())
}

fn validate_hash(field: &str, value: &str) -> Result<(), String> {
    if value.len() != 71 || !value.starts_with("blake3:") {
        return Err(format!(
            "{field} must be a canonical blake3:<64-hex> digest"
        ));
    }
    if !value[7..]
        .bytes()
        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(format!("{field} must use lowercase hexadecimal"));
    }
    Ok(())
}

fn is_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("blake3:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn digest(value: &[u8]) -> String {
    format!("blake3:{}", blake3::hash(value).to_hex())
}

fn bounded_nonempty(field: &str, value: &str, max: usize) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("{field} must not be empty"));
    }
    if value.len() > max {
        return Err(format!("{field} exceeds {max}-byte limit"));
    }
    if value.bytes().any(|byte| byte == 0) {
        return Err(format!("{field} contains a null byte"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use astrid_core::kernel_api::DistroCapsuleProvenance;

    fn valid() -> DistroProvenance {
        DistroProvenance {
            schema_version: 1,
            distro_id: "example".into(),
            distro_version: "1.0.0".into(),
            resolved_at: "2026-01-01T00:00:00Z".into(),
            capsules: vec![DistroCapsuleProvenance {
                name: "cli".into(),
                version: "1.0.0".into(),
                source: "@example/cli".into(),
                hash: format!("blake3:{}", "a".repeat(64)),
                resolved_ref: None,
            }],
            manifest_hash: Some(format!("blake3:{}", "b".repeat(64))),
        }
    }

    #[test]
    fn canonical_record_is_accepted() {
        assert!(validate(&valid()).is_ok());
    }

    #[test]
    fn duplicate_or_noncanonical_hash_is_rejected() {
        let mut duplicate = valid();
        duplicate.capsules.push(duplicate.capsules[0].clone());
        assert!(validate(&duplicate).unwrap_err().contains("duplicate"));

        let mut uppercase = valid();
        uppercase.capsules[0].hash = format!("blake3:{}", "A".repeat(64));
        let error = validate(&uppercase).unwrap_err();
        assert!(
            error.contains("canonical") || error.contains("lowercase"),
            "uppercase digest must be rejected as non-canonical: {error}"
        );
    }
}
