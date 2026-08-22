//! Typed capsule environment state over the authoritative KV store.
//!
//! Environment values are kept in a host-only, owner-scoped KV projection.
//! Principal control namespaces use
//! `principal-uid:{uid}:control:env:{capsule}` /
//! `principal-uid:{uid}:control:secret:{capsule}`;
//! host-wide values use the corresponding `system:control:*` scopes. These
//! namespaces are host-constructed and are never handed to a guest's ordinary
//! `ScopedKvStore`.

use std::collections::HashMap;
use std::sync::Arc;

use astrid_core::identity::PrincipalUid;

use crate::error::{StorageError, StorageResult};
use crate::kv::{KvStore, ScopedKvStore};
use crate::secret::SecretStore;

/// Reserved prefix used by [`crate::secret::KvSecretStore`] inside a
/// host-only secret control namespace.
pub const SECRET_KEY_PREFIX: &str = "__secret:";

/// Reserved prefix for non-secret capsule environment values.
pub const ENV_KEY_PREFIX: &str = "__env:";

/// Reserved marker used by explicit legacy imports to record completion.
pub const LEGACY_IMPORT_MARKER_KEY: &str = "__legacy_import:v1";

mod legacy_import;
pub use legacy_import::{import_legacy_scope, import_legacy_system_scope};

/// Build a principal-owned capsule namespace.
#[must_use]
pub fn principal_capsule_namespace(principal: PrincipalUid, capsule: &str) -> String {
    format!("principal-uid:{principal}:control:env:{capsule}")
}

/// Build the host/system-owned capsule namespace used for shared values.
#[must_use]
pub fn system_capsule_namespace(capsule: &str) -> String {
    format!("system:control:env:{capsule}")
}

/// Build a principal-owned secret namespace, hidden from guest KV.
#[must_use]
pub fn principal_secret_namespace(principal: PrincipalUid, capsule: &str) -> String {
    format!("principal-uid:{principal}:control:secret:{capsule}")
}

/// Build a host-wide secret namespace, hidden from guest KV.
#[must_use]
pub fn system_secret_namespace(capsule: &str) -> String {
    format!("system:control:secret:{capsule}")
}

/// Build the typed environment key for one manifest field.
#[must_use]
pub fn env_key(field: &str) -> String {
    format!("{ENV_KEY_PREFIX}{field}")
}

/// Return the field name encoded by an environment key.
#[must_use]
pub fn env_field(key: &str) -> Option<&str> {
    key.strip_prefix(ENV_KEY_PREFIX)
        .filter(|field| !field.is_empty())
}

async fn rollback_imported_env(store: &ScopedKvStore, entries: &[(String, String)]) {
    for (field, value) in entries {
        if get_env(store, field).await.ok().flatten().as_deref() == Some(value.as_str()) {
            let _ = delete_env(store, field).await;
        }
    }
}

async fn rollback_imported_secrets(store: &ScopedKvStore, entries: &[(String, String)]) {
    for (key, value) in entries {
        let prefixed = format!("{SECRET_KEY_PREFIX}{key}");
        if store.get(&prefixed).await.ok().flatten().as_deref() == Some(value.as_bytes()) {
            let _ = store.delete(&prefixed).await;
        }
    }
}

/// Read one secret from a host-only control scope.
///
/// # Errors
///
/// Returns a storage or serialization error when the value cannot be read or
/// decoded as UTF-8.
pub async fn get_secret(store: &ScopedKvStore, key: &str) -> StorageResult<Option<String>> {
    get_control_secret(store, key).await
}

async fn get_control_secret(store: &ScopedKvStore, key: &str) -> StorageResult<Option<String>> {
    let prefixed = format!("{SECRET_KEY_PREFIX}{key}");
    store
        .get(&prefixed)
        .await?
        .map(|bytes| {
            String::from_utf8(bytes).map_err(|error| {
                StorageError::Serialization(format!("secret {key:?} is not UTF-8: {error}"))
            })
        })
        .transpose()
}

/// Return secret names in a host-only control scope without exposing values.
///
/// # Errors
///
/// Returns a storage error when the backing namespace cannot be listed.
pub async fn list_secret_keys(store: &ScopedKvStore) -> StorageResult<Vec<String>> {
    let mut keys = store
        .list_keys_with_prefix(SECRET_KEY_PREFIX)
        .await?
        .into_iter()
        .filter_map(|key| key.strip_prefix(SECRET_KEY_PREFIX).map(str::to_owned))
        .filter(|key| !key.is_empty())
        .collect::<Vec<_>>();
    keys.sort();
    Ok(keys)
}

/// Create a host-only scoped view for one principal's capsule environment.
///
/// # Errors
///
/// Returns a storage error when the namespace is invalid.
pub fn principal_env_store(
    backend: Arc<dyn KvStore>,
    principal: PrincipalUid,
    capsule: &str,
) -> StorageResult<ScopedKvStore> {
    ScopedKvStore::new(backend, principal_capsule_namespace(principal, capsule))
}

/// Create a host-only scoped view for one principal's capsule secrets.
///
/// # Errors
///
/// Returns a storage error when the namespace is invalid.
pub fn principal_secret_store(
    backend: Arc<dyn KvStore>,
    principal: PrincipalUid,
    capsule: &str,
) -> StorageResult<ScopedKvStore> {
    ScopedKvStore::new(backend, principal_secret_namespace(principal, capsule))
}

/// Create a host-only scoped view for one host/system capsule environment.
///
/// # Errors
///
/// Returns a storage error when the namespace is invalid.
pub fn system_env_store(backend: Arc<dyn KvStore>, capsule: &str) -> StorageResult<ScopedKvStore> {
    ScopedKvStore::new(backend, system_capsule_namespace(capsule))
}

/// Create a host-only scoped view for one host/system capsule secret.
///
/// # Errors
///
/// Returns a storage error when the namespace is invalid.
pub fn system_secret_store(
    backend: Arc<dyn KvStore>,
    capsule: &str,
) -> StorageResult<ScopedKvStore> {
    ScopedKvStore::new(backend, system_secret_namespace(capsule))
}

/// Read all non-secret environment fields from one typed scope.
///
/// # Errors
///
/// Returns a storage or serialization error when the scope cannot be read or
/// contains a non-UTF-8 value.
pub async fn read_env(store: &ScopedKvStore) -> StorageResult<HashMap<String, String>> {
    let mut result = HashMap::new();
    let mut keys = store.list_keys_with_prefix(ENV_KEY_PREFIX).await?;
    keys.sort();
    for key in keys {
        let Some(field) = env_field(&key) else {
            continue;
        };
        let Some(bytes) = store.get(&key).await? else {
            continue;
        };
        let value = String::from_utf8(bytes).map_err(|error| {
            StorageError::Serialization(format!(
                "environment value {field:?} is not UTF-8: {error}"
            ))
        })?;
        result.insert(field.to_owned(), value);
    }
    Ok(result)
}

/// Read one non-secret environment field.
///
/// # Errors
///
/// Returns a storage or serialization error when the value cannot be read or
/// decoded as UTF-8.
pub async fn get_env(store: &ScopedKvStore, field: &str) -> StorageResult<Option<String>> {
    let key = env_key(field);
    store
        .get(&key)
        .await?
        .map(|bytes| {
            String::from_utf8(bytes).map_err(|error| {
                StorageError::Serialization(format!(
                    "environment value {field:?} is not UTF-8: {error}"
                ))
            })
        })
        .transpose()
}

/// Set one non-secret environment field.
///
/// # Errors
///
/// Returns a storage error when the value cannot be persisted.
pub async fn set_env(store: &ScopedKvStore, field: &str, value: &str) -> StorageResult<()> {
    store.set(&env_key(field), value.as_bytes().to_vec()).await
}

/// Delete one non-secret environment field.
///
/// # Errors
///
/// Returns a storage error when the value cannot be deleted.
pub async fn delete_env(store: &ScopedKvStore, field: &str) -> StorageResult<bool> {
    store.delete(&env_key(field)).await
}

/// Append one value to an array-typed environment field using CAS.
///
/// Values are stored as a JSON array string under the typed `__env:` key. A
/// compare-and-swap loop makes concurrent gateway writes lossless.
///
/// # Errors
///
/// Returns a storage or serialization error when the existing value is
/// malformed or a bounded CAS retry does not converge.
pub async fn append_env(store: &ScopedKvStore, field: &str, value: &str) -> StorageResult<()> {
    let key = env_key(field);
    for _ in 0..32 {
        let current = store.get(&key).await?;
        let mut values = match current.as_deref() {
            None => Vec::new(),
            Some(bytes) => serde_json::from_slice::<Vec<String>>(bytes).map_err(|error| {
                StorageError::Serialization(format!(
                    "array environment value {field:?} is not a JSON array: {error}"
                ))
            })?,
        };
        values.push(value.to_owned());
        let replacement = serde_json::to_vec(&values)
            .map_err(|error| StorageError::Serialization(error.to_string()))?;
        if store
            .compare_and_swap(&key, current.as_deref(), replacement)
            .await?
        {
            return Ok(());
        }
    }
    Err(StorageError::Internal(format!(
        "concurrent environment updates for {field:?} did not converge"
    )))
}

/// Copy all non-secret environment entries from `source` to `destination`.
///
/// The operation is idempotent: an identical destination value is accepted;
/// a differing existing value is a conflict. All source values are read and
/// destination conflicts are checked before the first write. If a backend
/// fails during the write phase, entries written by this invocation are
/// removed, so callers never observe a knowingly partial copy. Callers must
/// invoke this while the destination owner is unpublished and its owner lock
/// is held (the inheritance path does so); the KV trait has no
/// compare-and-delete primitive for safe rollback against arbitrary writers.
///
/// # Errors
///
/// Returns a storage error on source/destination I/O, conflicting values, or
/// a concurrent destination change.
pub async fn copy_env_namespace(
    source: &ScopedKvStore,
    destination: &ScopedKvStore,
) -> StorageResult<usize> {
    let source_values = read_env(source).await?;
    let source_count = source_values.len();
    let mut pending = Vec::with_capacity(source_values.len());
    for (field, value) in source_values {
        let key = env_key(&field);
        let expected = value.as_bytes();
        match destination.get(&key).await? {
            Some(existing) if existing != expected => {
                return Err(StorageError::Internal(format!(
                    "destination environment field {field:?} already has a different value"
                )));
            },
            Some(_) => {},
            None => pending.push((key, value.into_bytes())),
        }
    }

    let mut written: Vec<(String, Vec<u8>)> = Vec::with_capacity(pending.len());
    for (key, value) in pending {
        if let Err(error) = destination
            .compare_and_swap(&key, None, value.clone())
            .await
            .and_then(|inserted| {
                inserted.then_some(()).ok_or_else(|| {
                    StorageError::Internal(format!(
                        "destination key {key:?} changed during environment copy"
                    ))
                })
            })
        {
            for (written_key, written_value) in written {
                if destination
                    .get(&written_key)
                    .await
                    .ok()
                    .flatten()
                    .as_deref()
                    == Some(written_value.as_slice())
                {
                    let _ = destination.delete(&written_key).await;
                }
            }
            return Err(error);
        }
        written.push((key, value));
    }
    Ok(source_count)
}

/// Copy selected secrets between authoritative KV control projections.
///
/// All destination conflicts are checked before the first write. New values
/// use compare-and-swap, and a failed copy removes only values written by this
/// invocation. Callers must keep the destination principal unpublished until
/// the complete inheritance transaction finishes.
///
/// # Errors
///
/// Returns a storage error on source/destination I/O, conflicting values, or
/// a concurrent destination change.
pub async fn copy_secret_scope(
    source: &ScopedKvStore,
    destination: &ScopedKvStore,
    keys: &[String],
) -> StorageResult<usize> {
    let mut values = Vec::with_capacity(keys.len());
    for key in keys {
        let storage_key = format!("{SECRET_KEY_PREFIX}{key}");
        if let Some(value) = source.get(&storage_key).await? {
            values.push((key.clone(), storage_key, value));
        }
    }

    let mut pending = Vec::with_capacity(values.len());
    for (key, storage_key, value) in &values {
        match destination.get(storage_key).await? {
            Some(existing) if existing != *value => {
                return Err(StorageError::Internal(format!(
                    "destination secret {key:?} already has a different value"
                )));
            },
            Some(_) => {},
            None => pending.push((storage_key.clone(), value.clone())),
        }
    }

    let mut written: Vec<(String, Vec<u8>)> = Vec::with_capacity(pending.len());
    for (storage_key, value) in pending {
        if !destination
            .compare_and_swap(&storage_key, None, value.clone())
            .await?
        {
            for (written_key, written_value) in written {
                if destination
                    .get(&written_key)
                    .await
                    .ok()
                    .flatten()
                    .as_deref()
                    == Some(written_value.as_slice())
                {
                    let _ = destination.delete(&written_key).await;
                }
            }
            return Err(StorageError::Internal(format!(
                "destination key {storage_key:?} changed during secret copy"
            )));
        }
        written.push((storage_key, value));
    }
    Ok(values.len())
}

/// Copy principal-scoped secret values for one capsule through [`SecretStore`].
///
/// Host-wide (`system:control:secret:*`) secrets are intentionally not copied:
/// inheritance grants the new principal access to the existing host scope.
/// The destination owner must still be unpublished/locked by the caller while
/// this operation runs; [`SecretStore`] has no compare-and-delete primitive.
///
/// # Errors
///
/// Returns a descriptive error when a source/destination probe or write fails,
/// or when an existing destination value conflicts.
pub fn copy_secret_store(
    source: &dyn SecretStore,
    destination: &dyn SecretStore,
    keys: &[String],
) -> Result<usize, String> {
    let mut values = Vec::with_capacity(keys.len());
    for key in keys {
        match source.get(key) {
            Ok(Some(value)) => values.push((key.clone(), value)),
            Ok(None) => {},
            Err(error) => return Err(format!("secret {key} read failed: {error}")),
        }
    }
    for (key, value) in &values {
        match destination.get(key) {
            Ok(Some(existing)) if existing != *value => {
                return Err(format!(
                    "destination secret {key} already has a different value"
                ));
            },
            Ok(_) => {},
            Err(error) => return Err(format!("secret {key} destination probe failed: {error}")),
        }
    }
    let mut written: Vec<(String, String)> = Vec::new();
    for (key, value) in &values {
        match destination.get(key) {
            Ok(Some(_)) => {},
            Ok(None) => {
                if let Err(error) = destination.set(key, value) {
                    for (written_key, written_value) in &written {
                        if destination.get(written_key).ok().flatten().as_deref()
                            == Some(written_value.as_str())
                        {
                            let _ = destination.delete(written_key);
                        }
                    }
                    return Err(format!("secret {key} write failed: {error}"));
                }
                written.push((key.clone(), value.clone()));
            },
            Err(error) => return Err(format!("secret {key} destination probe failed: {error}")),
        }
    }
    Ok(values.len())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use astrid_core::PrincipalId;

    use super::*;
    use crate::PrincipalDirectory;
    use crate::kv::MemoryKvStore;
    #[cfg(feature = "legacy-surrealkv")]
    use crate::kv::SurrealKvStore;
    use crate::secret::{FileSecretStore, SecretStore};

    fn principal(name: &str) -> PrincipalUid {
        PrincipalUid::from_bytes(*blake3::hash(name.as_bytes()).as_bytes())
    }

    #[tokio::test]
    async fn control_environment_is_principal_isolated_from_guest_kv() {
        let backend = Arc::new(MemoryKvStore::new());
        let alice = principal("agent-alice");
        let bob = principal("agent-bob");
        let alice_scope = principal_env_store(backend.clone(), alice, "runner").unwrap();
        let bob_scope = principal_env_store(backend.clone(), bob, "runner").unwrap();
        set_env(&alice_scope, "OWNER", "alice").await.unwrap();

        assert_eq!(
            get_env(&alice_scope, "OWNER").await.unwrap().as_deref(),
            Some("alice")
        );
        assert!(get_env(&bob_scope, "OWNER").await.unwrap().is_none());

        let guest = ScopedKvStore::new(backend, "agent-alice:capsule:runner").unwrap();
        assert!(
            guest
                .list_keys_with_prefix(ENV_KEY_PREFIX)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(guest.get(&env_key("OWNER")).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn control_secrets_are_principal_isolated_from_guest_kv() {
        let backend = Arc::new(MemoryKvStore::new());
        let alice = principal("agent-alice");
        let scope = principal_secret_store(backend.clone(), alice, "runner").unwrap();
        scope
            .set(&format!("{SECRET_KEY_PREFIX}api_key"), b"sk".to_vec())
            .await
            .unwrap();
        assert_eq!(
            get_secret(&scope, "api_key").await.unwrap().as_deref(),
            Some("sk")
        );
        let guest = ScopedKvStore::new(backend, "agent-alice:capsule:runner").unwrap();
        assert!(guest.get("api_key").await.unwrap().is_none());
        assert!(
            guest
                .get(&format!("{SECRET_KEY_PREFIX}api_key"))
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn system_environment_scope_is_not_principal_or_guest_scope() {
        let backend = Arc::new(MemoryKvStore::new());
        let alice = principal("agent-alice");
        let system = system_env_store(backend.clone(), "runner").unwrap();
        let alice_scope = principal_env_store(backend.clone(), alice, "runner").unwrap();
        set_env(&system, "BASE_URL", "https://system.example")
            .await
            .unwrap();

        assert_eq!(
            get_env(&system, "BASE_URL").await.unwrap().as_deref(),
            Some("https://system.example")
        );
        assert!(get_env(&alice_scope, "BASE_URL").await.unwrap().is_none());
        let guest = ScopedKvStore::new(backend, "agent-alice:capsule:runner").unwrap();
        assert!(guest.get(&env_key("BASE_URL")).await.unwrap().is_none());
    }

    #[test]
    fn control_namespace_is_stable_across_alias_rename_and_reuse() {
        let original_uid = PrincipalUid::from_bytes([0x11; 32]);
        let replacement_uid = PrincipalUid::from_bytes([0x22; 32]);
        let original = principal_capsule_namespace(original_uid, "runner");
        let renamed = principal_capsule_namespace(original_uid, "runner");
        let reused = principal_capsule_namespace(replacement_uid, "runner");
        assert_eq!(
            original, renamed,
            "alias changes must not move durable state"
        );
        assert_ne!(
            original, reused,
            "alias reuse must receive an isolated UID scope"
        );
        assert_eq!(
            principal_secret_namespace(original_uid, "runner"),
            "principal-uid:1111111111111111111111111111111111111111111111111111111111111111:control:secret:runner"
        );
    }

    #[test]
    fn directory_rename_and_alias_reuse_preserve_uid_isolation() {
        let directory = PrincipalDirectory::default();
        let old_alias = PrincipalId::new("agent-alice").unwrap();
        let renamed_alias = PrincipalId::new("agent-renamed").unwrap();
        let reused_alias = PrincipalId::new("agent-alice").unwrap();
        let original_uid = PrincipalUid::from_bytes([0x31; 32]);
        let replacement_uid = PrincipalUid::from_bytes([0x42; 32]);
        directory.register(old_alias.clone(), original_uid).unwrap();
        directory
            .rename(original_uid, &old_alias, renamed_alias.clone())
            .unwrap();
        assert_eq!(directory.uid_for(&renamed_alias).unwrap(), original_uid);
        directory.unregister(&renamed_alias, original_uid);
        directory
            .register(reused_alias.clone(), replacement_uid)
            .unwrap();
        assert_eq!(directory.uid_for(&reused_alias).unwrap(), replacement_uid);
        assert_ne!(
            principal_capsule_namespace(original_uid, "runner"),
            principal_capsule_namespace(replacement_uid, "runner")
        );
    }

    #[cfg(feature = "legacy-surrealkv")]
    #[tokio::test]
    async fn typed_environment_survives_backend_reopen() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("kv");
        let principal = principal("agent-alice");
        {
            let backend = Arc::new(SurrealKvStore::open(&path).unwrap());
            let scope = principal_env_store(backend.clone(), principal, "runner").unwrap();
            set_env(&scope, "DURABLE", "yes").await.unwrap();
            backend.close().await.unwrap();
        }
        let backend = Arc::new(SurrealKvStore::open(&path).unwrap());
        let scope = principal_env_store(backend, principal, "runner").unwrap();
        assert_eq!(
            get_env(&scope, "DURABLE").await.unwrap().as_deref(),
            Some("yes")
        );
    }

    #[tokio::test]
    async fn environment_copy_is_idempotent_and_rejects_conflicts_before_writes() {
        let backend = Arc::new(MemoryKvStore::new());
        let source = principal_env_store(backend.clone(), principal("source"), "runner").unwrap();
        let destination =
            principal_env_store(backend.clone(), principal("destination"), "runner").unwrap();
        set_env(&source, "ONE", "1").await.unwrap();
        set_env(&source, "TWO", "2").await.unwrap();
        assert_eq!(copy_env_namespace(&source, &destination).await.unwrap(), 2);
        assert_eq!(copy_env_namespace(&source, &destination).await.unwrap(), 2);

        set_env(&destination, "ONE", "different").await.unwrap();
        assert!(copy_env_namespace(&source, &destination).await.is_err());
        assert_eq!(
            get_env(&destination, "TWO").await.unwrap().as_deref(),
            Some("2")
        );
    }

    #[tokio::test]
    async fn secret_copy_uses_control_scope_and_guest_cannot_enumerate_it() {
        let backend = Arc::new(MemoryKvStore::new());
        let source_scope = ScopedKvStore::new(
            backend.clone(),
            principal_secret_namespace(principal("source"), "runner"),
        )
        .unwrap();
        let destination_scope = ScopedKvStore::new(
            backend.clone(),
            principal_secret_namespace(principal("destination"), "runner"),
        )
        .unwrap();
        source_scope
            .set(
                &format!("{SECRET_KEY_PREFIX}TOKEN"),
                b"secret-value".to_vec(),
            )
            .await
            .unwrap();
        let copied = copy_secret_scope(&source_scope, &destination_scope, &["TOKEN".into()])
            .await
            .unwrap();
        assert_eq!(copied, 1);

        let guest = ScopedKvStore::new(backend, "agent-destination:capsule:runner").unwrap();
        assert!(
            guest
                .list_keys_with_prefix(SECRET_KEY_PREFIX)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn legacy_import_is_explicit_receipted_and_retires_only_verified_sources() {
        let root = tempfile::tempdir().unwrap();
        let env_path = root.path().join("runner.env.json");
        let secret_root = root.path().join("secrets");
        std::fs::create_dir(&secret_root).unwrap();
        std::fs::write(&env_path, br#"{"OWNER":"alice"}"#).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&env_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let legacy = FileSecretStore::new(&secret_root);
        legacy.set("TOKEN", "secret-value").unwrap();

        let backend = Arc::new(MemoryKvStore::new());
        let count = import_legacy_scope(
            backend.clone(),
            principal("agent-alice"),
            "runner",
            Some(env_path.clone()),
            Some(secret_root.clone()),
            true,
            tokio::runtime::Handle::current(),
        )
        .await
        .unwrap();
        assert_eq!(count, 2);
        assert!(!env_path.exists());
        assert!(!secret_root.exists());
        let scope = principal_env_store(backend, principal("agent-alice"), "runner").unwrap();
        assert!(scope.get(LEGACY_IMPORT_MARKER_KEY).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn legacy_system_import_isolated_and_receipted() {
        let root = tempfile::tempdir().unwrap();
        let secret_root = root.path().join("host-runner");
        std::fs::create_dir(&secret_root).unwrap();
        let legacy = FileSecretStore::new(&secret_root);
        legacy.set("TOKEN", "host-secret").unwrap();

        let backend = Arc::new(MemoryKvStore::new());
        let count = import_legacy_system_scope(
            backend.clone(),
            "runner",
            None,
            Some(secret_root.clone()),
            true,
            tokio::runtime::Handle::current(),
        )
        .await
        .unwrap();
        assert_eq!(count, 1);
        assert!(!secret_root.exists());

        let system = system_env_store(backend.clone(), "runner").unwrap();
        assert!(
            system
                .get(LEGACY_IMPORT_MARKER_KEY)
                .await
                .unwrap()
                .is_some()
        );
        let secret_scope =
            ScopedKvStore::new(backend.clone(), system_secret_namespace("runner")).unwrap();
        assert_eq!(
            get_control_secret(&secret_scope, "TOKEN")
                .await
                .unwrap()
                .as_deref(),
            Some("host-secret")
        );
        let principal = principal_env_store(backend, principal("alice"), "runner").unwrap();
        assert!(
            principal
                .get(LEGACY_IMPORT_MARKER_KEY)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn legacy_import_rejects_symlink_and_non_private_sources() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().unwrap();
        let real = root.path().join("real.env.json");
        let link = root.path().join("link.env.json");
        std::fs::write(&real, br#"{"OWNER":"alice"}"#).unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let backend = Arc::new(MemoryKvStore::new());
        let result = import_legacy_scope(
            backend.clone(),
            principal("agent-alice"),
            "runner",
            Some(link),
            None,
            false,
            tokio::runtime::Handle::current(),
        )
        .await;
        assert!(result.is_err());

        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o644)).unwrap();
        let result = import_legacy_scope(
            backend,
            principal("agent-alice"),
            "runner",
            Some(real),
            None,
            false,
            tokio::runtime::Handle::current(),
        )
        .await;
        assert!(result.is_err());

        let secret_root = root.path().join("legacy-secrets");
        std::fs::create_dir(&secret_root).unwrap();
        std::fs::set_permissions(&secret_root, std::fs::Permissions::from_mode(0o755)).unwrap();
        let backend = Arc::new(MemoryKvStore::new());
        let result = import_legacy_scope(
            backend,
            principal("agent-alice"),
            "runner",
            None,
            Some(secret_root),
            false,
            tokio::runtime::Handle::current(),
        )
        .await;
        assert!(
            result.is_err(),
            "world-readable secret roots must fail closed"
        );

        let oversized = root.path().join("oversized.env.json");
        std::fs::write(&oversized, vec![b'x'; (1 << 20) + 1]).unwrap();
        std::fs::set_permissions(&oversized, std::fs::Permissions::from_mode(0o600)).unwrap();
        let backend = Arc::new(MemoryKvStore::new());
        let result = import_legacy_scope(
            backend,
            principal("agent-alice"),
            "runner",
            Some(oversized),
            None,
            false,
            tokio::runtime::Handle::current(),
        )
        .await;
        assert!(result.is_err(), "oversized legacy env must fail closed");
    }

    #[tokio::test]
    async fn legacy_conflict_fails_before_writing_other_values() {
        let root = tempfile::tempdir().unwrap();
        let env_path = root.path().join("runner.env.json");
        std::fs::write(&env_path, br#"{"CONFLICT":"legacy","NEW":"must-not-land"}"#).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&env_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let backend = Arc::new(MemoryKvStore::new());
        let scope =
            principal_env_store(backend.clone(), principal("agent-alice"), "runner").unwrap();
        set_env(&scope, "CONFLICT", "durable").await.unwrap();
        let result = import_legacy_scope(
            backend,
            principal("agent-alice"),
            "runner",
            Some(env_path),
            None,
            false,
            tokio::runtime::Handle::current(),
        )
        .await;
        assert!(result.is_err());
        assert!(get_env(&scope, "NEW").await.unwrap().is_none());
    }
}
