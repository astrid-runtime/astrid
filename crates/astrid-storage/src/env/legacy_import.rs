// Legacy filesystem import and retirement; runtime lookups stay in env.rs.
use std::collections::HashMap;
use std::sync::Arc;

use astrid_core::identity::PrincipalUid;

use super::{
    LEGACY_IMPORT_MARKER_KEY, SECRET_KEY_PREFIX, env_key, get_control_secret, get_env,
    principal_env_store, principal_secret_namespace, rollback_imported_env,
    rollback_imported_secrets, system_env_store, system_secret_namespace,
};
use crate::error::{StorageError, StorageResult};
use crate::kv::{KvStore, ScopedKvStore};
use crate::secret::{FileSecretStore, SecretStore};

fn verify_legacy_file(path: &std::path::Path, max_bytes: u64, label: &str) -> StorageResult<()> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        StorageError::Connection(format!("stat legacy {label} {}: {error}", path.display()))
    })?;
    if !metadata.file_type().is_file() {
        return Err(StorageError::InvalidKey(format!(
            "legacy {label} {} is not a regular file",
            path.display()
        )));
    }
    if metadata.len() > max_bytes {
        return Err(StorageError::InvalidKey(format!(
            "legacy {label} {} exceeds the {max_bytes}-byte limit",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(StorageError::InvalidKey(format!(
                "legacy {label} {} is not private (expected no group/world bits)",
                path.display()
            )));
        }
    }
    Ok(())
}

fn read_legacy_env(path: Option<&std::path::Path>) -> StorageResult<HashMap<String, String>> {
    let Some(path) = path else {
        return Ok(HashMap::new());
    };
    match std::fs::symlink_metadata(path) {
        Ok(_) => {
            verify_legacy_file(path, 1 << 20, "environment file")?;
            let text = std::fs::read_to_string(path).map_err(|error| {
                StorageError::Connection(format!("read legacy env {}: {error}", path.display()))
            })?;
            serde_json::from_str(&text).map_err(|error| {
                StorageError::Serialization(format!("parse legacy env {}: {error}", path.display()))
            })
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(HashMap::new()),
        Err(error) => Err(StorageError::Connection(format!(
            "stat legacy env {}: {error}",
            path.display()
        ))),
    }
}

fn read_legacy_secrets(root: Option<&std::path::Path>) -> StorageResult<Vec<(String, String)>> {
    let Some(root) = root else {
        return Ok(Vec::new());
    };
    let metadata = std::fs::symlink_metadata(root).map_err(|error| {
        StorageError::Connection(format!(
            "stat legacy secret root {}: {error}",
            root.display()
        ))
    })?;
    if !metadata.is_dir() {
        return Err(StorageError::InvalidKey(format!(
            "legacy secret root {} is not a directory",
            root.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(StorageError::InvalidKey(format!(
                "legacy secret root {} is not private",
                root.display()
            )));
        }
    }
    let source = FileSecretStore::new(root.to_path_buf());
    let mut values = Vec::new();
    for entry in std::fs::read_dir(root)
        .map_err(|error| StorageError::Connection(format!("read legacy secret root: {error}")))?
    {
        let entry = entry.map_err(|error| StorageError::Connection(error.to_string()))?;
        let path = entry.path();
        let metadata = std::fs::symlink_metadata(&path).map_err(|error| {
            StorageError::Connection(format!(
                "stat legacy secret entry {}: {error}",
                path.display()
            ))
        })?;
        if !metadata.file_type().is_file() {
            return Err(StorageError::InvalidKey(format!(
                "legacy secret entry {} is not a regular file",
                path.display()
            )));
        }
        let Some(key) = entry.file_name().to_str().map(str::to_owned) else {
            return Err(StorageError::InvalidKey(
                "legacy secret filename is not valid UTF-8".to_owned(),
            ));
        };
        verify_legacy_file(&path, 64 * 1024, "secret")?;
        if let Some(value) = source.get(&key).map_err(|error| {
            StorageError::Connection(format!("read legacy secret {key}: {error}"))
        })? {
            values.push((key, value));
        }
    }
    Ok(values)
}

async fn check_import_conflicts(
    env_store: &ScopedKvStore,
    secret_scope: &ScopedKvStore,
    env_values: &HashMap<String, String>,
    secret_values: &[(String, String)],
) -> StorageResult<()> {
    for (field, value) in env_values {
        if let Some(existing) = get_env(env_store, field).await?
            && existing != *value
        {
            return Err(StorageError::Internal(format!(
                "legacy environment field {field:?} conflicts with durable state"
            )));
        }
    }
    for (key, value) in secret_values {
        if let Some(existing) = get_control_secret(secret_scope, key).await?
            && existing != *value
        {
            return Err(StorageError::Internal(format!(
                "legacy secret {key:?} conflicts with durable state"
            )));
        }
    }
    Ok(())
}

async fn write_import_env(
    env_store: &ScopedKvStore,
    values: &HashMap<String, String>,
) -> StorageResult<(usize, Vec<(String, String)>)> {
    let mut count = 0usize;
    let mut written = Vec::new();
    for (field, value) in values {
        let existing = match get_env(env_store, field).await {
            Ok(existing) => existing,
            Err(error) => {
                rollback_imported_env(env_store, &written).await;
                return Err(error);
            },
        };
        if existing.is_some() {
            continue;
        }
        match env_store
            .compare_and_swap(&env_key(field), None, value.as_bytes().to_vec())
            .await
        {
            Ok(true) => {
                written.push((field.clone(), value.clone()));
                count = count.saturating_add(1);
            },
            Ok(false) => {
                rollback_imported_env(env_store, &written).await;
                return Err(StorageError::Internal(format!(
                    "legacy environment field {field:?} changed during import"
                )));
            },
            Err(error) => {
                rollback_imported_env(env_store, &written).await;
                return Err(error);
            },
        }
    }
    Ok((count, written))
}

async fn write_import_secrets(
    env_store: &ScopedKvStore,
    secret_scope: &ScopedKvStore,
    values: &[(String, String)],
    env_written: &[(String, String)],
) -> StorageResult<(usize, Vec<(String, String)>)> {
    let mut count = 0usize;
    let mut written = Vec::new();
    for (key, value) in values {
        let existing = match get_control_secret(secret_scope, key).await {
            Ok(existing) => existing,
            Err(error) => {
                rollback_imported_env(env_store, env_written).await;
                rollback_imported_secrets(secret_scope, &written).await;
                return Err(error);
            },
        };
        if existing.is_some() {
            continue;
        }
        let result = secret_scope
            .compare_and_swap(
                &format!("{SECRET_KEY_PREFIX}{key}"),
                None,
                value.as_bytes().to_vec(),
            )
            .await;
        match result {
            Ok(true) => {
                written.push((key.clone(), value.clone()));
                count = count.saturating_add(1);
            },
            Ok(false) => {
                rollback_imported_env(env_store, env_written).await;
                rollback_imported_secrets(secret_scope, &written).await;
                return Err(StorageError::Internal(format!(
                    "legacy secret {key:?} changed during import"
                )));
            },
            Err(error) => {
                rollback_imported_env(env_store, env_written).await;
                rollback_imported_secrets(secret_scope, &written).await;
                return Err(error);
            },
        }
    }
    Ok((count, written))
}

async fn verify_import_values(
    env_store: &ScopedKvStore,
    secret_scope: &ScopedKvStore,
    env_values: &HashMap<String, String>,
    secret_values: &[(String, String)],
    env_written: &[(String, String)],
    secret_written: &[(String, String)],
) -> StorageResult<()> {
    for (field, value) in env_values {
        let current = match get_env(env_store, field).await {
            Ok(current) => current,
            Err(error) => {
                rollback_imported_env(env_store, env_written).await;
                rollback_imported_secrets(secret_scope, secret_written).await;
                return Err(error);
            },
        };
        if current.as_deref() != Some(value.as_str()) {
            rollback_imported_env(env_store, env_written).await;
            rollback_imported_secrets(secret_scope, secret_written).await;
            return Err(StorageError::Internal(format!(
                "legacy environment field {field:?} failed durable read-back"
            )));
        }
    }
    for (key, value) in secret_values {
        let current = match get_control_secret(secret_scope, key).await {
            Ok(current) => current,
            Err(error) => {
                rollback_imported_env(env_store, env_written).await;
                rollback_imported_secrets(secret_scope, secret_written).await;
                return Err(error);
            },
        };
        if current.as_deref() != Some(value.as_str()) {
            rollback_imported_env(env_store, env_written).await;
            rollback_imported_secrets(secret_scope, secret_written).await;
            return Err(StorageError::Internal(format!(
                "legacy secret {key:?} failed durable read-back"
            )));
        }
    }
    Ok(())
}

async fn write_import_receipt(
    env_store: &ScopedKvStore,
    env_count: usize,
    secret_count: usize,
    env_written: &[(String, String)],
    secret_scope: &ScopedKvStore,
    secret_written: &[(String, String)],
) -> StorageResult<()> {
    let receipt = format!("legacy-import-v1 env={env_count} secrets={secret_count}");
    match env_store
        .compare_and_swap(LEGACY_IMPORT_MARKER_KEY, None, receipt.as_bytes().to_vec())
        .await
    {
        Ok(true) => Ok(()),
        Ok(false) => {
            let existing = env_store.get(LEGACY_IMPORT_MARKER_KEY).await?;
            if existing.as_deref() == Some(receipt.as_bytes()) {
                return Ok(());
            }
            rollback_imported_env(env_store, env_written).await;
            rollback_imported_secrets(secret_scope, secret_written).await;
            Err(StorageError::Internal(
                "legacy import receipt conflicts with durable state".to_owned(),
            ))
        },
        Err(error) => {
            rollback_imported_env(env_store, env_written).await;
            rollback_imported_secrets(secret_scope, secret_written).await;
            Err(error)
        },
    }
}

fn retire_legacy_env(path: Option<std::path::PathBuf>) -> StorageResult<()> {
    let Some(path) = path else { return Ok(()) };
    match std::fs::symlink_metadata(&path) {
        Ok(_) => {
            verify_legacy_file(&path, 1 << 20, "environment file")?;
            std::fs::remove_file(path)
                .map_err(|error| StorageError::Connection(format!("retire legacy env: {error}")))
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(StorageError::Connection(format!(
            "stat legacy env for retirement: {error}"
        ))),
    }
}

fn retire_legacy_secrets(
    root: Option<std::path::PathBuf>,
    values: &[(String, String)],
) -> StorageResult<()> {
    let Some(root) = root else { return Ok(()) };
    let metadata = match std::fs::symlink_metadata(&root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(StorageError::Connection(format!(
                "stat legacy secret directory for retirement: {error}"
            )));
        },
    };
    if !metadata.is_dir() {
        return Err(StorageError::InvalidKey(format!(
            "legacy secret root {} is not a directory",
            root.display()
        )));
    }
    let source = FileSecretStore::new(root.clone());
    for (key, _) in values {
        source.delete(key).map_err(|error| {
            StorageError::Connection(format!("retire legacy secret {key}: {error}"))
        })?;
    }
    match std::fs::remove_dir(&root) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::DirectoryNotEmpty => {
            Err(StorageError::Connection(format!(
                "legacy secret directory {} is not empty after retirement",
                root.display()
            )))
        },
        Err(error) => Err(StorageError::Connection(format!(
            "retire legacy secret directory {}: {error}",
            root.display()
        ))),
    }
}

/// Explicitly import one legacy env JSON and file-secret scope.
///
/// This helper is the only supported bridge for released homes that still
/// contain native env/secrets paths. It never participates in runtime lookup.
/// Conflicts are detected before writes; when `retire` is true, source files
/// are removed only after every imported value is read back from KV/SecretStore
/// and matches byte-for-byte.
///
/// # Errors
///
/// Returns an error when a source is unsafe, values conflict, durable writes
/// fail, read-back verification fails, or verified retirement fails.
pub async fn import_legacy_scope(
    backend: Arc<dyn KvStore>,
    principal: PrincipalUid,
    capsule: &str,
    legacy_env_file: Option<std::path::PathBuf>,
    legacy_secret_root: Option<std::path::PathBuf>,
    retire: bool,
    _runtime_handle: tokio::runtime::Handle,
) -> StorageResult<usize> {
    let env_store = principal_env_store(Arc::clone(&backend), principal, capsule)?;
    let secret_scope = ScopedKvStore::new(
        Arc::clone(&backend),
        principal_secret_namespace(principal, capsule),
    )?;
    import_legacy_scoped_scope(
        env_store,
        secret_scope,
        legacy_env_file,
        legacy_secret_root,
        retire,
    )
    .await
}

/// Import one host/system-owned legacy env and secret scope.
///
/// Host scopes use the same bounded source validation, conflict checks,
/// durable read-back, and receipt marker as principal scopes, but their
/// destination is the `system:control:*` namespace and is therefore isolated
/// from every principal UID.
///
/// # Errors
///
/// Returns an error when a source is unsafe, values conflict, durable writes
/// fail, read-back verification fails, or verified retirement fails.
pub async fn import_legacy_system_scope(
    backend: Arc<dyn KvStore>,
    capsule: &str,
    legacy_env_file: Option<std::path::PathBuf>,
    legacy_secret_root: Option<std::path::PathBuf>,
    retire: bool,
    _runtime_handle: tokio::runtime::Handle,
) -> StorageResult<usize> {
    let env_store = system_env_store(Arc::clone(&backend), capsule)?;
    let secret_scope = ScopedKvStore::new(Arc::clone(&backend), system_secret_namespace(capsule))?;
    import_legacy_scoped_scope(
        env_store,
        secret_scope,
        legacy_env_file,
        legacy_secret_root,
        retire,
    )
    .await
}

async fn import_legacy_scoped_scope(
    env_store: ScopedKvStore,
    secret_scope: ScopedKvStore,
    legacy_env_file: Option<std::path::PathBuf>,
    legacy_secret_root: Option<std::path::PathBuf>,
    retire: bool,
) -> StorageResult<usize> {
    let env_values = read_legacy_env(legacy_env_file.as_deref())?;
    let secret_values = read_legacy_secrets(legacy_secret_root.as_deref())?;
    check_import_conflicts(&env_store, &secret_scope, &env_values, &secret_values).await?;
    let (env_count, env_written) = write_import_env(&env_store, &env_values).await?;
    let (secret_count, secret_written) =
        write_import_secrets(&env_store, &secret_scope, &secret_values, &env_written).await?;
    verify_import_values(
        &env_store,
        &secret_scope,
        &env_values,
        &secret_values,
        &env_written,
        &secret_written,
    )
    .await?;
    write_import_receipt(
        &env_store,
        env_values.len(),
        secret_values.len(),
        &env_written,
        &secret_scope,
        &secret_written,
    )
    .await?;
    if retire {
        retire_legacy_env(legacy_env_file)?;
        retire_legacy_secrets(legacy_secret_root, &secret_values)?;
    }
    Ok(env_count.saturating_add(secret_count))
}
