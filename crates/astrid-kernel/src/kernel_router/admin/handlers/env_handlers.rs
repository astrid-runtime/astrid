use std::sync::Arc;

use astrid_capsule::capsule::CapsuleId;
use astrid_core::principal::PrincipalId;
use astrid_events::kernel_api::{AdminResponseBody, EnvEntry, EnvStorageScope, EnvValueKind};

use crate::Kernel;

const MAX_ENV_VALUE_BYTES: usize = 1 << 20;
const MAX_SECRET_VALUE_BYTES: usize = 64 * 1024;

pub(super) fn validate_env_request(
    capsule: &str,
    key: &str,
    kind: EnvValueKind,
) -> Result<(), String> {
    astrid_capsule::capsule::CapsuleId::new(capsule.to_owned())
        .map_err(|error| format!("invalid capsule id: {error}"))?;
    if key.is_empty() || key.contains('\0') || key.contains(':') {
        return Err("environment key must be non-empty and must not contain ':'".to_owned());
    }
    if matches!(kind, EnvValueKind::Secret) && key.contains('/') {
        return Err("secret key must not contain path separators".to_owned());
    }
    Ok(())
}

pub(super) fn env_scope(
    kernel: &Arc<crate::Kernel>,
    principal: &PrincipalId,
    capsule: &str,
    kind: EnvValueKind,
    scope: EnvStorageScope,
) -> Result<astrid_storage::ScopedKvStore, String> {
    let principal_uid = kernel
        .principal_directory
        .uid_for(principal)
        .map_err(|error| format!("resolve principal durable UID: {error}"))?;
    let namespace = match (kind, scope) {
        (EnvValueKind::Text, EnvStorageScope::Agent) => {
            astrid_storage::env::principal_capsule_namespace(principal_uid, capsule)
        },
        (EnvValueKind::Text, EnvStorageScope::Shared) => {
            astrid_storage::env::system_capsule_namespace(capsule)
        },
        (EnvValueKind::Secret, EnvStorageScope::Agent) => {
            astrid_storage::env::principal_secret_namespace(principal_uid, capsule)
        },
        (EnvValueKind::Secret, EnvStorageScope::Shared) => {
            astrid_storage::env::system_secret_namespace(capsule)
        },
    };
    astrid_storage::ScopedKvStore::new(Arc::clone(&kernel.kv), namespace)
        .map_err(|error| format!("create host control scope: {error}"))
}

pub(super) struct EnvSetRequest {
    pub(super) principal: PrincipalId,
    pub(super) capsule: String,
    pub(super) key: String,
    pub(super) value: String,
    pub(super) kind: EnvValueKind,
    pub(super) scope: EnvStorageScope,
    pub(super) append: bool,
}

/// Refresh only the target principal's runtime after a durable env mutation.
///
/// A principal that has not loaded this capsule yet has no stale in-memory
/// state to repair; its next load reads the newly persisted control value.
/// Once a runtime is live, however, a failed refresh must be visible to the
/// caller rather than returning success while the old configuration remains
/// active.
async fn reload_after_env_change(
    kernel: &Arc<Kernel>,
    principal: &PrincipalId,
    capsule: &str,
) -> Result<(), String> {
    let id = CapsuleId::new(capsule.to_owned())
        .map_err(|error| format!("invalid capsule id: {error}"))?;
    let was_loaded = kernel
        .capsules
        .read()
        .await
        .get_for(principal, &id)
        .is_some();
    match kernel.reload_one_capsule(&id, principal).await {
        Ok(()) => Ok(()),
        Err(error) if !was_loaded => {
            tracing::debug!(
                %principal,
                capsule = %id,
                error = %error,
                "environment changed before capsule was loaded; next load will use the new value"
            );
            Ok(())
        },
        Err(error) => Err(format!(
            "reload of capsule '{id}' for principal '{principal}' failed: {error:#}"
        )),
    }
}

pub(super) async fn env_set(kernel: &Arc<Kernel>, request: EnvSetRequest) -> AdminResponseBody {
    let EnvSetRequest {
        principal,
        capsule,
        key,
        value,
        kind,
        scope,
        append,
    } = request;
    if let Err(error) = validate_env_request(&capsule, &key, kind) {
        return AdminResponseBody::Error(error);
    }
    let limit = match kind {
        EnvValueKind::Text => MAX_ENV_VALUE_BYTES,
        EnvValueKind::Secret => MAX_SECRET_VALUE_BYTES,
    };
    if value.len() > limit {
        return AdminResponseBody::Error(format!("environment value exceeds {limit}-byte limit"));
    }
    let _guard = kernel.admin_write_lock.lock().await;
    let scope_store = match env_scope(kernel, &principal, &capsule, kind, scope) {
        Ok(store) => store,
        Err(error) => return AdminResponseBody::Error(error),
    };
    let result = match kind {
        EnvValueKind::Text if append => astrid_storage::env::append_env(&scope_store, &key, &value)
            .await
            .map_err(|error| error.to_string()),
        EnvValueKind::Text => astrid_storage::env::set_env(&scope_store, &key, &value)
            .await
            .map_err(|error| error.to_string()),
        EnvValueKind::Secret => {
            if append {
                return AdminResponseBody::Error(
                    "secret environment values cannot be appended".to_owned(),
                );
            }
            let store =
                astrid_storage::KvSecretStore::new(scope_store, tokio::runtime::Handle::current());
            astrid_storage::SecretStore::set(&store, &key, &value)
                .map_err(|error| error.to_string())
        },
    };
    match result {
        Ok(()) => match reload_after_env_change(kernel, &principal, &capsule).await {
            Ok(()) => AdminResponseBody::Success(serde_json::json!({"stored": true})),
            Err(error) => AdminResponseBody::Error(error),
        },
        Err(error) => AdminResponseBody::Error(error),
    }
}

pub(super) async fn env_delete(
    kernel: &Arc<Kernel>,
    principal: PrincipalId,
    capsule: String,
    key: String,
    kind: EnvValueKind,
    scope: EnvStorageScope,
) -> AdminResponseBody {
    if let Err(error) = validate_env_request(&capsule, &key, kind) {
        return AdminResponseBody::Error(error);
    }
    let _guard = kernel.admin_write_lock.lock().await;
    let scope_store = match env_scope(kernel, &principal, &capsule, kind, scope) {
        Ok(store) => store,
        Err(error) => return AdminResponseBody::Error(error),
    };
    let deleted = match kind {
        EnvValueKind::Text => astrid_storage::env::delete_env(&scope_store, &key)
            .await
            .map_err(|error| error.to_string()),
        EnvValueKind::Secret => {
            let store =
                astrid_storage::KvSecretStore::new(scope_store, tokio::runtime::Handle::current());
            astrid_storage::SecretStore::delete(&store, &key).map_err(|error| error.to_string())
        },
    };
    match deleted {
        Ok(deleted) => match reload_after_env_change(kernel, &principal, &capsule).await {
            Ok(()) => AdminResponseBody::Success(serde_json::json!({"deleted": deleted})),
            Err(error) => AdminResponseBody::Error(error),
        },
        Err(error) => AdminResponseBody::Error(error),
    }
}

pub(super) async fn env_list(
    kernel: &Arc<Kernel>,
    principal: PrincipalId,
    capsule_filter: Option<String>,
) -> AdminResponseBody {
    let capsules = if let Some(capsule) = capsule_filter {
        if let Err(error) = astrid_capsule::capsule::CapsuleId::new(capsule.clone()) {
            return AdminResponseBody::Error(format!("invalid capsule id: {error}"));
        }
        vec![capsule]
    } else {
        kernel
            .capsules
            .read()
            .await
            .list()
            .into_iter()
            .map(ToString::to_string)
            .collect()
    };
    let mut entries = Vec::<EnvEntry>::new();
    for capsule in capsules {
        for scope in [EnvStorageScope::Agent, EnvStorageScope::Shared] {
            let text_scope =
                match env_scope(kernel, &principal, &capsule, EnvValueKind::Text, scope) {
                    Ok(scope) => scope,
                    Err(error) => return AdminResponseBody::Error(error),
                };
            match astrid_storage::env::read_env(&text_scope).await {
                Ok(values) => entries.extend(values.into_keys().map(|key| EnvEntry {
                    capsule: capsule.clone(),
                    key,
                    kind: EnvValueKind::Text,
                    scope,
                })),
                Err(error) => return AdminResponseBody::Error(error.to_string()),
            }
            let secret_scope =
                match env_scope(kernel, &principal, &capsule, EnvValueKind::Secret, scope) {
                    Ok(scope) => scope,
                    Err(error) => return AdminResponseBody::Error(error),
                };
            match astrid_storage::env::list_secret_keys(&secret_scope).await {
                Ok(keys) => entries.extend(keys.into_iter().map(|key| EnvEntry {
                    capsule: capsule.clone(),
                    key,
                    kind: EnvValueKind::Secret,
                    scope,
                })),
                Err(error) => return AdminResponseBody::Error(error.to_string()),
            }
        }
    }
    entries.sort_by(|a, b| {
        a.capsule
            .cmp(&b.capsule)
            .then_with(|| a.key.cmp(&b.key))
            .then_with(|| a.kind.cmp(&b.kind))
            .then_with(|| a.scope.cmp(&b.scope))
    });
    AdminResponseBody::EnvList(entries)
}
