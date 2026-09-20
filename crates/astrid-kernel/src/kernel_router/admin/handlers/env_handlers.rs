use std::sync::Arc;

use astrid_capsule::capsule::CapsuleId;
use astrid_core::principal::PrincipalId;
use astrid_events::kernel_api::{AdminResponseBody, EnvEntry, EnvStorageScope, EnvValueKind};

use crate::Kernel;

const MAX_ENV_VALUE_BYTES: usize = 1 << 20;
const MAX_SECRET_VALUE_BYTES: usize = 64 * 1024;

#[cfg(test)]
mod tests;

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
    pub(super) only_if_absent: bool,
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

fn validate_env_value(kind: EnvValueKind, value: &str) -> Result<(), String> {
    let limit = match kind {
        EnvValueKind::Text => MAX_ENV_VALUE_BYTES,
        EnvValueKind::Secret => MAX_SECRET_VALUE_BYTES,
    };
    if value.len() > limit {
        return Err(format!("environment value exceeds {limit}-byte limit"));
    }
    if kind == EnvValueKind::Secret && value.is_empty() {
        return Err("secret value must not be empty".to_owned());
    }
    Ok(())
}

pub(super) async fn env_set(kernel: &Arc<Kernel>, request: EnvSetRequest) -> AdminResponseBody {
    env_set_with_refresh(kernel, request, reload_after_env_change).await
}

async fn env_set_with_refresh(
    kernel: &Arc<Kernel>,
    request: EnvSetRequest,
    refresh: impl AsyncFnOnce(&Arc<Kernel>, &PrincipalId, &str) -> Result<(), String>,
) -> AdminResponseBody {
    if let Err(error) = validate_env_request(&request.capsule, &request.key, request.kind) {
        return AdminResponseBody::Error(error);
    }
    if let Err(error) = validate_env_value(request.kind, &request.value) {
        return AdminResponseBody::Error(error);
    }
    let capsule = match CapsuleId::new(request.capsule.clone()) {
        Ok(id) => id,
        Err(error) => return AdminResponseBody::Error(error.to_string()),
    };
    let refresh_key = (request.principal.clone(), capsule);
    // Queue ordinary writers before probing the install fence so concurrent
    // defaults do not mistake one another for an unresolved install.
    let write_guard = kernel.admin_write_lock.lock().await;
    // Fail visibly rather than treating an install's staged value as durable.
    // Never wait here: activation can itself need an admin operation.
    let install_guard = if request.only_if_absent {
        match kernel.env_install_fence.try_write() {
            Ok(guard) => Some(guard),
            Err(_) => return AdminResponseBody::Error(
                "capsule environment transaction in progress; retry initialization after the install completes".to_owned(),
            ),
        }
    } else {
        None
    };
    let ticket = match persist_env_value(kernel, &request).await {
        Ok(true) => {
            let ticket = Arc::new(());
            kernel
                .env_refresh_pending
                .insert(refresh_key.clone(), Arc::clone(&ticket));
            Some(ticket)
        },
        Ok(false) => kernel
            .env_refresh_pending
            .get(&refresh_key)
            .map(|entry| Arc::clone(entry.value())),
        Err(error) => return AdminResponseBody::Error(error),
    };
    // Activation may call mutating admin or install APIs. Neither guard may
    // survive into it. A failed/cancelled refresh keeps its ticket for retry.
    drop(install_guard);
    drop(write_guard);
    if let Some(ticket) = ticket {
        if let Err(error) = refresh(kernel, &request.principal, &request.capsule).await {
            return AdminResponseBody::Error(error);
        }
        kernel
            .env_refresh_pending
            .remove_if(&refresh_key, |_, current| Arc::ptr_eq(current, &ticket));
    }
    env_write_success(request.only_if_absent)
}

/// Called under the admin lock and (for defaults) the install fence.
async fn persist_env_value(kernel: &Arc<Kernel>, request: &EnvSetRequest) -> Result<bool, String> {
    let EnvSetRequest {
        principal,
        capsule,
        key,
        value,
        kind,
        scope,
        append,
        only_if_absent,
    } = request;
    if *only_if_absent && has_effective_value(kernel, principal, capsule, key, *kind).await? {
        return Ok(false);
    }
    let scope_store = env_scope(kernel, principal, capsule, *kind, *scope)?;
    match kind {
        _ if *only_if_absent => {
            let storage_key = match kind {
                EnvValueKind::Text => astrid_storage::env::env_key(key),
                EnvValueKind::Secret => format!("{}{key}", astrid_storage::env::SECRET_KEY_PREFIX),
            };
            scope_store
                .compare_and_swap(&storage_key, None, value.as_bytes().to_vec())
                .await
                .map_err(|error| error.to_string())
        },
        EnvValueKind::Text if *append => astrid_storage::env::append_env(&scope_store, key, value)
            .await
            .map(|()| true)
            .map_err(|error| error.to_string()),
        EnvValueKind::Text => astrid_storage::env::set_env(&scope_store, key, value)
            .await
            .map(|()| true)
            .map_err(|error| error.to_string()),
        EnvValueKind::Secret => {
            if *append {
                return Err("secret environment values cannot be appended".to_owned());
            }
            let store =
                astrid_storage::KvSecretStore::new(scope_store, tokio::runtime::Handle::current());
            astrid_storage::SecretStore::set(&store, key, value)
                .map(|()| true)
                .map_err(|error| error.to_string())
        },
    }
}

fn env_write_success(only_if_absent: bool) -> AdminResponseBody {
    // Default writers need no read authority. Do not reveal whether an
    // agent or shared value existed through the conditional response.
    AdminResponseBody::Success(if only_if_absent {
        serde_json::json!({})
    } else {
        serde_json::json!({"stored": true})
    })
}

/// Defaults always target the principal overlay and never replace shared state.
pub(super) async fn env_set_default(
    kernel: &Arc<Kernel>,
    principal: PrincipalId,
    capsule: String,
    key: String,
    value: String,
    kind: EnvValueKind,
) -> AdminResponseBody {
    env_set(
        kernel,
        EnvSetRequest {
            principal,
            capsule,
            key,
            value,
            kind,
            scope: EnvStorageScope::Agent,
            append: false,
            only_if_absent: true,
        },
    )
    .await
}

async fn has_effective_value(
    kernel: &Arc<Kernel>,
    principal: &PrincipalId,
    capsule: &str,
    key: &str,
    kind: EnvValueKind,
) -> Result<bool, String> {
    for scope in [EnvStorageScope::Agent, EnvStorageScope::Shared] {
        let store = env_scope(kernel, principal, capsule, kind, scope)?;
        let value = match kind {
            EnvValueKind::Text => astrid_storage::env::get_env(&store, key).await,
            EnvValueKind::Secret => astrid_storage::env::get_secret(&store, key).await,
        }
        .map_err(|error| error.to_string())?;
        if value.is_some() {
            return Ok(true);
        }
    }
    Ok(false)
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
    let write_guard = kernel.admin_write_lock.lock().await;
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
    let deleted = match deleted {
        Ok(deleted) => deleted,
        Err(error) => return AdminResponseBody::Error(error),
    };
    let id = match CapsuleId::new(capsule.clone()) {
        Ok(id) => id,
        Err(error) => return AdminResponseBody::Error(error.to_string()),
    };
    let refresh_key = (principal.clone(), id);
    let ticket = Arc::new(());
    kernel
        .env_refresh_pending
        .insert(refresh_key.clone(), Arc::clone(&ticket));
    drop(write_guard);
    match reload_after_env_change(kernel, &principal, &capsule).await {
        Ok(()) => {
            kernel
                .env_refresh_pending
                .remove_if(&refresh_key, |_, current| Arc::ptr_eq(current, &ticket));
            AdminResponseBody::Success(serde_json::json!({"deleted": deleted}))
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
