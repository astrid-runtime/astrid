//! Load-time capsule environment resolution.
//!
//! Manifest `[env]` values live in host-only control namespaces. Guest
//! `ScopedKvStore` views never see those keys.

use std::collections::HashMap;

use crate::context::CapsuleContext;
use crate::error::CapsuleResult;
use crate::manifest::{CapsuleManifest, EnvDef};

/// Build an [`OnboardingField`] from a manifest [`EnvDef`].
///
/// Shared between `WasmEngine` and `McpHostEngine` so both resolve
/// field types identically.
pub(crate) fn build_onboarding_field(
    key: &str,
    def: &EnvDef,
) -> astrid_events::ipc::OnboardingField {
    use astrid_events::ipc::OnboardingFieldType;

    let field_type = if def.env_type == "secret" {
        if !def.enum_values.is_empty() {
            tracing::warn!(
                key = %key,
                "Secret field has enum_values - ignoring enum and using masked input"
            );
        }
        OnboardingFieldType::Secret
    } else if def.env_type == "array" {
        OnboardingFieldType::Array
    } else if def.enum_values.len() > 1 {
        OnboardingFieldType::Enum(def.enum_values.clone())
    } else {
        OnboardingFieldType::Text
    };

    let mut default = def.default.as_ref().and_then(|d| match d {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Null => None,
        other => Some(other.to_string()),
    });

    // Single-choice enums degrade to text - auto-fill the sole valid value.
    if def.enum_values.len() == 1 && default.is_none() {
        default = Some(def.enum_values[0].clone());
    }

    let prompt = def
        .request
        .clone()
        .unwrap_or_else(|| format!("Please enter value for {key}"));

    astrid_events::ipc::OnboardingField {
        key: key.to_string(),
        prompt,
        description: def.description.clone(),
        field_type,
        default,
        placeholder: def.placeholder.clone(),
    }
}

/// Read one staged install value from the host-only control projection.
///
/// Principal control namespaces are tried first:
/// `principal-uid:{uid}:control:secret:{capsule}` / `__secret:` and
/// `principal-uid:{uid}:control:env:{capsule}` / `__env:`. Missing values
/// fall back to the Shared site credential in `system:control:secret:{capsule}`
/// / `system:control:env:{capsule}`. Guest `{principal}:capsule:{id}` keys
/// never satisfy this lookup.
async fn host_control_env_value(
    ctx: &CapsuleContext,
    capsule: &str,
    key: &str,
    def: &EnvDef,
) -> Option<String> {
    let uid = ctx.principal_directory.uid_for(&ctx.principal).ok()?;
    let backend = ctx.kv.backend();
    let is_secret = def.env_type.eq_ignore_ascii_case("secret");
    let principal = if is_secret {
        let store =
            astrid_storage::env::principal_secret_store(backend.clone(), uid, capsule).ok()?;
        astrid_storage::env::get_secret(&store, key).await
    } else {
        let store = astrid_storage::env::principal_env_store(backend.clone(), uid, capsule).ok()?;
        astrid_storage::env::get_env(&store, key).await
    };
    match principal {
        Ok(Some(value)) => return Some(value),
        Ok(None) => {},
        Err(error) => {
            tracing::warn!(
                capsule,
                key,
                error = %error,
                "principal host control environment value could not be read; requiring onboarding"
            );
            return None;
        },
    }

    let shared = if is_secret {
        let store = astrid_storage::env::system_secret_store(backend, capsule).ok()?;
        astrid_storage::env::get_secret(&store, key).await
    } else {
        let store = astrid_storage::env::system_env_store(backend, capsule).ok()?;
        astrid_storage::env::get_env(&store, key).await
    };
    match shared {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(
                capsule,
                key,
                error = %error,
                "shared host control environment value could not be read; requiring onboarding"
            );
            None
        },
    }
}

/// Resolve manifest `[env]` entries against the host-only control store.
///
/// Returns `Ok(resolved_env)` if all required values are satisfied (from the
/// control projection or defaults). Returns `Err` if any fields need
/// onboarding, after publishing `OnboardingRequired` on the event bus.
pub(crate) async fn resolve_env(
    manifest: &CapsuleManifest,
    ctx: &CapsuleContext,
    reserved_keys: &[String],
    source: &str,
) -> CapsuleResult<HashMap<String, String>> {
    let mut resolved = HashMap::new();
    let mut onboarding_fields = Vec::new();

    for (key, def) in &manifest.env {
        if reserved_keys.iter().any(|k| k == key) {
            tracing::warn!(
                capsule = %manifest.package.name,
                key = %key,
                "Capsule manifest [env] declares reserved key - ignoring"
            );
            continue;
        }

        if let Some(val) = host_control_env_value(ctx, &manifest.package.name, key, def).await {
            resolved.insert(key.clone(), val);
        } else if def.enum_values.len() > 1 {
            // Multi-choice enum fields always go through onboarding.
            onboarding_fields.push(build_onboarding_field(key, def));
        } else if let Some(default_val) = &def.default {
            let val = match default_val {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Null => String::new(),
                other => other.to_string(),
            };
            resolved.insert(key.clone(), val);
        } else {
            onboarding_fields.push(build_onboarding_field(key, def));
        }
    }

    if !onboarding_fields.is_empty() {
        let missing_display: String = onboarding_fields
            .iter()
            .map(|f| f.key.as_str())
            .collect::<Vec<_>>()
            .join(", ");

        tracing::warn!(
            capsule = %manifest.package.name,
            missing = %missing_display,
            "Capsule has unconfigured env fields — not starting until configured"
        );

        let msg = astrid_events::ipc::IpcMessage::new(
            astrid_events::ipc::Topic::from_raw("astrid.v1.onboarding.required"),
            astrid_events::ipc::IpcPayload::OnboardingRequired {
                capsule_id: manifest.package.name.clone(),
                fields: onboarding_fields,
            },
            uuid::Uuid::nil(),
        )
        .with_principal(ctx.principal.to_string());
        let _ = ctx.event_bus.publish(astrid_events::AstridEvent::Ipc {
            metadata: astrid_events::EventMetadata::new(source),
            message: msg,
        });
        return Err(astrid_capsule_types::CapsuleError::ExecutionFailed(
            format!(
                "capsule '{}' is not configured ({missing_display})",
                manifest.package.name
            ),
        ));
    }

    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use astrid_core::PrincipalId;
    use astrid_storage::env::{SECRET_KEY_PREFIX, set_env};
    use astrid_storage::{MemoryKvStore, PrincipalDirectory, PrincipalUid, ScopedKvStore};

    fn uid(name: &str) -> PrincipalUid {
        PrincipalUid::from_bytes(*blake3::hash(name.as_bytes()).as_bytes())
    }

    fn openai_compat_manifest() -> CapsuleManifest {
        toml::from_str(
            r#"
[package]
name = "astrid-capsule-openai-compat"
version = "0.2.0"

[env.api_key]
type = "secret"

[env.temperature]
type = "string"
"#,
        )
        .expect("openai-compat env fixture")
    }

    fn context_with_directory(
        backend: Arc<dyn astrid_storage::KvStore>,
        directory: PrincipalDirectory,
        guest_namespace: &str,
    ) -> CapsuleContext {
        context_for_principal(backend, directory, PrincipalId::default(), guest_namespace)
    }

    fn context_for_principal(
        backend: Arc<dyn astrid_storage::KvStore>,
        directory: PrincipalDirectory,
        principal: PrincipalId,
        guest_namespace: &str,
    ) -> CapsuleContext {
        let kv = ScopedKvStore::new(backend, guest_namespace).expect("guest namespace");
        CapsuleContext::new(
            principal,
            std::path::PathBuf::from("/"),
            None,
            kv,
            Arc::new(astrid_events::EventBus::new()),
            None,
        )
        .with_principal_storage_directory(directory)
    }

    // CapsuleContext::with_principal_storage requires a RuntimePrincipalStore.
    // Tests only need the directory + shared KV backend.
    trait DirectoryOnly {
        fn with_principal_storage_directory(self, directory: PrincipalDirectory) -> Self;
    }

    impl DirectoryOnly for CapsuleContext {
        fn with_principal_storage_directory(mut self, directory: PrincipalDirectory) -> Self {
            self.principal_directory = directory;
            self
        }
    }

    #[tokio::test]
    async fn staged_host_control_env_loads_without_guest_keys() {
        let backend = Arc::new(MemoryKvStore::new());
        let principal = PrincipalId::default();
        let uid = uid("default");
        let directory = PrincipalDirectory::default();
        directory.register(principal.clone(), uid).unwrap();

        let env_store = astrid_storage::env::principal_env_store(
            backend.clone(),
            uid,
            "astrid-capsule-openai-compat",
        )
        .unwrap();
        set_env(&env_store, "temperature", "0.7").await.unwrap();
        let secret_store = astrid_storage::env::principal_secret_store(
            backend.clone(),
            uid,
            "astrid-capsule-openai-compat",
        )
        .unwrap();
        secret_store
            .set(&format!("{SECRET_KEY_PREFIX}api_key"), b"sk-test".to_vec())
            .await
            .unwrap();

        let guest = ScopedKvStore::new(
            backend.clone(),
            format!("{principal}:capsule:astrid-capsule-openai-compat"),
        )
        .unwrap();
        assert!(guest.get("api_key").await.unwrap().is_none());
        assert!(guest.get("temperature").await.unwrap().is_none());

        let ctx = context_with_directory(
            backend,
            directory,
            &format!("{principal}:capsule:astrid-capsule-openai-compat"),
        );
        let resolved = resolve_env(&openai_compat_manifest(), &ctx, &[], "test")
            .await
            .expect("staged control env must load");
        assert_eq!(resolved.get("api_key").map(String::as_str), Some("sk-test"));
        assert_eq!(resolved.get("temperature").map(String::as_str), Some("0.7"));
    }

    #[tokio::test]
    async fn guest_kv_values_do_not_satisfy_control_env() {
        let backend = Arc::new(MemoryKvStore::new());
        let principal = PrincipalId::default();
        let uid = uid("default");
        let directory = PrincipalDirectory::default();
        directory.register(principal.clone(), uid).unwrap();
        let guest_ns = format!("{principal}:capsule:astrid-capsule-openai-compat");
        let guest = ScopedKvStore::new(backend.clone(), &guest_ns).unwrap();
        guest.set("api_key", b"from-guest".to_vec()).await.unwrap();
        guest.set("temperature", b"1".to_vec()).await.unwrap();

        let ctx = context_with_directory(backend, directory, &guest_ns);
        let err = resolve_env(&openai_compat_manifest(), &ctx, &[], "test")
            .await
            .expect_err("guest keys must not satisfy host control env");
        let msg = err.to_string();
        assert!(
            msg.contains("is not configured (api_key, temperature)")
                || (msg.contains("api_key") && msg.contains("temperature")),
            "got {msg}"
        );
    }

    #[tokio::test]
    async fn missing_secret_stays_unconfigured() {
        let backend = Arc::new(MemoryKvStore::new());
        let principal = PrincipalId::default();
        let uid = uid("default");
        let directory = PrincipalDirectory::default();
        directory.register(principal.clone(), uid).unwrap();
        let env_store = astrid_storage::env::principal_env_store(
            backend.clone(),
            uid,
            "astrid-capsule-openai-compat",
        )
        .unwrap();
        set_env(&env_store, "temperature", "0.7").await.unwrap();

        let ctx = context_with_directory(
            backend,
            directory,
            &format!("{principal}:capsule:astrid-capsule-openai-compat"),
        );
        let err = resolve_env(&openai_compat_manifest(), &ctx, &[], "test")
            .await
            .expect_err("missing api_key must onboarding");
        let msg = err.to_string();
        assert!(msg.contains("api_key"), "got {msg}");
    }

    #[tokio::test]
    async fn new_principal_resolves_shared_install_secret() {
        let backend = Arc::new(MemoryKvStore::new());
        let assigned = PrincipalId::new("assigned-agent").unwrap();
        let assigned_uid = uid("assigned-agent");
        let directory = PrincipalDirectory::default();
        directory.register(assigned.clone(), assigned_uid).unwrap();

        let shared_secret = astrid_storage::env::system_secret_store(
            backend.clone(),
            "astrid-capsule-openai-compat",
        )
        .unwrap();
        shared_secret
            .set(&format!("{SECRET_KEY_PREFIX}api_key"), b"sk-site".to_vec())
            .await
            .unwrap();
        let assigned_env = astrid_storage::env::principal_env_store(
            backend.clone(),
            assigned_uid,
            "astrid-capsule-openai-compat",
        )
        .unwrap();
        set_env(&assigned_env, "temperature", "0.7").await.unwrap();
        let assigned_secret = astrid_storage::env::principal_secret_store(
            backend.clone(),
            assigned_uid,
            "astrid-capsule-openai-compat",
        )
        .unwrap();
        assert!(
            assigned_secret
                .get(&format!("{SECRET_KEY_PREFIX}api_key"))
                .await
                .unwrap()
                .is_none()
        );

        let ctx = context_for_principal(
            backend,
            directory,
            assigned.clone(),
            &format!("{assigned}:capsule:astrid-capsule-openai-compat"),
        );
        let resolved = resolve_env(&openai_compat_manifest(), &ctx, &[], "test")
            .await
            .expect("shared install secret must satisfy a principal with no Agent api_key");
        assert_eq!(resolved.get("api_key").map(String::as_str), Some("sk-site"));
        assert_eq!(resolved.get("temperature").map(String::as_str), Some("0.7"));
    }

    #[tokio::test]
    async fn agent_secret_overrides_shared_install_secret() {
        let backend = Arc::new(MemoryKvStore::new());
        let principal = PrincipalId::default();
        let uid = uid("default");
        let directory = PrincipalDirectory::default();
        directory.register(principal.clone(), uid).unwrap();

        let shared_secret = astrid_storage::env::system_secret_store(
            backend.clone(),
            "astrid-capsule-openai-compat",
        )
        .unwrap();
        shared_secret
            .set(&format!("{SECRET_KEY_PREFIX}api_key"), b"sk-site".to_vec())
            .await
            .unwrap();
        let agent_secret = astrid_storage::env::principal_secret_store(
            backend.clone(),
            uid,
            "astrid-capsule-openai-compat",
        )
        .unwrap();
        agent_secret
            .set(&format!("{SECRET_KEY_PREFIX}api_key"), b"sk-agent".to_vec())
            .await
            .unwrap();
        let env_store = astrid_storage::env::principal_env_store(
            backend.clone(),
            uid,
            "astrid-capsule-openai-compat",
        )
        .unwrap();
        set_env(&env_store, "temperature", "0.2").await.unwrap();

        let ctx = context_with_directory(
            backend,
            directory,
            &format!("{principal}:capsule:astrid-capsule-openai-compat"),
        );
        let resolved = resolve_env(&openai_compat_manifest(), &ctx, &[], "test")
            .await
            .expect("agent secret must win over shared");
        assert_eq!(
            resolved.get("api_key").map(String::as_str),
            Some("sk-agent")
        );
    }
}
