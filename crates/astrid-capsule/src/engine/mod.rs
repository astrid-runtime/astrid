//! Execution engine trait for Composite Capsules.
//!
//! Because a single `Capsule.toml` can define multiple execution units
//! (e.g. a WASM component AND a legacy MCP host process), the OS uses
//! an additive "Composite" architecture. The capsule iterates over its
//! registered engines to handle lifecycle events.

pub mod mcp;
#[cfg(test)]
mod mcp_tests;
mod static_engine;
pub mod wasm;

pub(crate) use mcp::McpHostEngine;
pub(crate) use static_engine::StaticEngine;
pub(crate) use wasm::WasmEngine;

use std::collections::HashMap;

use async_trait::async_trait;

use crate::context::CapsuleContext;
use crate::error::CapsuleResult;
use crate::manifest::{CapsuleManifest, EnvDef};

/// A runtime environment capable of executing capsule logic.
///
/// Examples include `WasmEngine`, `McpHostEngine`, and `StaticEngine`.
#[async_trait]
pub(crate) trait ExecutionEngine: Send + Sync {
    /// Load the engine (e.g., spawn the WASM VM or start the Node.js process).
    async fn load(&mut self, ctx: &CapsuleContext) -> CapsuleResult<()>;

    /// Unload the engine (e.g., drop WASM memory or SIGTERM the child process).
    async fn unload(&mut self) -> CapsuleResult<()>;

    /// Request cooperative cancellation of blocking work before exclusive unload.
    ///
    /// This is intentionally synchronous and `&self`: callers may still have
    /// in-flight `Arc` clones that prevent `unload(&mut self)`, but those same
    /// in-flight tasks need a cancellation signal so they can release the Arc.
    fn request_cancel(&self) {}

    /// Extract the inbound receiver if this engine provides one.
    fn take_inbound_rx(
        &mut self,
    ) -> Option<tokio::sync::mpsc::Receiver<astrid_core::InboundMessage>> {
        None
    }

    /// Wait for the engine's background task to signal readiness.
    ///
    /// Returns [`ReadyStatus::Ready`] if the engine is ready or has no
    /// background task. Returns [`ReadyStatus::Timeout`] or
    /// [`ReadyStatus::Crashed`] on failure.
    /// Engines without background tasks return `Ready` immediately.
    async fn wait_ready(&self, _timeout: std::time::Duration) -> crate::capsule::ReadyStatus {
        crate::capsule::ReadyStatus::Ready
    }

    /// Invoke an interceptor handler by action name.
    ///
    /// `action` is the handler name (e.g., `handle_user_prompt`) and
    /// `payload` is the serialized IPC payload. `caller` is the originating
    /// IPC message used to set per-invocation principal context on `HostState`.
    ///
    /// The default implementation returns an error. Engines that support
    /// interceptors (e.g., `WasmEngine`) override this.
    ///
    /// **Async contract:** the future returned by this method MAY be
    /// cancelled (e.g. the dispatcher task is aborted). Implementations
    /// must ensure any per-invocation state set on the engine is cleared
    /// before any `.await` that may not return — typically via an RAII
    /// guard that runs in `Drop`. The wasm engine uses `ClearOnDrop`
    /// across the `call_async` await.
    async fn invoke_interceptor(
        &self,
        _action: &str,
        _payload: &[u8],
        _caller: Option<&astrid_events::ipc::IpcMessage>,
    ) -> CapsuleResult<crate::capsule::InterceptResult> {
        Err(crate::error::CapsuleError::NotSupported(
            "interceptors not supported by this engine".into(),
        ))
    }

    /// Probe engine liveness beyond what `state()` reports.
    ///
    /// The default implementation returns the capsule's current state.
    /// Engines with background tasks (e.g., `WasmEngine`) override this
    /// to detect when a run loop has silently exited.
    fn check_health(&self) -> crate::capsule::CapsuleState {
        crate::capsule::CapsuleState::Ready
    }
}

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

/// Resolve manifest `[env]` entries against the KV store.
///
/// Returns `Ok(resolved_env)` if all required values are satisfied (from KV
/// or defaults). Returns `Err` if any fields need onboarding, after
/// publishing `OnboardingRequired` on the event bus.
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

        if let Ok(Some(val_bytes)) = ctx.kv.get(key).await {
            match String::from_utf8(val_bytes) {
                Ok(val) => {
                    resolved.insert(key.clone(), val);
                },
                Err(e) => {
                    tracing::warn!(
                        capsule = %manifest.package.name,
                        key = %key,
                        error = %e,
                        "Value from KV store is not valid UTF-8; requiring onboarding"
                    );
                    onboarding_fields.push(build_onboarding_field(key, def));
                },
            }
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

        tracing::info!(
            capsule = %manifest.package.name,
            missing = %missing_display,
            "Capsule has unconfigured env fields — loading with empty defaults"
        );

        // Fill missing fields with empty strings BEFORE publishing the
        // onboarding event (which moves onboarding_fields). Uplink capsules
        // load at daemon boot before any client connects, so the onboarding
        // event would be lost. The install-time CLI prompts are the primary
        // mechanism; this is the fallback.
        for field in &onboarding_fields {
            resolved.entry(field.key.clone()).or_default();
        }

        let msg = astrid_events::ipc::IpcMessage::new(
            astrid_events::ipc::Topic::from_raw("astrid.v1.onboarding.required"),
            astrid_events::ipc::IpcPayload::OnboardingRequired {
                capsule_id: manifest.package.name.clone(),
                fields: onboarding_fields,
            },
            uuid::Uuid::nil(),
        );
        let _ = ctx.event_bus.publish(astrid_events::AstridEvent::Ipc {
            metadata: astrid_events::EventMetadata::new(source),
            message: msg,
        });
    }

    Ok(resolved)
}
