//! `/api/capsules/{id}/env` — per-principal capsule env management.
//!
//! Two routes:
//!
//! * `GET  /api/capsules/{id}/env` — return the env schema declared
//!   in the capsule's `Capsule.toml` so the dashboard can render
//!   the right input widget per field.
//! * `POST /api/capsules/{id}/env/{field}` — write a value for the
//!   caller's principal. Secret values use the KV-backed `SecretStore`
//!   primitive and non-secret values use typed `__env:` keys in the same
//!   owner-scoped KV namespace. The caller's verified principal is the only
//!   source of scoping — request bodies can't redirect.
//!
//! ## Trust shape
//!
//! These routes are authenticated (the gateway's bearer middleware
//! gates the parent path). The verified principal determines the
//! storage scope:
//!
//! * Secrets land in a host-only principal control scope under the
//!   `SecretStore`'s `__secret:` namespace.
//! * Non-secrets land in a separate host-only principal control scope under
//!   typed `__env:` keys; the guest capsule namespace is never used.
//!
//! No principal can write into another's slot — the path is built
//! from `caller.principal`, never the request body. Field names are
//! validated against the manifest (anything not declared is rejected
//! with 404) so a malicious caller can't drop arbitrary files into
//! the secrets tree.
//!
//! ## Audit
//!
//! Each successful write is logged at `info` with the caller, capsule, field
//! name, and declared env type. Values and reversible fingerprints of
//! low-entropy values are never logged. The kernel-side audit log
//! covers admin-API mutations; env writes are gateway-side only
//! today. A proper IPC audit topic for env writes is a follow-up
//! (would need a new `AdminRequestKind` or a dedicated topic for
//! the gateway to publish to so the kernel can persist the trail).

use std::collections::HashMap;
#[cfg(test)]
use std::path::Path as FsPath;
use std::sync::Arc;

#[cfg(test)]
use astrid_core::PrincipalId;
#[cfg(test)]
use astrid_core::dirs::{AstridHome, WorkspaceLayout};
use astrid_core::kernel_api::{
    AdminRequestKind, AdminResponseBody, CapsuleMetadataEntry, EnvStorageScope, EnvValueKind,
    KernelRequest, KernelResponse,
};
use axum::Extension;
use axum::Json;
use axum::extract::{Path, State};
use axum::http::{Request, StatusCode};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::error::{ErrorBody, GatewayError, GatewayResult};
use crate::routes::principals::{caller_from, daemon_internal, unexpected};
use crate::routes::{WorkspaceContext, daemon_kernel_error};
use crate::state::GatewayState;

/// Subset of `Capsule.toml [env.<field>]` surfaced to the dashboard.
/// Drops the operator-only `scope` field (kernel enforces that via
/// `skip_deserializing`); everything else is verbatim.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct EnvFieldSchema {
    /// `"text"`, `"secret"`, `"select"`, or `"array"`.
    #[serde(rename = "type")]
    pub env_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<serde_json::Value>)]
    pub default: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub enum_values: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placeholder: Option<String>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct EnvSchemaResponse {
    pub capsule_id: String,
    pub fields: HashMap<String, EnvFieldSchema>,
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct EnvWriteRequest {
    /// The value to set. For `array`-typed fields this is one
    /// element appended to the existing array; the existing list
    /// (if any) is preserved.
    pub value: String,
}

/// `GET /api/capsules/{id}/env` — env schema from `Capsule.toml`.
#[utoipa::path(
    get,
    path = "/api/capsules/{id}/env",
    tag = "env",
    params(("id" = String, Path, description = "Capsule id")),
    responses(
        (status = 200, body = EnvSchemaResponse, description = "Env schema declared in `Capsule.toml`."),
        (status = 401, body = ErrorBody),
        (status = 404, body = ErrorBody, description = "Unknown capsule id."),
    )
)]
pub async fn get_env_schema(
    State(state): State<Arc<GatewayState>>,
    Path(capsule_id): Path<String>,
    req: Request<axum::body::Body>,
) -> GatewayResult<Json<EnvSchemaResponse>> {
    get_env_schema_inner(state, &WorkspaceContext::default(), capsule_id, req).await
}

pub(crate) async fn get_env_schema_with_workspace(
    State(state): State<Arc<GatewayState>>,
    Extension(workspace): Extension<WorkspaceContext>,
    Path(capsule_id): Path<String>,
    req: Request<axum::body::Body>,
) -> GatewayResult<Json<EnvSchemaResponse>> {
    get_env_schema_inner(state, &workspace, capsule_id, req).await
}

async fn get_env_schema_inner(
    state: Arc<GatewayState>,
    _workspace: &WorkspaceContext,
    capsule_id: String,
    req: Request<axum::body::Body>,
) -> GatewayResult<Json<EnvSchemaResponse>> {
    let caller = caller_from(&req)?.clone();
    let metadata = capsule_metadata_for(&state, &caller).await?;
    let entry = metadata_entry(&metadata, &capsule_id, caller.principal.as_str())?;
    let schema = env_schema_from_metadata(&entry);
    Ok(Json(EnvSchemaResponse {
        capsule_id,
        fields: schema,
    }))
}

/// `POST /api/capsules/{id}/env/{field}` — write the value for the
/// authenticated principal.
#[utoipa::path(
    post,
    path = "/api/capsules/{id}/env/{field}",
    tag = "env",
    params(
        ("id" = String, Path, description = "Capsule id"),
        ("field" = String, Path, description = "Env field name from the capsule's schema"),
    ),
    request_body = EnvWriteRequest,
    responses(
        (status = 204, description = "Value persisted to the caller's scope."),
        (status = 400, body = ErrorBody, description = "Malformed value or empty body."),
        (status = 401, body = ErrorBody),
        (status = 404, body = ErrorBody, description = "Unknown capsule id, or field not declared in the schema."),
    )
)]
pub async fn write_env(
    State(state): State<Arc<GatewayState>>,
    Path((capsule_id, field)): Path<(String, String)>,
    req: Request<axum::body::Body>,
) -> GatewayResult<StatusCode> {
    write_env_inner(state, &WorkspaceContext::default(), capsule_id, field, req).await
}

pub(crate) async fn write_env_with_workspace(
    State(state): State<Arc<GatewayState>>,
    Extension(workspace): Extension<WorkspaceContext>,
    Path((capsule_id, field)): Path<(String, String)>,
    req: Request<axum::body::Body>,
) -> GatewayResult<StatusCode> {
    write_env_inner(state, &workspace, capsule_id, field, req).await
}

async fn write_env_inner(
    state: Arc<GatewayState>,
    _workspace: &WorkspaceContext,
    capsule_id: String,
    field: String,
    req: Request<axum::body::Body>,
) -> GatewayResult<StatusCode> {
    let caller = caller_from(&req)?.clone();
    let metadata = capsule_metadata_for(&state, &caller).await?;
    let entry = metadata_entry(&metadata, &capsule_id, caller.principal.as_str())?;
    if !is_safe_field_name(&field) {
        return Err(GatewayError::BadRequest(format!(
            "invalid env field name {field:?}"
        )));
    }
    let body: EnvWriteRequest = crate::routes::principals::read_json_body(req).await?;
    let schema = env_schema_from_metadata(&entry);
    let def = schema.get(&field).ok_or(GatewayError::NotFound)?;
    let (kind, append) = match def.env_type.as_str() {
        "secret" => (EnvValueKind::Secret, false),
        "text" | "select" => (EnvValueKind::Text, false),
        "array" => (EnvValueKind::Text, true),
        other => {
            return Err(GatewayError::BadRequest(format!(
                "unsupported env type {other:?} for field {field:?}"
            )));
        },
    };
    let client = state.admin_client_for(&caller)?;
    let response = client
        .request(AdminRequestKind::EnvSet {
            principal: caller.principal.clone(),
            capsule: capsule_id.clone(),
            key: field.clone(),
            value: body.value,
            kind,
            scope: EnvStorageScope::Agent,
            append,
        })
        .await
        .map_err(daemon_internal)?;
    match response {
        AdminResponseBody::Success(_) => {},
        AdminResponseBody::Error(message) => return Err(GatewayError::BadRequest(message)),
        other => return Err(unexpected(other)),
    }

    tracing::info!(
        principal = %caller.principal,
        capsule = %capsule_id,
        field = %field,
        env_type = %def.env_type,
        "gateway env-write"
    );

    Ok(StatusCode::NO_CONTENT)
}

// ── helpers ──────────────────────────────────────────────────────

async fn capsule_metadata_for(
    state: &GatewayState,
    caller: &crate::auth::CallerContext,
) -> GatewayResult<Vec<CapsuleMetadataEntry>> {
    let client = state.kernel_client_for(caller)?;
    let resp = client
        .request(KernelRequest::GetCapsuleMetadata)
        .await
        .map_err(daemon_kernel_error)?;
    match resp {
        KernelResponse::CapsuleMetadata(entries) => Ok(entries),
        KernelResponse::Error(msg) => {
            tracing::warn!(
                security_event = true,
                principal = %caller.principal,
                reason = %msg,
                "capsule env visibility probe denied; returning hidden not-found"
            );
            Err(GatewayError::NotFound)
        },
        other => Err(GatewayError::Internal(anyhow::anyhow!(
            "unexpected response shape for GetCapsuleMetadata: {other:?}"
        ))),
    }
}

fn metadata_entry(
    entries: &[CapsuleMetadataEntry],
    capsule_id: &str,
    caller: &str,
) -> GatewayResult<CapsuleMetadataEntry> {
    entries
        .iter()
        .find(|entry| entry.name == capsule_id)
        .cloned()
        .ok_or_else(|| {
            tracing::debug!(
                security_event = true,
                principal = %caller,
                capsule = %capsule_id,
                "capsule env visibility probe returned no matching entry"
            );
            GatewayError::NotFound
        })
}

#[cfg(test)]
fn ensure_capsule_visible_from_response(
    resp: KernelResponse,
    caller: &str,
    capsule_id: &str,
) -> GatewayResult<()> {
    match resp {
        KernelResponse::CapsuleMetadata(entries) => entries
            .iter()
            .any(|entry| entry.name == capsule_id)
            .then_some(())
            .ok_or(GatewayError::NotFound),
        KernelResponse::Error(msg) => {
            tracing::warn!(
                security_event = true,
                principal = %caller,
                capsule = %capsule_id,
                reason = %msg,
                "capsule env visibility probe denied; returning hidden not-found"
            );
            Err(GatewayError::NotFound)
        },
        other => Err(GatewayError::Internal(anyhow::anyhow!(
            "unexpected response shape for GetCapsuleMetadata: {other:?}"
        ))),
    }
}

fn env_schema_from_metadata(entry: &CapsuleMetadataEntry) -> HashMap<String, EnvFieldSchema> {
    entry
        .env
        .iter()
        .map(|(name, def)| {
            (
                name.clone(),
                EnvFieldSchema {
                    env_type: def.env_type.clone(),
                    description: def.description.clone(),
                    request: def.request.clone(),
                    default: def.default.clone(),
                    enum_values: def.enum_values.clone(),
                    placeholder: def.placeholder.clone(),
                },
            )
        })
        .collect()
}

#[cfg(test)]
fn load_env_schema_from_home(
    home: &AstridHome,
    principal: &PrincipalId,
    capsule_id: &str,
) -> GatewayResult<HashMap<String, EnvFieldSchema>> {
    load_env_schema_from_home_in_workspace(
        home,
        principal,
        capsule_id,
        None,
        &WorkspaceLayout::default(),
    )
}

#[cfg(test)]
fn load_env_schema_from_home_in_workspace(
    home: &AstridHome,
    principal: &PrincipalId,
    capsule_id: &str,
    workspace_root: Option<&FsPath>,
    workspace_layout: &WorkspaceLayout,
) -> GatewayResult<HashMap<String, EnvFieldSchema>> {
    // Principal installs override workspace capsules, matching runtime
    // discovery. The manifest is read only after `ensure_capsule_visible` has
    // confirmed that the same principal is allowed to see the capsule.
    let principal_manifest = home
        .principal_home(principal)
        .capsules_dir()
        .join(capsule_id)
        .join("Capsule.toml");
    if principal_manifest.exists() {
        return parse_env_schema(&principal_manifest);
    }

    let Some(workspace_root) = workspace_root else {
        return Err(GatewayError::NotFound);
    };
    let workspace = workspace_layout
        .resolve(workspace_root)
        .map_err(|e| GatewayError::Internal(anyhow::anyhow!("resolve selected workspace: {e}")))?;
    let manifest_relative = FsPath::new("capsules")
        .join(capsule_id)
        .join("Capsule.toml");
    let workspace_manifest = workspace.resolve_file(&manifest_relative).map_err(|e| {
        GatewayError::Internal(anyhow::anyhow!("resolve workspace capsule manifest: {e}"))
    })?;
    if !workspace_manifest.exists() {
        return Err(GatewayError::NotFound);
    }
    let schema = parse_env_schema(&workspace_manifest)?;
    workspace.resolve_file(&manifest_relative).map_err(|e| {
        GatewayError::Internal(anyhow::anyhow!(
            "workspace capsule manifest changed while it was being read: {e}"
        ))
    })?;
    Ok(schema)
}

#[cfg(test)]
fn parse_env_schema(manifest_path: &FsPath) -> GatewayResult<HashMap<String, EnvFieldSchema>> {
    let text = match std::fs::read_to_string(manifest_path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(GatewayError::NotFound);
        },
        Err(e) => {
            return Err(GatewayError::Internal(anyhow::anyhow!(
                "read {}: {e}",
                manifest_path.display()
            )));
        },
    };
    let parsed: toml::Value = toml::from_str(&text)
        .map_err(|e| GatewayError::Internal(anyhow::anyhow!("parse Capsule.toml: {e}")))?;
    let env_tbl = parsed
        .get("env")
        .and_then(toml::Value::as_table)
        .cloned()
        .unwrap_or_default();

    let mut fields = HashMap::with_capacity(env_tbl.len());
    for (name, val) in env_tbl {
        // Re-serialise the per-field subtable through our schema
        // shape; non-conforming entries are skipped (capsule authors
        // can declare extra keys, and we don't want to fail the
        // whole load on one weird field).
        let Some(tbl) = val.as_table() else { continue };
        let env_type = env_type_from_manifest_table(tbl);
        fields.insert(
            name,
            EnvFieldSchema {
                env_type,
                description: tbl
                    .get("description")
                    .and_then(toml::Value::as_str)
                    .map(str::to_string),
                request: tbl
                    .get("request")
                    .and_then(toml::Value::as_str)
                    .map(str::to_string),
                default: tbl
                    .get("default")
                    .map(|v| serde_json::to_value(v).unwrap_or(serde_json::Value::Null)),
                enum_values: tbl
                    .get("enum_values")
                    .and_then(toml::Value::as_array)
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default(),
                placeholder: tbl
                    .get("placeholder")
                    .and_then(toml::Value::as_str)
                    .map(str::to_string),
            },
        );
    }
    Ok(fields)
}

#[cfg(test)]
fn env_type_from_manifest_table(tbl: &toml::map::Map<String, toml::Value>) -> String {
    let raw = tbl
        .get("env_type")
        .or_else(|| tbl.get("type"))
        .and_then(toml::Value::as_str)
        .unwrap_or("text")
        .to_ascii_lowercase();

    match raw.as_str() {
        "secret" | "select" | "array" => raw,
        "text" | "string" | "integer" | "number" | "boolean" => "text".to_string(),
        other => other.to_string(),
    }
}

/// Validate a capsule id or env field name. Same shape as principal
/// ids — lowercase alphanumeric + dash + underscore. Belt-and-suspenders
/// against path-traversal: we already build the path from
/// `AstridHome::root()` + `capsules` + `id`, but rejecting `..` /
/// `/` here keeps the failure mode obvious.
fn is_safe_field_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
        && !name.contains("..")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_field_name_accepts_normal() {
        assert!(is_safe_field_name("api_key"));
        assert!(is_safe_field_name("alice"));
        assert!(is_safe_field_name("astrid-capsule-telegram"));
        assert!(is_safe_field_name("v1.0"));
    }

    #[test]
    fn safe_field_name_rejects_traversal_and_garbage() {
        assert!(!is_safe_field_name(""));
        assert!(!is_safe_field_name(".."));
        assert!(!is_safe_field_name("../etc/passwd"));
        assert!(!is_safe_field_name("a/b"));
        assert!(!is_safe_field_name("a..b"));
        assert!(!is_safe_field_name(&"a".repeat(129)));
    }

    #[test]
    fn env_type_reads_manifest_type_and_preserves_secret() {
        let parsed: toml::Value = toml::from_str(
            r#"
            [env]
            api_key = { type = "secret" }
            model = { type = "select" }
            context_window = { type = "integer" }
            legacy = { env_type = "array" }
            "#,
        )
        .unwrap();
        let env = parsed.get("env").and_then(toml::Value::as_table).unwrap();

        let field_type = |name: &str| {
            env.get(name)
                .and_then(toml::Value::as_table)
                .map(env_type_from_manifest_table)
                .unwrap()
        };

        assert_eq!(field_type("api_key"), "secret");
        assert_eq!(field_type("model"), "select");
        assert_eq!(field_type("context_window"), "text");
        assert_eq!(field_type("legacy"), "array");
    }

    #[test]
    fn denied_capsule_visibility_probe_is_hidden_as_not_found() {
        let err = ensure_capsule_visible_from_response(
            KernelResponse::Error("missing self:capsule:list".to_string()),
            "regular-user",
            "astrid-capsule-cli",
        )
        .expect_err("denied visibility probe should be hidden");

        assert!(matches!(err, GatewayError::NotFound));
    }

    #[test]
    fn env_schema_loads_from_the_requested_principal_capsule_manifest() {
        let home_dir = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(home_dir.path());
        let default = PrincipalId::default();
        let alice = PrincipalId::new("alice").unwrap();
        for (principal, description) in [(&default, "default API key"), (&alice, "Alice API key")] {
            let manifest_dir = home
                .principal_home(principal)
                .capsules_dir()
                .join("astrid-capsule-test");
            std::fs::create_dir_all(&manifest_dir).unwrap();
            std::fs::write(
                manifest_dir.join("Capsule.toml"),
                format!(
                    r#"
                    [package]
                    name = "astrid-capsule-test"
                    version = "1.0.0"

                    [env]
                    api_key = {{ type = "secret", description = "{description}" }}
                    region = {{ type = "select", enum_values = ["us", "eu"] }}
                    "#
                ),
            )
            .unwrap();
        }

        let schema = load_env_schema_from_home(&home, &alice, "astrid-capsule-test").unwrap();

        assert_eq!(schema["api_key"].env_type, "secret");
        assert_eq!(
            schema["api_key"].description.as_deref(),
            Some("Alice API key")
        );
        assert_eq!(schema["region"].env_type, "select");
        assert_eq!(schema["region"].enum_values, ["us", "eu"]);
    }

    #[test]
    fn env_schema_falls_back_to_the_verified_workspace_manifest() {
        let home_dir = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(home_dir.path());
        let workspace = tempfile::tempdir().unwrap();
        let manifest_dir = workspace
            .path()
            .join(".alternate-runtime/capsules/astrid-capsule-test");
        std::fs::create_dir_all(&manifest_dir).unwrap();
        std::fs::write(
            manifest_dir.join("Capsule.toml"),
            r#"
            [package]
            name = "astrid-capsule-test"
            version = "1.0.0"

            [env]
            api_key = { type = "secret", description = "Workspace API key" }
            "#,
        )
        .unwrap();

        let schema = load_env_schema_from_home_in_workspace(
            &home,
            &PrincipalId::new("alice").unwrap(),
            "astrid-capsule-test",
            Some(workspace.path()),
            &WorkspaceLayout::new(".alternate-runtime").unwrap(),
        )
        .unwrap();

        assert_eq!(schema["api_key"].env_type, "secret");
        assert_eq!(
            schema["api_key"].description.as_deref(),
            Some("Workspace API key")
        );
    }

    #[test]
    fn principal_env_schema_takes_precedence_over_workspace_manifest() {
        let home_dir = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(home_dir.path());
        let workspace = tempfile::tempdir().unwrap();
        let principal = PrincipalId::new("alice").unwrap();
        let principal_manifest = home
            .principal_home(&principal)
            .capsules_dir()
            .join("astrid-capsule-test");
        let workspace_manifest = workspace
            .path()
            .join(".astrid/capsules/astrid-capsule-test");
        for (manifest_dir, description) in [
            (&principal_manifest, "Principal API key"),
            (&workspace_manifest, "Workspace API key"),
        ] {
            std::fs::create_dir_all(manifest_dir).unwrap();
            std::fs::write(
                manifest_dir.join("Capsule.toml"),
                format!(
                    r#"
                    [package]
                    name = "astrid-capsule-test"
                    version = "1.0.0"

                    [env]
                    api_key = {{ type = "secret", description = "{description}" }}
                    "#
                ),
            )
            .unwrap();
        }

        let schema = load_env_schema_from_home_in_workspace(
            &home,
            &principal,
            "astrid-capsule-test",
            Some(workspace.path()),
            &WorkspaceLayout::default(),
        )
        .unwrap();

        assert_eq!(
            schema["api_key"].description.as_deref(),
            Some("Principal API key")
        );
    }

    #[cfg(unix)]
    #[test]
    fn env_schema_rejects_redirected_workspace_capsules() {
        use std::os::unix::fs::symlink;

        let home_dir = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(home_dir.path());
        let workspace = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::create_dir(workspace.path().join(".astrid")).unwrap();
        symlink(outside.path(), workspace.path().join(".astrid/capsules")).unwrap();

        let result = load_env_schema_from_home_in_workspace(
            &home,
            &PrincipalId::new("alice").unwrap(),
            "astrid-capsule-test",
            Some(workspace.path()),
            &WorkspaceLayout::default(),
        );

        assert!(matches!(result, Err(GatewayError::Internal(_))));
    }

    #[cfg(unix)]
    #[test]
    fn env_schema_verifies_only_the_requested_workspace_manifest() {
        use std::os::unix::fs::symlink;

        let home_dir = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(home_dir.path());
        let workspace = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let capsules = workspace.path().join(".astrid/capsules");
        let requested = capsules.join("astrid-capsule-test");
        std::fs::create_dir_all(&requested).unwrap();
        std::fs::write(
            requested.join("Capsule.toml"),
            r#"
            [package]
            name = "astrid-capsule-test"
            version = "1.0.0"

            [env]
            api_key = { type = "secret" }
            "#,
        )
        .unwrap();
        symlink(outside.path(), capsules.join("unrelated-capsule")).unwrap();

        let schema = load_env_schema_from_home_in_workspace(
            &home,
            &PrincipalId::new("alice").unwrap(),
            "astrid-capsule-test",
            Some(workspace.path()),
            &WorkspaceLayout::default(),
        )
        .expect("an unrelated capsule must not make the requested manifest unsafe");

        assert_eq!(schema["api_key"].env_type, "secret");
    }
}
