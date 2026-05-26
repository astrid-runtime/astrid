//! `/api/capsules/{id}/env` — per-principal capsule env management.
//!
//! Two routes:
//!
//! * `GET  /api/capsules/{id}/env` — return the env schema declared
//!   in the capsule's `Capsule.toml` so the dashboard can render
//!   the right input widget per field.
//! * `POST /api/capsules/{id}/env/{field}` — write a value for the
//!   caller's principal. Routes to `FileSecretStore` (when the
//!   field's `env_type = "secret"`) or to the per-principal env
//!   JSON (text / select / array). The caller's verified principal
//!   is the only source of scoping — request bodies can't redirect.
//!
//! ## Trust shape
//!
//! These routes are authenticated (the gateway's bearer middleware
//! gates the parent path). The verified principal determines the
//! storage scope:
//!
//! * Secrets land at
//!   `$ASTRID_HOME/secrets/<principal>/<capsule>/<field>` (0600).
//! * Non-secrets land in
//!   `$ASTRID_HOME/home/<principal>/.config/env/<capsule>.env.json`.
//!
//! No principal can write into another's slot — the path is built
//! from `caller.principal`, never the request body. Field names are
//! validated against the manifest (anything not declared is rejected
//! with 404) so a malicious caller can't drop arbitrary files into
//! the secrets tree.
//!
//! ## Audit
//!
//! Each successful write is logged at `info` with the caller, the
//! capsule, the field name, and the SHA-256 fingerprint of the
//! value (never the value itself). The kernel-side audit log
//! covers admin-API mutations; env writes are gateway-side only
//! today. A proper IPC audit topic for env writes is a follow-up
//! (would need a new `AdminRequestKind` or a dedicated topic for
//! the gateway to publish to so the kernel can persist the trail).

use std::collections::HashMap;
use std::sync::Arc;

use astrid_core::dirs::AstridHome;
use astrid_storage::{FileSecretStore, SecretStore};
use axum::Json;
use axum::extract::{Path, State};
use axum::http::{Request, StatusCode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{GatewayError, GatewayResult};
use crate::routes::principals::caller_from;
use crate::state::GatewayState;

/// Subset of `Capsule.toml [env.<field>]` surfaced to the dashboard.
/// Drops the operator-only `scope` field (kernel enforces that via
/// `skip_deserializing`); everything else is verbatim.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvFieldSchema {
    /// `"text"`, `"secret"`, `"select"`, or `"array"`.
    #[serde(rename = "type")]
    pub env_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub enum_values: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placeholder: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EnvSchemaResponse {
    pub capsule_id: String,
    pub fields: HashMap<String, EnvFieldSchema>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EnvWriteRequest {
    /// The value to set. For `array`-typed fields this is one
    /// element appended to the existing array; the existing list
    /// (if any) is preserved.
    pub value: String,
}

/// `GET /api/capsules/{id}/env` — env schema from `Capsule.toml`.
pub async fn get_env_schema(
    State(_state): State<Arc<GatewayState>>,
    Path(capsule_id): Path<String>,
    req: Request<axum::body::Body>,
) -> GatewayResult<Json<EnvSchemaResponse>> {
    let _caller = caller_from(&req)?;
    let schema = load_env_schema(&capsule_id)?;
    Ok(Json(EnvSchemaResponse {
        capsule_id,
        fields: schema,
    }))
}

/// `POST /api/capsules/{id}/env/{field}` — write the value for the
/// authenticated principal.
pub async fn write_env(
    State(_state): State<Arc<GatewayState>>,
    Path((capsule_id, field)): Path<(String, String)>,
    req: Request<axum::body::Body>,
) -> GatewayResult<StatusCode> {
    let caller = caller_from(&req)?.clone();
    if !is_safe_field_name(&field) {
        return Err(GatewayError::BadRequest(format!(
            "invalid env field name {field:?}"
        )));
    }
    let body: EnvWriteRequest = crate::routes::principals::read_json_body(req).await?;
    let schema = load_env_schema(&capsule_id)?;
    let def = schema.get(&field).ok_or(GatewayError::NotFound)?;

    let home = AstridHome::resolve()
        .map_err(|e| GatewayError::Internal(anyhow::anyhow!("resolve ASTRID_HOME: {e}")))?;

    let value_fp = fingerprint(&body.value);

    match def.env_type.as_str() {
        "secret" => {
            let root = home
                .secrets_dir()
                .join(caller.principal.as_str())
                .join(&capsule_id);
            let store = FileSecretStore::new(root);
            store
                .set(&field, &body.value)
                .map_err(|e| GatewayError::Internal(anyhow::anyhow!("secret write: {e}")))?;
        },
        "text" | "select" => {
            write_env_string(&home, &caller.principal, &capsule_id, &field, &body.value)?;
        },
        "array" => {
            append_env_array(&home, &caller.principal, &capsule_id, &field, &body.value)?;
        },
        other => {
            return Err(GatewayError::BadRequest(format!(
                "unsupported env type {other:?} for field {field:?}"
            )));
        },
    }

    tracing::info!(
        principal = %caller.principal,
        capsule = %capsule_id,
        field = %field,
        env_type = %def.env_type,
        value_fingerprint = %value_fp,
        "gateway env-write"
    );

    Ok(StatusCode::NO_CONTENT)
}

// ── helpers ──────────────────────────────────────────────────────

/// Parse `[env]` from `$ASTRID_HOME/capsules/<id>/Capsule.toml`.
///
/// The gateway intentionally does NOT take a dep on
/// `astrid-capsule` (which would drag in wasmtime); a minimal TOML
/// read of just the `[env]` subtable is enough.
fn load_env_schema(capsule_id: &str) -> GatewayResult<HashMap<String, EnvFieldSchema>> {
    if !is_safe_field_name(capsule_id) {
        return Err(GatewayError::BadRequest(format!(
            "invalid capsule id {capsule_id:?}"
        )));
    }
    let home = AstridHome::resolve()
        .map_err(|e| GatewayError::Internal(anyhow::anyhow!("resolve ASTRID_HOME: {e}")))?;
    let manifest_path = home
        .root()
        .join("capsules")
        .join(capsule_id)
        .join("Capsule.toml");
    let text = match std::fs::read_to_string(&manifest_path) {
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
        let env_type = tbl
            .get("env_type")
            .and_then(toml::Value::as_str)
            .unwrap_or("text")
            .to_string();
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

fn fingerprint(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    hex::encode(hasher.finalize())
}

/// Write or replace a single string field in
/// `$ASTRID_HOME/home/<principal>/.config/env/<capsule>.env.json`.
/// Atomic write-then-rename; existing fields are preserved.
fn write_env_string(
    home: &AstridHome,
    principal: &astrid_core::PrincipalId,
    capsule_id: &str,
    field: &str,
    value: &str,
) -> GatewayResult<()> {
    let env_dir = home.principal_home(principal).env_dir();
    std::fs::create_dir_all(&env_dir).map_err(|e| {
        GatewayError::Internal(anyhow::anyhow!("create env dir {}: {e}", env_dir.display()))
    })?;
    let path = env_dir.join(format!("{capsule_id}.env.json"));

    let mut map: HashMap<String, serde_json::Value> = if path.exists() {
        let text = std::fs::read_to_string(&path)
            .map_err(|e| GatewayError::Internal(anyhow::anyhow!("read env JSON: {e}")))?;
        serde_json::from_str(&text)
            .map_err(|e| GatewayError::Internal(anyhow::anyhow!("parse env JSON: {e}")))?
    } else {
        HashMap::new()
    };
    map.insert(field.to_string(), serde_json::Value::String(value.into()));

    write_json_atomic(&path, &map)
}

/// Append `value` to the array field, preserving prior entries.
fn append_env_array(
    home: &AstridHome,
    principal: &astrid_core::PrincipalId,
    capsule_id: &str,
    field: &str,
    value: &str,
) -> GatewayResult<()> {
    let env_dir = home.principal_home(principal).env_dir();
    std::fs::create_dir_all(&env_dir).map_err(|e| {
        GatewayError::Internal(anyhow::anyhow!("create env dir {}: {e}", env_dir.display()))
    })?;
    let path = env_dir.join(format!("{capsule_id}.env.json"));

    let mut map: HashMap<String, serde_json::Value> = if path.exists() {
        let text = std::fs::read_to_string(&path)
            .map_err(|e| GatewayError::Internal(anyhow::anyhow!("read env JSON: {e}")))?;
        serde_json::from_str(&text)
            .map_err(|e| GatewayError::Internal(anyhow::anyhow!("parse env JSON: {e}")))?
    } else {
        HashMap::new()
    };
    let entry = map
        .entry(field.to_string())
        .or_insert_with(|| serde_json::Value::Array(Vec::new()));
    if let serde_json::Value::Array(arr) = entry {
        arr.push(serde_json::Value::String(value.into()));
    } else {
        // Field exists but isn't an array — replace with a fresh
        // singleton. Surface the divergence in logs rather than
        // silently growing JSON state of unexpected shape.
        tracing::warn!(
            field = %field,
            capsule = %capsule_id,
            "env field declared as array but on-disk shape was scalar; resetting"
        );
        *entry = serde_json::Value::Array(vec![serde_json::Value::String(value.into())]);
    }

    write_json_atomic(&path, &map)
}

fn write_json_atomic(
    path: &std::path::Path,
    map: &HashMap<String, serde_json::Value>,
) -> GatewayResult<()> {
    let body = serde_json::to_vec_pretty(map)
        .map_err(|e| GatewayError::Internal(anyhow::anyhow!("serialise env JSON: {e}")))?;
    let tmp = path.with_extension(format!("{}.tmp", std::process::id()));
    std::fs::write(&tmp, &body)
        .map_err(|e| GatewayError::Internal(anyhow::anyhow!("write env JSON: {e}")))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
    }
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        GatewayError::Internal(anyhow::anyhow!("rename env JSON: {e}"))
    })
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
    fn fingerprint_is_deterministic_sha256() {
        let a = fingerprint("hello");
        let b = fingerprint("hello");
        let c = fingerprint("world");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 64);
    }
}
