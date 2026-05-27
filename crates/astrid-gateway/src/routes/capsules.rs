//! `/api/capsules` — capsule introspection + install.
//!
//! The dashboard's "available capsules" view: list, detail,
//! declared topics, install (forward-compatible).
//!
//! ## Permission surface
//!
//! `POST /api/capsules` exists today, gated by the existing
//! `capsule:install` capability that's already in
//! `astrid_core::capability_grammar::KNOWN_CAPABILITIES` and the
//! kernel's `required_capability` table. Enterprise admins can
//! grant the cap to a group right now (e.g. a
//! `capsule-installers` group with
//! `caps: ["capsule:install"]`); the kernel's cap-gate enforces
//! it before the handler runs.
//!
//! The handler that actually unpacks a `.capsule` archive and
//! writes it to disk is a stub in the kernel today (`kernel_router/
//! mod.rs:186-193` returns "Installation logic not yet
//! implemented"). The route forwards that error verbatim — the
//! cap-gate still works, the route is reachable, and when the
//! kernel handler lands no gateway change is needed.
//!
//! Routes:
//!
//! * `GET  /api/capsules` — list of capsule ids
//! * `POST /api/capsules` — install (cap-gated, kernel handler currently stubbed)
//! * `GET  /api/capsules/{id}` — manifest excerpt (env defs, etc.)
//! * `GET  /api/capsules/{id}/topics` — declared `TopicDef` entries

use std::sync::Arc;

use astrid_core::kernel_api::{CapsuleMetadataEntry, KernelRequest, KernelResponse};
use astrid_uplink::KernelClient;
use axum::Json;
use axum::extract::{Path, State};
use axum::http::Request;
use serde::{Deserialize, Serialize};

use crate::error::{GatewayError, GatewayResult};
use crate::routes::principals::caller_from;
use crate::state::GatewayState;

#[derive(Debug, Clone, Serialize)]
pub struct CapsuleListResponse {
    pub capsules: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CapsuleDetail {
    pub id: String,
    /// Interceptor event patterns declared by the capsule.
    pub interceptor_events: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CapsuleTopic {
    pub name: String,
    pub direction: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CapsuleTopicsResponse {
    pub topics: Vec<CapsuleTopic>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct InstallRequest {
    /// Source path or package locator (e.g. `@unicity-astrid/capsule-telegram`).
    pub source: String,
    /// `true` to install into the workspace-local capsules slot
    /// instead of the system-wide one.
    #[serde(default)]
    pub workspace: bool,
}

pub async fn list_capsules(
    State(_state): State<Arc<GatewayState>>,
    req: Request<axum::body::Body>,
) -> GatewayResult<Json<CapsuleListResponse>> {
    let caller = caller_from(&req)?.clone();
    let mut client = KernelClient::connect(caller.principal)
        .await
        .map_err(daemon_internal)?;
    let resp = client
        .request(KernelRequest::ListCapsules)
        .await
        .map_err(daemon_internal)?;
    match resp {
        // `ListCapsules` returns `KernelResponse::Success(JsonArray)`
        // (kernel_router/mod.rs handler) — a list of capsule-id
        // strings serialised straight into a JSON array. Project
        // that into the typed envelope for the dashboard.
        KernelResponse::Success(v) => {
            let capsules: Vec<String> = serde_json::from_value(v)
                .map_err(|e| internal(format!("malformed capsule list: {e}")))?;
            Ok(Json(CapsuleListResponse { capsules }))
        },
        KernelResponse::Error(msg) => Err(GatewayError::Forbidden { reason: msg }),
        other => Err(internal(format!(
            "unexpected response shape for ListCapsules: {other:?}"
        ))),
    }
}

/// `POST /api/capsules` — install a capsule. Cap-gated by
/// `capsule:install` (or `self:capsule:install` for self-scope) at
/// the kernel boundary. The kernel handler is currently stubbed
/// (`Installation logic not yet implemented`) — when it lands, this
/// route works without modification.
pub async fn install_capsule(
    State(_state): State<Arc<GatewayState>>,
    req: Request<axum::body::Body>,
) -> GatewayResult<Json<serde_json::Value>> {
    let caller = caller_from(&req)?.clone();
    let body: InstallRequest = crate::routes::principals::read_json_body(req).await?;
    let mut client = KernelClient::connect(caller.principal)
        .await
        .map_err(daemon_internal)?;
    let resp = client
        .request(KernelRequest::InstallCapsule {
            source: body.source,
            workspace: body.workspace,
        })
        .await
        .map_err(daemon_internal)?;
    match resp {
        KernelResponse::Success(v) => Ok(Json(v)),
        // `ApprovalRequired` is the kernel's way of saying "this
        // capsule wants caps the operator needs to OK out-of-band."
        // Pass it through with structured fields so the dashboard
        // can render the approval prompt rather than treating it
        // as a generic error.
        KernelResponse::ApprovalRequired {
            request_id,
            description,
            capabilities,
        } => Ok(Json(serde_json::json!({
            "status": "approval_required",
            "request_id": request_id,
            "description": description,
            "capabilities": capabilities,
        }))),
        // The kernel returns `Error` either for cap-denied (kernel
        // gate refused) or "Installation logic not yet implemented"
        // (handler stub). Surface both as 403 Forbidden for the
        // cap-denied shape; the stub message will read clearly to
        // operators inspecting the response.
        KernelResponse::Error(msg) => Err(GatewayError::Forbidden { reason: msg }),
        other => Err(internal(format!(
            "unexpected response shape for InstallCapsule: {other:?}"
        ))),
    }
}

pub async fn get_capsule(
    State(_state): State<Arc<GatewayState>>,
    Path(id): Path<String>,
    req: Request<axum::body::Body>,
) -> GatewayResult<Json<CapsuleDetail>> {
    let caller = caller_from(&req)?.clone();
    let mut client = KernelClient::connect(caller.principal)
        .await
        .map_err(daemon_internal)?;
    let resp = client
        .request(KernelRequest::GetCapsuleMetadata)
        .await
        .map_err(daemon_internal)?;
    match resp {
        KernelResponse::CapsuleMetadata(meta) => meta
            .into_iter()
            .find(|m: &CapsuleMetadataEntry| m.name == id)
            .map(|m| {
                Json(CapsuleDetail {
                    id: m.name,
                    interceptor_events: m.interceptor_events,
                })
            })
            .ok_or(GatewayError::NotFound),
        KernelResponse::Error(msg) => Err(GatewayError::Forbidden { reason: msg }),
        other => Err(internal(format!(
            "unexpected response shape for GetCapsuleMetadata: {other:?}"
        ))),
    }
}

/// `GET /api/capsules/{id}/topics` — the capsule's declared
/// `[publish]` / `[subscribe]` topics, as the manifest describes
/// them. Today the kernel's `GetCapsuleMetadata` only surfaces
/// interceptor events; topic enumeration through IPC is a TODO
/// (the manifest itself carries the data — see
/// `astrid_capsule::manifest::TopicDef`). This route returns an
/// empty topic list with a deprecation-friendly shape so the
/// dashboard can render the section without crashing; the field
/// fills in once the kernel exposes it.
pub async fn list_capsule_topics(
    State(_state): State<Arc<GatewayState>>,
    Path(_id): Path<String>,
    req: Request<axum::body::Body>,
) -> GatewayResult<Json<CapsuleTopicsResponse>> {
    caller_from(&req)?;
    Ok(Json(CapsuleTopicsResponse { topics: vec![] }))
}

// ── helpers (kernel client error mapping) ────────────────────────

#[allow(
    clippy::needless_pass_by_value,
    reason = "consumed by Display formatting"
)]
fn daemon_internal(e: anyhow::Error) -> GatewayError {
    GatewayError::Internal(anyhow::anyhow!("daemon kernel-request: {e}"))
}

fn internal(msg: String) -> GatewayError {
    GatewayError::Internal(anyhow::anyhow!(msg))
}
