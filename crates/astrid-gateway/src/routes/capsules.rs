//! `/api/capsules` — read-only capsule introspection.
//!
//! The dashboard's "available capsules" view: list, detail,
//! declared topics. **Install / uninstall are NOT exposed** here —
//! `KernelRequest::InstallCapsule` is a stub in the kernel today
//! (returns "Installation logic not yet implemented", see
//! `kernel_router/mod.rs`) and the actual CLI install path does
//! file-system ops directly. Wiring a real HTTP install needs the
//! kernel-side handler to land first; the gateway is purely a
//! translator. Tracked as a follow-up under #756.
//!
//! Routes shipping here:
//!
//! * `GET /api/capsules` — list of capsule ids
//! * `GET /api/capsules/{id}` — manifest excerpt (env defs, etc.)
//! * `GET /api/capsules/{id}/topics` — declared `TopicDef` entries

use std::sync::Arc;

use astrid_core::kernel_api::{CapsuleMetadataEntry, KernelRequest, KernelResponse};
use astrid_uplink::KernelClient;
use axum::Json;
use axum::extract::{Path, State};
use axum::http::Request;
use serde::Serialize;

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
