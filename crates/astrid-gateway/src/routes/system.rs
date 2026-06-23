//! `/api/sys/{status,capsules/reload}` — kernel system ops.
//!
//! Status reflects [`DaemonStatus`] (PID, uptime, connection
//! counts, loaded capsules). Reload triggers a capsule
//! re-discovery — operator-only via `capsule:reload`. Both go
//! through `KernelRequest`, not `AdminRequestKind`.

use std::sync::Arc;

use astrid_core::kernel_api::{AgentLoopReadiness, DaemonStatus, KernelRequest, KernelResponse};
use astrid_uplink::KernelClient;
use axum::Json;
use axum::extract::State;
use axum::http::{Request, StatusCode};

use crate::error::{ErrorBody, GatewayError, GatewayResult};
use crate::routes::principals::caller_from;
use crate::state::GatewayState;

#[utoipa::path(
    get,
    path = "/api/sys/status",
    tag = "system",
    responses(
        (status = 200, description = "`DaemonStatus` JSON shape: `{ pid, started_at, uptime_secs, active_connections, ephemeral, capsules: { loaded, failed }, session_id }`.", content_type = "application/json"),
        (status = 401, body = ErrorBody),
        (status = 403, body = ErrorBody, description = "Caller lacks `system:status`."),
    )
)]
pub async fn get_status(
    State(_state): State<Arc<GatewayState>>,
    req: Request<axum::body::Body>,
) -> GatewayResult<Json<DaemonStatus>> {
    let caller = caller_from(&req)?.clone();
    let mut client = KernelClient::connect(caller.principal.clone())
        .await
        .map_err(daemon_internal)?
        .with_device_key_id(caller.device_key_id.clone());
    let resp = client
        .request(KernelRequest::GetStatus)
        .await
        .map_err(daemon_internal)?;
    match resp {
        KernelResponse::Status(s) => Ok(Json(s)),
        KernelResponse::Error(msg) => Err(GatewayError::Forbidden { reason: msg }),
        other => Err(GatewayError::Internal(anyhow::anyhow!(
            "unexpected response for GetStatus: {other:?}"
        ))),
    }
}

#[utoipa::path(
    get,
    path = "/api/sys/readiness",
    tag = "system",
    responses(
        (status = 200, description = "`AgentLoopReadiness` JSON shape: `{ ready: bool, prompt_subscribers: [string], response_publishers: [string], unsatisfied_required_imports: [{ capsule, namespace, interface, requirement }], loaded_capsules: [string] }`. `ready` is false when the installed capsule set can't serve an agent chat turn.", content_type = "application/json"),
        (status = 401, body = ErrorBody),
        (status = 403, body = ErrorBody, description = "Caller lacks `capsule:list`."),
    )
)]
pub async fn get_readiness(
    State(_state): State<Arc<GatewayState>>,
    req: Request<axum::body::Body>,
) -> GatewayResult<Json<AgentLoopReadiness>> {
    let caller = caller_from(&req)?.clone();
    let mut client = KernelClient::connect(caller.principal.clone())
        .await
        .map_err(daemon_internal)?
        .with_device_key_id(caller.device_key_id.clone());
    let resp = client
        .request(KernelRequest::GetAgentReadiness)
        .await
        .map_err(daemon_internal)?;
    match resp {
        KernelResponse::AgentReadiness(r) => Ok(Json(r)),
        KernelResponse::Error(msg) => Err(GatewayError::Forbidden { reason: msg }),
        other => Err(GatewayError::Internal(anyhow::anyhow!(
            "unexpected response for GetAgentReadiness: {other:?}"
        ))),
    }
}

#[utoipa::path(
    post,
    path = "/api/sys/capsules/reload",
    tag = "system",
    responses(
        (status = 204, description = "Capsules reloaded."),
        (status = 401, body = ErrorBody),
        (status = 403, body = ErrorBody, description = "Caller lacks `capsule:reload`."),
    )
)]
pub async fn reload_capsules(
    State(_state): State<Arc<GatewayState>>,
    req: Request<axum::body::Body>,
) -> GatewayResult<StatusCode> {
    let caller = caller_from(&req)?.clone();
    let mut client = KernelClient::connect(caller.principal.clone())
        .await
        .map_err(daemon_internal)?
        .with_device_key_id(caller.device_key_id.clone());
    let resp = client
        .request(KernelRequest::ReloadCapsules)
        .await
        .map_err(daemon_internal)?;
    match resp {
        KernelResponse::Success(_) => Ok(StatusCode::NO_CONTENT),
        KernelResponse::Error(msg) => Err(GatewayError::Forbidden { reason: msg }),
        other => Err(GatewayError::Internal(anyhow::anyhow!(
            "unexpected response for ReloadCapsules: {other:?}"
        ))),
    }
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "consumed by Display formatting"
)]
fn daemon_internal(e: anyhow::Error) -> GatewayError {
    GatewayError::Internal(anyhow::anyhow!("daemon kernel-request: {e}"))
}
