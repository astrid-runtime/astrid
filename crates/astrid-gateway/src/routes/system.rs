//! `/api/sys/{status,capsules/reload}` — kernel system ops.
//!
//! Status reflects [`DaemonStatus`] (PID, uptime, connection
//! counts, loaded capsules). Reload triggers a capsule
//! re-discovery — operator-only via `capsule:reload`. Both go
//! through `KernelRequest`, not `AdminRequestKind`.

use std::sync::Arc;

use astrid_core::kernel_api::{DaemonStatus, KernelRequest, KernelResponse};
use astrid_uplink::KernelClient;
use axum::Json;
use axum::extract::State;
use axum::http::{Request, StatusCode};

use crate::error::{GatewayError, GatewayResult};
use crate::routes::principals::caller_from;
use crate::state::GatewayState;

pub async fn get_status(
    State(_state): State<Arc<GatewayState>>,
    req: Request<axum::body::Body>,
) -> GatewayResult<Json<DaemonStatus>> {
    let caller = caller_from(&req)?.clone();
    let mut client = KernelClient::connect(caller.principal)
        .await
        .map_err(daemon_internal)?;
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

pub async fn reload_capsules(
    State(_state): State<Arc<GatewayState>>,
    req: Request<axum::body::Body>,
) -> GatewayResult<StatusCode> {
    let caller = caller_from(&req)?.clone();
    let mut client = KernelClient::connect(caller.principal)
        .await
        .map_err(daemon_internal)?;
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
