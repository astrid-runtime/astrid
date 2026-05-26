//! `/api/sys/groups` — capability-group CRUD.
//!
//! Built-in groups (`admin`, `agent`, `restricted`) are read-only;
//! mutations against them are rejected kernel-side. Custom groups
//! can be created, modified, deleted. The `unsafe_admin` rail
//! covers the wildcard-grant case — same shape as `astrid group
//! create --unsafe-admin`.

use std::sync::Arc;

use astrid_core::kernel_api::{AdminRequestKind, AdminResponseBody, GroupSummary};
use astrid_uplink::AdminClient;
use axum::Json;
use axum::extract::{Path, State};
use axum::http::{Request, StatusCode};
use serde::{Deserialize, Serialize};

use crate::error::{GatewayError, GatewayResult};
use crate::routes::principals::{caller_from, daemon_internal, read_json_body, unexpected};
use crate::state::GatewayState;

#[derive(Debug, Clone, Serialize)]
pub struct GroupListResponse {
    pub groups: Vec<GroupSummary>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateGroupRequest {
    pub name: String,
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub description: Option<String>,
    /// Required when `capabilities` contains the universal `*`.
    #[serde(default)]
    pub unsafe_admin: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ModifyGroupRequest {
    /// Replace the capability list. `None` keeps the existing list.
    #[serde(default)]
    pub capabilities: Option<Vec<String>>,
    /// Replace the description. `None` keeps existing; `Some(None)`
    /// clears.
    #[serde(default)]
    #[allow(clippy::option_option, reason = "tri-state: keep / clear / replace")]
    pub description: Option<Option<String>>,
    /// Replace the `unsafe_admin` flag.
    #[serde(default)]
    pub unsafe_admin: Option<bool>,
}

pub async fn list_groups(
    State(_state): State<Arc<GatewayState>>,
    req: Request<axum::body::Body>,
) -> GatewayResult<Json<GroupListResponse>> {
    let caller = caller_from(&req)?.clone();
    let mut client = AdminClient::connect(caller.principal)
        .await
        .map_err(daemon_internal)?;
    let resp = client
        .request(AdminRequestKind::GroupList)
        .await
        .map_err(daemon_internal)?;
    match resp {
        AdminResponseBody::GroupList(groups) => Ok(Json(GroupListResponse { groups })),
        AdminResponseBody::Error(msg) => Err(GatewayError::Forbidden { reason: msg }),
        other => Err(unexpected(other)),
    }
}

pub async fn create_group(
    State(_state): State<Arc<GatewayState>>,
    req: Request<axum::body::Body>,
) -> GatewayResult<Json<serde_json::Value>> {
    let caller = caller_from(&req)?.clone();
    let body: CreateGroupRequest = read_json_body(req).await?;
    let mut client = AdminClient::connect(caller.principal)
        .await
        .map_err(daemon_internal)?;
    let resp = client
        .request(AdminRequestKind::GroupCreate {
            name: body.name,
            capabilities: body.capabilities,
            description: body.description,
            unsafe_admin: body.unsafe_admin,
        })
        .await
        .map_err(daemon_internal)?;
    match resp {
        AdminResponseBody::Success(v) => Ok(Json(v)),
        AdminResponseBody::Error(msg) => Err(GatewayError::Forbidden { reason: msg }),
        other => Err(unexpected(other)),
    }
}

pub async fn modify_group(
    State(_state): State<Arc<GatewayState>>,
    Path(name): Path<String>,
    req: Request<axum::body::Body>,
) -> GatewayResult<Json<serde_json::Value>> {
    let caller = caller_from(&req)?.clone();
    let body: ModifyGroupRequest = read_json_body(req).await?;
    let mut client = AdminClient::connect(caller.principal)
        .await
        .map_err(daemon_internal)?;
    let resp = client
        .request(AdminRequestKind::GroupModify {
            name,
            capabilities: body.capabilities,
            description: body.description,
            unsafe_admin: body.unsafe_admin,
        })
        .await
        .map_err(daemon_internal)?;
    match resp {
        AdminResponseBody::Success(v) => Ok(Json(v)),
        AdminResponseBody::Error(msg) => Err(GatewayError::Forbidden { reason: msg }),
        other => Err(unexpected(other)),
    }
}

pub async fn delete_group(
    State(_state): State<Arc<GatewayState>>,
    Path(name): Path<String>,
    req: Request<axum::body::Body>,
) -> GatewayResult<StatusCode> {
    let caller = caller_from(&req)?.clone();
    let mut client = AdminClient::connect(caller.principal)
        .await
        .map_err(daemon_internal)?;
    let resp = client
        .request(AdminRequestKind::GroupDelete { name })
        .await
        .map_err(daemon_internal)?;
    match resp {
        AdminResponseBody::Success(_) => Ok(StatusCode::NO_CONTENT),
        AdminResponseBody::Error(msg) => Err(GatewayError::Forbidden { reason: msg }),
        other => Err(unexpected(other)),
    }
}
