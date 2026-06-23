//! `/api/sys/groups` — capability-group CRUD.
//!
//! Built-in groups (`admin`, `agent`, `restricted`) are read-only;
//! mutations against them are rejected kernel-side. Custom groups
//! can be created, modified, deleted. The `unsafe_admin` rail
//! covers the wildcard-grant case — same shape as `astrid group
//! create --unsafe-admin`.

use std::sync::Arc;

use astrid_core::kernel_api::{AdminRequestKind, AdminResponseBody, GroupSummary};
use axum::Json;
use axum::extract::{Path, State};
use axum::http::{Request, StatusCode};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::error::{ErrorBody, GatewayError, GatewayResult};
use crate::routes::principals::{caller_from, daemon_internal, read_json_body, unexpected};
use crate::state::GatewayState;

/// `OpenAPI` schema mirror of [`astrid_core::kernel_api::GroupSummary`].
/// Never constructed; resolves the `value_type` on
/// [`GroupListResponse::groups`] to a typed schema. Keep it
/// field-for-field with the serialized shape of `GroupSummary`.
#[derive(ToSchema)]
pub struct GroupSummaryView {
    /// Group name.
    pub name: String,
    /// Capability patterns conferred by this group.
    pub capabilities: Vec<String>,
    /// Human-readable description.
    pub description: Option<String>,
    /// Whether the group opted in to granting the universal `*`.
    pub unsafe_admin: bool,
    /// `true` for built-in groups (`admin`, `agent`, `restricted`);
    /// clients should treat built-ins as read-only.
    pub builtin: bool,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct GroupListResponse {
    #[schema(value_type = Vec<GroupSummaryView>)]
    pub groups: Vec<GroupSummary>,
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct CreateGroupRequest {
    pub name: String,
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub description: Option<String>,
    /// Required when `capabilities` contains the universal `*`.
    #[serde(default)]
    pub unsafe_admin: bool,
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
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

#[utoipa::path(
    get,
    path = "/api/sys/groups",
    tag = "groups",
    responses(
        (status = 200, body = GroupListResponse, description = "All capability groups."),
        (status = 401, body = ErrorBody),
        (status = 403, body = ErrorBody, description = "Caller lacks `group:list`."),
    )
)]
pub async fn list_groups(
    State(state): State<Arc<GatewayState>>,
    req: Request<axum::body::Body>,
) -> GatewayResult<Json<GroupListResponse>> {
    let caller = caller_from(&req)?.clone();
    let client = state.admin_client_for(&caller)?;
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

#[utoipa::path(
    post,
    path = "/api/sys/groups",
    tag = "groups",
    request_body = CreateGroupRequest,
    responses(
        (status = 200, description = "Group created.", content_type = "application/json"),
        (status = 401, body = ErrorBody),
        (status = 403, body = ErrorBody, description = "Caller lacks `group:create`, or wildcard cap without `unsafe_admin: true`."),
    )
)]
pub async fn create_group(
    State(state): State<Arc<GatewayState>>,
    req: Request<axum::body::Body>,
) -> GatewayResult<Json<serde_json::Value>> {
    let caller = caller_from(&req)?.clone();
    let body: CreateGroupRequest = read_json_body(req).await?;
    let client = state.admin_client_for(&caller)?;
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

#[utoipa::path(
    patch,
    path = "/api/sys/groups/{name}",
    tag = "groups",
    params(("name" = String, Path, description = "Group name")),
    request_body = ModifyGroupRequest,
    responses(
        (status = 200, description = "Group updated.", content_type = "application/json"),
        (status = 401, body = ErrorBody),
        (status = 403, body = ErrorBody, description = "Caller lacks `group:modify`, or the group is built-in."),
    )
)]
pub async fn modify_group(
    State(state): State<Arc<GatewayState>>,
    Path(name): Path<String>,
    req: Request<axum::body::Body>,
) -> GatewayResult<Json<serde_json::Value>> {
    let caller = caller_from(&req)?.clone();
    let body: ModifyGroupRequest = read_json_body(req).await?;
    let client = state.admin_client_for(&caller)?;
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

#[utoipa::path(
    delete,
    path = "/api/sys/groups/{name}",
    tag = "groups",
    params(("name" = String, Path, description = "Group name")),
    responses(
        (status = 204, description = "Group deleted."),
        (status = 401, body = ErrorBody),
        (status = 403, body = ErrorBody, description = "Caller lacks `group:delete`, or the group is built-in."),
    )
)]
pub async fn delete_group(
    State(state): State<Arc<GatewayState>>,
    Path(name): Path<String>,
    req: Request<axum::body::Body>,
) -> GatewayResult<StatusCode> {
    let caller = caller_from(&req)?.clone();
    let client = state.admin_client_for(&caller)?;
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
