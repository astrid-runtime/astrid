//! Axum adapters for session routes using the daemon-selected workspace.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::Request;
use axum::{Extension, Json};

use crate::error::GatewayResult;
use crate::state::GatewayState;

use super::WorkspaceContext;
use super::sessions::{
    DeleteResponse, SearchQuery, SearchResponse, SessionListQuery, SessionListResponse,
    SessionSummary, TranscriptResponse, delete_session_inner, get_session_inner,
    get_session_messages_inner, list_sessions_inner, search_sessions_inner, update_session_inner,
};

pub(super) async fn list_sessions_with_layout(
    State(state): State<Arc<GatewayState>>,
    Extension(workspace): Extension<WorkspaceContext>,
    Query(query): Query<SessionListQuery>,
    req: Request<axum::body::Body>,
) -> GatewayResult<Json<SessionListResponse>> {
    list_sessions_inner(state, &workspace, query, req).await
}

pub(super) async fn get_session_messages_with_layout(
    State(state): State<Arc<GatewayState>>,
    Extension(workspace): Extension<WorkspaceContext>,
    Path(id): Path<String>,
    req: Request<axum::body::Body>,
) -> GatewayResult<Json<TranscriptResponse>> {
    get_session_messages_inner(state, &workspace, id, req).await
}

pub(super) async fn get_session_with_layout(
    State(state): State<Arc<GatewayState>>,
    Extension(workspace): Extension<WorkspaceContext>,
    Path(id): Path<String>,
    req: Request<axum::body::Body>,
) -> GatewayResult<Json<SessionSummary>> {
    get_session_inner(state, &workspace, id, req).await
}

pub(super) async fn update_session_with_layout(
    State(state): State<Arc<GatewayState>>,
    Extension(workspace): Extension<WorkspaceContext>,
    Path(id): Path<String>,
    req: Request<axum::body::Body>,
) -> GatewayResult<Json<SessionSummary>> {
    update_session_inner(state, &workspace, id, req).await
}

pub(super) async fn delete_session_with_layout(
    State(state): State<Arc<GatewayState>>,
    Extension(workspace): Extension<WorkspaceContext>,
    Path(id): Path<String>,
    req: Request<axum::body::Body>,
) -> GatewayResult<Json<DeleteResponse>> {
    delete_session_inner(state, &workspace, id, req).await
}

pub(super) async fn search_sessions_with_layout(
    State(state): State<Arc<GatewayState>>,
    Extension(workspace): Extension<WorkspaceContext>,
    Query(query): Query<SearchQuery>,
    req: Request<axum::body::Body>,
) -> GatewayResult<Json<SearchResponse>> {
    search_sessions_inner(state, &workspace, query, req).await
}
