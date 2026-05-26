//! Gateway error type with `IntoResponse` for axum.
//!
//! Every handler returns `Result<T, GatewayError>`. Errors map to
//! HTTP status codes and structured JSON bodies so the dashboard can
//! display useful messages without leaking internal details.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use thiserror::Error;

/// Typed gateway error. Each variant carries the operator-facing
/// message; internal context is logged at warn/error instead of
/// returned in the response body.
#[derive(Debug, Error)]
pub enum GatewayError {
    /// Bearer token missing, malformed, or signature failed.
    #[error("authentication failed")]
    Unauthorized,
    /// Caller authenticated but lacks the required capability.
    /// The kernel-side cap message is preserved in `reason`.
    #[error("forbidden: {reason}")]
    Forbidden {
        /// Operator-facing reason (e.g. `"missing caps:grant"`).
        reason: String,
    },
    /// Invalid client input (malformed body, bad enum, etc.).
    #[error("bad request: {0}")]
    BadRequest(String),
    /// Resource missing.
    #[error("not found")]
    NotFound,
    /// Rate limit hit (typically invite redeem).
    #[error("rate limit exceeded; retry after {retry_after_secs}s")]
    RateLimited {
        /// Seconds the client should wait before retrying.
        retry_after_secs: u64,
    },
    /// Upstream kernel returned an error.
    #[error("kernel rejected request: {0}")]
    Kernel(String),
    /// Anything else — exposed as a 500 with a stable message.
    #[error("internal error")]
    Internal(#[from] anyhow::Error),
}

impl IntoResponse for GatewayError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, json!({"error": "unauthorized"})),
            Self::Forbidden { reason } => (
                StatusCode::FORBIDDEN,
                json!({"error": "forbidden", "reason": reason}),
            ),
            Self::BadRequest(msg) => (
                StatusCode::BAD_REQUEST,
                json!({"error": "bad_request", "reason": msg}),
            ),
            Self::NotFound => (StatusCode::NOT_FOUND, json!({"error": "not_found"})),
            Self::RateLimited { retry_after_secs } => (
                StatusCode::TOO_MANY_REQUESTS,
                json!({"error": "rate_limited", "retry_after_secs": retry_after_secs}),
            ),
            Self::Kernel(msg) => (
                StatusCode::BAD_GATEWAY,
                json!({"error": "kernel", "reason": msg}),
            ),
            Self::Internal(e) => {
                tracing::warn!(error = %e, "gateway internal error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    json!({"error": "internal"}),
                )
            },
        };
        (status, Json(body)).into_response()
    }
}

/// Convenience for handlers: convert an `anyhow::Error` into a
/// `GatewayError::Internal`.
impl From<serde_json::Error> for GatewayError {
    fn from(e: serde_json::Error) -> Self {
        Self::BadRequest(format!("invalid JSON: {e}"))
    }
}

/// Result alias used by handlers.
pub type GatewayResult<T> = Result<T, GatewayError>;
