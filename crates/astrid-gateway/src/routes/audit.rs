//! `GET /api/sys/audit` — historical-query endpoint over the
//! persistent audit log.
//!
//! Companion to `GET /api/events` (live SSE feed): the SSE stream
//! delivers events from the moment the connection opens, so a
//! dashboard that wants to render "the last 24 h of admin activity"
//! has no way to backfill from SSE alone. This route exposes the
//! persistent log instead.
//!
//! Same trust shape as the SSE handler:
//!
//! * Caller with `audit:read_all` → firehose (every entry in the
//!   session).
//! * Anyone else → only entries whose `principal` matches the
//!   caller's own principal.

use std::sync::Arc;

use astrid_audit::{AuditAction, AuditEntry, AuditOutcome};
use astrid_core::PrincipalId;
use axum::Json;
use axum::extract::{Query, State};
use axum::http::Request;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::error::{ErrorBody, GatewayError, GatewayResult};
use crate::routes::events::AUDIT_FIREHOSE_CAP;
use crate::routes::principals::caller_from;
use crate::state::GatewayState;

/// Default page size. Matches the `limit` knob's default in the
/// issue spec. Keeps response bodies bounded for casual scraping
/// while still allowing a single page to cover a quiet hour.
const DEFAULT_LIMIT: usize = 100;

/// Hard upper bound on `limit`. A dashboard that wants more should
/// paginate; the cap exists so a malicious bearer can't request a
/// 10-million-entry page and OOM the gateway.
const MAX_LIMIT: usize = 1000;

/// Query parameters for `GET /api/sys/audit`. All optional —
/// the default behaviour is "the last [`DEFAULT_LIMIT`] entries
/// scoped to whatever the caller is allowed to see".
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
pub struct AuditQuery {
    /// Lower bound on `ts_epoch`, inclusive.
    #[serde(default)]
    pub since: Option<u64>,
    /// Upper bound on `ts_epoch`, inclusive.
    #[serde(default)]
    pub until: Option<u64>,
    /// Filter to one admin method (e.g. `"AgentDelete"`,
    /// `"InviteIssue"`). Matched verbatim against the audit
    /// envelope's `method` field.
    #[serde(default)]
    pub method: Option<String>,
    /// Filter to one principal. Admin-only — non-admin callers see
    /// only their own principal regardless of this field.
    #[serde(default)]
    pub principal: Option<String>,
    /// Page size, default [`DEFAULT_LIMIT`], capped at [`MAX_LIMIT`].
    #[serde(default)]
    pub limit: Option<usize>,
    /// Opaque cursor returned by a previous page. Today the cursor
    /// is the timestamp of the last entry on the previous page;
    /// keeping it opaque means we can swap implementations later
    /// without breaking dashboards.
    #[serde(default)]
    pub cursor: Option<String>,
}

/// One audit entry as rendered for the JSON wire. Mirrors the flat
/// shape the live SSE feed publishes on `astrid.v1.audit.entry` so a
/// dashboard can treat backfill + live the same way.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AuditEntryView {
    /// Wall-clock epoch (seconds) when the entry was recorded.
    pub ts_epoch: u64,
    /// Admin method name (e.g. `"AgentDelete"`, `"InviteIssue"`).
    /// `null` for non-`AdminRequest` entries the kernel records
    /// elsewhere — most queries will only see `AdminRequest` rows.
    pub method: Option<String>,
    /// Capability the kernel evaluated for this request.
    pub required_capability: Option<String>,
    /// Principal that acted (the caller).
    pub principal: Option<String>,
    /// Principal the action was scoped to, when distinct from the
    /// caller. `None` for self-targeted ops.
    pub target_principal: Option<String>,
    /// Request params for forensic replay.
    pub params: Option<serde_json::Value>,
    /// `"success"` or `"failure"`.
    pub outcome: &'static str,
}

/// Response shape for `GET /api/sys/audit`.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AuditQueryResponse {
    /// Page of entries, newest first.
    pub entries: Vec<AuditEntryView>,
    /// Opaque cursor for the next page, or `null` when the result
    /// is the last page.
    pub next_cursor: Option<String>,
}

/// `GET /api/sys/audit` handler.
#[utoipa::path(
    get,
    path = "/api/sys/audit",
    tag = "audit",
    params(
        ("since" = Option<u64>, Query, description = "Lower bound on ts_epoch, inclusive."),
        ("until" = Option<u64>, Query, description = "Upper bound on ts_epoch, inclusive."),
        ("method" = Option<String>, Query, description = "Filter to one admin method."),
        ("principal" = Option<String>, Query, description = "Filter to one principal. Admin-only — non-admin callers see only their own principal regardless."),
        ("limit" = Option<usize>, Query, description = "Page size; default 100, max 1000."),
        ("cursor" = Option<String>, Query, description = "Opaque cursor from a previous page."),
    ),
    responses(
        (status = 200, body = AuditQueryResponse, description = "Page of audit entries newest-first; non-admin callers see only their own principal."),
        (status = 400, body = ErrorBody, description = "Bad query params (e.g. limit > 1000)."),
        (status = 401, body = ErrorBody, description = "Missing / invalid bearer."),
        (status = 502, body = ErrorBody, description = "Gateway not wired to a live audit log."),
    )
)]
pub async fn get_audit(
    State(state): State<Arc<GatewayState>>,
    Query(query): Query<AuditQuery>,
    req: Request<axum::body::Body>,
) -> GatewayResult<Json<AuditQueryResponse>> {
    let caller = caller_from(&req)?.clone();

    let (audit_log, session_id) = match (state.audit_log.as_ref(), state.session_id.as_ref()) {
        (Some(log), Some(sid)) => (log.clone(), sid.clone()),
        _ => {
            return Err(GatewayError::Internal(anyhow::anyhow!(
                "gateway is not wired to a live audit log; historical-query unavailable"
            )));
        },
    };

    let limit = match query.limit {
        Some(l) if l > MAX_LIMIT => {
            return Err(GatewayError::BadRequest(format!(
                "limit {l} exceeds the cap of {MAX_LIMIT}"
            )));
        },
        Some(0) | None => DEFAULT_LIMIT,
        Some(l) => l,
    };

    // Cap-gate: admin / `audit:read_all` callers get the firehose;
    // everyone else is silently scoped to their own principal,
    // matching the SSE handler's posture.
    let firehose = super::events::caller_holds(&state, &caller.principal, AUDIT_FIREHOSE_CAP).await;

    // Pull the full session slice from the audit log. The audit log
    // doesn't expose an "after cursor" query primitive today, so we
    // fetch + filter + paginate in-process. The persistent log on
    // disk is bounded by the operator's rotation policy; for a
    // routine workload (thousands of entries per day, not millions)
    // this is fine. Tracked as a perf follow-up if/when it bites.
    let log_for_read = audit_log.clone();
    let session_for_read = session_id.clone();
    let all =
        tokio::task::spawn_blocking(move || log_for_read.get_session_entries(&session_for_read))
            .await
            .map_err(|e| GatewayError::Internal(anyhow::anyhow!("audit read task panicked: {e}")))?
            .map_err(|e| GatewayError::Internal(anyhow::anyhow!("audit read failed: {e}")))?;

    // Newest first. The storage backend returns entries in
    // insertion order; reverse so the dashboard's "page 1" is
    // "most recent".
    let mut entries: Vec<AuditEntry> = all;
    entries.sort_by_key(|e| std::cmp::Reverse(e.timestamp.0.timestamp()));

    // Effective principal filter: admins can use the `principal=`
    // query param; non-admins are pinned to their own principal
    // regardless of what they ask for.
    let principal_filter: Option<PrincipalId> = if firehose {
        match query.principal.as_deref() {
            Some(s) => Some(PrincipalId::new(s).map_err(|e| {
                GatewayError::BadRequest(format!("invalid `principal` query value: {e}"))
            })?),
            None => None,
        }
    } else {
        Some(caller.principal.clone())
    };

    let cursor_ts: Option<u64> =
        match query.cursor.as_deref() {
            Some(c) => Some(c.parse::<u64>().map_err(|_| {
                GatewayError::BadRequest("cursor must be an integer timestamp".into())
            })?),
            None => None,
        };

    let mut page: Vec<AuditEntryView> = Vec::with_capacity(limit);
    let mut last_ts: Option<u64> = None;
    for entry in entries {
        // Skip non-`AdminRequest` entries — those belong to a
        // different feed (MCP tool calls, capsule events).
        let Some(view) = render_entry(&entry) else {
            continue;
        };

        // Cursor: entries with ts >= cursor_ts have already been
        // delivered, so skip them. Equal-ts collisions are handled
        // by dropping at the boundary; in practice ts is seconds-
        // granular and the kernel sees fewer than one admin op per
        // second.
        if let Some(c) = cursor_ts
            && view.ts_epoch >= c
        {
            continue;
        }
        if let Some(s) = query.since
            && view.ts_epoch < s
        {
            continue;
        }
        if let Some(u) = query.until
            && view.ts_epoch > u
        {
            continue;
        }
        if let Some(m) = query.method.as_deref()
            && view.method.as_deref() != Some(m)
        {
            continue;
        }
        if let Some(p) = principal_filter.as_ref()
            && view.principal.as_deref() != Some(p.as_str())
        {
            continue;
        }

        last_ts = Some(view.ts_epoch);
        page.push(view);
        if page.len() >= limit {
            break;
        }
    }

    let next_cursor = if page.len() == limit {
        last_ts.map(|t| t.to_string())
    } else {
        None
    };

    Ok(Json(AuditQueryResponse {
        entries: page,
        next_cursor,
    }))
}

/// Map an `AuditEntry` into the flat JSON shape we ship over the
/// wire. Today only `AuditAction::AdminRequest` rounds-trip into
/// `AuditEntryView`; other actions (MCP tool calls, capsule events)
/// return `None` and are dropped from the response so the
/// historical surface mirrors what the SSE feed delivers.
fn render_entry(entry: &AuditEntry) -> Option<AuditEntryView> {
    let AuditAction::AdminRequest {
        method,
        required_capability,
        target_principal,
        params,
    } = &entry.action
    else {
        return None;
    };
    let outcome = match entry.outcome {
        AuditOutcome::Success { .. } => "success",
        AuditOutcome::Failure { .. } => "failure",
    };
    Some(AuditEntryView {
        ts_epoch: u64::try_from(entry.timestamp.0.timestamp()).unwrap_or(0),
        method: Some(method.clone()),
        required_capability: Some(required_capability.clone()),
        principal: entry.principal.as_ref().map(ToString::to_string),
        target_principal: target_principal.as_ref().map(ToString::to_string),
        params: params.clone(),
        outcome,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use astrid_audit::{AuditLog, AuthorizationProof};
    use astrid_core::SessionId;
    use astrid_crypto::KeyPair;

    fn admin_action(method: &str, target: Option<&str>) -> AuditAction {
        AuditAction::AdminRequest {
            method: method.into(),
            required_capability: "*".into(),
            target_principal: target.map(|s| PrincipalId::new(s).unwrap()),
            params: None,
        }
    }

    #[test]
    fn render_drops_non_admin_actions() {
        // Non-admin entries (MCP tool calls, capsule events) belong
        // to a different audit feed; they must not surface in the
        // historical-admin view.
        let log = AuditLog::in_memory(KeyPair::generate());
        let session = SessionId::from_uuid(uuid::Uuid::nil());
        log.append(
            session.clone(),
            AuditAction::McpToolCall {
                server: "x".into(),
                tool: "y".into(),
                args_hash: astrid_crypto::ContentHash::from_bytes([0u8; 32]),
            },
            AuthorizationProof::System {
                reason: "test".into(),
            },
            AuditOutcome::Success { details: None },
        )
        .expect("append");
        let entries = log.get_session_entries(&session).expect("read");
        assert_eq!(entries.len(), 1);
        assert!(
            render_entry(&entries[0]).is_none(),
            "McpToolCall must not render into the admin-history view"
        );
    }

    #[test]
    fn render_admin_request_round_trips() {
        let log = AuditLog::in_memory(KeyPair::generate());
        let session = SessionId::from_uuid(uuid::Uuid::nil());
        log.append_with_principal(
            session.clone(),
            PrincipalId::new("admin").unwrap(),
            admin_action("AgentDelete", Some("alice")),
            AuthorizationProof::System {
                reason: "test".into(),
            },
            AuditOutcome::Success { details: None },
        )
        .expect("append");
        let entries = log.get_session_entries(&session).expect("read");
        let view = render_entry(&entries[0]).expect("admin entry must render");
        assert_eq!(view.method.as_deref(), Some("AgentDelete"));
        assert_eq!(view.principal.as_deref(), Some("admin"));
        assert_eq!(view.target_principal.as_deref(), Some("alice"));
        assert_eq!(view.outcome, "success");
    }
}
