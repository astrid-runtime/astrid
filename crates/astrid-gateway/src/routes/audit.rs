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
const CURSOR_SCOPE_ALL: &str = "all";
const CURSOR_SCOPE_PRINCIPAL_PREFIX: char = 'p';
const CURSOR_SCOPE_CHANGED: &str = "audit visibility widened or changed principal during pagination; restart pagination without a cursor";

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
    /// The authenticating device `key_id` when the request was device-scoped.
    /// `None` for a full-authority request. Non-secret (derived from the
    /// device's public key); lets an auditor see which paired device acted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_key_id: Option<String>,
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

#[derive(Debug, Clone, PartialEq, Eq)]
enum CursorScope {
    All,
    Principal(PrincipalId),
}

impl CursorScope {
    fn encode(&self) -> String {
        match self {
            Self::All => CURSOR_SCOPE_ALL.into(),
            Self::Principal(principal) => format!(
                "{CURSOR_SCOPE_PRINCIPAL_PREFIX}{}",
                hex::encode(principal.as_str())
            ),
        }
    }

    fn decode(raw: &str) -> GatewayResult<Self> {
        if raw == CURSOR_SCOPE_ALL {
            return Ok(Self::All);
        }
        let encoded = raw
            .strip_prefix(CURSOR_SCOPE_PRINCIPAL_PREFIX)
            .ok_or_else(|| {
                GatewayError::BadRequest(
                    "cursor scope must be \"all\" or \"p<hex-encoded-principal>\"".into(),
                )
            })?;
        let principal = String::from_utf8(hex::decode(encoded).map_err(|_| {
            GatewayError::BadRequest("cursor scope principal must be valid hex".into())
        })?)
        .map_err(|_| GatewayError::BadRequest("cursor scope principal must be UTF-8".into()))?;
        let principal = PrincipalId::new(&principal)
            .map_err(|e| GatewayError::BadRequest(format!("invalid cursor principal: {e}")))?;
        Ok(Self::Principal(principal))
    }

    fn principal_filter(&self) -> Option<&PrincipalId> {
        match self {
            Self::All => None,
            Self::Principal(principal) => Some(principal),
        }
    }

    // A raw-offset cursor may safely continue only when the next page
    // sees the same principal scope or a narrower one. If visibility
    // widens (for example self-only → firehose or principal A →
    // principal B), records skipped above the raw boundary could
    // become newly visible and would otherwise be lost silently.
    fn accepts_continuation_from(&self, previous: &Self) -> bool {
        matches!(previous, Self::All) || previous == self
    }
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
    let caller = caller_from(&req)?;
    let capability_probe = req
        .extensions()
        .get::<super::events::CapabilityProbe>()
        .cloned()
        .unwrap_or_else(super::events::CapabilityProbe::deny_all);
    let caller_principal = caller.principal.clone();

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

    // Pull the full session slice from the audit log. The audit log
    // doesn't expose an "after cursor" query primitive today, so we
    // fetch + filter + paginate in-process. The persistent log on
    // disk is bounded by the operator's rotation policy; for a
    // routine workload (thousands of entries per day, not millions)
    // this is fine. Tracked as a perf follow-up if/when it bites.
    let all = audit_log
        .get_session_entries(&session_id)
        .await
        .map_err(|e| GatewayError::Internal(anyhow::anyhow!("audit read failed: {e}")))?;

    // Newest first. The storage backend already returns entries in
    // insertion order (oldest first), so a plain `reverse()` is both
    // cheaper (O(N) vs O(N log N) sort, zero allocation) AND
    // preserves true insertion order for entries that share a
    // second-granular timestamp — a stable sort with `Reverse` would
    // keep equal-ts entries oldest-first inside the slice, which
    // breaks the cursor's expectation that "page 1" lists every
    // entry strictly newer than page 2.
    let mut entries: Vec<AuditEntry> = all;
    entries.reverse();

    // Resolve an explicit filter only under post-read authority. Pagination
    // applies the current policy to each record, so narrowing takes effect at
    // the next record boundary.
    let firehose_at_query_boundary = super::events::caller_holds(
        &capability_probe,
        &caller_principal,
        caller.device_key_id.as_deref(),
        AUDIT_FIREHOSE_CAP,
    );
    let requested_principal: Option<PrincipalId> = if firehose_at_query_boundary {
        match query.principal.as_deref() {
            Some(s) => Some(PrincipalId::new(s).map_err(|e| {
                GatewayError::BadRequest(format!("invalid `principal` query value: {e}"))
            })?),
            None => None,
        }
    } else {
        None
    };
    let access = AuditAccess {
        capability_probe: &capability_probe,
        caller_principal: &caller_principal,
        device_key_id: caller.device_key_id.as_deref(),
        requested_principal: requested_principal.as_ref(),
    };

    // Cursor is `"<ts_epoch>_<offset>_<scope>"` — `offset` is the
    // number of same-second entries we've already traversed after the
    // stable query filters and before the live principal filter.
    // Encoding both means same-second batches (timer ticks, scripted
    // ops) can't silently lose or duplicate entries across the page
    // boundary when authority narrows between page fetches. We also
    // encode the last page's effective principal scope so a later
    // scope-widening fetch fails closed instead of silently skipping
    // newly visible rows above the raw cursor boundary. The legacy
    // plain `"<ts_epoch>"` and v2 `"<ts_epoch>_<offset>"` shapes are
    // accepted only when they resume the unambiguous default self view.
    // Broader or different principal scopes must restart without a cursor.
    let mut cursor = parse_cursor(query.cursor.as_deref())?;
    cursor.2 = validate_cursor_scope(cursor.0, cursor.2.as_ref(), &query, &access)?;
    let (page, next_cursor) = paginate_page(entries, &query, &access, cursor, limit)?;

    Ok(Json(AuditQueryResponse {
        entries: page,
        next_cursor,
    }))
}

struct AuditAccess<'a> {
    capability_probe: &'a super::events::CapabilityProbe,
    caller_principal: &'a PrincipalId,
    device_key_id: Option<&'a str>,
    requested_principal: Option<&'a PrincipalId>,
}

impl AuditAccess<'_> {
    fn current_principal_filter(&self) -> Option<&PrincipalId> {
        if super::events::caller_holds(
            self.capability_probe,
            self.caller_principal,
            self.device_key_id,
            AUDIT_FIREHOSE_CAP,
        ) {
            self.requested_principal
        } else {
            Some(self.caller_principal)
        }
    }

    fn current_cursor_scope(&self) -> CursorScope {
        match self.current_principal_filter() {
            Some(principal) => CursorScope::Principal(principal.clone()),
            None => CursorScope::All,
        }
    }
}

fn validate_cursor_scope(
    cursor_ts: Option<u64>,
    cursor_scope: Option<&CursorScope>,
    query: &AuditQuery,
    access: &AuditAccess<'_>,
) -> GatewayResult<Option<CursorScope>> {
    let current_scope = access.current_cursor_scope();
    match cursor_scope {
        Some(previous_scope) => {
            validate_scope_continuation(previous_scope, &current_scope)?;
            Ok(Some(previous_scope.clone()))
        },
        None if cursor_ts.is_some() => {
            validate_legacy_cursor_scope(query, access, &current_scope)?;
            Ok(Some(current_scope))
        },
        None => Ok(None),
    }
}

fn validate_legacy_cursor_scope(
    query: &AuditQuery,
    access: &AuditAccess<'_>,
    current_scope: &CursorScope,
) -> GatewayResult<()> {
    match current_scope {
        CursorScope::Principal(principal)
            if query.principal.is_none() && principal == access.caller_principal =>
        {
            Ok(())
        },
        _ => Err(GatewayError::BadRequest(CURSOR_SCOPE_CHANGED.into())),
    }
}

fn validate_scope_continuation(
    previous_scope: &CursorScope,
    current_scope: &CursorScope,
) -> GatewayResult<()> {
    if current_scope.accepts_continuation_from(previous_scope) {
        Ok(())
    } else {
        Err(GatewayError::BadRequest(CURSOR_SCOPE_CHANGED.into()))
    }
}

/// Walk the entries (newest first) and assemble one page worth of
/// rendered views, honouring every stable filter plus the live
/// principal restriction. Returns the page plus the next-page cursor
/// (or `None` if the result is the last page), and rejects a live
/// scope widening that would invalidate the raw cursor boundary. Pulled out of
/// [`get_audit`] so the handler stays inside the function-length
/// budget and the cursor arithmetic lives in one place.
fn paginate_page(
    entries: Vec<AuditEntry>,
    query: &AuditQuery,
    access: &AuditAccess<'_>,
    cursor: (Option<u64>, usize, Option<CursorScope>),
    limit: usize,
) -> GatewayResult<(Vec<AuditEntryView>, Option<String>)> {
    let (cursor_ts, cursor_offset, cursor_scope) = cursor;
    let mut page: Vec<AuditEntryView> = Vec::with_capacity(limit);
    let mut raw_last_ts: Option<u64> = None;
    let mut raw_ts_position: usize = 0;
    let mut last_visible_ts: Option<u64> = None;
    let mut last_visible_ts_position: usize = 0;
    let mut last_visible_scope: Option<CursorScope> = None;
    let mut effective_scope = access.current_cursor_scope();
    if let Some(cursor_scope) = cursor_scope.as_ref() {
        validate_scope_continuation(cursor_scope, &effective_scope)?;
    }
    for entry in entries {
        let Some(view) = render_entry(&entry) else {
            continue;
        };

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

        raw_ts_position = match raw_last_ts {
            Some(t) if t == view.ts_epoch => raw_ts_position.saturating_add(1),
            _ => 1,
        };
        raw_last_ts = Some(view.ts_epoch);

        let current_scope = access.current_cursor_scope();
        validate_scope_continuation(&effective_scope, &current_scope)?;
        effective_scope = current_scope;

        // Cursor positioning: drop everything strictly newer than
        // the cursor's `ts`, then skip the first `cursor_offset`
        // same-second entries in the stable pre-authorization order.
        if let Some(c_ts) = cursor_ts {
            if view.ts_epoch > c_ts {
                continue;
            }
            if view.ts_epoch == c_ts && raw_ts_position <= cursor_offset {
                continue;
            }
        }

        if let Some(p) = effective_scope.principal_filter()
            && view.principal.as_deref() != Some(p.as_str())
        {
            continue;
        }

        last_visible_ts = Some(view.ts_epoch);
        last_visible_ts_position = raw_ts_position;
        last_visible_scope = Some(effective_scope.clone());
        page.push(view);
        if page.len() >= limit {
            break;
        }
    }

    let next_cursor = if page.len() == limit {
        last_visible_ts
            .zip(last_visible_scope)
            .map(|(t, scope)| format!("{t}_{last_visible_ts_position}_{}", scope.encode()))
    } else {
        None
    };

    Ok((page, next_cursor))
}

/// Parse an opaque cursor into `(ts_epoch, equal_ts_offset, scope)`.
/// Supports the v3 shape (`"<ts>_<offset>_<scope>"`), the v2 shape
/// (`"<ts>_<offset>"`), and the legacy v1 plain-`"<ts>"` shape. Legacy
/// cursors are accepted only for the caller's effective self scope because
/// they do not encode enough information to resume a broader scope safely.
fn parse_cursor(cursor: Option<&str>) -> GatewayResult<(Option<u64>, usize, Option<CursorScope>)> {
    let Some(raw) = cursor else {
        return Ok((None, 0, None));
    };
    let mut parts = raw.splitn(3, '_');
    let ts_str = parts.next().unwrap_or_default();
    let Some(off_str) = parts.next() else {
        let ts = raw.parse::<u64>().map_err(|_| {
            GatewayError::BadRequest("cursor must be \"<ts>\" or \"<ts>_<offset>\"".into())
        })?;
        return Ok((Some(ts), 0, None));
    };
    let scope = match parts.next() {
        Some(scope) => Some(CursorScope::decode(scope)?),
        None => None,
    };
    let ts = ts_str
        .parse::<u64>()
        .map_err(|_| GatewayError::BadRequest("cursor timestamp must be an integer".into()))?;
    let off = off_str.parse::<usize>().map_err(|_| {
        GatewayError::BadRequest("cursor offset must be a non-negative integer".into())
    })?;
    Ok((Some(ts), off, scope))
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
        device_key_id,
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
        device_key_id: device_key_id.clone(),
        target_principal: target_principal.as_ref().map(ToString::to_string),
        params: params.clone(),
        outcome,
    })
}

#[cfg(test)]
mod tests;
