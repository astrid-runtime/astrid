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
            Self::All => "all".into(),
            Self::Principal(principal) => format!("p{}", hex::encode(principal.as_str())),
        }
    }

    fn decode(raw: &str) -> GatewayResult<Self> {
        if raw == "all" {
            return Ok(Self::All);
        }
        let encoded = raw.strip_prefix('p').ok_or_else(|| {
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
    // still accepted for compatibility.
    let cursor = parse_cursor(query.cursor.as_deref())?;
    validate_cursor_scope(cursor.2.as_ref(), &access)?;
    let (page, next_cursor) = paginate_page(entries, &query, &access, cursor, limit);

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
    cursor_scope: Option<&CursorScope>,
    access: &AuditAccess<'_>,
) -> GatewayResult<()> {
    let Some(previous_scope) = cursor_scope else {
        return Ok(());
    };
    let current_scope = access.current_cursor_scope();
    if current_scope.accepts_continuation_from(previous_scope) {
        Ok(())
    } else {
        Err(GatewayError::BadRequest(
            "cursor scope no longer matches the caller's current audit visibility; restart pagination without a cursor".into(),
        ))
    }
}

/// Walk the entries (newest first) and assemble one page worth of
/// rendered views, honouring every stable filter plus the live
/// principal restriction. Returns the page plus the next-page cursor
/// (or `None` if the result is the last page). Pulled out of
/// [`get_audit`] so the handler stays inside the function-length
/// budget and the cursor arithmetic lives in one place.
fn paginate_page(
    entries: Vec<AuditEntry>,
    query: &AuditQuery,
    access: &AuditAccess<'_>,
    cursor: (Option<u64>, usize, Option<CursorScope>),
    limit: usize,
) -> (Vec<AuditEntryView>, Option<String>) {
    let (cursor_ts, cursor_offset, _) = cursor;
    let mut page: Vec<AuditEntryView> = Vec::with_capacity(limit);
    let mut raw_last_ts: Option<u64> = None;
    let mut raw_ts_position: usize = 0;
    let mut last_visible_ts: Option<u64> = None;
    let mut last_visible_ts_position: usize = 0;
    let mut last_visible_scope: Option<CursorScope> = None;
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

        let current_scope = access.current_cursor_scope();
        if let Some(p) = current_scope.principal_filter()
            && view.principal.as_deref() != Some(p.as_str())
        {
            continue;
        }

        last_visible_ts = Some(view.ts_epoch);
        last_visible_ts_position = raw_ts_position;
        last_visible_scope = Some(current_scope);
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

    (page, next_cursor)
}

/// Parse an opaque cursor into `(ts_epoch, equal_ts_offset, scope)`.
/// Supports the v3 shape (`"<ts>_<offset>_<scope>"`), the v2 shape
/// (`"<ts>_<offset>"`), and the legacy v1 plain-`"<ts>"` shape so
/// dashboards holding older cursors across the upgrade don't fail
/// their next paginated fetch.
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
    if raw.contains('_') {
        let ts = ts_str
            .parse::<u64>()
            .map_err(|_| GatewayError::BadRequest("cursor timestamp must be an integer".into()))?;
        let off = off_str.parse::<usize>().map_err(|_| {
            GatewayError::BadRequest("cursor offset must be a non-negative integer".into())
        })?;
        Ok((Some(ts), off, scope))
    } else {
        unreachable!("plain cursor shape handled above")
    }
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
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicUsize, Ordering};

    use astrid_audit::{AuditLog, AuthorizationProof};
    use astrid_core::{SessionId, Timestamp};
    use astrid_crypto::KeyPair;
    use chrono::TimeZone;

    fn admin_action(method: &str, target: Option<&str>) -> AuditAction {
        AuditAction::AdminRequest {
            method: method.into(),
            required_capability: "*".into(),
            target_principal: target.map(|s| PrincipalId::new(s).unwrap()),
            params: None,
            device_key_id: None,
        }
    }

    #[tokio::test]
    async fn render_drops_non_admin_actions() {
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
        .await
        .expect("append");
        let entries = log.get_session_entries(&session).await.expect("read");
        assert_eq!(entries.len(), 1);
        assert!(
            render_entry(&entries[0]).is_none(),
            "McpToolCall must not render into the admin-history view"
        );
    }

    #[tokio::test]
    async fn render_admin_request_round_trips() {
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
        .await
        .expect("append");
        let entries = log.get_session_entries(&session).await.expect("read");
        let view = render_entry(&entries[0]).expect("admin entry must render");
        assert_eq!(view.method.as_deref(), Some("AgentDelete"));
        assert_eq!(view.principal.as_deref(), Some("admin"));
        assert_eq!(view.target_principal.as_deref(), Some("alice"));
        assert_eq!(view.outcome, "success");
    }

    #[tokio::test]
    async fn pagination_narrows_live_without_hiding_the_callers_records() {
        let log = AuditLog::in_memory(KeyPair::generate());
        let session = SessionId::from_uuid(uuid::Uuid::nil());
        for (principal, method) in [
            ("alice", "AliceOwnAfterNarrowing"),
            ("bob", "BobHiddenAfterNarrowing"),
            ("bob", "BobVisibleBeforeNarrowing"),
        ] {
            log.append_with_principal(
                session.clone(),
                PrincipalId::new(principal).unwrap(),
                admin_action(method, None),
                AuthorizationProof::System {
                    reason: "test".into(),
                },
                AuditOutcome::Success { details: None },
            )
            .await
            .expect("append");
        }
        let mut entries = log.get_session_entries(&session).await.expect("read");
        entries.reverse();

        let checks = Arc::new(AtomicUsize::new(0));
        let checks_for_probe = Arc::clone(&checks);
        let capability_probe = super::super::events::CapabilityProbe::new(move |_, _, _| {
            checks_for_probe.fetch_add(1, Ordering::SeqCst) == 0
        });
        let caller = PrincipalId::new("alice").unwrap();
        let access = AuditAccess {
            capability_probe: &capability_probe,
            caller_principal: &caller,
            device_key_id: Some("0123456789abcdef"),
            requested_principal: None,
        };

        let (page, _) = paginate_page(
            entries,
            &AuditQuery::default(),
            &access,
            (None, 0, None),
            DEFAULT_LIMIT,
        );
        let methods: Vec<_> = page
            .iter()
            .filter_map(|entry| entry.method.as_deref())
            .collect();

        assert_eq!(
            methods,
            vec!["BobVisibleBeforeNarrowing", "AliceOwnAfterNarrowing"]
        );
        assert!(!methods.contains(&"BobHiddenAfterNarrowing"));
    }

    #[tokio::test]
    async fn pagination_cursor_survives_live_narrowing_with_same_second_batch() {
        let log = AuditLog::in_memory(KeyPair::generate());
        let session = SessionId::from_uuid(uuid::Uuid::nil());
        for (principal, method) in [
            ("alice", "AliceOlder"),
            ("alice", "AliceVisibleAfterNarrowing"),
            ("bob", "BobHiddenAfterNarrowing"),
            ("bob", "BobVisibleBeforeNarrowing"),
        ] {
            log.append_with_principal(
                session.clone(),
                PrincipalId::new(principal).unwrap(),
                admin_action(method, None),
                AuthorizationProof::System {
                    reason: "test".into(),
                },
                AuditOutcome::Success { details: None },
            )
            .await
            .expect("append");
        }
        let mut entries = log.get_session_entries(&session).await.expect("read");
        entries.reverse();
        let same_second = Timestamp::from_datetime(
            chrono::Utc
                .timestamp_opt(1_700_000_000, 0)
                .single()
                .unwrap(),
        );
        let next_second = Timestamp::from_datetime(
            chrono::Utc
                .timestamp_opt(1_699_999_999, 0)
                .single()
                .unwrap(),
        );
        for entry in &mut entries[..3] {
            entry.timestamp = same_second;
        }
        entries[3].timestamp = next_second;

        let firehose_probe = super::super::events::CapabilityProbe::new(|_, _, _| true);
        let self_only_probe = super::super::events::CapabilityProbe::new(|_, _, _| false);
        let caller = PrincipalId::new("alice").unwrap();
        let firehose_access = AuditAccess {
            capability_probe: &firehose_probe,
            caller_principal: &caller,
            device_key_id: Some("0123456789abcdef"),
            requested_principal: None,
        };
        let self_only_access = AuditAccess {
            capability_probe: &self_only_probe,
            caller_principal: &caller,
            device_key_id: Some("0123456789abcdef"),
            requested_principal: None,
        };

        let (page_one, next_cursor) = paginate_page(
            entries.clone(),
            &AuditQuery::default(),
            &firehose_access,
            (None, 0, None),
            1,
        );
        assert_eq!(
            page_one[0].method.as_deref(),
            Some("BobVisibleBeforeNarrowing")
        );
        assert_eq!(next_cursor.as_deref(), Some("1700000000_1_all"));

        let (cursor_ts, cursor_offset, cursor_scope) =
            parse_cursor(next_cursor.as_deref()).expect("page-one cursor parses");
        validate_cursor_scope(cursor_scope.as_ref(), &self_only_access)
            .expect("all-scope cursor may narrow to self-only");
        let (page_two, next_cursor) = paginate_page(
            entries.clone(),
            &AuditQuery::default(),
            &self_only_access,
            (cursor_ts, cursor_offset, cursor_scope),
            1,
        );
        assert_eq!(
            page_two[0].method.as_deref(),
            Some("AliceVisibleAfterNarrowing")
        );
        assert_eq!(next_cursor.as_deref(), Some("1700000000_3_p616c696365"));

        let (cursor_ts, cursor_offset, cursor_scope) =
            parse_cursor(next_cursor.as_deref()).expect("page-two cursor parses");
        validate_cursor_scope(cursor_scope.as_ref(), &self_only_access)
            .expect("self-only cursor continues under same scope");
        let (page_three, next_cursor) = paginate_page(
            entries.clone(),
            &AuditQuery::default(),
            &self_only_access,
            (cursor_ts, cursor_offset, cursor_scope),
            1,
        );
        assert_eq!(page_three[0].method.as_deref(), Some("AliceOlder"));
        assert_eq!(next_cursor.as_deref(), Some("1699999999_1_p616c696365"));

        let (cursor_ts, cursor_offset, cursor_scope) =
            parse_cursor(next_cursor.as_deref()).expect("page-three cursor parses");
        validate_cursor_scope(cursor_scope.as_ref(), &self_only_access)
            .expect("self-only cursor continues under same scope");
        let (page_four, next_cursor) = paginate_page(
            entries,
            &AuditQuery::default(),
            &self_only_access,
            (cursor_ts, cursor_offset, cursor_scope),
            1,
        );
        assert!(page_four.is_empty());
        assert_eq!(next_cursor.as_deref(), None);
    }

    #[test]
    fn parse_cursor_handles_v1_v2_and_v3_shapes() {
        // v1 (legacy): bare integer, no underscore — offset
        // defaults to 0. We accept this shape so v0.7.0 cursors
        // already in flight don't fail the next paginated fetch.
        let (ts, off, scope) = parse_cursor(Some("1700000000")).expect("bare ts parses");
        assert_eq!(ts, Some(1_700_000_000));
        assert_eq!(off, 0);
        assert_eq!(scope, None);

        // v2: `<ts>_<offset>` — same-second batches resume cleanly
        // without losing or duplicating entries across the page
        // boundary.
        let (ts, off, scope) = parse_cursor(Some("1700000000_3")).expect("v2 cursor parses");
        assert_eq!(ts, Some(1_700_000_000));
        assert_eq!(off, 3);
        assert_eq!(scope, None);

        // v3: `<ts>_<offset>_<scope>` — carries the last page's
        // effective scope so incompatible widens fail closed.
        let (ts, off, scope) =
            parse_cursor(Some("1700000000_3_p616c696365")).expect("v3 cursor parses");
        assert_eq!(ts, Some(1_700_000_000));
        assert_eq!(off, 3);
        assert_eq!(
            scope,
            Some(CursorScope::Principal(PrincipalId::new("alice").unwrap()))
        );

        // None: no cursor → no positioning, start from newest.
        let (ts, off, scope) = parse_cursor(None).expect("None passes");
        assert_eq!(ts, None);
        assert_eq!(off, 0);
        assert_eq!(scope, None);

        // Garbage rejected with `BadRequest`.
        assert!(parse_cursor(Some("not-a-number")).is_err());
        assert!(parse_cursor(Some("123_not-a-number")).is_err());
        assert!(parse_cursor(Some("not-a-number_4")).is_err());
    }

    #[tokio::test]
    async fn pagination_cursor_rejects_scope_widening_after_self_only_page() {
        let log = AuditLog::in_memory(KeyPair::generate());
        let session = SessionId::from_uuid(uuid::Uuid::nil());
        for (principal, method) in [
            ("alice", "AliceOlder"),
            ("alice", "AliceVisibleWhileScoped"),
            ("bob", "BobNewlyVisibleAfterWidening"),
        ] {
            log.append_with_principal(
                session.clone(),
                PrincipalId::new(principal).unwrap(),
                admin_action(method, None),
                AuthorizationProof::System {
                    reason: "test".into(),
                },
                AuditOutcome::Success { details: None },
            )
            .await
            .expect("append");
        }
        let mut entries = log.get_session_entries(&session).await.expect("read");
        entries.reverse();
        let same_second = Timestamp::from_datetime(
            chrono::Utc
                .timestamp_opt(1_700_000_000, 0)
                .single()
                .unwrap(),
        );
        let next_second = Timestamp::from_datetime(
            chrono::Utc
                .timestamp_opt(1_699_999_999, 0)
                .single()
                .unwrap(),
        );
        for entry in &mut entries[..2] {
            entry.timestamp = same_second;
        }
        entries[2].timestamp = next_second;

        let self_only_probe = super::super::events::CapabilityProbe::new(|_, _, _| false);
        let firehose_probe = super::super::events::CapabilityProbe::new(|_, _, _| true);
        let caller = PrincipalId::new("alice").unwrap();
        let self_only_access = AuditAccess {
            capability_probe: &self_only_probe,
            caller_principal: &caller,
            device_key_id: Some("0123456789abcdef"),
            requested_principal: None,
        };
        let firehose_access = AuditAccess {
            capability_probe: &firehose_probe,
            caller_principal: &caller,
            device_key_id: Some("0123456789abcdef"),
            requested_principal: None,
        };

        let (page_one, next_cursor) = paginate_page(
            entries,
            &AuditQuery::default(),
            &self_only_access,
            (None, 0, None),
            1,
        );
        assert_eq!(
            page_one[0].method.as_deref(),
            Some("AliceVisibleWhileScoped")
        );
        let (_, _, cursor_scope) = parse_cursor(next_cursor.as_deref()).expect("cursor parses");
        let err = validate_cursor_scope(cursor_scope.as_ref(), &firehose_access)
            .expect_err("widening must fail closed");
        assert!(
            err.to_string()
                .contains("restart pagination without a cursor"),
            "unexpected error: {err}"
        );
    }
}
