//! Shim-side grant-on-use elicitation: relay the broker's "this capsule is
//! not granted to you — grant it?" prompt to the MCP client via
//! [`Peer::elicit`], and on approve forward the decision so the kernel
//! persists the capsule grant.
//!
//! grant-on-use mirrors the INGRESS flow — **gate → consent → re-send** —
//! NOT the capability-approval flow (park → consent → resume). When a
//! principal invokes a capsule tool it does not yet hold, the kernel
//! access-gate DROPS the original `tool.call` (nothing is parked) and the
//! broker replies a `grant_required` signal instead of a terminal result.
//! This module turns that signal into a user consent and, on approve,
//! forwards `astrid.v1.request.mcp.grant.respond` so the kernel persists the
//! capsule on the principal; the caller in `server.rs` then RE-SENDS the
//! original `tool.call` (now passing the gate). The original was dropped —
//! there is nothing to resume.
//!
//! ## Contract (must match `sage-mcp`)
//!
//! * The broker `tools/call` reply carries a `grant_required` OBJECT
//!   `{ request_id, capsule_id, principal, tool_name, call_id }` when the
//!   caller does not hold the capsule. `request_id` is the kernel-minted
//!   grant correlation id, echoed back verbatim so the broker routes the
//!   decision; `capsule_id` is echoed back so the broker can clear its dedup
//!   marker; the rest are display/diagnostic. Both `request_id` and
//!   `capsule_id` MUST be present and non-empty — a signal missing either is
//!   unanswerable and is rejected as malformed (see [`GrantRequest::classify`]).
//!   The signal is NOT `isError` — it is a prompt-needed state, not a failure.
//! * The respond body the broker expects on [`GRANT_RESPOND_TOPIC`] is
//!   `{ req_id, request_id, decision, capsule_id }`, where `req_id` is a fresh
//!   proxy correlation token (the ack lands on `astrid.v1.response.<req_id>`),
//!   `request_id` is the grant id echoed verbatim, `decision` is `"approve"` or
//!   `"deny"`, and `capsule_id` is echoed so the broker can clear its
//!   per-`(principal, capsule)` dedup marker. `capsule_id` is display/routing
//!   only — never a grant target (the kernel derives the target from its own
//!   observed signal), so it cannot forge a grant.
//! * The broker acks on `astrid.v1.response.<req_id>` with
//!   `{ kind:"grant.respond", req_id, granted:bool }`. The caller only
//!   re-sends the dropped `tools/call` when `granted` is true.
//!
//! ## Binary Grant / Deny (no approve-verbs)
//!
//! Unlike [`crate::commands::mcp::elicit`], the grant elicitation is a flat
//! BINARY allow/deny, not the four host approval verbs. The kernel grant is
//! always PERSISTENT (it writes `profile.capsules`); "allow once" is not
//! expressible without a separate kernel one-time-allowance mechanism, so a
//! binary form is the honest UI. The respond `decision` is therefore only
//! ever `"approve"` or `"deny"`.
//!
//! ## Marker discipline (the divergence from ingress)
//!
//! The broker holds a per-`(principal, capsule)` pending marker so a second
//! ungranted call does not spawn a duplicate prompt. That marker is consumed
//! on EVERY respond — approve AND deny — so the shim MUST always respond,
//! including a `deny` on decline / cancel / elicit error. (Ingress sends no
//! respond on decline; grant always does, or the marker would stick.)
//!
//! ## Capability gating and fail-secure
//!
//! Elicitation is attempted ONLY when the client advertised the elicitation
//! capability at `initialize` (checked via
//! [`Peer::supported_elicitation_modes`]). When the client did not, or the
//! user declines / cancels / the elicit transport errors, we DENY. Fail
//! secure — the absence of an explicit accept is never treated as consent.
//!
//! ## Never elicit secrets
//!
//! The elicited type ([`GrantForm`]) is a single boolean `grant` field. No
//! free-form text, no tool argument, and no secret is surfaced or
//! round-tripped. The prompt is built only from the display fields.

use std::fmt::Write as _;

use rmcp::schemars::{self, JsonSchema};
use rmcp::service::{ElicitationError, Peer, RoleServer};
use serde::Deserialize;
use serde_json::{Value, json};
use tracing::{debug, warn};

/// Broker front door for the shim's elicited grant-on-use decision. Maps to
/// `sage-mcp::SageMcp::handle_mcp_grant_respond`.
pub(super) const GRANT_RESPOND_TOPIC: &str = "astrid.v1.request.mcp.grant.respond";

/// The user's grant-on-use choice, as a flat single-property object so it
/// satisfies rmcp's `ElicitationSafe` object-schema requirement.
///
/// A plain boolean keeps the schema a primitive property the MCP elicitation
/// spec accepts without `$ref`/`oneOf` flattening concerns (unlike a string
/// enum, see `elicit::ApprovalForm`).
#[derive(Debug, Deserialize, JsonSchema)]
pub(super) struct GrantForm {
    /// Whether to grant this capsule to the calling principal.
    pub(super) grant: bool,
}

rmcp::elicit_safe!(GrantForm);

/// The `grant_required` signal a gated `tools/call` reply carries.
///
/// `request_id` is the kernel-minted grant correlation id — echoed verbatim
/// back to the broker so it can route the decision; it is NOT shown to the
/// user. `capsule_id` / `principal` / `tool_name` are display/diagnostic
/// strings only — they are never echoed back as a grant target (the kernel
/// derives the grant target from its own observed signal, never a body
/// field), so they can never be used to forge a grant for a different
/// capsule or principal.
#[derive(Debug, Deserialize)]
pub(super) struct GrantRequest {
    /// Kernel-minted grant correlation id; echoed onto the respond body.
    request_id: String,
    /// The capsule the caller lacks access to, for the prompt context.
    #[serde(default)]
    capsule_id: String,
    /// The principal the call attributes to, for display/diagnostics only.
    #[serde(default)]
    principal: String,
    /// The tool the user was trying to call, for the prompt context.
    #[serde(default)]
    tool_name: String,
}

/// Classification of a broker `tools/call` reply's `grant_required` field.
///
/// The three states are deliberately distinct so the caller never collapses a
/// *present-but-broken* signal into the already-granted path: a dropped call
/// must surface as a terminal error, never a silent empty success.
pub(super) enum GrantSignal {
    /// No actionable signal — the `grant_required` field is absent or JSON
    /// `null` (the common, already-granted path). Fall through to the normal
    /// result handling.
    Absent,
    /// A `grant_required` field is present but cannot be answered: wrong shape,
    /// or missing the routing token (`request_id`) / the `capsule_id` the
    /// broker needs to clear its dedup marker. The caller MUST surface a
    /// terminal error rather than treat the (empty) reply as a result.
    Malformed,
    /// A well-formed grant signal to elicit consent on.
    Present(GrantRequest),
}

impl GrantRequest {
    /// Classify the `grant_required` field of a broker `tools/call` reply.
    ///
    /// An absent field — or an explicit JSON `null`, treated as absent to
    /// mirror typed deserialization where `null` maps to `None` — is
    /// [`GrantSignal::Absent`]. A present field that cannot be answered
    /// (unparseable, or missing the non-empty `request_id` / `capsule_id` the
    /// respond needs) is [`GrantSignal::Malformed`] so the caller fails the
    /// call loudly instead of returning the empty body as a success. A
    /// well-formed signal is [`GrantSignal::Present`]. This is a shape check,
    /// not a trust check: the kernel mints `request_id` and derives the grant
    /// target itself.
    pub(super) fn classify(reply: &Value) -> GrantSignal {
        let Some(flag) = reply.get("grant_required").filter(|v| !v.is_null()) else {
            return GrantSignal::Absent;
        };
        match serde_json::from_value::<Self>(flag.clone()) {
            Ok(req) if req.request_id.is_empty() => {
                warn!("MCP shim: grant_required signal missing request_id; treating as malformed");
                GrantSignal::Malformed
            },
            Ok(req) if req.capsule_id.is_empty() => {
                // The broker needs `capsule_id` echoed back to clear its
                // `(principal, capsule)` dedup marker; without it the respond is
                // unusable and the marker would stick. Refuse the signal.
                warn!("MCP shim: grant_required signal missing capsule_id; treating as malformed");
                GrantSignal::Malformed
            },
            Ok(req) => GrantSignal::Present(req),
            Err(e) => {
                warn!(error = %e, "MCP shim: malformed grant_required signal");
                GrantSignal::Malformed
            },
        }
    }

    /// Build the respond body the broker expects on [`GRANT_RESPOND_TOPIC`].
    /// `req_id` is the fresh proxy correlation token for the ack; `request_id`
    /// is the grant id echoed verbatim; `decision` is `"approve"` or `"deny"`;
    /// `capsule_id` is echoed so the broker can clear its per-`(principal,
    /// capsule)` dedup marker on respond. `capsule_id` is display/routing only —
    /// never a grant target (the kernel derives the target from its own observed
    /// signal, never a body field), so it cannot forge a grant.
    pub(super) fn respond_body(&self, req_id: &str, decision: &str) -> Value {
        json!({
            "req_id": req_id,
            "request_id": self.request_id,
            "decision": decision,
            "capsule_id": self.capsule_id,
        })
    }

    /// Render the human-facing consent prompt. Only the display fields are
    /// woven in; the grant correlation id (`request_id`) never reaches the
    /// user.
    fn prompt(&self) -> String {
        let mut p = String::from(
            "An MCP client invoked a tool from a capsule this identity is not yet allowed to use.",
        );
        // `write!` to a `String` is infallible; the `let _` discards the
        // always-`Ok` result without an `unwrap`.
        if !self.tool_name.is_empty() {
            let _ = write!(p, "\n\nTool requested: {}", self.tool_name);
        }
        if !self.capsule_id.is_empty() {
            let _ = write!(p, "\nCapsule: {}", self.capsule_id);
        }
        if !self.principal.is_empty() {
            let _ = write!(p, "\nIdentity: {}", self.principal);
        }
        p.push_str("\n\nGrant this capsule to the identity?");
        p
    }
}

/// Map an elicited accept/decline onto the broker decision verb the respond
/// body carries. Binary by construction: an accept is `"approve"`, anything
/// else (decline / cancel / no-capability / elicit error, all of which
/// [`elicit_grant`] collapses to `false`) is `"deny"`. A `deny` is still
/// PUBLISHED on every non-accept path so the broker's pending marker clears —
/// the shim must always respond.
pub(super) fn grant_decision(approved: bool) -> &'static str {
    if approved { "approve" } else { "deny" }
}

/// Elicit the user's grant-on-use decision from `peer`.
///
/// Returns `true` only on an explicit accept of a `grant:true` form.
/// Fail-secure: a client without elicitation, a decline / cancel, an empty
/// response, or any elicit transport error all return `false`.
pub(super) async fn elicit_grant(peer: &Peer<RoleServer>, request: &GrantRequest) -> bool {
    if peer.supported_elicitation_modes().is_empty() {
        debug!("MCP shim: client did not advertise elicitation; denying grant-on-use");
        return false;
    }

    match peer.elicit::<GrantForm>(request.prompt()).await {
        Ok(Some(form)) => {
            debug!(
                grant = form.grant,
                "MCP shim: grant-on-use decision resolved"
            );
            form.grant
        },
        Ok(None) => {
            warn!("MCP shim: grant elicitation returned no content; denying");
            false
        },
        Err(ElicitationError::UserDeclined | ElicitationError::UserCancelled) => {
            debug!("MCP shim: user declined/cancelled grant-on-use; denying");
            false
        },
        Err(ElicitationError::CapabilityNotSupported) => {
            debug!("MCP shim: client lacks elicitation capability; denying grant-on-use");
            false
        },
        Err(e) => {
            warn!(error = %e, "MCP shim: grant elicitation failed; denying");
            false
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_parses_present_signal() {
        let reply = json!({
            "kind": "tool.call",
            "content": [],
            "isError": false,
            "grant_required": {
                "request_id": "grant-123",
                "capsule_id": "shell",
                "principal": "claude-code",
                "tool_name": "shell.exec",
                "call_id": "call-abc"
            }
        });
        let GrantSignal::Present(req) = GrantRequest::classify(&reply) else {
            panic!("a complete signal should classify as Present");
        };
        assert_eq!(req.request_id, "grant-123");
        assert_eq!(req.capsule_id, "shell");
        assert_eq!(req.principal, "claude-code");
        assert_eq!(req.tool_name, "shell.exec");
    }

    #[test]
    fn classify_absent_when_field_missing() {
        let reply = json!({ "kind": "tool.call", "content": [], "isError": false });
        assert!(matches!(
            GrantRequest::classify(&reply),
            GrantSignal::Absent
        ));
    }

    #[test]
    fn classify_absent_when_field_is_null() {
        // An explicit JSON null is treated as absent (mirrors typed
        // deserialization where null maps to None), not as a malformed signal.
        let reply = json!({ "grant_required": Value::Null });
        assert!(matches!(
            GrantRequest::classify(&reply),
            GrantSignal::Absent
        ));
    }

    #[test]
    fn classify_malformed_when_request_id_blank() {
        let reply = json!({
            "grant_required": {
                "request_id": "",
                "capsule_id": "shell",
                "tool_name": "t"
            }
        });
        assert!(matches!(
            GrantRequest::classify(&reply),
            GrantSignal::Malformed
        ));
    }

    #[test]
    fn classify_malformed_when_capsule_id_missing() {
        // The routing token alone is NOT answerable: the broker needs the
        // capsule id echoed back to clear its dedup marker, so a signal without
        // it is malformed rather than a partial-but-usable Present.
        let reply = json!({ "grant_required": { "request_id": "g1" } });
        assert!(matches!(
            GrantRequest::classify(&reply),
            GrantSignal::Malformed
        ));
    }

    #[test]
    fn respond_body_echoes_grant_id_and_decision() {
        let req = GrantRequest {
            request_id: "grant-1".into(),
            capsule_id: "shell".into(),
            principal: "claude-code".into(),
            tool_name: "shell.exec".into(),
        };
        let approve = req.respond_body("proxy-req", "approve");
        assert_eq!(approve["req_id"], "proxy-req");
        assert_eq!(approve["request_id"], "grant-1");
        assert_eq!(approve["decision"], "approve");
        let deny = req.respond_body("proxy-req-2", "deny");
        assert_eq!(deny["decision"], "deny");
        // `capsule_id` is echoed so the broker can clear its `(principal,
        // capsule)` dedup marker — but it is NOT a grant target (the kernel
        // derives that from its own observed signal, never a respond body
        // field). `principal` is not sent at all.
        assert_eq!(deny["capsule_id"], "shell");
        assert!(deny.get("principal").is_none());
    }

    #[test]
    fn decision_is_binary_approve_or_deny() {
        assert_eq!(grant_decision(true), "approve");
        assert_eq!(grant_decision(false), "deny");
    }

    #[test]
    fn respond_body_carries_approve_on_accept_deny_otherwise() {
        // The full path `resolve_grant` takes: an accept produces an `approve`
        // respond, every non-accept produces a `deny` respond — and a `deny` is
        // always published (the marker must clear).
        let req = GrantRequest {
            request_id: "grant-1".into(),
            capsule_id: "shell".into(),
            principal: "claude-code".into(),
            tool_name: "shell.exec".into(),
        };
        let on_accept = req.respond_body("p1", grant_decision(true));
        assert_eq!(on_accept["decision"], "approve");
        assert_eq!(on_accept["request_id"], "grant-1");
        let on_decline = req.respond_body("p2", grant_decision(false));
        assert_eq!(on_decline["decision"], "deny");
        assert_eq!(on_decline["request_id"], "grant-1");
    }

    #[test]
    fn form_schema_is_elicitation_safe() {
        let schema = rmcp::model::ElicitationSchema::from_type::<GrantForm>();
        assert!(
            schema.is_ok(),
            "GrantForm must produce a valid elicitation schema: {schema:?}"
        );
    }

    #[test]
    fn prompt_includes_display_fields_not_routing_id() {
        let req = GrantRequest {
            request_id: "secret-grant-id".into(),
            capsule_id: "shell".into(),
            principal: "claude-code".into(),
            tool_name: "shell.exec".into(),
        };
        let p = req.prompt();
        assert!(p.contains("shell.exec"));
        assert!(p.contains("shell"));
        assert!(p.contains("claude-code"));
        assert!(p.contains("Grant this capsule"));
        // The grant correlation id must never leak into the prompt.
        assert!(!p.contains("secret-grant-id"));
    }
}
