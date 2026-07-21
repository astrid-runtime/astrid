//! Shim-side ingress-consent elicitation: relay the broker's
//! "is this ingress allowed?" prompt to the MCP client via [`Peer::elicit`].
//!
//! The broker (`sage-mcp`) gates its state-mutating `tools/call` front door
//! on a confused-deputy check: the kernel-stamped `source_id` of whoever
//! forwarded the call (this shim's uplink, via the cli proxy) must be a
//! TRUSTED ingress. Trust is no longer an operator-maintained allow-list —
//! it is recorded interactively. When a `tools/call` arrives from a not-yet
//! trusted `source_id`, the broker replies an `ingress_approval_required`
//! signal instead of dispatching, and asks this shim to collect the user's
//! consent. We do that with [`Peer::elicit`] and, on accept, forward
//! `astrid.v1.request.mcp.ingress.respond` so the broker records trust
//! (keyed on the kernel-stamped caller — never a body field) and a re-sent
//! call passes the gate.
//!
//! ## Contract (must match `sage-mcp`)
//!
//! * The broker `tools/call` reply carries `ingress_approval_required: true`
//!   (plus `source_id` / `tool_name` for display/diagnostics) when the
//!   ingress is untrusted. The signal is NOT `isError` — it is a
//!   prompt-needed state, not a failure.
//! * The respond body the broker expects on
//!   [`INGRESS_RESPOND_TOPIC`] is `{ req_id, accept }`. There is
//!   DELIBERATELY no `source_id`: the broker trusts the kernel-stamped caller
//!   of the respond message, never a value the shim could send.
//! * The broker acks on `astrid.v1.response.<req_id>` with
//!   `{ kind:"ingress.respond", req_id, granted:bool }`. The shim only
//!   re-sends the parked `tools/call` when `granted` is true.
//!
//! ## Capability gating and fail-secure
//!
//! Prefer wire **form-mode** elicitation when the client advertised it at
//! `initialize` ([`Peer::supported_elicitation_modes`]). Clients with form
//! support (Claude, Codex, …) never leave that path.
//!
//! When the client advertised **no** elicitation modes (e.g. Grok Build
//! today), fall back to a **local native system dialog**
//! ([`super::host_dialog`]) for the same boolean consent. Decline, cancel,
//! dialog error, or kill-switch still DENY: no `ingress.respond`, no trust
//! recorded. Fail secure — the absence of an explicit accept is never
//! treated as consent. Capable clients never see this path.
//!
//! ## Never elicit secrets (this flow)
//!
//! The elicited type ([`IngressForm`]) is a single boolean `allow` field. No
//! free-form text, no tool argument, and no secret is surfaced or
//! round-tripped here.

use std::fmt::Write as _;

use rmcp::schemars::{self, JsonSchema};
use rmcp::service::{ElicitationError, Peer, RoleServer};
use serde::Deserialize;
use serde_json::Value;
use tracing::{debug, warn};

/// Broker front door for the shim's elicited ingress-consent decision. Maps
/// to `sage-mcp::SageMcp::handle_mcp_ingress_respond`.
pub(super) const INGRESS_RESPOND_TOPIC: &str = "astrid.v1.request.mcp.ingress.respond";

/// The user's ingress-consent choice, as a flat single-property object so it
/// satisfies rmcp's `ElicitationSafe` object-schema requirement.
///
/// A plain boolean keeps the schema a primitive property the MCP elicitation
/// spec accepts without `$ref`/`oneOf` flattening concerns (unlike a string
/// enum, see `elicit::ApprovalForm`).
#[derive(Debug, Deserialize, JsonSchema)]
pub(super) struct IngressForm {
    /// Whether to allow Astrid tool calls from this session's ingress.
    pub(super) allow: bool,
}

rmcp::elicit_safe!(IngressForm);

/// The `ingress_approval_required` signal a gated `tools/call` reply carries.
///
/// `source_id` / `tool_name` are display/diagnostic strings only — they are
/// NOT echoed back to the broker (the respond body carries neither), so they
/// can never be used to forge a trust grant for a different ingress.
#[derive(Debug, Deserialize)]
pub(super) struct IngressRequest {
    /// The kernel-stamped ingress `source_id`, for display/diagnostics only.
    #[serde(default)]
    source_id: String,
    /// The tool the user was trying to call, for the prompt context.
    #[serde(default)]
    tool_name: String,
}

impl IngressRequest {
    /// Parse the `ingress_approval_required` signal from a broker `tools/call`
    /// reply, or `None` when the reply does not carry one (the common, already
    /// trusted path).
    ///
    /// Gated on the boolean flag being explicitly `true`; any other shape
    /// (absent, `false`, non-bool) returns `None` and the caller treats the
    /// reply as a normal terminal result.
    pub(super) fn from_reply(reply: &Value) -> Option<Self> {
        if reply
            .get("ingress_approval_required")
            .and_then(Value::as_bool)
            != Some(true)
        {
            return None;
        }
        // Display fields are best-effort; default-deserialize so a signal
        // missing them still parses (it is the flag that matters).
        match serde_json::from_value::<Self>(reply.clone()) {
            Ok(req) => Some(req),
            Err(e) => {
                warn!(error = %e, "MCP shim: malformed ingress_approval_required signal; treating as present with no display fields");
                Some(IngressRequest {
                    source_id: String::new(),
                    tool_name: String::new(),
                })
            },
        }
    }

    /// Render the human-facing consent prompt. Only the tool name (display)
    /// is woven in; the `source_id` is shown for transparency but is not a
    /// secret.
    fn prompt(&self) -> String {
        let mut p = String::from(
            "An MCP client is asking Astrid to run tool calls through this session for the first time.",
        );
        // `write!` to a `String` is infallible; the `let _` discards the
        // always-`Ok` result without an `unwrap`.
        if !self.tool_name.is_empty() {
            let _ = write!(p, "\n\nFirst tool requested: {}", self.tool_name);
        }
        if !self.source_id.is_empty() {
            let _ = write!(p, "\nSession ingress: {}", self.source_id);
        }
        p.push_str("\n\nAllow Astrid tool calls from this session?");
        p
    }
}

/// Elicit the user's ingress-consent decision from `peer`.
///
/// Returns `true` only on an explicit accept of an `allow:true` form (wire)
/// or an equivalent host form dialog when the client has no elicitation.
/// Fail-secure: decline / cancel / empty / transport error / dialog fail all
/// return `false`.
pub(super) async fn elicit_consent(peer: &Peer<RoleServer>, request: &IngressRequest) -> bool {
    // Spec: only send elicitation/create when the client advertised a mode.
    // No modes → host form-shaped fallback (non-secret boolean), not deny-only.
    if peer.supported_elicitation_modes().is_empty() {
        debug!(
            "MCP shim: client did not advertise elicitation; using host form dialog for ingress"
        );
        return super::host_dialog::binary_form_consent(
            "Unicity AOS",
            &request.prompt(),
            "Allow",
            "Deny",
        )
        .await;
    }

    match super::form_elicitation::elicit::<IngressForm>(peer, request.prompt()).await {
        Ok(Some(form)) => {
            debug!(allow = form.allow, "MCP shim: ingress consent resolved");
            form.allow
        },
        Ok(None) => {
            warn!("MCP shim: ingress elicitation returned no content; denying");
            false
        },
        Err(ElicitationError::UserDeclined | ElicitationError::UserCancelled) => {
            debug!("MCP shim: user declined/cancelled ingress consent; denying");
            false
        },
        Err(ElicitationError::CapabilityNotSupported) => {
            debug!("MCP shim: client lacks elicitation capability; denying ingress consent");
            false
        },
        Err(e) => {
            warn!(error = %e, "MCP shim: ingress elicitation failed; denying");
            false
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn from_reply_parses_signal() {
        let reply = json!({
            "kind": "tool.call",
            "req_id": "r1",
            "ingress_approval_required": true,
            "source_id": "abc-123",
            "tool_name": "fs.read",
            "isError": false,
        });
        let req = IngressRequest::from_reply(&reply).expect("signal should parse");
        assert_eq!(req.source_id, "abc-123");
        assert_eq!(req.tool_name, "fs.read");
    }

    #[test]
    fn from_reply_none_when_absent_or_false() {
        let none = json!({ "kind": "tool.call", "content": [], "isError": false });
        assert!(IngressRequest::from_reply(&none).is_none());
        let falsey = json!({ "ingress_approval_required": false });
        assert!(IngressRequest::from_reply(&falsey).is_none());
        // Non-bool flag is not a valid signal.
        let nonbool = json!({ "ingress_approval_required": "yes" });
        assert!(IngressRequest::from_reply(&nonbool).is_none());
    }

    #[test]
    fn from_reply_present_with_missing_display_fields() {
        // The flag alone is a valid signal; display fields are best-effort.
        let reply = json!({ "ingress_approval_required": true });
        let req = IngressRequest::from_reply(&reply).expect("flag alone is a valid signal");
        assert_eq!(req.source_id, "");
        assert_eq!(req.tool_name, "");
    }

    #[test]
    fn form_schema_is_elicitation_safe() {
        let schema = rmcp::model::ElicitationSchema::from_type::<IngressForm>();
        assert!(
            schema.is_ok(),
            "IngressForm must produce a valid elicitation schema: {schema:?}"
        );
    }

    #[test]
    fn prompt_includes_tool_name_when_present() {
        let req = IngressRequest {
            source_id: "src-1".into(),
            tool_name: "shell.exec".into(),
        };
        let p = req.prompt();
        assert!(p.contains("shell.exec"));
        assert!(p.contains("Allow Astrid tool calls"));
    }
}
