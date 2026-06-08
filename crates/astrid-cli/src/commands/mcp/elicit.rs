//! Shim-side approval elicitation: relay broker approval prompts to the
//! MCP client via [`Peer::elicit`].
//!
//! When a `tools/call` reply carries an `approval_required` flag, the
//! routed capsule tool is parked host-side on a capability approval and the
//! broker is waiting for a decision. The broker cannot call the host
//! `astrid:elicit` syscall (it is install/upgrade-gated), so it relays the
//! bus envelope and asks this shim to collect the choice from the connected
//! MCP client. We do that with [`Peer::elicit`], map the chosen variant onto
//! the broker's decision verb, and forward it through the
//! `astrid.v1.request.mcp.approval.respond` front door — meeting the broker
//! contract documented in `sage-mcp::approval`.
//!
//! ## Contract (must match `sage-mcp::approval`)
//!
//! * The reply flag carries `{ request_id, action, resource, reason,
//!   tool_name, call_id }` — host-sanitized display fields plus the routing
//!   tokens the broker needs to re-establish the result drain. None of these
//!   are secrets; the bridge never round-trips a tool argument.
//! * The respond body the broker expects is `{ req_id, request_id, decision,
//!   tool_name, call_id, reason? }`, where `req_id` is a fresh proxy
//!   correlation token (the terminal reply lands on
//!   `astrid.v1.response.<req_id>`), `request_id` / `tool_name` / `call_id`
//!   are echoed verbatim from the flag, and `decision` is one of the four
//!   host approval verbs.
//! * The terminal reply has the same `{ content, isError }` shape a
//!   non-parked `tools/call` reply has, so it reshapes identically.
//!
//! ## Capability gating and fail-secure
//!
//! Elicitation is attempted ONLY when the client advertised the elicitation
//! capability at `initialize` (checked via
//! [`Peer::supported_elicitation_modes`]). When the client did not, or the
//! user declines / cancels / the elicit transport errors, we fall through to
//! a `Deny` decision: the broker publishes `deny`, the parked tool retires
//! cleanly host-side, and the shim returns the resulting `isError` terminal
//! reply rather than leaving the tool to time out. Fail secure — the absence
//! of an explicit approval is never treated as consent.
//!
//! ## Never elicit secrets
//!
//! The elicited type ([`ApprovalForm`]) is a single constrained-string
//! `choice` field. No free-form text, no tool argument, and no secret is
//! ever surfaced to the client or round-tripped back into the tool. The
//! prompt rendered to the user is built only from the host-sanitized
//! display fields the flag carries.

use std::fmt::Write as _;

use rmcp::schemars::{self, JsonSchema};
use rmcp::service::{ElicitationError, Peer, RoleServer};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tracing::{debug, warn};

/// Broker front door for the shim's elicited approval choice. Maps to
/// `sage-mcp::SageMcp::handle_mcp_approval`.
pub(super) const APPROVAL_RESPOND_TOPIC: &str = "astrid.v1.request.mcp.approval.respond";

/// The user's approval choice, as a flat single-property object so it
/// satisfies rmcp's [`ElicitationSafe`] object-schema requirement.
///
/// The `choice` field is an inlined string-enum (see [`ApprovalChoice`]);
/// `#[schemars(inline)]` on the enum is load-bearing — without it schemars
/// emits a `$ref` into `$defs` that `ElicitationSchema::from_type` cannot
/// flatten into the primitive-property schema the MCP elicitation spec
/// requires, and the elicit call would fail at runtime.
#[derive(Debug, Deserialize, JsonSchema)]
pub(super) struct ApprovalForm {
    /// The selected approval decision.
    pub(super) choice: ApprovalChoice,
}

rmcp::elicit_safe!(ApprovalForm);

/// The four approval decisions, mirroring the host's recognised verbs:
/// `approve_once` (this invocation only), `approve_session` (remainder of
/// the session), `approve_always` (persist the grant), and `deny`.
///
/// Marked `#[schemars(inline)]` so it renders inline as
/// `{ "type": "string", "enum": [...] }` on the parent `choice` property
/// rather than as a `$ref` — required for [`ApprovalForm`] to be a valid
/// elicitation schema. The variants are deliberately left WITHOUT per-variant
/// doc comments: a documented variant makes schemars emit a `oneOf` of
/// `const` strings instead of a flat `enum`, which the MCP `PrimitiveSchema`
/// rejects. Variants are `snake_case`-serialized; [`Self::verb`] maps each
/// onto the exact decision string the broker's `normalize_decision` accepts.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[schemars(inline)]
pub(super) enum ApprovalChoice {
    ApproveOnce,
    ApproveSession,
    ApproveAlways,
    Deny,
}

impl ApprovalChoice {
    /// Map the choice onto the broker decision verb. These strings are the
    /// exact tokens `sage-mcp::approval::normalize_decision` recognises;
    /// anything else collapses to `deny` broker-side, but we never emit
    /// anything else.
    ///
    /// NOTE: the broker reads THIS verb, never the variant's `snake_case`
    /// serialization — they deliberately differ (`ApproveOnce` serializes
    /// to `approve_once` but its verb is the bare `approve`). Always forward
    /// `verb()`; never send the serialized name to the broker.
    fn verb(self) -> &'static str {
        match self {
            Self::ApproveOnce => "approve",
            Self::ApproveSession => "approve_session",
            Self::ApproveAlways => "approve_always",
            Self::Deny => "deny",
        }
    }
}

/// The `approval_required` flag a parked `tools/call` reply carries.
///
/// All fields are host-sanitized display strings or routing tokens — no
/// secret and no tool argument. `request_id` / `tool_name` / `call_id` are
/// echoed verbatim back to the broker so it can route the decision and
/// re-establish the result drain; `action` / `resource` / `reason` are
/// rendered into the elicitation prompt for the user.
#[derive(Debug, Deserialize)]
pub(super) struct ApprovalRequest {
    /// Host-minted approval correlation id; echoed onto the respond body.
    request_id: String,
    /// The action being requested (e.g. `"git push"`). Display only.
    #[serde(default)]
    action: String,
    /// The resource target (e.g. the command string). Display only.
    #[serde(default)]
    resource: String,
    /// Justification shown to the user. Display only.
    #[serde(default)]
    reason: String,
    /// The dispatch tool name; echoed back so the broker re-subscribes to
    /// the correct `tool.v1.execute.<name>.result` topic.
    tool_name: String,
    /// The dispatch correlation id; echoed back so the broker drains the
    /// matching result.
    call_id: String,
}

impl ApprovalRequest {
    /// Parse the `approval_required` flag from a broker `tools/call` reply,
    /// or `None` when the reply does not carry one (the common,
    /// non-parked path).
    ///
    /// A flag present but missing the routing tokens (`request_id` /
    /// `tool_name` / `call_id`) cannot be answered — it deserializes to
    /// `None` and the caller falls through to the non-elicit path. This is
    /// a shape check, not a trust check: the broker mints these fields.
    pub(super) fn from_reply(reply: &Value) -> Option<Self> {
        let flag = reply.get("approval_required")?;
        match serde_json::from_value::<Self>(flag.clone()) {
            Ok(req) if !req.request_id.is_empty() => Some(req),
            Ok(_) => {
                warn!("MCP shim: approval_required flag missing request_id; ignoring");
                None
            },
            Err(e) => {
                warn!(error = %e, "MCP shim: malformed approval_required flag; ignoring");
                None
            },
        }
    }

    /// Build the respond body the broker expects on
    /// [`APPROVAL_RESPOND_TOPIC`]. `req_id` is the fresh proxy correlation
    /// token for the terminal reply; `decision` is the chosen verb. No
    /// `reason` is forwarded — the shim has no free-form audit text to add,
    /// and omitting it keeps the bridge strictly to the constrained verb.
    fn respond_body(&self, req_id: &str, decision: &str) -> Value {
        json!({
            "req_id": req_id,
            "request_id": self.request_id,
            "decision": decision,
            "tool_name": self.tool_name,
            "call_id": self.call_id,
        })
    }

    /// Render the human-facing elicitation prompt from the host-sanitized
    /// display fields. Only `action` / `resource` / `reason` are shown; the
    /// routing tokens never reach the user.
    fn prompt(&self) -> String {
        let mut p = String::from("A capsule tool is requesting capability approval.");
        // `write!` to a `String` is infallible; the `let _` discards the
        // always-`Ok` result without an `unwrap`.
        if !self.action.is_empty() {
            let _ = write!(p, "\n\nAction: {}", self.action);
        }
        if !self.resource.is_empty() {
            let _ = write!(p, "\nResource: {}", self.resource);
        }
        if !self.reason.is_empty() {
            let _ = write!(p, "\nReason: {}", self.reason);
        }
        p.push_str("\n\nApprove this request?");
        p
    }
}

/// Resolve an approval `request` by eliciting a choice from `peer` and
/// returning the broker decision verb plus the respond body to forward on
/// [`APPROVAL_RESPOND_TOPIC`].
///
/// `req_id` is the fresh proxy correlation token the terminal reply will be
/// keyed on. The returned tuple is `(decision_verb, respond_body)`.
///
/// Fail-secure: if `peer` did not advertise elicitation at initialize, or
/// the user declines / cancels, or the elicit transport errors, the
/// decision is `deny`. Only an explicit accept of an approve-variant grants.
pub(super) async fn resolve_decision(
    peer: &Peer<RoleServer>,
    request: &ApprovalRequest,
    req_id: &str,
) -> (&'static str, Value) {
    let choice = elicit_choice(peer, request).await;
    let verb = choice.verb();
    debug!(
        decision = verb,
        tool = %request.tool_name,
        "MCP shim: approval decision resolved"
    );
    (verb, request.respond_body(req_id, verb))
}

/// Elicit a single [`ApprovalChoice`] from the client, defaulting to
/// [`ApprovalChoice::Deny`] on every non-accept outcome.
async fn elicit_choice(peer: &Peer<RoleServer>, request: &ApprovalRequest) -> ApprovalChoice {
    // Only elicit if the client advertised the capability at initialize.
    // `elicit` itself also guards this, but checking first lets us log the
    // precise reason and skip building a prompt the client cannot render.
    if peer.supported_elicitation_modes().is_empty() {
        debug!("MCP shim: client did not advertise elicitation; defaulting approval to deny");
        return ApprovalChoice::Deny;
    }

    match peer.elicit::<ApprovalForm>(request.prompt()).await {
        Ok(Some(form)) => form.choice,
        Ok(None) => {
            // Accepted but no content — treat as no decision -> deny.
            warn!("MCP shim: elicitation returned no content; defaulting approval to deny");
            ApprovalChoice::Deny
        },
        Err(ElicitationError::UserDeclined | ElicitationError::UserCancelled) => {
            debug!("MCP shim: user declined/cancelled approval; denying");
            ApprovalChoice::Deny
        },
        Err(ElicitationError::CapabilityNotSupported) => {
            debug!("MCP shim: client lacks elicitation capability; denying");
            ApprovalChoice::Deny
        },
        Err(e) => {
            warn!(error = %e, "MCP shim: elicitation failed; defaulting approval to deny");
            ApprovalChoice::Deny
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn choice_maps_to_broker_verbs() {
        assert_eq!(ApprovalChoice::ApproveOnce.verb(), "approve");
        assert_eq!(ApprovalChoice::ApproveSession.verb(), "approve_session");
        assert_eq!(ApprovalChoice::ApproveAlways.verb(), "approve_always");
        assert_eq!(ApprovalChoice::Deny.verb(), "deny");
    }

    #[test]
    fn form_schema_is_elicitation_safe() {
        // The inlined string-enum must flatten into a valid elicitation
        // schema; a `$ref`- or `oneOf`-based schema would fail here at
        // runtime and the elicit call would always error. Lock the shape
        // down so a future derive/macro/doc-comment change that breaks
        // inlining is caught (per-variant docs, for instance, make schemars
        // emit a rejected `oneOf` of `const`s).
        let schema = rmcp::model::ElicitationSchema::from_type::<ApprovalForm>();
        assert!(
            schema.is_ok(),
            "ApprovalForm must produce a valid elicitation schema: {schema:?}"
        );
    }

    #[test]
    fn from_reply_parses_flag() {
        let reply = json!({
            "kind": "tool.call",
            "content": [],
            "isError": false,
            "approval_required": {
                "request_id": "req-123",
                "action": "git push",
                "resource": "origin main",
                "reason": "needs network",
                "tool_name": "shell_exec",
                "call_id": "call-abc"
            }
        });
        let req = ApprovalRequest::from_reply(&reply).expect("flag should parse");
        assert_eq!(req.request_id, "req-123");
        assert_eq!(req.tool_name, "shell_exec");
        assert_eq!(req.call_id, "call-abc");
    }

    #[test]
    fn from_reply_none_when_absent() {
        let reply = json!({ "kind": "tool.call", "content": [], "isError": false });
        assert!(ApprovalRequest::from_reply(&reply).is_none());
    }

    #[test]
    fn from_reply_none_when_request_id_blank() {
        let reply = json!({
            "approval_required": {
                "request_id": "",
                "tool_name": "t",
                "call_id": "c"
            }
        });
        assert!(ApprovalRequest::from_reply(&reply).is_none());
    }

    #[test]
    fn respond_body_echoes_routing_tokens() {
        let req = ApprovalRequest {
            request_id: "req-1".into(),
            action: String::new(),
            resource: String::new(),
            reason: String::new(),
            tool_name: "tool-x".into(),
            call_id: "call-y".into(),
        };
        let body = req.respond_body("proxy-req", "approve_session");
        assert_eq!(body["req_id"], "proxy-req");
        assert_eq!(body["request_id"], "req-1");
        assert_eq!(body["decision"], "approve_session");
        assert_eq!(body["tool_name"], "tool-x");
        assert_eq!(body["call_id"], "call-y");
        // The bridge never forwards free-form text into the tool.
        assert!(body.get("reason").is_none());
    }

    #[test]
    fn prompt_renders_only_display_fields() {
        let req = ApprovalRequest {
            request_id: "secret-routing-id".into(),
            action: "git push".into(),
            resource: "origin main".into(),
            reason: "deploy".into(),
            tool_name: "tool-routing".into(),
            call_id: "call-routing".into(),
        };
        let prompt = req.prompt();
        assert!(prompt.contains("git push"));
        assert!(prompt.contains("origin main"));
        assert!(prompt.contains("deploy"));
        // Routing tokens must never leak into the user-facing prompt.
        assert!(!prompt.contains("secret-routing-id"));
        assert!(!prompt.contains("tool-routing"));
        assert!(!prompt.contains("call-routing"));
    }
}
