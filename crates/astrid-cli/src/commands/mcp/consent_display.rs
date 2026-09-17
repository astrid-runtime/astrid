//! Structured consent *display* metadata for MCP form elicitation.
//!
//! This is an Astrid display extension, not a new MCP spec. It rides in
//! request `_meta` under the namespaced key [`CONSENT_META_KEY`]. Strict
//! clients that ignore unknown `_meta` still see the existing message plus
//! interoperable form schema.
//!
//! `kind` and `choices` describe presentation semantics, not authority.
//! Authorization stays in the host-owned request/response path. Consumers
//! MUST NOT infer capsule grants, capability approval, or ingress trust from
//! this metadata or form field names such as `grant`, `choice`, or `allow`.
//!
//! `reason` is host-generated display text. Guest WIT `approval-request`
//! carries only `action` and `target-resource`; it has no reason field,
//! and this module never treats a guest string as a reason claim.
//!
//! Routing tokens (`request_id`, `call_id`, ingress `source_id`) are never
//! placed in this map. Serialized `principal` and `capsule` on capsule-access
//! payloads are display-only labels; authorization stays host-side and is
//! not inferred from these fields.

use rmcp::model::RequestMetaObject;
use serde::Serialize;

/// Namespaced request `_meta` key. Unknown `_meta` is ignored by
/// spec-compliant clients.
pub(super) const CONSENT_META_KEY: &str = "org.astrid/consent";

/// Display-extension version carried in every payload.
pub(super) const CONSENT_VERSION: u32 = 1;

/// Shim-authored consent kind. Never inferred from AOS/form field names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ConsentKind {
    CapsuleAccess,
    ActionApproval,
    Ingress,
}

/// Current host lifetime claim for one form choice.
///
/// Durable choices persist before approval success is reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ConsentLifetime {
    None,
    Session,
    Durable,
}

/// Form-field value the user returns. Boolean kinds use `bool`; action
/// approval uses the existing `choice` tokens (`approve_once`, …).
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(untagged)]
pub(super) enum ConsentChoiceValue {
    Bool(bool),
    Token(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub(super) struct ConsentChoice {
    pub(super) value: ConsentChoiceValue,
    pub(super) lifetime: ConsentLifetime,
}

/// Display-only consent descriptor serialized under [`CONSENT_META_KEY`].
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(super) struct ConsentDisplay {
    version: u32,
    kind: ConsentKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resource: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    principal: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    capsule: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool: Option<String>,
    choices: Vec<ConsentChoice>,
}

impl ConsentDisplay {
    fn base(kind: ConsentKind, choices: Vec<ConsentChoice>) -> Self {
        Self {
            version: CONSENT_VERSION,
            kind,
            action: None,
            resource: None,
            reason: None,
            principal: None,
            capsule: None,
            tool: None,
            choices,
        }
    }

    /// Capability approval: `{choice: enum}` with persisted Always grants.
    pub(super) fn action_approval() -> Self {
        Self::base(
            ConsentKind::ActionApproval,
            vec![
                choice_token("approve_once", ConsentLifetime::None),
                choice_token("approve_session", ConsentLifetime::Session),
                choice_token("approve_always", ConsentLifetime::Durable),
                choice_token("deny", ConsentLifetime::None),
            ],
        )
    }

    /// Grant-on-use: `{grant: bool}`. `true` is durable `profile.capsules`.
    pub(super) fn capsule_access() -> Self {
        Self::base(
            ConsentKind::CapsuleAccess,
            vec![
                choice_bool(true, ConsentLifetime::Durable),
                choice_bool(false, ConsentLifetime::None),
            ],
        )
    }

    /// Ingress trust: `{allow: bool}`. `true` lasts this MCP session.
    pub(super) fn ingress() -> Self {
        Self::base(
            ConsentKind::Ingress,
            vec![
                choice_bool(true, ConsentLifetime::Session),
                choice_bool(false, ConsentLifetime::None),
            ],
        )
    }

    pub(super) fn with_action(mut self, value: impl Into<String>) -> Self {
        self.action = nonempty(value);
        self
    }

    pub(super) fn with_resource(mut self, value: impl Into<String>) -> Self {
        self.resource = nonempty(value);
        self
    }

    /// Host-generated justification only. Empty strings are omitted.
    pub(super) fn with_reason(mut self, value: impl Into<String>) -> Self {
        self.reason = nonempty(value);
        self
    }

    pub(super) fn with_principal(mut self, value: impl Into<String>) -> Self {
        self.principal = nonempty(value);
        self
    }

    pub(super) fn with_capsule(mut self, value: impl Into<String>) -> Self {
        self.capsule = nonempty(value);
        self
    }

    pub(super) fn with_tool(mut self, value: impl Into<String>) -> Self {
        self.tool = nonempty(value);
        self
    }

    /// Request `_meta` map containing only [`CONSENT_META_KEY`].
    pub(super) fn to_request_meta(&self) -> RequestMetaObject {
        let value = serde_json::to_value(self)
            .expect("ConsentDisplay is a closed JSON shape and must serialize");
        let mut meta = RequestMetaObject::new();
        meta.insert(CONSENT_META_KEY.to_owned(), value);
        meta
    }
}

fn nonempty(value: impl Into<String>) -> Option<String> {
    let value = value.into();
    if value.is_empty() { None } else { Some(value) }
}

fn choice_token(value: &'static str, lifetime: ConsentLifetime) -> ConsentChoice {
    ConsentChoice {
        value: ConsentChoiceValue::Token(value),
        lifetime,
    }
}

fn choice_bool(value: bool, lifetime: ConsentLifetime) -> ConsentChoice {
    ConsentChoice {
        value: ConsentChoiceValue::Bool(value),
        lifetime,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use astrid_core::PrincipalId;
    use rmcp::model::{CallToolResponse, ElicitRequestParams};
    use serde_json::{Value, json};

    use super::super::elicit::{ApprovalForm, ApprovalRequest};
    use super::super::form_elicitation::{form_params, interoperable_schema};
    use super::super::grant::{GrantForm, GrantRequest, GrantSignal};
    use super::super::ingress::{IngressForm, IngressRequest};
    use super::super::mrtr::MrtrBridge;
    use super::*;

    fn consent_from_params(params: &ElicitRequestParams) -> Value {
        let wire = serde_json::to_value(params).expect("params should serialize");
        assert_eq!(wire["mode"], "form");
        let schema_keys: BTreeSet<_> = wire["requestedSchema"]
            .as_object()
            .expect("requestedSchema object")
            .keys()
            .map(String::as_str)
            .collect();
        let allowed = BTreeSet::from(["$schema", "properties", "required", "type"]);
        assert!(
            schema_keys.is_subset(&allowed),
            "consent must not add requestedSchema keys: {:?}",
            schema_keys.difference(&allowed).collect::<Vec<_>>()
        );
        wire["_meta"][CONSENT_META_KEY].clone()
    }

    #[test]
    fn action_approval_serializes_choice_lifetimes_and_omits_routing() {
        let reply = json!({
            "approval_required": {
                "request_id": "req-secret",
                "action": "git push",
                "resource": "origin main",
                "reason": "host-generated justification",
                "tool_name": "shell_exec",
                "call_id": "call-secret"
            }
        });
        let request = ApprovalRequest::from_reply(&reply).expect("flag");
        let params = form_params::<ApprovalForm>(request.prompt(), &request.consent_display())
            .expect("form params");
        let consent = consent_from_params(&params);
        assert_eq!(consent["version"], 1);
        assert_eq!(consent["kind"], "action_approval");
        assert_eq!(consent["action"], "git push");
        assert_eq!(consent["resource"], "origin main");
        assert_eq!(consent["reason"], "host-generated justification");
        assert_eq!(consent["tool"], "shell_exec");
        assert_eq!(
            consent["choices"],
            json!([
                {"value": "approve_once", "lifetime": "none"},
                {"value": "approve_session", "lifetime": "session"},
                {"value": "approve_always", "lifetime": "durable"},
                {"value": "deny", "lifetime": "none"}
            ])
        );
        for forbidden in ["request_id", "call_id", "principal", "capsule"] {
            assert!(
                consent.get(forbidden).is_none(),
                "{forbidden} must be absent"
            );
        }
        let blob = consent.to_string();
        assert!(!blob.contains("req-secret"));
        assert!(!blob.contains("call-secret"));
    }

    #[test]
    fn capsule_access_serializes_bool_choices_and_omits_grant_id() {
        let reply = json!({
            "grant_required": {
                "request_id": "grant-secret",
                "capsule_id": "shell",
                "principal": "claude-code",
                "tool_name": "shell.exec",
                "call_id": "call-secret"
            }
        });
        let GrantSignal::Present(request) = GrantRequest::classify(&reply) else {
            panic!("present grant signal");
        };
        let params = form_params::<GrantForm>(request.prompt(), &request.consent_display())
            .expect("form params");
        let consent = consent_from_params(&params);
        assert_eq!(consent["kind"], "capsule_access");
        assert_eq!(consent["capsule"], "shell");
        assert_eq!(consent["principal"], "claude-code");
        assert_eq!(consent["tool"], "shell.exec");
        assert_eq!(
            consent["choices"],
            json!([
                {"value": true, "lifetime": "durable"},
                {"value": false, "lifetime": "none"}
            ])
        );
        for forbidden in ["request_id", "call_id", "action", "resource", "reason"] {
            assert!(
                consent.get(forbidden).is_none(),
                "{forbidden} must be absent"
            );
        }
        assert!(!consent.to_string().contains("grant-secret"));
    }

    #[test]
    fn ingress_omits_source_id_and_empty_identity() {
        let reply = json!({
            "ingress_approval_required": true,
            "source_id": "src-secret",
            "tool_name": "fs.read"
        });
        let request = IngressRequest::from_reply(&reply).expect("signal");
        let params = form_params::<IngressForm>(request.prompt(), &request.consent_display())
            .expect("form params");
        let consent = consent_from_params(&params);
        assert_eq!(consent["kind"], "ingress");
        assert_eq!(consent["tool"], "fs.read");
        assert_eq!(
            consent["choices"],
            json!([
                {"value": true, "lifetime": "session"},
                {"value": false, "lifetime": "none"}
            ])
        );
        for forbidden in [
            "source_id",
            "request_id",
            "call_id",
            "action",
            "resource",
            "reason",
            "principal",
            "capsule",
        ] {
            assert!(
                consent.get(forbidden).is_none(),
                "{forbidden} must be absent"
            );
        }
        assert!(!consent.to_string().contains("src-secret"));
    }

    #[test]
    fn empty_display_fields_are_omitted_not_null() {
        let display = ConsentDisplay::action_approval()
            .with_action("")
            .with_resource("")
            .with_reason("")
            .with_tool("");
        let wire = serde_json::to_value(&display).expect("display json");
        for key in [
            "action",
            "resource",
            "reason",
            "principal",
            "capsule",
            "tool",
        ] {
            assert!(wire.get(key).is_none(), "{key} must be omitted when empty");
        }
        assert_eq!(wire["kind"], "action_approval");
        assert_eq!(wire["version"], 1);
    }

    #[test]
    fn form_params_keep_interoperable_schema_keys_only() {
        let schema = serde_json::to_value(interoperable_schema::<ApprovalForm>().expect("schema"))
            .expect("schema json");
        let params = form_params::<ApprovalForm>(
            "Approve this request?",
            &ConsentDisplay::action_approval(),
        )
        .expect("params");
        let wire = serde_json::to_value(params).expect("params json");
        assert_eq!(wire["requestedSchema"], schema);
        assert!(wire["_meta"][CONSENT_META_KEY].is_object());
        assert!(wire["requestedSchema"].get("_meta").is_none());
        assert!(wire["requestedSchema"].get("title").is_none());
        assert!(wire["requestedSchema"].get("description").is_none());
    }

    fn consent_from_mrtr(response: CallToolResponse) -> Value {
        let CallToolResponse::InputRequired(result) = response else {
            panic!("expected input_required");
        };
        let request = result
            .input_requests
            .as_ref()
            .expect("inputRequests")
            .get("astrid-consent")
            .expect("astrid-consent");
        let wire = serde_json::to_value(request).expect("request json");
        assert_eq!(wire["params"]["mode"], "form");
        wire["params"]["_meta"][CONSENT_META_KEY].clone()
    }

    #[test]
    fn mrtr_input_requests_carry_identical_consent_meta() {
        let bridge = MrtrBridge::new().expect("signing key");
        let principal = PrincipalId::new("codex-code").unwrap();
        let arguments = json!({});

        let ingress = consent_from_mrtr(
            bridge
                .ingress_required(&principal, "fs.read", &arguments, "Allow?".into())
                .expect("ingress mrtr"),
        );
        let ingress_legacy = consent_from_params(
            &form_params::<IngressForm>("Allow?", &ConsentDisplay::ingress().with_tool("fs.read"))
                .expect("legacy ingress"),
        );
        assert_eq!(ingress, ingress_legacy);
        assert_eq!(ingress["kind"], "ingress");
        assert_eq!(ingress["tool"], "fs.read");

        let GrantSignal::Present(grant_request) = GrantRequest::classify(&json!({
            "grant_required": {
                "request_id": "grant-secret",
                "capsule_id": "shell",
                "principal": "claude-code",
                "tool_name": "shell.exec"
            }
        })) else {
            panic!("present grant");
        };
        let grant = consent_from_mrtr(
            bridge
                .grant_required(
                    &principal,
                    "shell.exec",
                    &arguments,
                    grant_request.clone(),
                    0,
                    grant_request.prompt(),
                )
                .expect("grant mrtr"),
        );
        let grant_legacy = consent_from_params(
            &form_params::<GrantForm>(grant_request.prompt(), &grant_request.consent_display())
                .expect("legacy grant"),
        );
        assert_eq!(grant, grant_legacy);
        assert!(grant.get("request_id").is_none());

        let approval_request = ApprovalRequest::from_reply(&json!({
            "approval_required": {
                "request_id": "req-secret",
                "action": "git push",
                "resource": "origin main",
                "reason": "host-generated justification",
                "tool_name": "shell_exec",
                "call_id": "call-secret"
            }
        }))
        .expect("approval flag");
        let approval = consent_from_mrtr(
            bridge
                .approval_required(
                    &principal,
                    "shell_exec",
                    &arguments,
                    approval_request.clone(),
                    approval_request.prompt(),
                )
                .expect("approval mrtr"),
        );
        let approval_legacy = consent_from_params(
            &form_params::<ApprovalForm>(
                approval_request.prompt(),
                &approval_request.consent_display(),
            )
            .expect("legacy approval"),
        );
        assert_eq!(approval, approval_legacy);
        assert_eq!(approval["kind"], "action_approval");
        assert!(approval.get("request_id").is_none());
        assert!(approval.get("call_id").is_none());
    }
}
