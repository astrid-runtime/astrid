//! Agent-specific management API payloads.

use crate::PrincipalId;
use serde::{Deserialize, Serialize};

/// Explicit input for atomically provisioning one restricted derived agent.
///
/// Unlike ordinary principal inheritance, omitted capsule installs and state
/// namespaces are never copied into the derived runtime.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentDeriveRequest {
    /// New throwaway principal name.
    pub name: String,
    /// Existing principal whose selected capsule installs/state are used.
    pub source: PrincipalId,
    /// Capsule installs to materialize and load for the derived runtime.
    #[serde(default)]
    pub load_capsules: Vec<String>,
    /// Loaded capsules whose user-invocable tool surface may be dispatched.
    #[serde(default)]
    pub allow_capsules: Vec<String>,
    /// Capsule namespaces whose env, KV, and declared secrets are copied.
    #[serde(default)]
    pub inherit_capsule_state: Vec<String>,
    /// Outbound `host:port` patterns allowed for the restricted principal.
    /// Empty means no outbound network access.
    #[serde(default)]
    pub network_egress: Vec<String>,
}

/// Request envelope for the additive `astrid.v1.admin.agent.derive` endpoint.
///
/// Derivation intentionally has its own topic and envelope instead of adding a
/// variant to [`super::AdminRequestKind`], whose exhaustive public enum is a
/// compatibility contract for existing Rust clients.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentDeriveKernelRequest {
    /// Optional client correlation identifier, echoed in the response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// Explicit restricted-principal shape.
    #[serde(flatten)]
    pub request: AgentDeriveRequest,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_request_keeps_the_existing_tagged_admin_wire_shape() {
        let request = AgentDeriveKernelRequest {
            request_id: Some("request-1".into()),
            request: AgentDeriveRequest {
                name: "worker".into(),
                source: PrincipalId::default(),
                load_capsules: vec!["harness".into()],
                allow_capsules: Vec::new(),
                inherit_capsule_state: Vec::new(),
                network_egress: Vec::new(),
            },
        };
        let json = serde_json::to_value(request).unwrap();
        assert_eq!(json["request_id"], "request-1");
        assert_eq!(json["name"], "worker");
        assert_eq!(json["source"], "default");
        assert_eq!(json["load_capsules"][0], "harness");
    }

    #[test]
    fn legacy_derive_grants_are_ignored() {
        let request: AgentDeriveKernelRequest = serde_json::from_value(serde_json::json!({
            "name": "worker",
            "source": "default",
            "grants": ["*"],
            "load_capsules": ["harness"]
        }))
        .unwrap();

        assert_eq!(request.request.load_capsules, ["harness"]);
        assert!(
            serde_json::to_value(request)
                .unwrap()
                .get("grants")
                .is_none(),
            "derived principals must not accept caller-selected capability grants"
        );
    }
}
