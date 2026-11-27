//! MCP 2026 multi-round-trip consent bridge.
//!
//! The client echoes `requestState` as untrusted input. Every state token is
//! integrity-protected, expires, and is bound to the authenticated Astrid
//! principal plus the exact tool name and argument digest. Broker correlation
//! identifiers remain kernel-minted and are useful only for that principal.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::time::Instant;

use astrid_core::PrincipalId;
use rand::RngExt;
use rmcp::ErrorData as McpError;
use rmcp::model::{
    CallToolResponse, ElicitRequest, ElicitResult, ElicitationAction, InputRequest,
    InputRequiredResult, InputResponses, RequestStateCodec, SealOptions,
};
use rmcp::service::ElicitationSafe;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::consent_display::ConsentDisplay;
use super::elicit::{ApprovalChoice, ApprovalForm, ApprovalRequest};
use super::form_elicitation::form_params;
use super::grant::{GrantForm, GrantRequest};
use super::ingress::IngressForm;

#[path = "mrtr_context.rs"]
mod context;
#[path = "mrtr_redemption.rs"]
mod redemption;

const INPUT_KEY: &str = "astrid-consent";
const STATE_TTL: Duration = Duration::from_mins(5);

#[derive(Debug, Serialize, Deserialize)]
pub(super) enum PendingConsent {
    Ingress,
    Grant {
        request: GrantRequest,
        grants_resolved: usize,
    },
    Approval {
        request: ApprovalRequest,
    },
}

pub(super) enum ConsentResolution {
    Ingress(bool),
    Grant {
        request: GrantRequest,
        approved: bool,
        grants_resolved: usize,
    },
    Approval {
        request: ApprovalRequest,
        choice: ApprovalChoice,
    },
}

pub(super) struct ResolvedConsent {
    pub(super) decision: ConsentResolution,
    pub(super) redemption: RedemptionLease,
}

pub(super) struct RedemptionLease {
    redeemed: Arc<Mutex<HashMap<[u8; 32], Instant>>>,
    claim: redemption::Claim,
}

impl RedemptionLease {
    pub(super) fn commit(mut self) {
        self.claim.commit();
    }
}

impl Drop for RedemptionLease {
    fn drop(&mut self) {
        if self.claim.committed() {
            return;
        }
        if let Ok(mut redeemed) = self.redeemed.lock() {
            self.claim.on_drop(&mut redeemed);
        }
    }
}

pub(super) struct MrtrBridge {
    codec: RequestStateCodec,
    /// One-time redemption fence. The stdio shim is one server process; a
    /// future replicated HTTP frontend must move this fence into shared
    /// durable state before reusing this bridge.
    redeemed: Arc<Mutex<HashMap<[u8; 32], Instant>>>,
}

impl MrtrBridge {
    pub(super) fn new() -> Result<Self, McpError> {
        let mut key = [0_u8; RequestStateCodec::MIN_KEY_LENGTH];
        rand::rng().fill(&mut key);
        Self::from_key(key)
    }

    fn from_key(key: impl Into<Vec<u8>>) -> Result<Self, McpError> {
        let codec = RequestStateCodec::try_new(key).map_err(|error| {
            McpError::internal_error(format!("invalid MRTR signing key: {error}"), None)
        })?;
        Ok(Self {
            codec,
            redeemed: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub(super) fn ingress_required(
        &self,
        principal: &PrincipalId,
        tool: &str,
        arguments: &Value,
        prompt: String,
    ) -> Result<CallToolResponse, McpError> {
        self.input_required::<IngressForm>(
            principal,
            tool,
            arguments,
            &PendingConsent::Ingress,
            prompt,
        )
    }

    pub(super) fn grant_required(
        &self,
        principal: &PrincipalId,
        tool: &str,
        arguments: &Value,
        request: GrantRequest,
        grants_resolved: usize,
        prompt: String,
    ) -> Result<CallToolResponse, McpError> {
        self.input_required::<GrantForm>(
            principal,
            tool,
            arguments,
            &PendingConsent::Grant {
                request,
                grants_resolved,
            },
            prompt,
        )
    }

    pub(super) fn approval_required(
        &self,
        principal: &PrincipalId,
        tool: &str,
        arguments: &Value,
        request: ApprovalRequest,
        prompt: String,
    ) -> Result<CallToolResponse, McpError> {
        self.input_required::<ApprovalForm>(
            principal,
            tool,
            arguments,
            &PendingConsent::Approval { request },
            prompt,
        )
    }

    fn input_required<T>(
        &self,
        principal: &PrincipalId,
        tool: &str,
        arguments: &Value,
        pending: &PendingConsent,
        prompt: String,
    ) -> Result<CallToolResponse, McpError>
    where
        T: ElicitationSafe,
    {
        let associated_data = associated_data(principal, tool, arguments);
        let state = self
            .codec
            .seal_json_with(
                &pending,
                &SealOptions::new()
                    .associated_data(&associated_data)
                    .ttl(STATE_TTL),
            )
            .map_err(|error| McpError::internal_error(error.to_string(), None))?;

        let params = form_params::<T>(prompt, &consent_display_for(pending, tool, principal))
            .map_err(|error| {
                McpError::internal_error(format!("failed to build consent schema: {error}"), None)
            })?;
        let request = ElicitRequest::new(params);
        let mut requests = BTreeMap::new();
        requests.insert(INPUT_KEY.to_owned(), InputRequest::Elicitation(request));
        Ok(InputRequiredResult::new(Some(requests), Some(state)).into())
    }

    pub(super) fn resolve(
        &self,
        principal: &PrincipalId,
        tool: &str,
        arguments: &Value,
        state: &str,
        responses: Option<&InputResponses>,
    ) -> Result<ResolvedConsent, McpError> {
        let associated_data = associated_data(principal, tool, arguments);
        let (pending, redemption) = context::open_and_redeem(
            state,
            &associated_data,
            |token, binding| {
                self.codec
                    .open_json_with(token, binding)
                    .map_err(|error| McpError::invalid_params(error.to_string(), None))
            },
            |token| self.redeem_once(token),
        )?;
        let response = responses.and_then(|values| values.get(INPUT_KEY));

        let decision = match pending {
            PendingConsent::Ingress => ConsentResolution::Ingress(
                accepted_form::<IngressForm>(response).is_some_and(|form| form.allow),
            ),
            PendingConsent::Grant {
                request,
                grants_resolved,
            } => ConsentResolution::Grant {
                request,
                approved: accepted_form::<GrantForm>(response).is_some_and(|form| form.grant),
                grants_resolved,
            },
            PendingConsent::Approval { request } => ConsentResolution::Approval {
                request,
                choice: accepted_form::<ApprovalForm>(response)
                    .map_or(ApprovalChoice::Deny, |form| form.choice),
            },
        };
        Ok(ResolvedConsent {
            decision,
            redemption,
        })
    }

    fn redeem_once(&self, state: &str) -> Result<RedemptionLease, McpError> {
        let now = Instant::now();
        let digest = *blake3::hash(state.as_bytes()).as_bytes();
        let mut redeemed = self
            .redeemed
            .lock()
            .map_err(|_| McpError::internal_error("MRTR replay fence is poisoned", None))?;
        redeemed.retain(|_, expiry| *expiry > now);
        let expiry = now
            .checked_add(STATE_TTL)
            .ok_or_else(|| McpError::internal_error("MRTR replay-fence deadline overflow", None))?;
        let claim = redemption::reserve(&mut redeemed, digest, expiry).ok_or_else(|| {
            McpError::invalid_params("requestState has already been redeemed", None)
        })?;
        Ok(RedemptionLease {
            redeemed: Arc::clone(&self.redeemed),
            claim,
        })
    }
}

fn consent_display_for(
    pending: &PendingConsent,
    tool: &str,
    principal: &PrincipalId,
) -> ConsentDisplay {
    match pending {
        PendingConsent::Ingress => ConsentDisplay::ingress()
            .with_tool(tool)
            .with_principal(principal.to_string()),
        PendingConsent::Grant { request, .. } => request.consent_display(),
        PendingConsent::Approval { request } => request.consent_display(),
    }
}

fn accepted_form<T>(response: Option<&Value>) -> Option<T>
where
    T: for<'de> Deserialize<'de>,
{
    let result: ElicitResult = serde_json::from_value(response?.clone()).ok()?;
    match result.action {
        ElicitationAction::Accept => serde_json::from_value(result.content?).ok(),
        _ => None,
    }
}

impl context::Digest for blake3::Hasher {
    fn absorb(&mut self, chunk: &[u8]) {
        self.update(chunk);
    }
}

fn associated_data(principal: &PrincipalId, tool: &str, arguments: &Value) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new();
    let encoded = serde_json::to_vec(arguments).unwrap_or_default();
    context::absorb_context(
        &mut hasher,
        principal.as_str().as_bytes(),
        tool.as_bytes(),
        &encoded,
    );
    hasher.finalize().as_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use rmcp::model::CallToolResponse;
    use serde_json::json;

    use super::*;

    fn state_from(response: CallToolResponse) -> String {
        let CallToolResponse::InputRequired(result) = response else {
            panic!("expected input_required");
        };
        assert!(
            result.input_requests.is_some_and(|requests| {
                requests.len() == 1 && requests.contains_key(INPUT_KEY)
            })
        );
        result.request_state.expect("request state")
    }

    fn accepted(content: &Value) -> InputResponses {
        BTreeMap::from([(
            INPUT_KEY.to_owned(),
            json!({ "action": "accept", "content": content }),
        )])
    }

    #[test]
    fn associated_data_preserves_v1_bytes_with_embedded_nuls() {
        let principal = PrincipalId::new("alice").unwrap();
        let arguments = json!({"key": "a\0b"});
        let expected =
            blake3::hash(b"astrid/mcp/mrtr/v1\0alice\0tool\0name\0{\"key\":\"a\\u0000b\"}");
        assert_eq!(
            associated_data(&principal, "tool\0name", &arguments),
            expected.as_bytes()
        );
    }

    #[test]
    fn state_is_bound_to_principal_tool_and_arguments() {
        let bridge = MrtrBridge::new().expect("random signing key is length-validated");
        let alice = PrincipalId::new("alice").unwrap();
        let bob = PrincipalId::new("bob").unwrap();
        let arguments = json!({ "path": "/tmp/report" });
        let state = state_from(
            bridge
                .ingress_required(&alice, "fs.read", &arguments, "Allow?".into())
                .unwrap(),
        );
        let responses = accepted(&json!({ "allow": true }));

        assert!(
            bridge
                .resolve(&bob, "fs.read", &arguments, &state, Some(&responses))
                .is_err()
        );
        assert!(
            bridge
                .resolve(&alice, "fs.write", &arguments, &state, Some(&responses))
                .is_err()
        );
        assert!(
            bridge
                .resolve(
                    &alice,
                    "fs.read",
                    &json!({ "path": "/tmp/other" }),
                    &state,
                    Some(&responses),
                )
                .is_err()
        );
        let resolved = bridge
            .resolve(&alice, "fs.read", &arguments, &state, Some(&responses))
            .unwrap();
        assert!(matches!(
            resolved.decision,
            ConsentResolution::Ingress(true)
        ));
        resolved.redemption.commit();
        assert!(
            bridge
                .resolve(&alice, "fs.read", &arguments, &state, Some(&responses))
                .is_err(),
            "requestState must be single-use"
        );
    }

    #[test]
    fn cancelled_redemption_can_retry_but_completed_redemption_cannot() {
        let bridge = MrtrBridge::new().expect("random signing key is length-validated");
        let alice = PrincipalId::new("alice").unwrap();
        let arguments = json!({ "path": "/tmp/report" });
        let state = state_from(
            bridge
                .ingress_required(&alice, "fs.read", &arguments, "Allow?".into())
                .unwrap(),
        );
        let responses = accepted(&json!({ "allow": true }));

        let interrupted = bridge
            .resolve(&alice, "fs.read", &arguments, &state, Some(&responses))
            .unwrap();
        drop(interrupted);

        let completed = bridge
            .resolve(&alice, "fs.read", &arguments, &state, Some(&responses))
            .expect("dropping an uncommitted lease must permit a safe retry");
        completed.redemption.commit();

        assert!(
            bridge
                .resolve(&alice, "fs.read", &arguments, &state, Some(&responses))
                .is_err(),
            "a completed broker mutation must consume requestState"
        );
    }

    #[test]
    fn concurrent_redemptions_issue_one_lease_until_cancellation() {
        let bridge = MrtrBridge::new().unwrap();
        let principal = PrincipalId::new("alice").unwrap();
        let arguments = json!({"path": "report"});
        let state = state_from(
            bridge
                .ingress_required(&principal, "fs.read", &arguments, "Allow?".into())
                .unwrap(),
        );
        let responses = accepted(&json!({"allow": true}));
        let resolve =
            || bridge.resolve(&principal, "fs.read", &arguments, &state, Some(&responses));
        let barrier = std::sync::Barrier::new(2);
        let results = std::thread::scope(|scope| {
            let workers = [(); 2].map(|()| {
                scope.spawn(|| {
                    barrier.wait();
                    resolve()
                })
            });
            workers.map(|worker| worker.join().unwrap())
        });
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
        let error = results.iter().find_map(|r| r.as_ref().err()).unwrap();
        assert!(error.message.contains("already been redeemed"));
        drop(results);
        resolve().unwrap().redemption.commit();
        assert!(resolve().is_err());
    }

    #[test]
    fn short_signing_key_is_rejected_before_a_bridge_is_created() {
        let actual = RequestStateCodec::MIN_KEY_LENGTH - 1;

        let Err(error) = MrtrBridge::from_key(vec![0_u8; actual]) else {
            panic!("a short signing key must not construct a codec");
        };

        assert_eq!(error.code, rmcp::model::ErrorCode::INTERNAL_ERROR);
        assert!(error.message.contains("expected at least 32 bytes, got 31"));
    }

    #[test]
    fn missing_declined_or_malformed_input_fails_closed() {
        let bridge = MrtrBridge::new().expect("random signing key is length-validated");
        let alice = PrincipalId::new("alice").unwrap();
        let arguments = json!({});
        for responses in [
            None,
            Some(BTreeMap::from([(
                INPUT_KEY.to_owned(),
                json!({ "action": "decline" }),
            )])),
            Some(accepted(&json!({ "allow": "yes" }))),
        ] {
            let state = state_from(
                bridge
                    .ingress_required(&alice, "shell.exec", &arguments, "Allow?".into())
                    .unwrap(),
            );
            assert!(matches!(
                bridge
                    .resolve(&alice, "shell.exec", &arguments, &state, responses.as_ref(),)
                    .unwrap(),
                ResolvedConsent {
                    decision: ConsentResolution::Ingress(false),
                    ..
                }
            ));
        }
    }
}
