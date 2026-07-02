//! Host function implementations for the `elicit` API.
//!
//! These functions are called by WASM guests to interactively collect user input
//! (secrets, text, selections, arrays).

use crate::engine::wasm::bindings::astrid::elicit::host::{
    self as elicit, ElicitRequest, ElicitResponse, ElicitType, ErrorCode,
};
use crate::engine::wasm::host::util;
use crate::engine::wasm::host_state::HostState;
use astrid_events::AstridEvent;
use astrid_events::ipc::{IpcMessage, IpcPayload, OnboardingField, OnboardingFieldType, Topic};
use uuid::Uuid;

/// Maximum timeout for interactive elicitation (120 seconds).
const MAX_ELICIT_TIMEOUT_MS: u64 = 120_000;

/// Map the typed [`ElicitRequest`] into the `OnboardingField` schema
/// used by the IPC layer and TUI.
fn map_to_onboarding_field(req: &ElicitRequest) -> Result<OnboardingField, ErrorCode> {
    let field_type = match req.kind {
        ElicitType::Text => OnboardingFieldType::Text,
        ElicitType::Secret => OnboardingFieldType::Secret,
        ElicitType::Select => {
            let options = req
                .options
                .as_ref()
                .filter(|o| !o.is_empty())
                .ok_or(ErrorCode::InvalidInput)?;
            OnboardingFieldType::Enum(options.clone())
        },
        ElicitType::Array => OnboardingFieldType::Array,
    };

    Ok(OnboardingField {
        key: req.key.clone(),
        prompt: if req.description.is_empty() {
            req.key.clone()
        } else {
            req.description.clone()
        },
        description: if req.description.is_empty() {
            None
        } else {
            Some(req.description.clone())
        },
        field_type,
        default: req.default_value.clone(),
        placeholder: None,
    })
}

/// The acting principal carried on an `AstridEvent::Ipc`, if any.
///
/// Used by the elicit wait loop (see [`elicit::Host::elicit`]) to authorize a
/// candidate reply against the originating principal before it is allowed to
/// unblock the waiter. Returns `None` for a non-IPC event or a system message
/// with no principal stamped.
fn event_principal(event: &AstridEvent) -> Option<&str> {
    match event {
        AstridEvent::Ipc { message, .. } => message.principal.as_deref(),
        _ => None,
    }
}

/// Whether an elicit-response `event` may answer an elicit originating from
/// `expected` principal.
///
/// The check is exact-equality on the principal string and is the security
/// boundary that stops a cross-principal elicit hijack: request_ids are
/// forwarded verbatim to every client, so a reply must additionally prove it
/// comes from the same principal the elicit is being collected for. A reply
/// with no principal (`None`) never matches — fail-closed.
///
/// Used inside the wait loop of [`elicit::Host::elicit`]; extracted as a pure
/// function so the responder-principal enforcement is unit-testable without a
/// live bus and blocking runtime.
fn response_principal_matches(expected: &str, event: &AstridEvent) -> bool {
    event_principal(event) == Some(expected)
}

/// Wait for an elicit reply on `receiver` that is attributed to
/// `expected_principal`, rejecting (and audit-logging) any cross-principal reply
/// and continuing on the REMAINING budget so a flood of mismatched replies
/// cannot extend the wait. Returns the matching event, or `None` on
/// deadline-expiry / closed channel.
///
/// `timeout` is the overall budget from now; the host fn passes
/// `MAX_ELICIT_TIMEOUT_MS`. Pulled out of [`elicit::Host::elicit`] so the
/// deadline-countdown + DoS-resistance can be unit-tested directly against a
/// real `EventBus` receiver — without the semaphore / cancel-token /
/// `block_in_place` machinery and with an injectable short timeout. The host fn
/// runs this as the future inside `bounded_block_on_cancellable`, so
/// cancellation (capsule unload) still races it at the outer layer, unchanged.
async fn await_matching_elicit_response(
    receiver: &mut astrid_events::EventReceiver,
    expected_principal: &str,
    capsule_id: &str,
    request_id: Uuid,
    timeout: std::time::Duration,
) -> Option<std::sync::Arc<AstridEvent>> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return None;
        }
        let Ok(Some(event)) = tokio::time::timeout(remaining, receiver.recv()).await else {
            // Inner timeout (deadline hit) or closed channel.
            return None;
        };
        if response_principal_matches(expected_principal, &event) {
            return Some(event);
        }
        // A response landed on our reply topic carrying a different
        // principal than the one this elicit is being collected for.
        // Reject it (audit) and keep waiting on the remaining budget
        // rather than letting an unauthorized caller unblock or
        // cancel another principal's elicit.
        let got = event_principal(&event);
        tracing::warn!(
            target: "astrid.audit.elicit",
            security_event = true,
            capsule_id = %capsule_id,
            request_id = %request_id,
            expected_principal = %expected_principal,
            got_principal = got.unwrap_or("<none>"),
            "elicit: rejected cross-principal response; continuing to wait",
        );
    }
}

impl elicit::Host for HostState {
    /// Host function: `elicit(request) -> ElicitResponse`
    ///
    /// Blocks the WASM thread until the frontend (TUI or CLI) collects user input
    /// and publishes an `ElicitResponse` on the response topic.
    ///
    fn elicit(&mut self, request: ElicitRequest) -> Result<ElicitResponse, ErrorCode> {
        let field = map_to_onboarding_field(&request)?;
        let request_id = Uuid::new_v4();
        let response_topic = Topic::elicit_response(request_id);

        // The principal this elicit is being collected on behalf of. The
        // matching reply must be attributed to the SAME principal — a request_id
        // is forwarded verbatim to every SSE/uplink client, so without this
        // check any authenticated caller who learns an in-flight request_id
        // could answer or cancel another principal's elicit. The kernel
        // enforces (kernel-is-dumb); the answering uplink only stamps the
        // verified principal it already proved.
        let originating_principal = self.effective_principal().to_string();

        // Subscribe to the response topic BEFORE publishing the request
        // to prevent a race where the response arrives before we're listening.
        let mut receiver = self.event_bus.subscribe_topic(response_topic.as_str());

        let runtime_handle = self.runtime_handle.clone();
        let event_bus = self.event_bus.clone();
        let capsule_id = self.capsule_id.to_string();
        let cancel_token = self.effective_cancel_token();
        let blocking_semaphore = self.blocking_semaphore.clone();

        // Publish the elicit request to the event bus, stamped with the
        // originating principal so request and reply principals are symmetric
        // (and the request is attributable in the audit trail).
        let request_payload = IpcPayload::ElicitRequest {
            request_id,
            capsule_id: capsule_id.clone(),
            field,
        };
        let message = IpcMessage::new(
            Topic::elicit_request(),
            request_payload,
            Uuid::nil(), // Kernel-originated
        )
        .with_principal(originating_principal.clone());
        event_bus.publish(AstridEvent::Ipc {
            message,
            metadata: astrid_events::EventMetadata::default(),
        });

        tracing::debug!(
            capsule = %capsule_id,
            key = %request.key,
            ?request.kind,
            %request_id,
            principal = %originating_principal,
            "Published elicit request, waiting for response"
        );

        // Block the WASM thread until a MATCHING response arrives, the overall
        // timeout expires, or the capsule is unloaded (cancellation). Routed
        // through the host semaphore to bound concurrent blocking operations
        // across all capsules — a single permit covers the whole wait.
        //
        // Note: the helper uses a biased select that strictly prioritises
        // cancellation over completion. If a response arrives in the same poll
        // tick as cancellation, the response is discarded. This is acceptable
        // during teardown and prevents delayed shutdown under high throughput.
        //
        // Inside the permit we run a deadline loop (the extracted
        // `await_matching_elicit_response`): a spurious or cross-principal
        // response must NOT unblock the legitimate waiter, nor reset its budget.
        // It keeps an overall deadline of `MAX_ELICIT_TIMEOUT_MS` from the start
        // and only counts down — each `recv` gets the *remaining* time, so a
        // flood of mismatched replies cannot extend the wait and DoS the real
        // answer.
        let expected_principal = originating_principal.clone();
        let event = util::bounded_block_on_cancellable(
            &runtime_handle,
            &blocking_semaphore,
            &cancel_token,
            async move {
                await_matching_elicit_response(
                    &mut receiver,
                    &expected_principal,
                    &capsule_id,
                    request_id,
                    std::time::Duration::from_millis(MAX_ELICIT_TIMEOUT_MS),
                )
                .await
            },
        )
        .flatten();

        // Extract the response, mapping the inner IPC reply into the typed
        // `ElicitResponse` variant required by the WIT contract. The principal
        // match was already enforced in the wait loop above.
        let response = match event {
            Some(event) => {
                let AstridEvent::Ipc { message, .. } = &*event else {
                    return Err(ErrorCode::Unknown(
                        "unexpected event type in elicit response".to_string(),
                    ));
                };
                match &message.payload {
                    IpcPayload::ElicitResponse { value, values, .. } => {
                        // Detect cancellation: both value and values are None.
                        if value.is_none() && values.is_none() {
                            return Err(ErrorCode::Cancelled);
                        }

                        match request.kind {
                            ElicitType::Secret => {
                                // Persist the secret via the SecretStore
                                // abstraction. OS keychain when available,
                                // file fallback otherwise. The value is NOT
                                // returned to the guest — the WIT contract
                                // is `secret-stored`, signaling the secret
                                // exists in the host store.
                                let secret_val = value.clone().unwrap_or_default();
                                if secret_val.is_empty() {
                                    return Err(ErrorCode::InvalidInput);
                                }
                                self.effective_secret_store()
                                    .set(&request.key, &secret_val)
                                    .map_err(|_| ErrorCode::StoreUnavailable)?;
                                ElicitResponse::SecretStored
                            },
                            ElicitType::Array => {
                                ElicitResponse::Values(values.clone().unwrap_or_default())
                            },
                            ElicitType::Text | ElicitType::Select => {
                                ElicitResponse::Value(value.clone().unwrap_or_default())
                            },
                        }
                    },
                    _ => {
                        return Err(ErrorCode::Unknown(
                            "unexpected IPC payload type in elicit response".to_string(),
                        ));
                    },
                }
            },
            None => {
                // Timeout / cancellation / closed channel.
                return Err(ErrorCode::Timeout);
            },
        };

        Ok(response)
    }

    /// Host function: `has_secret(key) -> bool`
    ///
    /// Checks whether a secret key has been stored for this capsule.
    fn has_secret(&mut self, key: String) -> Result<bool, ErrorCode> {
        self.effective_secret_store()
            .exists(&key)
            .map_err(|_| ErrorCode::StoreUnavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_elicit_request(
        kind: ElicitType,
        key: &str,
        description: &str,
        options: Option<Vec<String>>,
        default: Option<String>,
    ) -> ElicitRequest {
        ElicitRequest {
            kind,
            key: key.to_string(),
            description: description.to_string(),
            options,
            default_value: default,
        }
    }

    #[test]
    fn map_text_request() {
        let req = make_elicit_request(
            ElicitType::Text,
            "api_url",
            "Enter API URL",
            None,
            Some("https://example.com".into()),
        );
        let field = map_to_onboarding_field(&req).unwrap();
        assert_eq!(field.key, "api_url");
        assert_eq!(field.field_type, OnboardingFieldType::Text);
        assert_eq!(field.default.as_deref(), Some("https://example.com"));
        assert_eq!(field.prompt, "Enter API URL");
    }

    #[test]
    fn map_secret_request() {
        let req = make_elicit_request(
            ElicitType::Secret,
            "api_key",
            "Enter your API key",
            None,
            None,
        );
        let field = map_to_onboarding_field(&req).unwrap();
        assert_eq!(field.field_type, OnboardingFieldType::Secret);
    }

    #[test]
    fn map_select_request() {
        let req = make_elicit_request(
            ElicitType::Select,
            "network",
            "Choose network",
            Some(vec!["mainnet".into(), "testnet".into()]),
            None,
        );
        let field = map_to_onboarding_field(&req).unwrap();
        assert_eq!(
            field.field_type,
            OnboardingFieldType::Enum(vec!["mainnet".into(), "testnet".into()])
        );
    }

    #[test]
    fn map_select_request_empty_options_fails() {
        let req = make_elicit_request(ElicitType::Select, "network", "", Some(vec![]), None);
        assert!(matches!(
            map_to_onboarding_field(&req),
            Err(ErrorCode::InvalidInput)
        ));
    }

    #[test]
    fn map_select_request_no_options_fails() {
        let req = make_elicit_request(ElicitType::Select, "network", "", None, None);
        assert!(matches!(
            map_to_onboarding_field(&req),
            Err(ErrorCode::InvalidInput)
        ));
    }

    #[test]
    fn map_array_request() {
        let req = make_elicit_request(ElicitType::Array, "relays", "Enter relay URLs", None, None);
        let field = map_to_onboarding_field(&req).unwrap();
        assert_eq!(field.field_type, OnboardingFieldType::Array);
    }

    #[test]
    fn map_text_uses_key_as_prompt_when_no_description() {
        let req = make_elicit_request(ElicitType::Text, "my_setting", "", None, None);
        let field = map_to_onboarding_field(&req).unwrap();
        assert_eq!(field.prompt, "my_setting");
        assert!(field.description.is_none());
    }

    /// Build an `AstridEvent::Ipc` carrying an `ElicitResponse` stamped (or not)
    /// with `principal`. Mirrors what a real answerer (`POST
    /// /api/agent/elicit-response`, the CLI, the TUI) publishes.
    fn elicit_response_event(
        request_id: Uuid,
        principal: Option<&str>,
        value: Option<String>,
    ) -> AstridEvent {
        let topic = Topic::elicit_response(request_id);
        let mut msg = IpcMessage::new(
            topic,
            IpcPayload::ElicitResponse {
                request_id,
                value,
                values: None,
            },
            Uuid::nil(),
        );
        if let Some(p) = principal {
            msg = msg.with_principal(p);
        }
        AstridEvent::Ipc {
            message: msg,
            metadata: astrid_events::EventMetadata::default(),
        }
    }

    /// SECURITY REGRESSION: the responder-principal check that backs the elicit
    /// wait loop must reject a reply whose principal differs from the one the
    /// elicit is being collected for, and must accept one that matches.
    ///
    /// This guards the actual `elicit()` wait loop (see
    /// [`response_principal_matches`]'s call site there): request_ids are
    /// forwarded verbatim to every client, so without this check any
    /// authenticated caller who learns an in-flight request_id could
    /// answer/cancel another principal's elicit. The test MUST fail if the
    /// principal check is removed (i.e. if the loop unblocked on any reply).
    #[test]
    fn response_principal_match_enforced() {
        let request_id = Uuid::new_v4();

        // Matching principal → may answer.
        let same = elicit_response_event(request_id, Some("agent-alice"), Some("v".into()));
        assert!(response_principal_matches("agent-alice", &same));

        // Different principal → rejected (the cross-principal hijack case).
        let other = elicit_response_event(request_id, Some("agent-bob"), Some("v".into()));
        assert!(!response_principal_matches("agent-alice", &other));

        // No principal stamped → fail-closed, never matches.
        let none = elicit_response_event(request_id, None, Some("v".into()));
        assert!(!response_principal_matches("agent-alice", &none));
    }

    /// A non-IPC event carries no principal — `event_principal` returns `None`
    /// and it can never satisfy the responder-principal check.
    #[test]
    fn non_ipc_event_has_no_principal() {
        let ev = AstridEvent::Custom {
            metadata: astrid_events::EventMetadata::default(),
            name: "noise".to_string(),
            data: serde_json::json!({}),
        };
        assert_eq!(event_principal(&ev), None);
        assert!(!response_principal_matches("agent-alice", &ev));
    }

    /// Publish an `ElicitResponse` for `request_id` onto its reply topic,
    /// stamped (or not) with `principal`. Mirrors a real answerer's publish.
    fn publish_reply(
        bus: &astrid_events::EventBus,
        request_id: Uuid,
        principal: Option<&str>,
        value: &str,
    ) {
        bus.publish(elicit_response_event(
            request_id,
            principal,
            Some(value.to_string()),
        ));
    }

    /// Test 1a — DEADLINE TERMINATION: with no reply at all,
    /// `await_matching_elicit_response` must return `None` at roughly the
    /// injected budget and NOT hang. Proves the deadline countdown terminates
    /// the wait (the bug it guards: a removed/inverted countdown would block the
    /// full `MAX_ELICIT_TIMEOUT_MS`).
    #[tokio::test]
    async fn await_response_times_out_when_no_reply() {
        let bus = astrid_events::EventBus::with_capacity(256);
        let request_id = Uuid::new_v4();
        let mut rx = bus.subscribe_topic(Topic::elicit_response(request_id).as_str());

        let budget = std::time::Duration::from_millis(150);
        let start = std::time::Instant::now();
        let got =
            await_matching_elicit_response(&mut rx, "agent-alice", "test", request_id, budget)
                .await;
        let elapsed = start.elapsed();

        assert!(got.is_none(), "no reply → must time out to None");
        // Generous upper bound for CI jitter while still proving it didn't wait
        // out anything near the 120s production timeout.
        assert!(
            elapsed < budget * 5,
            "must terminate near the budget, took {elapsed:?} for a {budget:?} budget"
        );
    }

    /// Test 1b — DoS-RESISTANCE: a STREAM of cross-principal replies arriving
    /// faster than the budget window must neither unblock the wait (returns
    /// `None`) nor EXTEND it (elapsed stays near the budget). This is the
    /// security guarantee: a mismatched-reply flood cannot reset or stretch the
    /// legitimate waiter's deadline.
    ///
    /// The replies are spread over ~2s (one every ~40ms, never matching), well
    /// past the ~150ms budget — so a buggy reset-the-deadline-per-reply
    /// implementation would keep getting pushed and not return until the stream
    /// stops (~2s), while the CORRECT fixed-deadline helper returns at ~150ms
    /// regardless of the ongoing stream. (Verified: with the deadline recompute
    /// moved inside the loop, this test fails with elapsed ~2s.) The instant
    /// (pre-buffered) drain case is covered by 1c.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn await_response_flood_does_not_extend_deadline() {
        let bus = astrid_events::EventBus::with_capacity(256);
        let request_id = Uuid::new_v4();
        let mut rx = bus.subscribe_topic(Topic::elicit_response(request_id).as_str());

        // Publisher: a cross-principal reply every ~40ms for ~2s. The 40ms
        // cadence is shorter than the 150ms budget, so a reset-per-reply bug
        // would never see an idle window long enough to expire — it would only
        // unblock when this stream ends.
        let pub_bus = bus.clone();
        let publisher = tokio::spawn(async move {
            for _ in 0..50 {
                publish_reply(&pub_bus, request_id, Some("agent-bob"), "intruder");
                tokio::time::sleep(std::time::Duration::from_millis(40)).await;
            }
        });

        let budget = std::time::Duration::from_millis(150);
        let start = std::time::Instant::now();
        let got =
            await_matching_elicit_response(&mut rx, "agent-alice", "test", request_id, budget)
                .await;
        let elapsed = start.elapsed();

        publisher.abort();

        assert!(got.is_none(), "mismatch flood must not unblock the waiter");
        assert!(
            elapsed < budget * 5,
            "a mismatch flood must not extend the deadline; took {elapsed:?} for {budget:?}"
        );
    }

    /// Test 1c — DRAIN-PAST-MISMATCHES: a few wrong-principal replies followed
    /// by one matching reply, all buffered before the wait. The helper must skip
    /// the bad ones and return the matching event.
    #[tokio::test]
    async fn await_response_drains_past_mismatches_to_match() {
        let bus = astrid_events::EventBus::with_capacity(256);
        let request_id = Uuid::new_v4();
        let mut rx = bus.subscribe_topic(Topic::elicit_response(request_id).as_str());

        publish_reply(&bus, request_id, Some("agent-bob"), "intruder-1");
        publish_reply(&bus, request_id, Some("agent-carol"), "intruder-2");
        publish_reply(&bus, request_id, Some("agent-alice"), "legit");

        let budget = std::time::Duration::from_millis(500);
        let got =
            await_matching_elicit_response(&mut rx, "agent-alice", "test", request_id, budget)
                .await
                .expect("matching reply must be returned after draining mismatches");

        // The returned event is the matching one carrying "legit".
        let AstridEvent::Ipc { message, .. } = &*got else {
            panic!("expected IPC event");
        };
        assert_eq!(message.principal.as_deref(), Some("agent-alice"));
        match &message.payload {
            IpcPayload::ElicitResponse { value, .. } => {
                assert_eq!(value.as_deref(), Some("legit"));
            },
            other => panic!("expected ElicitResponse, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn concurrent_waiters_keep_correlation_and_principal_scopes() {
        let bus = astrid_events::EventBus::with_capacity(256);
        let alice_id = Uuid::new_v4();
        let bob_id = Uuid::new_v4();
        let mut rx_alice = bus.subscribe_topic(Topic::elicit_response(alice_id).as_str());
        let mut rx_bob = bus.subscribe_topic(Topic::elicit_response(bob_id).as_str());

        let alice = await_matching_elicit_response(
            &mut rx_alice,
            "agent-alice",
            "test",
            alice_id,
            std::time::Duration::from_secs(1),
        );
        let bob = await_matching_elicit_response(
            &mut rx_bob,
            "agent-bob",
            "test",
            bob_id,
            std::time::Duration::from_secs(1),
        );

        publish_reply(&bus, alice_id, Some("agent-bob"), "wrong-alice");
        publish_reply(&bus, bob_id, Some("agent-alice"), "wrong-bob");
        publish_reply(&bus, alice_id, Some("agent-alice"), "alice");
        publish_reply(&bus, bob_id, Some("agent-bob"), "bob");

        let (alice, bob) = tokio::join!(alice, bob);
        let alice = alice.expect("alice elicit should resolve");
        let bob = bob.expect("bob elicit should resolve");

        assert!(response_principal_matches("agent-alice", &alice));
        assert!(response_principal_matches("agent-bob", &bob));
    }
}

#[cfg(test)]
#[path = "elicit/wait_loop_tests.rs"]
mod wait_loop_tests;

#[cfg(test)]
#[path = "elicit/secret_chain_tests.rs"]
mod secret_chain_tests;
