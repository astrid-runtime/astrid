//! Host function implementations for the `elicit` lifecycle API.
//!
//! These functions are called by WASM guests during `#[install]` or `#[upgrade]`
//! hooks to interactively collect user input (secrets, text, selections, arrays).

use crate::engine::wasm::bindings::astrid::elicit::host::{
    self as elicit, ElicitRequest, ElicitResponse, ElicitType, ErrorCode,
};
use crate::engine::wasm::host::util;
use crate::engine::wasm::host_state::HostState;
use astrid_events::AstridEvent;
use astrid_events::ipc::{IpcMessage, IpcPayload, OnboardingField, OnboardingFieldType};
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

impl elicit::Host for HostState {
    /// Host function: `elicit(request) -> ElicitResponse`
    ///
    /// Blocks the WASM thread until the frontend (TUI or CLI) collects user input
    /// and publishes an `ElicitResponse` on the response topic.
    ///
    /// Only callable during a lifecycle phase (install/upgrade). Returns
    /// `not-in-lifecycle` if called during normal runtime.
    fn elicit(&mut self, request: ElicitRequest) -> Result<ElicitResponse, ErrorCode> {
        // Gate: elicit is only allowed during lifecycle hooks
        if self.lifecycle_phase.is_none() {
            return Err(ErrorCode::NotInLifecycle);
        }

        let field = map_to_onboarding_field(&request)?;
        let request_id = Uuid::new_v4();
        let response_topic = format!("astrid.v1.elicit.response.{request_id}");

        // The principal this elicit is being collected on behalf of. The
        // matching reply must be attributed to the SAME principal — a request_id
        // is forwarded verbatim to every SSE/uplink client, so without this
        // check any authenticated caller who learns an in-flight request_id
        // could answer or cancel another principal's elicit. The kernel
        // enforces (kernel-is-dumb); the answering uplink only stamps the
        // verified principal it already proved.
        let originating_principal = self.principal.to_string();

        // Subscribe to the response topic BEFORE publishing the request
        // to prevent a race where the response arrives before we're listening.
        let mut receiver = self.event_bus.subscribe_topic(&response_topic);

        let runtime_handle = self.runtime_handle.clone();
        let event_bus = self.event_bus.clone();
        let capsule_id = self.capsule_id.to_string();
        let secret_store = self.effective_secret_store().clone();
        let cancel_token = self.cancel_token.clone();
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
            "astrid.v1.elicit",
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
        // Inside the permit we run a deadline loop: a spurious or cross-principal
        // response must NOT unblock the legitimate waiter, nor reset its budget.
        // We keep an overall deadline of `MAX_ELICIT_TIMEOUT_MS` from the start
        // and only count down — each `recv` gets the *remaining* time, so a flood
        // of mismatched replies cannot extend the wait and DoS the real answer.
        let request_id_for_wait = request_id;
        let expected_principal = originating_principal.clone();
        let event = util::bounded_block_on_cancellable(
            &runtime_handle,
            &blocking_semaphore,
            &cancel_token,
            async move {
                let deadline = tokio::time::Instant::now()
                    + std::time::Duration::from_millis(MAX_ELICIT_TIMEOUT_MS);
                loop {
                    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                    if remaining.is_zero() {
                        return None;
                    }
                    let Ok(Some(event)) = tokio::time::timeout(remaining, receiver.recv()).await
                    else {
                        // Inner timeout (deadline hit) or closed channel.
                        return None;
                    };
                    if response_principal_matches(&expected_principal, &event) {
                        return Some(event);
                    }
                    // A response landed on our reply topic carrying a different
                    // principal than the one this elicit is being collected for.
                    // Reject it (audit) and keep waiting on the remaining budget
                    // rather than letting an unauthorized caller unblock or
                    // cancel another principal's elicit.
                    let got = event_principal(&event);
                    tracing::warn!(
                        capsule = %capsule_id,
                        %request_id_for_wait,
                        expected_principal = %expected_principal,
                        got_principal = got.unwrap_or("<none>"),
                        "Rejected cross-principal elicit response; continuing to wait"
                    );
                }
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
                                secret_store
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
        let topic = format!("astrid.v1.elicit.response.{request_id}");
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
}

// ---------------------------------------------------------------------------
// Wait-loop integration test: drive the real `elicit()` host fn against a live
// `EventBus` and prove the responder-principal enforcement end to end — a reply
// from the WRONG principal does NOT unblock the waiter, while a reply from the
// MATCHING principal does. The pure-helper test above guards the decision; this
// one guards the loop that consumes it (the cross-principal reply must be
// skipped and the wait must continue on its remaining budget).
// ---------------------------------------------------------------------------
#[cfg(test)]
mod wait_loop_tests {
    use std::time::Duration;

    use crate::engine::wasm::bindings::astrid::elicit::host::{
        ElicitRequest, ElicitResponse, ElicitType, Host as ElicitHost,
    };
    use crate::engine::wasm::host_state::LifecyclePhase;
    use crate::engine::wasm::test_fixtures::minimal_host_state;
    use astrid_events::AstridEvent;
    use astrid_events::ipc::{IpcMessage, IpcPayload};
    use uuid::Uuid;

    fn text_request(key: &str) -> ElicitRequest {
        ElicitRequest {
            kind: ElicitType::Text,
            key: key.to_string(),
            description: "Enter a value".to_string(),
            options: None,
            default_value: None,
        }
    }

    /// Publish an `ElicitResponse` for `request_id` stamped with `principal`.
    fn publish_response(
        bus: &astrid_events::EventBus,
        request_id: Uuid,
        principal: &str,
        value: &str,
    ) {
        let topic = format!("astrid.v1.elicit.response.{request_id}");
        let msg = IpcMessage::new(
            topic,
            IpcPayload::ElicitResponse {
                request_id,
                value: Some(value.to_string()),
                values: None,
            },
            Uuid::nil(),
        )
        .with_principal(principal);
        bus.publish(AstridEvent::Ipc {
            message: msg,
            metadata: astrid_events::EventMetadata::default(),
        });
    }

    /// Subscribe to `astrid.v1.elicit`, wait for the request, return its
    /// `request_id`. The host mints the id internally, so a driver learns it
    /// the same way every real answerer does — off the published request.
    async fn await_request_id(mut req_rx: astrid_events::EventReceiver) -> Uuid {
        loop {
            let ev = tokio::time::timeout(Duration::from_secs(5), req_rx.recv())
                .await
                .expect("elicit request observed")
                .expect("bus open");
            if let AstridEvent::Ipc { message, .. } = &*ev
                && let IpcPayload::ElicitRequest { request_id, .. } = &message.payload
            {
                return *request_id;
            }
        }
    }

    /// End-to-end: a cross-principal reply must be ignored; the matching reply
    /// (published AFTER the bad one) unblocks the waiter with the right value.
    /// Fails if the principal check is removed — the waiter would unblock on
    /// the wrong-principal reply and return "intruder".
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cross_principal_reply_does_not_unblock_matching_does() {
        let rt = tokio::runtime::Handle::current();
        let mut state = minimal_host_state(rt);
        state.principal = astrid_core::PrincipalId::new("agent-alice").unwrap();
        state.lifecycle_phase = Some(LifecyclePhase::Install);

        let bus = state.event_bus.clone();
        let req_rx = bus.subscribe_topic("astrid.v1.elicit");

        // Drive the blocking host fn on a dedicated thread (it uses
        // block_in_place). We can't move the non-Send HostState across an
        // await, so run it inside spawn_blocking and bridge the result back.
        let elicit_handle =
            tokio::task::spawn_blocking(move || (state.elicit(text_request("api_url")), state));

        // Learn the request_id, then publish a WRONG-principal reply first.
        let request_id = await_request_id(req_rx).await;
        publish_response(&bus, request_id, "agent-bob", "intruder");

        // Give the loop a beat to (correctly) reject the intruder reply, then
        // send the legitimate one.
        tokio::time::sleep(Duration::from_millis(100)).await;
        publish_response(&bus, request_id, "agent-alice", "legit");

        let (result, _state) = elicit_handle.await.expect("elicit thread joined");
        match result {
            Ok(ElicitResponse::Value(v)) => {
                assert_eq!(v, "legit", "must return the matching principal's value");
                assert_ne!(v, "intruder", "cross-principal reply must not win");
            },
            other => panic!("expected matching value, got {other:?}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Chain tests: drive `has_secret` synchronously on a HostState with manually-
// installed invocation fields. Verifies `effective_secret_store()` wiring: a
// key set via the invocation store must not be visible via the load-time
// store and vice versa. Mirrors the pattern established in `host/fs.rs` for
// per-invocation VFS re-scoping (#549).
// ---------------------------------------------------------------------------
#[cfg(test)]
mod secret_chain_tests {
    use std::sync::Arc;

    use crate::engine::wasm::bindings::astrid::elicit::host::Host as ElicitHost;
    use crate::engine::wasm::host_state::HostState;
    use crate::engine::wasm::test_fixtures::{mem_secret_store, minimal_host_state};
    use astrid_storage::secret::SecretStore;

    /// Build a HostState whose load-time `secret_store` points at a fresh,
    /// namespace-isolated KV-backed store. Returns the state and an `Arc`
    /// handle to that owner store so tests can seed secrets through it.
    fn make_host_state_with_secret(
        rt: tokio::runtime::Handle,
        owner_namespace: &str,
    ) -> (HostState, Arc<dyn SecretStore>) {
        let owner_secret = mem_secret_store(owner_namespace, rt.clone());
        let mut state = minimal_host_state(rt);
        state.secret_store = Arc::clone(&owner_secret);
        (state, owner_secret)
    }

    /// Fresh invocation-scoped secret store (principal-namespaced in real
    /// `invoke_interceptor`; arbitrary in tests).
    fn make_invocation_store(rt: tokio::runtime::Handle, namespace: &str) -> Arc<dyn SecretStore> {
        mem_secret_store(namespace, rt)
    }

    /// Drive a closure in a blocking context so KvSecretStore's internal
    /// `Handle::block_on` works — same sync/async bridge pattern as
    /// production host functions.
    async fn blocking<T, F>(f: F) -> T
    where
        T: Send + 'static,
        F: FnOnce() -> T + Send + 'static,
    {
        tokio::task::spawn_blocking(f)
            .await
            .expect("spawn_blocking join")
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn has_secret_reads_invocation_store_when_installed() {
        let rt = tokio::runtime::Handle::current();
        let (mut state, owner_secret) =
            make_host_state_with_secret(rt.clone(), "capsule:test-owner");
        let alice_secret = make_invocation_store(rt, "capsule:test-alice");

        // Owner has `shared_key`; Alice does not.
        {
            let s = Arc::clone(&owner_secret);
            blocking(move || s.set("shared_key", "owner-val").unwrap()).await;
        }
        state.invocation_secret_store = Some(Arc::clone(&alice_secret));

        // Via the accessor, `has_secret` consults Alice's store — the owner's
        // entry is not visible.
        let (state, got) = blocking(move || {
            let mut s = state;
            let got = s.has_secret("shared_key".to_string()).unwrap();
            (s, got)
        })
        .await;
        assert!(!got, "invocation store is empty; owner's key must not leak");

        // Alice sets her own; owner's view is unchanged.
        {
            let s = Arc::clone(&alice_secret);
            blocking(move || s.set("shared_key", "alice-val").unwrap()).await;
        }
        let (mut state, got) = blocking(move || {
            let mut s = state;
            let got = s.has_secret("shared_key".to_string()).unwrap();
            (s, got)
        })
        .await;
        assert!(got);

        // Drop invocation context: falls back to owner's store.
        state.invocation_secret_store = None;
        let (_state, got) = blocking(move || {
            let mut s = state;
            let got = s.has_secret("shared_key".to_string()).unwrap();
            (s, got)
        })
        .await;
        assert!(got, "owner's key still present after clear");

        // Sanity: owner never saw Alice's value.
        let (owner_val, alice_val) = blocking(move || {
            (
                owner_secret.get("shared_key").unwrap(),
                alice_secret.get("shared_key").unwrap(),
            )
        })
        .await;
        assert_eq!(owner_val.as_deref(), Some("owner-val"));
        assert_eq!(alice_val.as_deref(), Some("alice-val"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn has_secret_falls_back_to_load_time_store() {
        // Regression guard: single-tenant path (no invocation store installed)
        // must see load-time secrets.
        let rt = tokio::runtime::Handle::current();
        let (state, owner_secret) = make_host_state_with_secret(rt, "capsule:test-owner");
        {
            let s = Arc::clone(&owner_secret);
            blocking(move || s.set("api_key", "sk-load").unwrap()).await;
        }
        assert!(state.invocation_secret_store.is_none());
        let (_state, got1, got2) = blocking(move || {
            let mut state = state;
            let got1 = state.has_secret("api_key".to_string()).unwrap();
            let got2 = state.has_secret("other_key".to_string()).unwrap();
            (state, got1, got2)
        })
        .await;
        assert!(got1);
        assert!(!got2);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn has_secret_isolates_across_sequential_invocations() {
        // Same HostState, invocation store swapped between calls — each call
        // sees only the currently-installed principal's secrets.
        let rt = tokio::runtime::Handle::current();
        let (mut state, _owner_secret) =
            make_host_state_with_secret(rt.clone(), "capsule:test-owner");

        let alice_secret = make_invocation_store(rt.clone(), "capsule:test-alice");
        let bob_secret = make_invocation_store(rt, "capsule:test-bob");
        {
            let a = Arc::clone(&alice_secret);
            let b = Arc::clone(&bob_secret);
            blocking(move || {
                a.set("pk", "alice-pk").unwrap();
                b.set("pk", "bob-pk").unwrap();
            })
            .await;
        }

        state.invocation_secret_store = Some(Arc::clone(&alice_secret));
        let (mut state, alice_view) = blocking(move || {
            let mut s = state;
            let v = s.has_secret("pk".to_string()).unwrap();
            (s, v)
        })
        .await;
        assert!(alice_view);
        state.invocation_secret_store = None;

        state.invocation_secret_store = Some(Arc::clone(&bob_secret));
        let (_state, bob_view) = blocking(move || {
            let mut s = state;
            let v = s.has_secret("pk".to_string()).unwrap();
            (s, v)
        })
        .await;
        assert!(bob_view);

        // Both isolated: each only sees its own key.
        let (a_val, b_val) = blocking(move || {
            (
                alice_secret.get("pk").unwrap(),
                bob_secret.get("pk").unwrap(),
            )
        })
        .await;
        assert_eq!(a_val.as_deref(), Some("alice-pk"));
        assert_eq!(b_val.as_deref(), Some("bob-pk"));
    }
}
