use std::time::Duration;

use crate::engine::wasm::bindings::astrid::elicit::host::{
    ElicitRequest, ElicitResponse, ElicitType, ErrorCode, Host as ElicitHost,
};
use crate::engine::wasm::host_state::LifecyclePhase;
use crate::engine::wasm::test_fixtures::minimal_host_state;
use astrid_events::AstridEvent;
use astrid_events::ipc::{IpcMessage, IpcPayload, Topic};
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

fn publish_response(bus: &astrid_events::EventBus, request_id: Uuid, principal: &str, value: &str) {
    let topic = Topic::elicit_response(request_id);
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

fn publish_cancel(bus: &astrid_events::EventBus, request_id: Uuid, principal: &str) {
    let topic = Topic::elicit_response(request_id);
    let msg = IpcMessage::new(
        topic,
        IpcPayload::ElicitResponse {
            request_id,
            value: None,
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

async fn await_request(mut req_rx: astrid_events::EventReceiver) -> (Uuid, Option<String>) {
    loop {
        let ev = tokio::time::timeout(Duration::from_secs(5), req_rx.recv())
            .await
            .expect("elicit request observed")
            .expect("bus open");
        if let AstridEvent::Ipc { message, .. } = &*ev
            && let IpcPayload::ElicitRequest { request_id, .. } = &message.payload
        {
            return (*request_id, message.principal.clone());
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn normal_runtime_cross_principal_reply_does_not_unblock_matching_does() {
    let rt = tokio::runtime::Handle::current();
    let mut state = minimal_host_state(rt);
    state.principal = astrid_core::PrincipalId::new("agent-alice").unwrap();
    assert!(
        state.lifecycle_phase.is_none(),
        "fixture starts outside a lifecycle hook"
    );

    let bus = state.event_bus.clone();
    let req_rx = bus.subscribe_topic("astrid.v1.elicit");

    let elicit_handle =
        tokio::task::spawn_blocking(move || (state.elicit(text_request("api_url")), state));

    let (request_id, req_principal) = await_request(req_rx).await;
    assert_eq!(
        req_principal.as_deref(),
        Some("agent-alice"),
        "host must stamp the originating principal on the outbound ElicitRequest"
    );
    publish_response(&bus, request_id, "agent-bob", "intruder");

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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn runtime_text_elicit_does_not_require_invocation_secret_store() {
    let rt = tokio::runtime::Handle::current();
    let mut state = minimal_host_state(rt);
    state.principal = astrid_core::PrincipalId::default();
    state.caller_context = Some(
        IpcMessage::new(
            Topic::from_raw("cli.v1.command.run.test"),
            IpcPayload::Connect,
            Uuid::nil(),
        )
        .with_principal("agent-alice"),
    );
    state.invocation_secret_store = None;
    assert!(
        state.lifecycle_phase.is_none(),
        "fixture starts outside a lifecycle hook"
    );

    let bus = state.event_bus.clone();
    let req_rx = bus.subscribe_topic("astrid.v1.elicit");

    let elicit_handle =
        tokio::task::spawn_blocking(move || (state.elicit(text_request("api_url")), state));

    let (request_id, req_principal) = await_request(req_rx).await;
    assert_eq!(
        req_principal.as_deref(),
        Some("agent-alice"),
        "runtime request must be attributed to the invoking principal"
    );
    publish_response(&bus, request_id, "agent-alice", "value");

    let (result, _state) = elicit_handle.await.expect("elicit thread joined");
    assert!(
        matches!(result, Ok(ElicitResponse::Value(ref v)) if v == "value"),
        "text elicit should not touch secret storage, got {result:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancel_token_unblocks_elicit_wait() {
    let rt = tokio::runtime::Handle::current();
    let mut state = minimal_host_state(rt);
    state.principal = astrid_core::PrincipalId::new("agent-alice").unwrap();
    state.lifecycle_phase = Some(LifecyclePhase::Install);

    let bus = state.event_bus.clone();
    let cancel_token = state.cancel_token.clone();
    let req_rx = bus.subscribe_topic("astrid.v1.elicit");

    let start = std::time::Instant::now();
    let elicit_handle =
        tokio::task::spawn_blocking(move || (state.elicit(text_request("api_url")), state));

    let (_request_id, _principal) = await_request(req_rx).await;
    cancel_token.cancel();

    let (result, _state) = elicit_handle.await.expect("elicit thread joined");
    let elapsed = start.elapsed();

    assert!(
        matches!(result, Err(ErrorCode::Timeout)),
        "cancelled wait must return Timeout, got {result:?}"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "cancel must unblock promptly, took {elapsed:?}"
    );
}

/// Per-principal cancellation on a SHARED runtime (issue #1069): releasing
/// ONE principal's view cancels that principal's per-principal token, which
/// must unblock its live elicit wait promptly — while the instance token
/// (and with it every other principal's work) stays uncancelled. This is the
/// unit-level pin for the "capsule remove while an elicit/approval is
/// pending must not wedge the shared instance" e2e scenario.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn principal_scoped_cancel_unblocks_elicit_wait_without_instance_cancel() {
    let rt = tokio::runtime::Handle::current();
    let mut state = minimal_host_state(rt);
    let alice = astrid_core::PrincipalId::new("agent-alice").unwrap();
    state.caller_context = Some(
        IpcMessage::new(
            Topic::from_raw("cli.v1.command.run.test"),
            IpcPayload::Connect,
            Uuid::nil(),
        )
        .with_principal("agent-alice"),
    );
    assert!(crate::engine::wasm::install_principal_overlays_sync(
        &mut state,
        Some(&alice)
    ));
    let tokens = state.principal_cancel_tokens.clone();
    let instance_token = state.cancel_token.clone();

    let bus = state.event_bus.clone();
    let req_rx = bus.subscribe_topic("astrid.v1.elicit");

    let start = std::time::Instant::now();
    let elicit_handle =
        tokio::task::spawn_blocking(move || (state.elicit(text_request("api_url")), state));

    let (_request_id, _principal) = await_request(req_rx).await;
    // The view-release path: cancel + remove exactly alice's token.
    crate::engine::wasm::cancel_principal_token(&tokens, &alice);

    let (result, state) = elicit_handle.await.expect("elicit thread joined");
    let elapsed = start.elapsed();

    assert!(
        matches!(result, Err(ErrorCode::Timeout)),
        "cancelled wait must return Timeout, got {result:?}"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "per-principal cancel must unblock promptly, took {elapsed:?}"
    );
    assert!(
        !instance_token.is_cancelled(),
        "the instance token must stay uncancelled — the shared runtime survives"
    );
    assert!(
        !state.cancel_token.is_cancelled(),
        "the instance token on the state must stay uncancelled too"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn matching_cancel_sentinel_returns_cancelled() {
    let rt = tokio::runtime::Handle::current();
    let mut state = minimal_host_state(rt);
    state.principal = astrid_core::PrincipalId::new("agent-alice").unwrap();
    state.lifecycle_phase = Some(LifecyclePhase::Install);

    let bus = state.event_bus.clone();
    let req_rx = bus.subscribe_topic("astrid.v1.elicit");

    let elicit_handle =
        tokio::task::spawn_blocking(move || (state.elicit(text_request("api_url")), state));

    let (request_id, _principal) = await_request(req_rx).await;
    publish_cancel(&bus, request_id, "agent-alice");

    let (result, _state) = elicit_handle.await.expect("elicit thread joined");
    assert!(
        matches!(result, Err(ErrorCode::Cancelled)),
        "both-None reply from the matching principal must map to Cancelled, got {result:?}"
    );
}
