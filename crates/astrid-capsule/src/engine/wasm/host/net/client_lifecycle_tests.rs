//! Tests for host-emitted client-connection lifecycle events.
//!
//! These prove the connection-tracker leak fix at the emission boundary: a
//! connect and its matching disconnect carry the IDENTICAL host-verified
//! principal (never `anonymous` for an authenticated connection), so the
//! kernel's per-principal counter — which keys off `IpcMessage.principal` —
//! balances. The end-to-end counter-balance assertion against a live `Kernel`
//! tracker lives in `astrid-kernel` (this crate has no dependency on it); here
//! we assert the wire-level shape the tracker consumes.

use astrid_core::principal::PrincipalId;
use astrid_events::AstridEvent;
use astrid_events::ipc::IpcPayload;

use super::{emit_client_disconnect, register_and_emit_connect};
use crate::engine::wasm::test_fixtures::minimal_host_state;

/// Drain the next `client.v1.*` IPC event off `receiver`, returning its topic
/// and principal. Panics if none arrives — the emission is synchronous, so the
/// event is already queued by the time we poll.
fn next_client_event(receiver: &mut astrid_events::EventReceiver) -> (String, Option<String>) {
    let event = receiver
        .try_recv()
        .expect("a client lifecycle event was emitted");
    match &*event {
        AstridEvent::Ipc { message, .. } => (message.topic.clone(), message.principal.clone()),
        other => panic!("expected an Ipc event, got {other:?}"),
    }
}

/// Connect emits `client.v1.connect` stamped with the supplied verified
/// principal; the subsequent drop emits `client.v1.disconnect` stamped with the
/// SAME principal — the core invariant: an authenticated connection's
/// disconnect must NOT collapse to `anonymous`.
#[tokio::test]
async fn connect_and_disconnect_stamp_the_same_verified_principal() {
    let state = minimal_host_state(tokio::runtime::Handle::current());
    let mut rx = state.event_bus.subscribe_topic_as("client.v1.*", "test");

    let claude = PrincipalId::new("claude-code").expect("valid principal");
    let rep = 42u32;

    register_and_emit_connect(&state, rep, claude.clone());
    let (connect_topic, connect_principal) = next_client_event(&mut rx);
    assert_eq!(connect_topic, "client.v1.connect");
    assert_eq!(connect_principal.as_deref(), Some("claude-code"));

    emit_client_disconnect(&state, rep);
    let (disconnect_topic, disconnect_principal) = next_client_event(&mut rx);
    assert_eq!(disconnect_topic, "client.v1.disconnect");
    // The whole point of the fix: disconnect carries the identical principal,
    // never `anonymous`.
    assert_eq!(disconnect_principal.as_deref(), Some("claude-code"));
    assert_eq!(connect_principal, disconnect_principal);
}

/// The disconnect payload carries `{"reason":"socket closed"}`, matching the
/// shape the proxy used to emit so the kernel tracker's reason extraction is
/// unchanged.
#[tokio::test]
async fn disconnect_payload_carries_socket_closed_reason() {
    let state = minimal_host_state(tokio::runtime::Handle::current());
    let mut rx = state.event_bus.subscribe_topic_as("client.v1.*", "test");

    let rep = 7u32;
    register_and_emit_connect(&state, rep, PrincipalId::default());
    let _ = rx.try_recv().expect("connect event");

    emit_client_disconnect(&state, rep);
    let event = rx.try_recv().expect("disconnect event");
    let AstridEvent::Ipc { message, .. } = &*event else {
        panic!("expected Ipc event");
    };
    match &message.payload {
        IpcPayload::RawJson(val) => {
            assert_eq!(
                val.get("reason").and_then(|r| r.as_str()),
                Some("socket closed")
            );
        },
        other => panic!("expected RawJson payload, got {other:?}"),
    }
}

/// A legacy/unauthenticated connection balances on the reserved `anonymous`
/// identity — connect AND disconnect both stamp `anonymous`, so the pair still
/// nets to zero on a single principal.
#[tokio::test]
async fn anonymous_connection_balances_on_anonymous() {
    let state = minimal_host_state(tokio::runtime::Handle::current());
    let mut rx = state.event_bus.subscribe_topic_as("client.v1.*", "test");

    let rep = 3u32;
    let anon = PrincipalId::anonymous();
    register_and_emit_connect(&state, rep, anon.clone());
    let (_, connect_principal) = next_client_event(&mut rx);
    assert_eq!(connect_principal.as_deref(), Some(anon.as_str()));

    emit_client_disconnect(&state, rep);
    let (_, disconnect_principal) = next_client_event(&mut rx);
    assert_eq!(disconnect_principal.as_deref(), Some(anon.as_str()));
}

/// Dropping a rep that was never registered (an outbound TCP stream, or a
/// non-net resource) emits NOTHING — a capsule-dialed socket must never move
/// the client connection counter.
#[tokio::test]
async fn unregistered_rep_drop_emits_nothing() {
    let state = minimal_host_state(tokio::runtime::Handle::current());
    let mut rx = state.event_bus.subscribe_topic_as("client.v1.*", "test");

    // Never registered via `register_and_emit_connect`.
    emit_client_disconnect(&state, 999u32);
    assert!(
        rx.try_recv().is_none(),
        "dropping an unregistered (outbound/non-client) rep must not emit a disconnect"
    );
}

/// The registry entry is removed on disconnect, so a second drop of the same
/// rep is a silent no-op (idempotent) and cannot double-decrement the counter.
#[tokio::test]
async fn disconnect_is_idempotent_after_entry_removed() {
    let state = minimal_host_state(tokio::runtime::Handle::current());
    let mut rx = state.event_bus.subscribe_topic_as("client.v1.*", "test");

    let rep = 11u32;
    register_and_emit_connect(&state, rep, PrincipalId::default());
    let _ = rx.try_recv().expect("connect");
    emit_client_disconnect(&state, rep);
    let _ = rx.try_recv().expect("first disconnect");

    // Second drop of the same rep: entry already gone, no further emission.
    emit_client_disconnect(&state, rep);
    assert!(
        rx.try_recv().is_none(),
        "a second disconnect for an already-removed rep must not emit"
    );
}
