//! Tests for per-principal cancellation-token scoping on `HostState`.
//!
//! A shared-by-hash runtime (issue #1069) serves N principals from one
//! instance; releasing ONE principal's view must interrupt exactly that
//! principal's in-flight blocking host calls (approval/elicit/net/io/ipc
//! waits) without cancelling the instance the others still use. Split from
//! `host_state_tests.rs` to keep both under the 1000-line CI cap; included
//! via `#[path]` from `host_state.rs`.

use std::sync::Arc;

use tokio::sync::Semaphore;

use super::super::test_fixtures::minimal_host_state;
use super::super::{cancel_principal_token, install_principal_overlays_sync};
use astrid_events::ipc::Topic;

fn alice() -> astrid_core::PrincipalId {
    astrid_core::PrincipalId::new("agent-alice").expect("valid principal")
}

fn msg_from(principal: &astrid_core::PrincipalId) -> astrid_events::ipc::IpcMessage {
    astrid_events::ipc::IpcMessage::new(
        Topic::from_raw("some.v1.event"),
        astrid_events::ipc::IpcPayload::RawJson(serde_json::json!({})),
        uuid::Uuid::new_v4(),
    )
    .with_principal(principal.to_string())
}

/// (a) A wait blocked under principal A's EFFECTIVE token unblocks with the
/// cancelled outcome (`None`) when A's per-principal token is cancelled on
/// view release — while the instance token, and with it every other
/// principal's work, stays uncancelled.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn view_release_cancel_unblocks_principal_wait_without_instance_cancel() {
    let mut state = minimal_host_state(tokio::runtime::Handle::current());
    let a = alice();
    assert!(install_principal_overlays_sync(&mut state, Some(&a)));

    let wait_token = state.effective_cancel_token();
    let semaphore = Arc::new(Semaphore::new(1));
    let waiter = tokio::spawn(async move {
        // The same primitive every converted host wait site rides on.
        crate::engine::wasm::host::util::bounded_await_cancellable(
            &semaphore,
            &wait_token,
            std::future::pending::<()>(),
        )
        .await
    });

    // The view-release path: cancel + REMOVE exactly A's token.
    cancel_principal_token(&state.principal_cancel_tokens, &a);

    let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), waiter)
        .await
        .expect("wait must unblock promptly after the per-principal cancel")
        .expect("waiter task joined");
    assert!(
        outcome.is_none(),
        "the blocked wait must resolve to the cancelled outcome"
    );
    assert!(
        !state.cancel_token.is_cancelled(),
        "the instance token must stay uncancelled — other principals' work survives"
    );
}

/// (b) Regression pin for the remove → reinstall path: after a view-release
/// cancel (which removes A's map entry), the NEXT overlay install for A must
/// lazily mint a FRESH, uncancelled token — not resurrect the cancelled one.
#[test]
fn fresh_overlay_after_view_release_cancel_yields_uncancelled_token() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let mut state = minimal_host_state(rt.handle().clone());
    let a = alice();

    assert!(install_principal_overlays_sync(&mut state, Some(&a)));
    let first = state.effective_cancel_token();
    cancel_principal_token(&state.principal_cancel_tokens, &a);
    assert!(first.is_cancelled(), "release must cancel the live token");

    // A reinstalls the capsule and invokes again: a fresh overlay install.
    assert!(install_principal_overlays_sync(&mut state, Some(&a)));
    assert!(
        !state.effective_cancel_token().is_cancelled(),
        "a re-registered principal must get a fresh, uncancelled token"
    );
}

/// (c) A principal-less context's effective token IS the instance token:
/// its waits die only on full unload (today's behaviour), never on another
/// principal's view release.
#[test]
fn principal_less_context_uses_instance_token() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let mut state = minimal_host_state(rt.handle().clone());
    install_principal_overlays_sync(&mut state, None);
    assert!(state.invocation_cancel_token.is_none());

    let effective = state.effective_cancel_token();
    assert!(!effective.is_cancelled());
    state.cancel_token.cancel();
    assert!(
        effective.is_cancelled(),
        "the principal-less fallback must be the instance token itself"
    );
}

/// A full-instance cancel (unload/replace/shutdown) must still cascade into
/// every per-principal child token — per-principal scoping narrows the
/// view-release path, never the teardown path.
#[test]
fn full_instance_cancel_cascades_to_principal_tokens() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let mut state = minimal_host_state(rt.handle().clone());
    assert!(install_principal_overlays_sync(&mut state, Some(&alice())));

    let per_principal = state.effective_cancel_token();
    state.cancel_token.cancel();
    assert!(
        per_principal.is_cancelled(),
        "instance cancel must cascade to per-principal child tokens"
    );
}

/// The recv pump re-arm: a DEPARTED principal's cancelled token persisted on
/// the run-loop Store must be cleared (falling back to the alive instance
/// token) so `ipc::recv` keeps draining every other principal's messages —
/// but a cancelled INSTANCE token (full teardown) keeps the short-circuit.
#[test]
fn clear_stale_invocation_cancel_token_rearms_only_while_instance_alive() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();

    // Departed principal, instance alive: clear and fall back.
    let mut state = minimal_host_state(rt.handle().clone());
    let a = alice();
    assert!(install_principal_overlays_sync(&mut state, Some(&a)));
    cancel_principal_token(&state.principal_cancel_tokens, &a);
    state.clear_stale_invocation_cancel_token();
    assert!(
        state.invocation_cancel_token.is_none(),
        "a departed principal's cancelled token must not poison the pump"
    );
    assert!(!state.effective_cancel_token().is_cancelled());

    // Uncancelled overlay: left untouched.
    assert!(install_principal_overlays_sync(&mut state, Some(&a)));
    state.clear_stale_invocation_cancel_token();
    assert!(
        state.invocation_cancel_token.is_some(),
        "a live per-principal token must survive the re-arm check"
    );

    // Full teardown (instance token cancelled): the short-circuit is desired.
    let mut torn_down = minimal_host_state(rt.handle().clone());
    assert!(install_principal_overlays_sync(&mut torn_down, Some(&a)));
    torn_down.cancel_token.cancel();
    torn_down.clear_stale_invocation_cancel_token();
    assert!(
        torn_down.invocation_cancel_token.is_some(),
        "full-unload cancellation must keep short-circuiting every wait"
    );
    assert!(torn_down.effective_cancel_token().is_cancelled());
}

/// The recv fast path (same-principal message) must refresh the token from
/// the shared map: a principal that departed (token cancelled + removed) and
/// re-registered gets a fresh token on its next message even though the
/// data overlays are deliberately kept.
#[test]
fn recv_fast_path_refreshes_token_after_view_release_cancel() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let mut state = minimal_host_state(rt.handle().clone());
    let a = alice();

    state.install_recv_invocation_context(&msg_from(&a));
    let first = state.effective_cancel_token();
    cancel_principal_token(&state.principal_cancel_tokens, &a);
    assert!(first.is_cancelled());

    // Same principal publishes again after re-registering: the fast path
    // keeps the KV/log overlays but must re-mint the cancel token.
    state.install_recv_invocation_context(&msg_from(&a));
    assert!(
        state
            .invocation_cancel_token
            .as_ref()
            .is_some_and(|t| !t.is_cancelled()),
        "the fast path must lazily mint a fresh token for a re-registered principal"
    );
}
