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
use super::super::{
    PrincipalInvocationTracker, cancel_principal_token, install_principal_overlays_sync,
    resume_principal_token,
};
use crate::engine::wasm::bindings::astrid::elicit::host::Host as ElicitHost;
use crate::engine::wasm::bindings::astrid::fs::host::{ErrorCode as FsError, Host as FsHost};
use crate::engine::wasm::bindings::astrid::kv::host::{ErrorCode as KvError, Host as KvHost};
use astrid_events::ipc::Topic;

fn alice() -> astrid_core::PrincipalId {
    astrid_core::PrincipalId::new("agent-alice").expect("valid principal")
}

struct BlockingSetStore {
    inner: astrid_storage::MemoryKvStore,
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
}

#[async_trait::async_trait]
impl astrid_storage::KvStore for BlockingSetStore {
    async fn get(
        &self,
        namespace: &str,
        key: &str,
    ) -> astrid_storage::StorageResult<Option<Vec<u8>>> {
        self.inner.get(namespace, key).await
    }
    async fn set(
        &self,
        namespace: &str,
        key: &str,
        value: Vec<u8>,
    ) -> astrid_storage::StorageResult<()> {
        self.entered.notify_one();
        self.release.notified().await;
        self.inner.set(namespace, key, value).await
    }
    async fn delete(&self, namespace: &str, key: &str) -> astrid_storage::StorageResult<bool> {
        self.inner.delete(namespace, key).await
    }
    async fn exists(&self, namespace: &str, key: &str) -> astrid_storage::StorageResult<bool> {
        self.inner.exists(namespace, key).await
    }
    async fn list_keys(&self, namespace: &str) -> astrid_storage::StorageResult<Vec<String>> {
        self.inner.list_keys(namespace).await
    }
    async fn list_keys_with_prefix(
        &self,
        namespace: &str,
        prefix: &str,
    ) -> astrid_storage::StorageResult<Vec<String>> {
        self.inner.list_keys_with_prefix(namespace, prefix).await
    }
    async fn compare_and_swap(
        &self,
        namespace: &str,
        key: &str,
        expected: Option<&[u8]>,
        new: Vec<u8>,
    ) -> astrid_storage::StorageResult<bool> {
        self.inner
            .compare_and_swap(namespace, key, expected, new)
            .await
    }
    async fn clear_namespace(&self, namespace: &str) -> astrid_storage::StorageResult<u64> {
        self.inner.clear_namespace(namespace).await
    }
    async fn clear_prefix(
        &self,
        namespace: &str,
        prefix: &str,
    ) -> astrid_storage::StorageResult<u64> {
        self.inner.clear_prefix(namespace, prefix).await
    }
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

    cancel_principal_token(&state.principal_cancel_tokens, &state.cancel_token, &a);

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

/// (b) A late invocation after unregister must keep the retirement tombstone;
/// only explicit view re-registration may mint a fresh token.
#[test]
fn retired_overlay_stays_cancelled_until_explicit_resume() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let mut state = minimal_host_state(rt.handle().clone());
    let a = alice();

    assert!(install_principal_overlays_sync(&mut state, Some(&a)));
    let first = state.effective_cancel_token();
    cancel_principal_token(&state.principal_cancel_tokens, &state.cancel_token, &a);
    assert!(first.is_cancelled(), "release must cancel the live token");

    // A late invocation that lost the unregister race remains cancelled.
    assert!(install_principal_overlays_sync(&mut state, Some(&a)));
    assert!(state.effective_cancel_token().is_cancelled());

    // A legitimate delete-then-recreate crosses an explicit registration edge.
    resume_principal_token(&state.principal_cancel_tokens, &a);
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
    cancel_principal_token(&state.principal_cancel_tokens, &state.cancel_token, &a);
    state.clear_stale_invocation_cancel_token();
    assert!(
        state.invocation_cancel_token.is_none(),
        "the local overlay must clear so the shared pump can receive another caller"
    );
    assert!(!state.effective_cancel_token().is_cancelled());
    state.install_recv_invocation_context(&msg_from(&a));
    assert!(
        state.effective_cancel_token().is_cancelled(),
        "a queued retired-principal message must restore the tombstone"
    );

    // Explicit registration reopens the identity.
    resume_principal_token(&state.principal_cancel_tokens, &a);
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

/// The recv fast path must not mint authority after unregister. Explicit view
/// registration is the only operation that may reopen the principal.
#[test]
fn recv_fast_path_refreshes_token_after_view_release_cancel() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let mut state = minimal_host_state(rt.handle().clone());
    let a = alice();

    state.install_recv_invocation_context(&msg_from(&a));
    let first = state.effective_cancel_token();
    cancel_principal_token(&state.principal_cancel_tokens, &state.cancel_token, &a);
    assert!(first.is_cancelled());

    // Same principal publishes after unregister, without a registration edge.
    state.install_recv_invocation_context(&msg_from(&a));
    assert!(
        state
            .invocation_cancel_token
            .as_ref()
            .is_some_and(tokio_util::sync::CancellationToken::is_cancelled),
        "the fast path must preserve the retirement tombstone"
    );

    resume_principal_token(&state.principal_cancel_tokens, &a);
    state.install_recv_invocation_context(&msg_from(&a));
    assert!(!state.effective_cancel_token().is_cancelled());
}

#[tokio::test]
async fn retirement_fence_rejects_late_admission_and_drains_existing_call() {
    let tracker = Arc::new(PrincipalInvocationTracker::default());
    let principal = alice();
    let admitted = tracker.begin(&principal).expect("initial admission");
    tracker.retire(&principal);
    assert!(
        tracker.begin(&principal).is_none(),
        "late work must be fenced"
    );

    let waiter = {
        let tracker = Arc::clone(&tracker);
        let principal = principal.clone();
        tokio::spawn(async move { tracker.wait_for_quiescence(&principal).await })
    };
    tokio::task::yield_now().await;
    assert!(
        !waiter.is_finished(),
        "retirement must wait for admitted work"
    );
    drop(admitted);
    waiter.await.unwrap();

    tracker.resume(&principal);
    assert!(tracker.begin(&principal).is_some());
}

#[test]
fn retired_principal_loses_kv_fs_and_secret_host_authority_without_harming_peer() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let mut state = minimal_host_state(rt.handle().clone());
    let a = alice();
    let bob = astrid_core::PrincipalId::new("agent-bob").unwrap();

    assert!(install_principal_overlays_sync(&mut state, Some(&a)));
    KvHost::kv_set(&mut state, "before".into(), b"allowed".to_vec()).unwrap();
    cancel_principal_token(&state.principal_cancel_tokens, &state.cancel_token, &a);

    assert!(matches!(
        KvHost::kv_set(&mut state, "after".into(), b"denied".to_vec()),
        Err(KvError::Unknown(_))
    ));
    assert!(matches!(
        FsHost::write_file(
            &mut state,
            "cwd://retired-effect".into(),
            b"denied".to_vec()
        ),
        Err(FsError::CapabilityDenied)
    ));
    assert!(ElicitHost::has_secret(&mut state, "token".into()).is_err());

    // The same shared Store may subsequently serve a peer. Installing Bob's
    // overlay selects his independent live token; Alice's tombstone remains.
    assert!(install_principal_overlays_sync(&mut state, Some(&bob)));
    KvHost::kv_set(&mut state, "peer".into(), b"alive".to_vec()).unwrap();
    assert_eq!(
        KvHost::kv_get(&mut state, "peer".into()).unwrap(),
        Some(b"alive".to_vec())
    );
    assert!(!state.cancel_token.is_cancelled());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retirement_waits_for_admitted_recv_kv_effect_before_reclamation() {
    let tracker = Arc::new(PrincipalInvocationTracker::default());
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let backend: Arc<dyn astrid_storage::KvStore> = Arc::new(BlockingSetStore {
        inner: astrid_storage::MemoryKvStore::new(),
        entered: Arc::clone(&entered),
        release: Arc::clone(&release),
    });
    let mut state = minimal_host_state(tokio::runtime::Handle::current());
    let a = alice();
    state.principal_invocations = Some(Arc::clone(&tracker));
    state.invocation_kv = Some(astrid_storage::ScopedKvStore::new(backend, "alice:test").unwrap());
    assert!(install_principal_overlays_sync(&mut state, Some(&a)));
    // Restore the barrier backend after overlay installation selected the
    // production principal store.
    let backend: Arc<dyn astrid_storage::KvStore> = Arc::new(BlockingSetStore {
        inner: astrid_storage::MemoryKvStore::new(),
        entered: Arc::clone(&entered),
        release: Arc::clone(&release),
    });
    state.invocation_kv = Some(astrid_storage::ScopedKvStore::new(backend, "alice:test").unwrap());

    let operation = tokio::task::spawn_blocking(move || {
        let result = KvHost::kv_set(&mut state, "effect".into(), b"committed".to_vec());
        (state, result)
    });
    entered.notified().await;
    tracker.retire(&a);
    let draining = {
        let tracker = Arc::clone(&tracker);
        let a = a.clone();
        tokio::spawn(async move { tracker.wait_for_quiescence(&a).await })
    };
    tokio::task::yield_now().await;
    assert!(
        !draining.is_finished(),
        "reclamation must wait behind the KV effect"
    );

    release.notify_one();
    let (mut state, result) = operation.await.unwrap();
    result.unwrap();
    draining.await.unwrap();

    let bob = astrid_core::PrincipalId::new("agent-bob-barrier").unwrap();
    tracker.resume(&bob);
    assert!(install_principal_overlays_sync(&mut state, Some(&bob)));
    assert!(
        state.begin_host_operation().is_ok(),
        "peer authority remains live"
    );
}
