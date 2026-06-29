use std::sync::Arc;

use crate::engine::wasm::bindings::astrid::elicit::host::Host as ElicitHost;
use crate::engine::wasm::host_state::HostState;
use crate::engine::wasm::test_fixtures::{mem_secret_store, minimal_host_state};
use astrid_storage::secret::SecretStore;

fn make_host_state_with_secret(
    rt: tokio::runtime::Handle,
    owner_namespace: &str,
) -> (HostState, Arc<dyn SecretStore>) {
    let owner_secret = mem_secret_store(owner_namespace, rt.clone());
    let mut state = minimal_host_state(rt);
    state.secret_store = Arc::clone(&owner_secret);
    (state, owner_secret)
}

fn make_invocation_store(rt: tokio::runtime::Handle, namespace: &str) -> Arc<dyn SecretStore> {
    mem_secret_store(namespace, rt)
}

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
    let (mut state, owner_secret) = make_host_state_with_secret(rt.clone(), "capsule:test-owner");
    let alice_secret = make_invocation_store(rt, "capsule:test-alice");

    {
        let s = Arc::clone(&owner_secret);
        blocking(move || s.set("shared_key", "owner-val").unwrap()).await;
    }
    state.invocation_secret_store = Some(Arc::clone(&alice_secret));

    let (state, got) = blocking(move || {
        let mut s = state;
        let got = s.has_secret("shared_key".to_string()).unwrap();
        (s, got)
    })
    .await;
    assert!(!got, "invocation store is empty; owner's key must not leak");

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

    state.invocation_secret_store = None;
    let (_state, got) = blocking(move || {
        let mut s = state;
        let got = s.has_secret("shared_key".to_string()).unwrap();
        (s, got)
    })
    .await;
    assert!(got, "owner's key still present after clear");

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
    let rt = tokio::runtime::Handle::current();
    let (mut state, _owner_secret) = make_host_state_with_secret(rt.clone(), "capsule:test-owner");

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
