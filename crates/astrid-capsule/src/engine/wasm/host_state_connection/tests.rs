use std::sync::Arc;

use super::*;
use crate::engine::wasm::test_fixtures::minimal_host_state;

fn alice() -> astrid_core::principal::PrincipalId {
    astrid_core::PrincipalId::new("alice").expect("valid principal")
}

fn bob() -> astrid_core::principal::PrincipalId {
    astrid_core::PrincipalId::new("bob").expect("valid principal")
}

fn current_thread_state() -> (tokio::runtime::Runtime, HostState) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime");
    let state = minimal_host_state(runtime.handle().clone());
    (runtime, state)
}

#[test]
fn unused_connection_registries_are_uninitialized() {
    assert!(HostState::new_connection_principals().get().is_none());
    assert!(HostState::new_client_connections().get().is_none());
    assert!(HostState::new_shared_listeners().get().is_none());
}

#[test]
fn idle_unbind_does_not_initialize_connection_registry() {
    let (_runtime, state) = current_thread_state();
    assert!(state.connection_principals.get().is_none());
    state.unbind_connection_principal(7);
    assert!(state.connection_principals.get().is_none());
    assert_eq!(state.connection_principal(7), None);
}

#[test]
fn first_bind_initializes_one_default_shared_map() {
    let (_runtime, mut first) = current_thread_state();
    let (_runtime_b, mut second) = current_thread_state();
    let shared = HostState::new_connection_principals();
    first.connection_principals = Arc::clone(&shared);
    second.connection_principals = Arc::clone(&shared);

    first.bind_connection_principal(1, alice(), Some("device-alice".to_owned()));
    second.bind_connection_principal(2, bob(), Some("device-bob".to_owned()));

    assert!(Arc::ptr_eq(
        &first.connection_principals,
        &second.connection_principals
    ));
    let map = shared.get().expect("first bind initializes the map");
    assert_eq!(
        map.shards().len(),
        dashmap::DashMap::<u32, ConnectionIdentity>::new()
            .shards()
            .len(),
        "first insert must use DashMap::new, not a reduced shard count"
    );
    assert_eq!(first.connection_principal(1), Some(alice()));
    assert_eq!(second.connection_principal(1), Some(alice()));
    assert_eq!(first.connection_principal(2), Some(bob()));
    first.unbind_connection_principal(1);
    assert_eq!(second.connection_principal(1), None);
    assert_eq!(second.connection_principal(2), Some(bob()));
}

#[test]
fn interceptor_style_clones_share_identity_run_loop_maps_stay_private() {
    let (_runtime, mut interceptor_a) = current_thread_state();
    let (_runtime_b, mut interceptor_b) = current_thread_state();
    let shared = HostState::new_connection_principals();
    interceptor_a.connection_principals = Arc::clone(&shared);
    interceptor_b.connection_principals = Arc::clone(&shared);
    interceptor_a.bind_connection_principal(9, alice(), None);
    assert_eq!(interceptor_b.connection_principal(9), Some(alice()));

    let (_runtime_c, mut worker_a) = current_thread_state();
    let (_runtime_d, mut worker_b) = current_thread_state();
    worker_a.connection_principals = HostState::new_connection_principals();
    worker_b.connection_principals = HostState::new_connection_principals();
    worker_a.bind_connection_principal(9, alice(), None);
    assert_eq!(worker_b.connection_principal(9), None);
    assert_eq!(worker_a.connection_principal(9), Some(alice()));
}

#[test]
fn concurrent_connection_bindings_preserve_identity_and_owner() {
    let registry = HostState::new_connection_principals();
    let first_bind = std::sync::Barrier::new(16);
    let all_bound = std::sync::Barrier::new(16);
    let all_checked = std::sync::Barrier::new(16);
    assert!(registry.get().is_none());
    std::thread::scope(|scope| {
        for rep in 0..16 {
            let registry = Arc::clone(&registry);
            let (first_bind, all_bound, all_checked) = (&first_bind, &all_bound, &all_checked);
            scope.spawn(move || {
                let (_runtime, mut state) = current_thread_state();
                state.connection_principals = registry;
                let principal = astrid_core::PrincipalId::new(format!("client-{rep}"))
                    .expect("valid principal");
                let device_key_id = Some(format!("device-{rep}"));
                first_bind.wait();
                state.bind_connection_principal(rep, principal.clone(), device_key_id.clone());
                all_bound.wait();
                let identity = state
                    .connection_principals
                    .get()
                    .and_then(|map| map.get(&rep).map(|entry| entry.value().clone()));
                let bound_count = state.connection_principals.get().map(dashmap::DashMap::len);
                all_checked.wait();
                let identity = identity.expect("concurrent first bind preserves identity");
                assert_eq!(identity.principal, principal);
                assert_eq!(identity.device_key_id, device_key_id);
                assert_eq!(bound_count, Some(16));
                state.unbind_connection_principal(rep);
                assert_eq!(state.connection_principal(rep), None);
            });
        }
    });
    let map = registry.get().expect("first concurrent insert initializes");
    assert!(map.is_empty());
}

#[test]
fn fresh_client_registries_keep_stream_identifiers_private() {
    let first = HostState::new_client_connections();
    let second = HostState::new_client_connections();
    first.get_or_init(dashmap::DashMap::new).insert(42, alice());
    assert_eq!(
        first.get().and_then(|map| map.get(&42).as_deref().cloned()),
        Some(alice())
    );
    assert!(second.get().is_none());
    first.get().expect("first insert initializes").remove(&42);
    assert!(first.get().is_some_and(dashmap::DashMap::is_empty));
    assert!(second.get().is_none());
}
