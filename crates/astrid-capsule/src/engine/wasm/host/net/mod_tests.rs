//! Bind / quota / shared-listener tests for `astrid:net` host TCP.
//!
//! Split out of `mod.rs` to stay under the 1000-line CI cap.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use super::*;
use crate::engine::wasm::bindings::astrid::net::host::{Host as _, HostTcpListener};
use crate::engine::wasm::test_fixtures::minimal_host_state;

#[test]
fn max_active_streams_pinned() {
    assert_eq!(MAX_ACTIVE_STREAMS, 8);
    assert_eq!(MAX_ACTIVE_TCP_LISTENERS, 4);
}

#[tokio::test(flavor = "multi_thread")]
async fn tcp_listener_quota_is_independent_and_released_on_drop() {
    let mut state = minimal_host_state(tokio::runtime::Handle::current());
    let mut listeners = Vec::new();
    for _ in 0..MAX_ACTIVE_TCP_LISTENERS {
        listeners.push(state.bind_tcp("127.0.0.1".into(), 0).unwrap());
    }
    assert!(matches!(
        state.bind_tcp("127.0.0.1".into(), 0),
        Err(ErrorCode::Quota)
    ));

    let released = listeners.pop().unwrap();
    HostTcpListener::drop(&mut state, released).unwrap();
    let replacement = state.bind_tcp("127.0.0.1".into(), 0).unwrap();
    HostTcpListener::drop(&mut state, replacement).unwrap();
    for listener in listeners {
        HostTcpListener::drop(&mut state, listener).unwrap();
    }
    assert_eq!(state.tcp_listener_count.load(Ordering::Acquire), 0);
}

/// #1231: the N worker Stores of one run-loop capsule must land on ONE
/// bound socket, not N. Models the real load path, where `shared_listeners`
/// and `tcp_listener_count` are created once per capsule and cloned into
/// every worker's HostState.
///
/// Asserts the quota too, because the obvious implementation charges the
/// listener quota per worker: `bind_workers = 8` would then burn 8 of
/// MAX_ACTIVE_TCP_LISTENERS (which is 4) for a single real listener, and a
/// capsule that binds one port could not start at all.
/// A concrete free port, the way a manifest declares one. Sharing is only
/// defined for a concrete port — port 0 means "any ephemeral port", so two
/// such requests are different addresses and never dedupe.
fn free_port() -> u16 {
    let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("probe bind");
    let port = probe.local_addr().expect("probe addr").port();
    drop(probe);
    port
}

#[tokio::test(flavor = "multi_thread")]
async fn worker_stores_dedupe_onto_one_bound_socket() {
    let port = free_port();
    let handle = tokio::runtime::Handle::current();
    let mut worker_a = minimal_host_state(handle.clone());
    let mut worker_b = minimal_host_state(handle);
    // Same capsule ⇒ shared registry and shared quota counter.
    worker_b.shared_listeners = Arc::clone(&worker_a.shared_listeners);
    worker_b.tcp_listener_count = Arc::clone(&worker_a.tcp_listener_count);

    let a = worker_a.bind_tcp("127.0.0.1".into(), port).unwrap();
    let b = worker_b.bind_tcp("127.0.0.1".into(), port).unwrap();

    assert_eq!(
        worker_a.shared_listeners.len(),
        1,
        "both workers must observe ONE registry entry for the address"
    );
    assert_eq!(
        worker_a.tcp_listener_count.load(Ordering::Acquire),
        1,
        "the quota bounds OS listeners, and there is exactly one"
    );

    HostTcpListener::drop(&mut worker_a, a).unwrap();
    HostTcpListener::drop(&mut worker_b, b).unwrap();
    assert_eq!(
        worker_a.shared_listeners.len(),
        0,
        "last slot drop must evict the registry so the OS socket closes"
    );
    assert_eq!(worker_a.tcp_listener_count.load(Ordering::Acquire), 0);
}

/// The registry key is the NORMALIZED host. `bind_tcp` rewrites `localhost`
/// to a loopback literal (local name service is mutable host config and may
/// not resolve to loopback), so the rewrite has to happen BEFORE the key is
/// taken — otherwise one worker saying `localhost` and another saying
/// `127.0.0.1` produce two entries and race for the same OS port, which on
/// macOS is an EADDRINUSE failure rather than a second socket.
#[tokio::test(flavor = "multi_thread")]
async fn localhost_and_loopback_literal_share_one_registry_entry() {
    let port = free_port();
    let handle = tokio::runtime::Handle::current();
    let mut worker_a = minimal_host_state(handle.clone());
    let mut worker_b = minimal_host_state(handle);
    worker_b.shared_listeners = Arc::clone(&worker_a.shared_listeners);
    worker_b.tcp_listener_count = Arc::clone(&worker_a.tcp_listener_count);

    let a = worker_a.bind_tcp("localhost".into(), port).unwrap();
    let b = worker_b.bind_tcp("127.0.0.1".into(), port).unwrap();

    assert_eq!(
        worker_a.shared_listeners.len(),
        1,
        "`localhost` and `127.0.0.1` are the same address and must share one entry"
    );
    assert!(
        worker_a
            .shared_listeners
            .contains_key(&("127.0.0.1".to_string(), port)),
        "the registry must be keyed on the normalized literal, never on `localhost`"
    );

    HostTcpListener::drop(&mut worker_a, a).unwrap();
    HostTcpListener::drop(&mut worker_b, b).unwrap();
    assert_eq!(worker_a.shared_listeners.len(), 0);
    assert_eq!(worker_a.tcp_listener_count.load(Ordering::Acquire), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn last_slot_drop_closes_os_socket_so_rebind_succeeds() {
    let port = free_port();
    let mut state = minimal_host_state(tokio::runtime::Handle::current());
    let first = state.bind_tcp("127.0.0.1".into(), port).unwrap();
    HostTcpListener::drop(&mut state, first).unwrap();
    assert_eq!(
        state.shared_listeners.len(),
        0,
        "N=1 must evict the registry on drop"
    );
    assert_eq!(state.tcp_listener_count.load(Ordering::Acquire), 0);
    let rebound = state
        .bind_tcp("127.0.0.1".into(), port)
        .expect("same concrete port must be bindable after last drop");
    HostTcpListener::drop(&mut state, rebound).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn binder_first_drop_keeps_quota_until_last_live_slot() {
    let port = free_port();
    let handle = tokio::runtime::Handle::current();
    let mut binder = minimal_host_state(handle.clone());
    let mut sibling = minimal_host_state(handle.clone());
    sibling.shared_listeners = Arc::clone(&binder.shared_listeners);
    sibling.tcp_listener_count = Arc::clone(&binder.tcp_listener_count);

    let binder_slot = binder.bind_tcp("127.0.0.1".into(), port).unwrap();
    let sibling_slot = sibling.bind_tcp("127.0.0.1".into(), port).unwrap();
    HostTcpListener::drop(&mut binder, binder_slot).unwrap();
    assert_eq!(
        binder.tcp_listener_count.load(Ordering::Acquire),
        1,
        "quota tracks the live socket, not the binder slot"
    );
    assert_eq!(binder.shared_listeners.len(), 1);

    let mut outsider = minimal_host_state(handle);
    assert!(
        matches!(
            outsider.bind_tcp("127.0.0.1".into(), port),
            Err(ErrorCode::AddressInUse)
        ),
        "sibling still holds the OS socket after binder-first drop"
    );

    HostTcpListener::drop(&mut sibling, sibling_slot).unwrap();
    assert_eq!(binder.tcp_listener_count.load(Ordering::Acquire), 0);
    assert_eq!(binder.shared_listeners.len(), 0);
    let rebound = outsider
        .bind_tcp("127.0.0.1".into(), port)
        .expect("port is free after last live slot drops");
    HostTcpListener::drop(&mut outsider, rebound).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn pooled_interceptor_instances_do_not_share_a_concrete_port() {
    let port = free_port();
    let handle = tokio::runtime::Handle::current();
    let mut first = minimal_host_state(handle.clone());
    let mut second = minimal_host_state(handle);
    second.tcp_listener_count = Arc::clone(&first.tcp_listener_count);
    // Deliberately do NOT clone shared_listeners: interceptor / non-worker
    // pool instances each get a fresh map.
    let first_slot = first.bind_tcp("127.0.0.1".into(), port).unwrap();
    assert!(
        matches!(
            second.bind_tcp("127.0.0.1".into(), port),
            Err(ErrorCode::AddressInUse)
        ),
        "two pooled instances must not clone one concrete-port socket"
    );
    HostTcpListener::drop(&mut first, first_slot).unwrap();
    let second_slot = second
        .bind_tcp("127.0.0.1".into(), port)
        .expect("second instance can bind after the first closes");
    HostTcpListener::drop(&mut second, second_slot).unwrap();
}

#[test]
fn public_store_count_excludes_other_pending_reservations() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let mut state = minimal_host_state(runtime.handle().clone());

    assert!(state.reserve_net_stream());
    state
        .capsule_net_stream_count
        .fetch_add(1, Ordering::AcqRel);
    state.local_net_stream_count.fetch_add(1, Ordering::AcqRel);
    assert_eq!(state.net_stream_count, 1);

    state.release_net_stream();
    assert_eq!(state.net_stream_count, 0);
    state.claim_reserved_net_stream();
    assert_eq!(state.net_stream_count, 1);
    assert_eq!(state.capsule_net_stream_count.load(Ordering::Acquire), 1);
    assert_eq!(state.local_net_stream_count.load(Ordering::Acquire), 1);
}

#[test]
fn public_store_count_excludes_existing_pending_on_direct_reserve() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let mut state = minimal_host_state(runtime.handle().clone());

    state
        .capsule_net_stream_count
        .fetch_add(1, Ordering::AcqRel);
    state.local_net_stream_count.fetch_add(1, Ordering::AcqRel);
    assert_eq!(state.net_stream_count, 0);

    assert!(state.reserve_net_stream());
    assert_eq!(state.net_stream_count, 1);
    state.claim_reserved_net_stream();
    assert_eq!(state.net_stream_count, 2);
    assert_eq!(state.capsule_net_stream_count.load(Ordering::Acquire), 2);
    assert_eq!(state.local_net_stream_count.load(Ordering::Acquire), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn localhost_binds_a_concrete_loopback_address() {
    let mut state = minimal_host_state(tokio::runtime::Handle::current());
    let listener = state.bind_tcp("localhost".into(), 0).unwrap();
    let local = state
        .local_addr(Resource::new_borrow(listener.rep()))
        .unwrap();
    let addr: std::net::SocketAddr = local.parse().unwrap();
    assert!(addr.ip().is_loopback());
    HostTcpListener::drop(&mut state, listener).unwrap();
}

#[test]
fn validate_host_accepts_normal_names() {
    assert!(validate_host("example.com").is_ok());
    assert!(validate_host("fulcrum.unicity.network").is_ok());
    assert!(validate_host("127.0.0.1").is_ok());
    assert!(validate_host("::1").is_ok());
}

#[test]
fn validate_host_rejects_empty() {
    assert!(validate_host("").is_err());
}

#[test]
fn validate_host_rejects_null_bytes() {
    assert!(validate_host("evil\0.com").is_err());
}

#[test]
fn validate_host_rejects_overlength() {
    let long = "a".repeat(256);
    assert!(validate_host(&long).is_err());
}

#[test]
fn validate_host_accepts_max_length() {
    let max = "a".repeat(255);
    assert!(validate_host(&max).is_ok());
}

#[test]
fn loopback_bind_host_accepts_loopback() {
    assert!(is_loopback_bind_host("127.0.0.1"));
    assert!(is_loopback_bind_host("127.0.0.5"));
    assert!(is_loopback_bind_host("::1"));
    assert!(is_loopback_bind_host("localhost"));
    assert!(is_loopback_bind_host("LOCALHOST"));
}

#[test]
fn loopback_bind_host_rejects_non_loopback() {
    assert!(!is_loopback_bind_host("0.0.0.0"));
    assert!(!is_loopback_bind_host("192.168.1.10"));
    assert!(!is_loopback_bind_host("8.8.8.8"));
    assert!(!is_loopback_bind_host("::"));
    // A hostname other than localhost is refused (not resolved).
    assert!(!is_loopback_bind_host("example.com"));
    assert!(!is_loopback_bind_host(""));
}
