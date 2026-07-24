//! Regression tests for the PR #752 `write` fix.
//!
//! The legacy implementation silently swallowed peer-disconnect
//! errors as `Ok(())` on the theory "the capsule will see it on
//! the next read". Capsules using TcpStream for request/response
//! could not detect a half-closed connection. We now surface
//! `ConnectionReset` for any peer-disconnect IO kind and
//! `Unknown` for everything else.
use super::*;
use std::io;

#[test]
fn write_frame_err_brokenpipe_maps_to_connection_reset() {
    let e = io::Error::new(io::ErrorKind::BrokenPipe, "peer gone");
    assert!(matches!(
        map_write_frame_err(&e),
        ErrorCode::ConnectionReset
    ));
}

#[test]
fn write_frame_err_connection_reset_maps_to_connection_reset() {
    let e = io::Error::new(io::ErrorKind::ConnectionReset, "rst");
    assert!(matches!(
        map_write_frame_err(&e),
        ErrorCode::ConnectionReset
    ));
}

#[test]
fn write_frame_err_connection_aborted_maps_to_connection_reset() {
    let e = io::Error::new(io::ErrorKind::ConnectionAborted, "abort");
    assert!(matches!(
        map_write_frame_err(&e),
        ErrorCode::ConnectionReset
    ));
}

#[test]
fn write_frame_err_unexpected_eof_maps_to_connection_reset() {
    let e = io::Error::new(io::ErrorKind::UnexpectedEof, "eof");
    assert!(matches!(
        map_write_frame_err(&e),
        ErrorCode::ConnectionReset
    ));
}

#[test]
fn write_frame_err_other_maps_to_unknown() {
    let e = io::Error::other("weird");
    assert!(matches!(map_write_frame_err(&e), ErrorCode::Unknown(_)));
}

#[test]
fn write_frame_err_timed_out_maps_to_unknown() {
    // Timeouts are NOT peer disconnect — capsule can retry.
    let e = io::Error::new(io::ErrorKind::TimedOut, "slow");
    assert!(matches!(map_write_frame_err(&e), ErrorCode::Unknown(_)));
}

/// ENFORCEMENT wiring for the per-connection principal registry
/// (issue #45/#852): a framed read off a kernel-bound connection must
/// record that connection's verified principal in
/// [`HostState::ingress_principal`], and a non-data read must clear it.
///
/// This guards the link DIRECTLY rather than via a manually-set field: the
/// `publish-as` override in `host/ipc.rs` consumes `ingress_principal`, so
/// if this read never populated it the override would silently fall back to
/// the capsule-supplied (forgeable) name and the self-stamp hole would
/// reopen — with `publish-as`-level tests still green. A loopback TCP pair
/// stands in for an accepted client connection without depending on the
/// platform's host-local transport implementation.
#[tokio::test(flavor = "multi_thread")]
async fn framed_read_records_then_clears_verified_ingress_principal() {
    use tokio::io::AsyncWriteExt;

    use crate::engine::wasm::test_fixtures::minimal_host_state;

    let rt = tokio::runtime::Handle::current();
    let mut state = minimal_host_state(rt);
    // Only the uplink records ingress principals (and only its accept path
    // ever binds an entry).
    state.has_uplink_capability = true;

    let Some((net, mut peer)) = framed_test_stream_pair().await else {
        return;
    };
    let rep = state.resource_table.push(net).expect("push stream").rep();

    // The handshake bound this connection to `claude` (Path 2 crypto, or a
    // Path 1 daemon spawn-binding), with the matched device key_id so the
    // cap-gate can scope it.
    let claude = astrid_core::PrincipalId::new("claude").unwrap();
    state.bind_connection_principal(rep, claude.clone(), Some("dev-abc123".to_string()));

    // Peer sends one length-prefixed frame (4-byte BE length + payload).
    let payload = br#"{"topic":"client.v1.connect","payload":{}}"#;
    peer.write_all(&(payload.len() as u32).to_be_bytes())
        .await
        .unwrap();
    peer.write_all(payload).await.unwrap();
    peer.flush().await.unwrap();

    // A data read records the connection's verified principal AND the
    // device key_id that authenticated it.
    let status =
        HostTcpStream::read(&mut state, Resource::new_borrow(rep)).expect("read should succeed");
    assert!(
        matches!(status, NetReadStatus::Data(_)),
        "expected a data frame, got {status:?}"
    );
    assert_eq!(
        state.ingress_principal,
        Some(claude),
        "a data read on a kernel-bound connection must record its verified principal"
    );
    assert_eq!(
        state.ingress_device_key_id.as_deref(),
        Some("dev-abc123"),
        "a data read must record the connection's authenticating device key_id"
    );
    assert_eq!(
        state.ingress_origin,
        Some(astrid_events::ipc::MessageOrigin::LocalSocket),
        "a data read on a kernel-BOUND connection must stamp LocalSocket origin"
    );

    // A subsequent non-data read (no more frames → pending) clears BOTH, so
    // a stale principal or device id can never leak onto a later forward.
    let status =
        HostTcpStream::read(&mut state, Resource::new_borrow(rep)).expect("read should succeed");
    assert!(
        matches!(status, NetReadStatus::Pending),
        "expected pending, got {status:?}"
    );
    assert_eq!(
        state.ingress_principal, None,
        "a non-data read must clear the in-flight ingress principal"
    );
    assert_eq!(
        state.ingress_device_key_id, None,
        "a non-data read must clear the in-flight ingress device key_id"
    );
    assert_eq!(
        state.ingress_origin, None,
        "a non-data read must clear the in-flight LocalSocket origin so a \
             stale local origin can never leak onto a later forward"
    );
}

/// A non-uplink capsule never records an ingress principal even when it
/// reads a (hypothetically) bound stream — the gate keeps the registry
/// lookup off every non-uplink framed read and prevents any cross-capsule
/// principal bleed through `ingress_principal`.
#[tokio::test(flavor = "multi_thread")]
async fn framed_read_is_inert_without_uplink_capability() {
    use tokio::io::AsyncWriteExt;

    use crate::engine::wasm::test_fixtures::minimal_host_state;

    let rt = tokio::runtime::Handle::current();
    let mut state = minimal_host_state(rt);
    // No uplink capability — the default.
    assert!(!state.has_uplink_capability);

    let Some((net, mut peer)) = framed_test_stream_pair().await else {
        return;
    };
    let rep = state.resource_table.push(net).expect("push stream").rep();
    state.bind_connection_principal(
        rep,
        astrid_core::PrincipalId::new("claude").unwrap(),
        Some("dev-abc123".to_string()),
    );

    let payload = br#"{"topic":"x","payload":{}}"#;
    peer.write_all(&(payload.len() as u32).to_be_bytes())
        .await
        .unwrap();
    peer.write_all(payload).await.unwrap();
    peer.flush().await.unwrap();

    let status =
        HostTcpStream::read(&mut state, Resource::new_borrow(rep)).expect("read should succeed");
    assert!(matches!(status, NetReadStatus::Data(_)));
    assert_eq!(
        state.ingress_principal, None,
        "a non-uplink read must not populate the ingress principal"
    );
    assert_eq!(
        state.ingress_device_key_id, None,
        "a non-uplink read must not populate the ingress device key_id"
    );
    assert_eq!(
        state.ingress_origin, None,
        "a non-uplink read must not stamp a transport origin"
    );
}

/// A framed read off an UNBOUND connection (no `ConnectionIdentity`) must
/// NOT earn `LocalSocket` — it stays `None` (= `System`, fail-closed,
/// non-local), parallel to the `anonymous` principal an unbound forward
/// earns. This is the security floor that stops a peer-cred-trusted-but-
/// unauthenticated local connection from claiming local-operator privilege.
#[tokio::test(flavor = "multi_thread")]
async fn framed_read_unbound_connection_does_not_earn_local_origin() {
    use tokio::io::AsyncWriteExt;

    use crate::engine::wasm::test_fixtures::minimal_host_state;

    let rt = tokio::runtime::Handle::current();
    let mut state = minimal_host_state(rt);
    // Uplink capability is set (so the registry lookup runs), but the
    // connection is never bound — no `bind_connection_principal` call.
    state.has_uplink_capability = true;

    let Some((net, mut peer)) = framed_test_stream_pair().await else {
        return;
    };
    let rep = state.resource_table.push(net).expect("push stream").rep();
    // Deliberately NO bind: this is an unbound (unauthenticated) connection.

    let payload = br#"{"topic":"x","payload":{}}"#;
    peer.write_all(&(payload.len() as u32).to_be_bytes())
        .await
        .unwrap();
    peer.write_all(payload).await.unwrap();
    peer.flush().await.unwrap();

    let status =
        HostTcpStream::read(&mut state, Resource::new_borrow(rep)).expect("read should succeed");
    assert!(matches!(status, NetReadStatus::Data(_)));
    assert_eq!(
        state.ingress_principal, None,
        "an unbound connection stamps no verified principal"
    );
    assert_eq!(
        state.ingress_origin, None,
        "an unbound connection must NOT earn LocalSocket — it stays System \
             (fail-closed, non-local)"
    );
}

/// Establish a connected loopback TCP pair with small socket buffers, so a
/// non-draining peer fills the send window quickly. Returns `None` (skip)
/// when the sandbox blocks the loopback bind, mirroring the http tests.
async fn small_buffer_tcp_pair() -> Option<(tokio::net::TcpStream, tokio::net::TcpStream)> {
    let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => l,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("skipping: sandbox blocks loopback bind: {e}");
            return None;
        },
        Err(e) => panic!("loopback bind failed: {e}"),
    };
    let addr = listener.local_addr().unwrap();
    let (host, accepted) = tokio::join!(tokio::net::TcpStream::connect(addr), listener.accept());
    let host = host.expect("connect");
    let (peer, _) = accepted.expect("accept");
    // Shrink the buffers (best-effort) so the send window closes after a
    // few KB rather than autotuning up to megabytes.
    socket2::SockRef::from(&host)
        .set_send_buffer_size(4096)
        .ok();
    socket2::SockRef::from(&peer)
        .set_recv_buffer_size(4096)
        .ok();
    Some((host, peer))
}

/// Wrap one side of a cross-platform loopback pair as a host resource.
async fn framed_test_stream_pair() -> Option<(
    crate::engine::wasm::host_state::NetStream,
    tokio::net::TcpStream,
)> {
    use crate::engine::wasm::host_state::{NetStream, TcpStreamSlot};

    let (host, peer) = small_buffer_tcp_pair().await?;
    Some((
        NetStream::Tcp(TcpStreamSlot {
            stream: std::sync::Arc::new(tokio::sync::Mutex::new(host)),
            read_timeout: None,
            write_timeout: None,
        }),
        peer,
    ))
}

/// Regression for issue #1144: a connected client that stops draining its
/// socket must not freeze the host write path. With the send buffer full
/// the framed `write` awaited forever before the fix — and because the
/// capsule-cli proxy services every uplink from a single run loop, that one
/// stalled write silenced accepts, binds, and forwards for the whole uplink
/// surface. The write is now bounded by the slot `write_timeout`, so a
/// non-draining peer becomes a prompt write error (the guest proxy evicts
/// the client on it) and the blocking-semaphore slot is released, not
/// leaked. Runs the (blocking) host fn on a spawned worker so a regression
/// surfaces as a fast timeout here instead of hanging the whole suite.
#[tokio::test(flavor = "multi_thread")]
async fn write_to_non_draining_peer_times_out_and_releases_slot() {
    use crate::engine::wasm::host_state::{NetStream, TcpStreamSlot};
    use crate::engine::wasm::test_fixtures::minimal_host_state;

    let Some((host, _peer)) = small_buffer_tcp_pair().await else {
        return;
    };

    let rt = tokio::runtime::Handle::current();
    let mut state = minimal_host_state(rt);
    let sem = state.blocking_semaphore.clone();
    let total_permits = sem.available_permits();

    // A short explicit write deadline keeps the test fast; the Tcp arm
    // honours it. `_peer` is held open and never read, so its receive
    // window closes and the host's send buffer fills.
    let slot = TcpStreamSlot {
        stream: std::sync::Arc::new(tokio::sync::Mutex::new(host)),
        read_timeout: None,
        write_timeout: Some(Duration::from_millis(200)),
    };
    let rep = state
        .resource_table
        .push(NetStream::Tcp(slot))
        .expect("push stream")
        .rep();

    // A payload far larger than the (shrunk) socket buffers guarantees the
    // write cannot drain and must block on writability until the deadline.
    let data = vec![0u8; 4 * 1024 * 1024];

    let write_task = tokio::spawn(async move {
        let start = std::time::Instant::now();
        let r = HostTcpStream::write(&mut state, Resource::new_borrow(rep), data);
        (r, start.elapsed())
    });
    let (result, elapsed) = tokio::time::timeout(Duration::from_secs(15), write_task)
        .await
        .expect("the bounded write must return, not hang — a hang means #1144 regressed")
        .expect("write task panicked");

    assert!(
        result.is_err(),
        "a write to a non-draining peer must return an error, not block forever"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "the bounded write must return promptly (~200ms deadline), took {elapsed:?}"
    );
    assert_eq!(
        sem.available_permits(),
        total_permits,
        "the blocking-semaphore slot must be released after the timeout (no leak)"
    );
}

/// A stuck write holds the per-stream mutex, so a second write must be
/// bounded on the LOCK too — not just on the socket (issue #1144). Hold the
/// stream lock and confirm a concurrent host write still times out and
/// releases its slot, rather than blocking unbounded on `lock().await`.
#[tokio::test(flavor = "multi_thread")]
async fn write_bounded_even_when_stream_lock_is_held() {
    use crate::engine::wasm::host_state::{NetStream, TcpStreamSlot};
    use crate::engine::wasm::test_fixtures::minimal_host_state;

    let Some((host, _peer)) = small_buffer_tcp_pair().await else {
        return;
    };

    let rt = tokio::runtime::Handle::current();
    let mut state = minimal_host_state(rt);
    let sem = state.blocking_semaphore.clone();
    let total_permits = sem.available_permits();

    let stream = std::sync::Arc::new(tokio::sync::Mutex::new(host));
    let slot = TcpStreamSlot {
        stream: stream.clone(),
        read_timeout: None,
        write_timeout: Some(Duration::from_millis(200)),
    };
    let rep = state
        .resource_table
        .push(NetStream::Tcp(slot))
        .expect("push stream")
        .rep();

    // Simulate a first, stuck write that owns the mutex for the whole test.
    let _guard = stream.lock().await;

    let data = vec![0u8; 64];
    let write_task =
        tokio::spawn(
            async move { HostTcpStream::write(&mut state, Resource::new_borrow(rep), data) },
        );
    let result = tokio::time::timeout(Duration::from_secs(15), write_task)
        .await
        .expect("a write blocked on the held lock must still time out, not hang")
        .expect("write task panicked");

    assert!(
        result.is_err(),
        "a write that cannot acquire the stream lock must error, not block forever"
    );
    assert_eq!(
        sem.available_permits(),
        total_permits,
        "the blocking slot must be released after the lock-acquisition timeout"
    );
}

/// The write deadline honours an explicit Tcp `write_timeout`, and
/// otherwise falls back to the payload-scaled default ceiling
/// (`5000 + len/1024` ms) on both transport arms — the Unix arm having no
/// per-slot timeout field (issue #1144, deadline policy).
#[tokio::test(flavor = "multi_thread")]
async fn write_deadline_honours_slot_timeout_else_scales_by_payload() {
    use crate::engine::wasm::host_state::{NetStream, TcpStreamSlot};

    // Unix arm: always the default ceiling, scaled by payload size.
    #[cfg(unix)]
    {
        let (host_end, _peer) = tokio::net::UnixStream::pair().expect("socketpair");
        let unix = NetStream::Unix(std::sync::Arc::new(tokio::sync::Mutex::new(host_end)));
        assert_eq!(
            write_deadline(&unix, 0),
            Duration::from_millis(5000),
            "Unix arm with an empty payload uses the 5s base ceiling"
        );
        assert_eq!(
            write_deadline(&unix, 1024 * 1024),
            Duration::from_millis(5000 + 1024),
            "Unix arm scales the ceiling by payload size"
        );
    }

    // Tcp arm needs a real stream; skip if the sandbox blocks the bind.
    let Some((host, _tcp_peer)) = small_buffer_tcp_pair().await else {
        return;
    };
    let stream = std::sync::Arc::new(tokio::sync::Mutex::new(host));

    let with_timeout = NetStream::Tcp(TcpStreamSlot {
        stream: stream.clone(),
        read_timeout: None,
        write_timeout: Some(Duration::from_millis(250)),
    });
    assert_eq!(
        write_deadline(&with_timeout, 8 * 1024 * 1024),
        Duration::from_millis(250),
        "an explicit write_timeout wins regardless of payload size"
    );

    let no_timeout = NetStream::Tcp(TcpStreamSlot {
        stream,
        read_timeout: None,
        write_timeout: None,
    });
    assert_eq!(
        write_deadline(&no_timeout, 2048),
        Duration::from_millis(5000 + 2),
        "a Tcp slot without a write_timeout falls back to the default ceiling"
    );
}
