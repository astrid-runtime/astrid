use std::sync::{Arc, Mutex as StdMutex};

use tokio::sync::{Notify, Semaphore};
use tokio::time::Instant;

use super::*;

thread_local! {
    static FINISH_SLOT_PROBE: std::cell::RefCell<Option<Arc<StdMutex<Option<bool>>>>> =
        const { std::cell::RefCell::new(None) };
}

struct FinishSlotProbeGuard;

fn register_finish_slot_probe(result: Arc<StdMutex<Option<bool>>>) -> FinishSlotProbeGuard {
    FINISH_SLOT_PROBE.with(|probe| {
        assert!(
            probe.replace(Some(result)).is_none(),
            "finish-slot probe already set"
        );
    });
    FinishSlotProbeGuard
}

impl Drop for FinishSlotProbeGuard {
    fn drop(&mut self) {
        FINISH_SLOT_PROBE.with(|probe| {
            probe.borrow_mut().take();
        });
    }
}

pub(super) fn probe_finish_slot(semaphore: &Semaphore) {
    FINISH_SLOT_PROBE.with(|probe| {
        let Some(result) = probe.borrow().clone() else {
            return;
        };
        let available = semaphore.try_acquire().is_ok();
        if let Ok(mut observed) = result.lock() {
            *observed = Some(available);
        }
    });
}
use std::path::PathBuf;

use tokio::io::{AsyncWriteExt, BufReader};

use super::{
    AttachSlot, GatewayState, MAX_ATTACHES, MAX_REGISTRATION_BYTES, authenticate_registration,
    mint_hook_token, read_registration, read_registration_inner, validate_workspace,
};
use crate::commands::mcp::lifecycle::AttachRegistration;

#[test]
fn attach_cap_is_bounded_per_principal_channel() {
    assert_eq!(MAX_ATTACHES, 16);
}

#[test]
fn control_tokens_have_distinct_lifetimes_and_widths() {
    let boot_token = mint_boot_token();
    let hook_token = mint_hook_token();
    assert_eq!(boot_token.len(), 32);
    assert_eq!(hook_token.len(), 64);
    assert_ne!(boot_token, hook_token);
}

#[tokio::test]
async fn every_stopper_is_counted_until_its_ack_delivery_finishes() {
    let principal = astrid_core::PrincipalId::new("codex-code").expect("principal");
    let state = GatewayState::new(
        PathBuf::from("/runtime-home"),
        principal,
        "gateway-token".into(),
    );
    state.begin_stop_ack();
    state.begin_stop_ack();

    let waiting = state.wait_for_stop_acks();
    tokio::pin!(waiting);
    tokio::task::yield_now().await;
    state.finish_stop_ack();
    tokio::time::timeout(std::time::Duration::from_millis(20), &mut waiting)
        .await
        .expect_err("the final stopper must not release the run loop early");

    tokio::task::yield_now().await;
    state.finish_stop_ack();
    tokio::time::timeout(std::time::Duration::from_millis(1), &mut waiting)
        .await
        .expect("final ACK delivery must be bounded");
}

#[tokio::test]
async fn attach_cap_rejects_the_seventeenth_live_session() {
    let principal = astrid_core::PrincipalId::new("codex-code").expect("principal");
    let state = GatewayState::new(
        PathBuf::from("/runtime-home"),
        principal,
        "gateway-token".into(),
    );
    let mut permits = Vec::with_capacity(MAX_ATTACHES);
    for _ in 0..MAX_ATTACHES {
        permits.push(state.acquire("codex-code").await.expect("attach permit"));
    }
    assert!(state.acquire("codex-code").await.is_err());
    drop(permits);
    assert!(state.acquire("codex-code").await.is_ok());
}

#[tokio::test]
async fn registration_preface_times_out_without_a_newline() {
    let (_peer, stream) = tokio::io::duplex(1);
    let mut reader = BufReader::new(stream);
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        read_registration(&mut reader),
    )
    .await
    .expect("registration timeout test must complete");
    let error = result.expect_err("a preface without a newline must time out");
    assert!(
        error
            .to_string()
            .contains("timed out reading MCP attach registration"),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn oversized_registration_preface_fails_without_waiting_for_a_newline() {
    let (mut peer, stream) = tokio::io::duplex(MAX_REGISTRATION_BYTES + 1);
    peer.write_all(&vec![b'x'; MAX_REGISTRATION_BYTES + 1])
        .await
        .expect("oversized preface must fit in the test peer");
    let mut reader = BufReader::new(stream);
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        read_registration_inner(&mut reader),
    )
    .await
    .expect("registration size test must complete");
    let error = result.expect_err("an oversized preface must be rejected");
    assert!(
        error
            .to_string()
            .contains("registration is missing or too large"),
        "unexpected error: {error}"
    );
}

#[test]
fn registration_workspace_must_be_absolute() {
    let workspace = tempfile::tempdir().expect("workspace tempdir");
    assert!(validate_workspace(&workspace.path().to_string_lossy()).is_ok());
    assert!(validate_workspace("project").is_err());
    assert!(validate_workspace("").is_err());
}

#[test]
fn forged_principal_cannot_select_another_gateway_uplink() {
    let principal = astrid_core::PrincipalId::new("codex-code").expect("principal");
    let forged = astrid_core::PrincipalId::new("other-agent").expect("principal");
    let state = GatewayState::new(
        PathBuf::from("/runtime-home"),
        principal,
        "gateway-token".into(),
    );
    let registration = AttachRegistration {
        version: super::ATTACH_REGISTRATION_VERSION,
        principal: forged.to_string(),
        host: "codex".into(),
        workspace_abs: "/tmp".into(),
        host_session_id: "thread-1".into(),
        hook_token: "gateway-token".into(),
    };
    let error = authenticate_registration(&registration, &state)
        .expect_err("forged principal must be rejected");
    assert!(
        error
            .to_string()
            .contains("authenticated gateway principal")
    );
}

#[test]
fn missing_hook_token_is_rejected_before_uplink_selection() {
    let principal = astrid_core::PrincipalId::new("codex-code").expect("principal");
    let state = GatewayState::new(
        PathBuf::from("/runtime-home"),
        principal.clone(),
        "gateway-token".into(),
    );
    let registration = AttachRegistration {
        version: super::ATTACH_REGISTRATION_VERSION,
        principal: principal.to_string(),
        host: "codex".into(),
        workspace_abs: "/tmp".into(),
        host_session_id: "thread-1".into(),
        hook_token: String::new(),
    };
    let error = authenticate_registration(&registration, &state)
        .expect_err("missing token must be rejected");
    assert!(error.to_string().contains("hook_token is invalid"));
}

#[test]
fn hook_token_is_minted_with_each_gateway_start() {
    let first = mint_hook_token();
    let second = mint_hook_token();
    assert_eq!(first.len(), 64);
    assert_ne!(first, second);
}

#[tokio::test]
async fn same_session_replaces_the_previous_attach() {
    use std::sync::{Arc, Mutex as StdMutex};

    use tokio::sync::Notify;
    use tokio::time::Instant;
    use tokio_util::sync::CancellationToken;

    use uuid::Uuid;

    let principal = astrid_core::PrincipalId::new("codex-code").expect("principal");
    let state = GatewayState::new(
        PathBuf::from("/runtime-home"),
        principal,
        "gateway-token".into(),
    );
    let permit = state.acquire("codex-code").await.expect("permit");
    let cancel = CancellationToken::new();
    let done = Arc::new(Notify::new());
    state
        .install_slot(
            "thread-1".into(),
            AttachSlot {
                id: Uuid::new_v4(),
                cancel: cancel.clone(),
                last_activity: Arc::new(StdMutex::new(Instant::now())),
                done: Arc::clone(&done),
            },
        )
        .await;
    tokio::spawn(async move {
        cancel.cancelled().await;
        drop(permit);
        done.notify_waiters();
    });
    state
        .replace_session("thread-1")
        .await
        .expect("replacement teardown must complete");
    let _permit = state
        .acquire("codex-code")
        .await
        .expect("replaced session must free the attach cap");
}

#[tokio::test]
async fn same_session_admission_serializes_reserve_acquire_install() {
    use std::sync::{Arc, Mutex as StdMutex};

    use tokio::sync::Notify;
    use tokio::time::{Duration, Instant, timeout};
    use tokio_util::sync::CancellationToken;
    use uuid::Uuid;

    let principal = astrid_core::PrincipalId::new("codex-code").expect("principal");
    let state = Arc::new(GatewayState::new(
        PathBuf::from("/runtime-home"),
        principal,
        "gateway-token".into(),
    ));
    let first = state
        .reserve_session("thread-1", "codex-code")
        .await
        .expect("first reservation");
    let second_state = Arc::clone(&state);
    let mut second =
        tokio::spawn(async move { second_state.reserve_session("thread-1", "codex-code").await });
    tokio::task::yield_now().await;
    assert!(
        timeout(Duration::from_millis(20), &mut second)
            .await
            .is_err()
    );

    let first_id = Uuid::new_v4();
    let first_cancel = CancellationToken::new();
    let first_done = Arc::new(Notify::new());
    let first_permit = first
        .install(
            &state,
            "thread-1".into(),
            AttachSlot {
                id: first_id,
                cancel: first_cancel.clone(),
                last_activity: Arc::new(StdMutex::new(Instant::now())),
                done: Arc::clone(&first_done),
            },
        )
        .await;
    let cleanup_state = Arc::clone(&state);
    tokio::spawn(async move {
        first_cancel.cancelled().await;
        cleanup_state.take_slot_if("thread-1", first_id).await;
        drop(first_permit);
        first_done.notify_waiters();
    });

    let second = timeout(Duration::from_secs(1), &mut second)
        .await
        .expect("second reservation must complete")
        .expect("second reservation task")
        .expect("second reservation");
    let second_id = Uuid::new_v4();
    let second_done = Arc::new(Notify::new());
    let second_permit = second
        .install(
            &state,
            "thread-1".into(),
            AttachSlot {
                id: second_id,
                cancel: CancellationToken::new(),
                last_activity: Arc::new(StdMutex::new(Instant::now())),
                done: Arc::clone(&second_done),
            },
        )
        .await;
    assert_eq!(
        state.slots.lock().await.get("thread-1").map(|slot| slot.id),
        Some(second_id)
    );
    state
        .finish_slot("thread-1", second_id, second_permit, second_done)
        .await;
}

struct SilentServer;

impl rmcp::ServerHandler for SilentServer {}

#[tokio::test]
async fn replacement_waits_for_pending_rmcp_initialization() {
    use std::sync::atomic::{AtomicBool, Ordering};

    use tokio::net::UnixStream;
    use tokio::time::{Duration, timeout};
    use tokio_util::sync::CancellationToken;
    use uuid::Uuid;

    let principal = astrid_core::PrincipalId::new("codex-code").expect("principal");
    let state = Arc::new(GatewayState::new(
        PathBuf::from("/runtime-home"),
        principal,
        "gateway-token".into(),
    ));
    let (peer, stream) = UnixStream::pair().expect("Unix stream pair");
    let (reader, write_half) = tokio::io::split(stream);
    let host_session_id = "thread-1";
    let slot_id = Uuid::new_v4();
    let cancel = CancellationToken::new();
    let done = Arc::new(Notify::new());
    let permit = state.acquire("codex-code").await.expect("old permit");
    state
        .install_slot(
            host_session_id.into(),
            AttachSlot {
                id: slot_id,
                cancel: cancel.clone(),
                last_activity: Arc::new(StdMutex::new(Instant::now())),
                done: Arc::clone(&done),
            },
        )
        .await;

    let peers = Arc::new(Mutex::new(HashMap::new()));
    let finished = Arc::new(AtomicBool::new(false));
    let cleanup_state = Arc::clone(&state);
    let cleanup_finished = Arc::clone(&finished);
    let cleanup_done = Arc::clone(&done);
    let cleanup_cancel = cancel.clone();
    let mut old_task = tokio::spawn(async move {
        let result = run_attached_session(
            SilentServer,
            reader,
            write_half,
            peers,
            slot_id,
            cleanup_cancel,
        )
        .await;
        cleanup_finished.store(true, Ordering::Release);
        cleanup_state
            .finish_slot(host_session_id, slot_id, permit, cleanup_done)
            .await;
        result
    });

    // Keep the transport open and silent: serve_with_ct must be cancellable
    // while waiting for the initialize request itself.
    let _peer = peer;
    let reservation = timeout(
        Duration::from_secs(2),
        state.reserve_session(host_session_id, "codex-code"),
    )
    .await
    .expect("replacement admission must be bounded")
    .expect("replacement must wait for the old RMCP session to finish");
    assert!(
        finished.load(Ordering::Acquire),
        "new admission must not proceed while the old attach is pending"
    );
    assert!(
        state.slots.lock().await.get(host_session_id).is_none(),
        "old slot must be removed before replacement admission"
    );
    let mut available = Vec::with_capacity(MAX_ATTACHES - 1);
    for _ in 0..MAX_ATTACHES - 1 {
        available.push(
            state
                .acquire("codex-code")
                .await
                .expect("old permit must be released before replacement admission"),
        );
    }
    drop(available);
    drop(reservation);

    let old_result = timeout(Duration::from_secs(1), &mut old_task)
        .await
        .expect("old attach cleanup must finish")
        .expect("old attach task");
    assert!(
        old_result.is_err(),
        "cancelled initialization must fail closed"
    );
    cancel.cancel();
}

#[tokio::test]
async fn replacement_timeout_rejects_new_admission() {
    use tokio::time::{Duration, timeout};
    use tokio_util::sync::CancellationToken;
    use uuid::Uuid;

    let principal = astrid_core::PrincipalId::new("codex-code").expect("principal");
    let state = GatewayState::new(
        PathBuf::from("/runtime-home"),
        principal,
        "gateway-token".into(),
    );
    let permit = state.acquire("codex-code").await.expect("old permit");
    state
        .install_slot(
            "thread-1".into(),
            AttachSlot {
                id: Uuid::new_v4(),
                cancel: CancellationToken::new(),
                last_activity: Arc::new(StdMutex::new(Instant::now())),
                done: Arc::new(Notify::new()),
            },
        )
        .await;

    let result = timeout(
        Duration::from_secs(2),
        state.reserve_session("thread-1", "codex-code"),
    )
    .await
    .expect("replacement timeout must be bounded");
    let Err(error) = result else {
        panic!("new admission must fail when teardown does not finish");
    };
    assert!(
        error.to_string().contains("replacement teardown timed out"),
        "unexpected replacement error: {error}"
    );
    drop(permit);
}

#[tokio::test]
async fn stale_session_cleanup_cannot_remove_a_replacement() {
    use std::sync::{Arc, Mutex as StdMutex};

    use tokio::sync::Notify;
    use tokio::time::Instant;
    use tokio_util::sync::CancellationToken;
    use uuid::Uuid;

    let principal = astrid_core::PrincipalId::new("codex-code").expect("principal");
    let state = GatewayState::new(
        PathBuf::from("/runtime-home"),
        principal,
        "gateway-token".into(),
    );
    let old_id = Uuid::new_v4();
    let old_cancel = CancellationToken::new();
    state
        .install_slot(
            "thread-1".into(),
            AttachSlot {
                id: old_id,
                cancel: old_cancel,
                last_activity: Arc::new(StdMutex::new(Instant::now())),
                done: Arc::new(Notify::new()),
            },
        )
        .await;
    assert!(state.take_slot_if("thread-1", old_id).await);

    let replacement_id = Uuid::new_v4();
    state
        .install_slot(
            "thread-1".into(),
            AttachSlot {
                id: replacement_id,
                cancel: CancellationToken::new(),
                last_activity: Arc::new(StdMutex::new(Instant::now())),
                done: Arc::new(Notify::new()),
            },
        )
        .await;
    assert!(!state.take_slot_if("thread-1", old_id).await);
    assert_eq!(
        state.slots.lock().await.get("thread-1").map(|slot| slot.id),
        Some(replacement_id)
    );
}

#[tokio::test]
async fn finish_slot_releases_cap_before_notifying_waiters() {
    use std::sync::{Arc, Mutex as StdMutex};

    use tokio::sync::Notify;
    use tokio::time::{Duration, timeout};
    use uuid::Uuid;

    let principal = astrid_core::PrincipalId::new("codex-code").expect("principal");
    let state = Arc::new(GatewayState::new(
        PathBuf::from("/runtime-home"),
        principal,
        "gateway-token".into(),
    ));
    let observed = Arc::new(StdMutex::new(None));
    let _probe = register_finish_slot_probe(Arc::clone(&observed));
    let finishing = state.acquire("codex-code").await.expect("permit");
    let mut occupied = Vec::with_capacity(MAX_ATTACHES - 1);
    for _ in 0..MAX_ATTACHES - 1 {
        occupied.push(state.acquire("codex-code").await.expect("permit"));
    }
    let done = Arc::new(Notify::new());
    let notified = Arc::clone(&done).notified_owned();
    let waiter_state = Arc::clone(&state);
    let waiter = tokio::spawn(async move {
        notified.await;
        waiter_state.acquire("codex-code").await
    });
    tokio::task::yield_now().await;
    state
        .finish_slot("thread-1", Uuid::new_v4(), finishing, done)
        .await;
    assert_eq!(
        *observed.lock().expect("finish-slot probe mutex"),
        Some(true),
        "permit must be available at the notification boundary"
    );
    let permit = timeout(Duration::from_secs(1), waiter)
        .await
        .expect("waiter must wake")
        .expect("waiter task")
        .expect("released permit must be available before notification");
    drop(permit);
    drop(occupied);
}

#[tokio::test]
async fn acquire_evicts_idle_lru_then_admits() {
    use std::sync::{Arc, Mutex as StdMutex};

    use tokio::sync::Notify;
    use tokio::time::Instant;
    use tokio_util::sync::CancellationToken;

    use super::{ATTACH_IDLE_EOF, AttachSlot};
    use uuid::Uuid;

    let principal = astrid_core::PrincipalId::new("codex-code").expect("principal");
    let state = GatewayState::new(
        PathBuf::from("/runtime-home"),
        principal,
        "gateway-token".into(),
    );
    for index in 0..MAX_ATTACHES {
        let permit = state.acquire("codex-code").await.expect("permit");
        let cancel = CancellationToken::new();
        let done = Arc::new(Notify::new());
        let last = Instant::now()
            .checked_sub(ATTACH_IDLE_EOF + std::time::Duration::from_millis(5))
            .expect("idle timestamp");
        state
            .install_slot(
                format!("idle-{index}"),
                AttachSlot {
                    id: Uuid::new_v4(),
                    cancel: cancel.clone(),
                    last_activity: Arc::new(StdMutex::new(last)),
                    done: Arc::clone(&done),
                },
            )
            .await;
        tokio::spawn(async move {
            cancel.cancelled().await;
            drop(permit);
            done.notify_waiters();
        });
    }
    let _permit = state
        .acquire("codex-code")
        .await
        .expect("idle LRU eviction must admit a new attach");
}

#[tokio::test]
async fn acquire_does_not_evict_active_slots() {
    use std::sync::{Arc, Mutex as StdMutex};

    use tokio::sync::Notify;
    use tokio::time::Instant;
    use tokio_util::sync::CancellationToken;

    use uuid::Uuid;

    let principal = astrid_core::PrincipalId::new("codex-code").expect("principal");
    let state = GatewayState::new(
        PathBuf::from("/runtime-home"),
        principal,
        "gateway-token".into(),
    );
    let mut cancels = Vec::new();
    for index in 0..MAX_ATTACHES {
        let permit = state.acquire("codex-code").await.expect("permit");
        let cancel = CancellationToken::new();
        let done = Arc::new(Notify::new());
        state
            .install_slot(
                format!("live-{index}"),
                AttachSlot {
                    id: Uuid::new_v4(),
                    cancel: cancel.clone(),
                    last_activity: Arc::new(StdMutex::new(Instant::now())),
                    done: Arc::clone(&done),
                },
            )
            .await;
        cancels.push(cancel.clone());
        tokio::spawn(async move {
            cancel.cancelled().await;
            drop(permit);
            done.notify_waiters();
        });
    }
    assert!(state.acquire("codex-code").await.is_err());
    for cancel in cancels {
        cancel.cancel();
    }
}

#[tokio::test]
async fn forged_gateway_stop_cannot_cancel_the_process() {
    use tokio::io::AsyncReadExt;

    let principal = astrid_core::PrincipalId::new("codex-code").expect("principal");
    let state = Arc::new(GatewayState::new(
        PathBuf::from("/runtime-home"),
        principal,
        "gateway-token".into(),
    ));
    let request = GatewayControlRequest {
        version: GATEWAY_CONTROL_VERSION,
        operation: GatewayControlOperation::Stop,
        pid: std::process::id(),
        hook_token: "forged-token".into(),
    };
    let (server, mut client) = tokio::io::duplex(4096);
    let connection = state.connection();

    serve_control(request, server, Arc::clone(&state), Some(connection))
        .await
        .expect("forged control receives a bounded rejection");
    let mut response = Vec::new();
    client
        .read_to_end(&mut response)
        .await
        .expect("control ACK");
    let ack: GatewayControlAck =
        serde_json::from_slice(&response).expect("rejection is valid JSON");
    assert!(!ack.ok);
    assert!(!state.shutdown.is_cancelled());
    assert_eq!(state.active_connections.load(Ordering::Acquire), 0);
}

#[tokio::test]
async fn authenticated_gateway_stop_waits_for_final_teardown_ack() {
    use tokio::io::AsyncReadExt;
    use tokio::time::{Duration, timeout};

    let principal = astrid_core::PrincipalId::new("codex-code").expect("principal");
    let state = Arc::new(GatewayState::new(
        PathBuf::from("/runtime-home"),
        principal,
        "gateway-token".into(),
    ));
    let request = GatewayControlRequest {
        version: GATEWAY_CONTROL_VERSION,
        operation: GatewayControlOperation::Stop,
        pid: std::process::id(),
        hook_token: "gateway-token".into(),
    };
    let (server, mut client) = tokio::io::duplex(4096);
    let serving_state = Arc::clone(&state);
    let connection = state.connection();
    let serving = tokio::spawn(async move {
        serve_control(request, server, serving_state, Some(connection)).await
    });

    timeout(Duration::from_secs(1), state.shutdown.cancelled())
        .await
        .expect("authenticated stop must cancel the gateway");
    assert_eq!(state.active_connections.load(Ordering::Acquire), 0);
    assert!(
        timeout(Duration::from_millis(20), client.read_u8())
            .await
            .is_err(),
        "no success ACK may precede final teardown"
    );

    state
        .finish_shutdown(GatewayControlAck::success(
            GatewayControlOperation::Stop,
            std::process::id(),
        ))
        .await;
    let mut response = Vec::new();
    client
        .read_to_end(&mut response)
        .await
        .expect("control ACK");
    serving
        .await
        .expect("control task")
        .expect("authenticated control");
    let ack: GatewayControlAck = serde_json::from_slice(&response).expect("valid ACK JSON");
    assert!(ack.ok);
    timeout(Duration::from_secs(1), state.shutdown_ack_sent.notified())
        .await
        .expect("ACK completion notification retains its permit");
}

#[tokio::test]
async fn shutdown_waits_for_precounted_connections() {
    use tokio::time::{Duration, timeout};

    let principal = astrid_core::PrincipalId::new("codex-code").expect("principal");
    let state = Arc::new(GatewayState::new(
        PathBuf::from("/runtime-home"),
        principal,
        "gateway-token".into(),
    ));
    let connection = state.connection();
    let waiting_state = Arc::clone(&state);
    let mut waiting = tokio::spawn(async move { waiting_state.wait_for_connections().await });

    assert!(
        timeout(Duration::from_millis(20), &mut waiting)
            .await
            .is_err(),
        "shutdown must not race past an accepted, not-yet-polled connection"
    );
    drop(connection);
    timeout(Duration::from_secs(1), waiting)
        .await
        .expect("connection drain")
        .expect("connection waiter");
}

#[tokio::test]
async fn concurrent_accepted_stoppers_receive_the_same_final_ack() {
    use tokio::io::AsyncWriteExt;
    use tokio::net::UnixListener;
    use tokio::time::{Duration, timeout};

    let principal = astrid_core::PrincipalId::new("codex-code").expect("principal");
    let state = Arc::new(GatewayState::new(
        PathBuf::from("/runtime-home"),
        principal,
        "gateway-token".into(),
    ));
    let socket = std::env::temp_dir().join(format!("astrid-1809-stop-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&socket);
    let listener = UnixListener::bind(&socket).expect("short-path gateway listener");
    let accepting_state = Arc::clone(&state);
    let accepting = tokio::spawn(async move { accept_loop(listener, accepting_state).await });

    let request = serde_json::to_vec(&GatewayControlRequest {
        version: GATEWAY_CONTROL_VERSION,
        operation: GatewayControlOperation::Stop,
        pid: std::process::id(),
        hook_token: "gateway-token".into(),
    })
    .expect("control request");
    let mut clients = Vec::new();
    for _ in 0..2 {
        let mut client = tokio::net::UnixStream::connect(&socket)
            .await
            .expect("connect stopper");
        client
            .write_all(&request)
            .await
            .expect("queue stop request");
        client.write_all(b"\n").await.expect("terminate request");
        clients.push(client);
    }
    tokio::task::yield_now().await;
    state.shutdown.cancel();

    state
        .finish_shutdown(GatewayControlAck::success(
            GatewayControlOperation::Stop,
            std::process::id(),
        ))
        .await;
    timeout(Duration::from_secs(1), accepting)
        .await
        .expect("accept loop drains all stoppers")
        .expect("accept loop task")
        .expect("normal accept exit");

    let mut acks = Vec::new();
    for mut client in clients {
        let mut response = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut client, &mut response)
            .await
            .expect("control ACK");
        acks.push(serde_json::from_slice::<GatewayControlAck>(&response).expect("valid ACK"));
    }
    assert!(acks.iter().all(|ack| ack.ok));
    let _ = std::fs::remove_file(&socket);
}

#[tokio::test]
async fn shutdown_rejects_late_attach_admission() {
    let principal = astrid_core::PrincipalId::new("codex-code").expect("principal");
    let state = GatewayState::new(
        PathBuf::from("/runtime-home"),
        principal,
        "gateway-token".into(),
    );
    state.shutdown.cancel();

    let Err(error) = state.reserve_session("thread-late", "codex-code").await else {
        panic!("stop must close attach admission");
    };
    assert!(error.to_string().contains("shutting down"));
}

#[test]
fn gateway_cleanup_failure_does_not_mask_accept_failure() {
    let error = combine_gateway_results(
        Err(anyhow::anyhow!("gateway.accept")),
        Err(anyhow::anyhow!("gateway.listener_cleanup")),
    )
    .expect_err("both failures must be returned");
    let message = format!("{error:#}");
    assert!(message.starts_with("gateway.accept"));
    assert!(message.contains("additional gateway cleanup failure"));
    assert!(message.contains("gateway.listener_cleanup"));
}
