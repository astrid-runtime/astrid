use super::super::HttpMethod;
use super::e2e::{follow_opts, get_request};
use crate::engine::wasm::test_fixtures::minimal_host_state;
use crate::security::AllowAllGate;
use std::sync::Arc;
use tokio::net::TcpListener;

use astrid_events::{
    AstridEvent, EventMetadata,
    ipc::{IpcMessage, IpcPayload, MessageOrigin, RequestOwnerId, Topic},
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

async fn receive_request(listener: TcpListener) -> (String, Option<String>) {
    let (mut socket, _) = listener.accept().await.unwrap();
    let mut lines = BufReader::new(&mut socket).lines();
    let first = lines.next_line().await.unwrap().unwrap();
    let mut host = None;
    while let Some(line) = lines.next_line().await.unwrap() {
        if line.is_empty() {
            break;
        }
        if let Some((key, value)) = line.split_once(':')
            && key.eq_ignore_ascii_case("host")
        {
            host = Some(value.trim().to_owned());
        }
    }
    socket
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
        .await
        .unwrap();
    (first, host)
}
fn answer(
    bus: astrid_events::EventBus,
    owner: RequestOwnerId,
    address: std::net::SocketAddr,
    approved: &'static str,
    device: Option<astrid_core::profile::DeviceKey>,
) -> tokio::task::JoinHandle<String> {
    let mut requests = bus.subscribe_topic(Topic::approval_request().as_str());
    tokio::spawn(async move {
        let event = tokio::time::timeout(std::time::Duration::from_secs(8), requests.recv())
            .await
            .expect("timed out waiting for an egress prompt")
            .unwrap();
        let AstridEvent::Ipc { message, .. } = &*event else {
            panic!("expected consent prompt")
        };
        let IpcPayload::ApprovalRequired {
            request_id,
            resource,
            ..
        } = &message.payload
        else {
            panic!("expected approval request")
        };
        let decision = if resource != &address.to_string() {
            "deny"
        } else {
            approved
        };
        let mut response = IpcMessage::new(
            Topic::approval_response(request_id),
            IpcPayload::ApprovalResponse {
                request_id: request_id.clone(),
                decision: decision.to_owned(),
                reason: None,
            },
            uuid::Uuid::nil(),
        )
        .with_principal("alice")
        .with_request_owner(owner);
        if let Some(device) = device {
            response.device_key_id = Some(device.key_id);
            response.device_registration_id = device.registration_id.map(Into::into);
        }
        bus.publish(AstridEvent::Ipc {
            message: response,
            metadata: EventMetadata::default(),
        });
        resource.clone()
    })
}

/// Compare the endpoint shown in the operator prompt to the peer that receives
/// the request. Both WIT backends must retain its method, path and query.
#[tokio::test(flavor = "multi_thread")]
async fn operator_approved_endpoint_receives_the_selected_hop() {
    for streaming in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let peer = tokio::spawn(receive_request(listener));

        let mut state = minimal_host_state(tokio::runtime::Handle::current());
        state.security = Some(Arc::new(AllowAllGate));
        state.allowance_store = Some(Arc::new(astrid_approval::AllowanceStore::new()));
        let owner = RequestOwnerId::generate();
        state.caller_context = Some(
            IpcMessage::new(
                Topic::from_raw("test"),
                IpcPayload::Connect,
                uuid::Uuid::nil(),
            )
            .with_principal("alice")
            .with_origin(MessageOrigin::LocalSocket)
            .with_request_owner(owner),
        );
        let approved = if streaming {
            "approve_always"
        } else {
            "approve"
        };
        let operator = answer(state.event_bus.clone(), owner, address, approved, None);
        let mut request = get_request(format!("http://{address}/v1/models?group=a%2Fb"));
        request.method = HttpMethod::Post;
        let opts =
            super::super::options::ResolvedOptions::from_options(follow_opts(), &state.http_limits);
        if streaming {
            let resource = state.http_stream_backend(request, opts).await.unwrap();
            assert_eq!(
                super::super::backend::stream_status(&mut state, resource.rep()),
                200
            );
        } else {
            assert_eq!(
                state
                    .http_request_backend(request, opts)
                    .await
                    .unwrap()
                    .status,
                200
            );
        }
        assert!(state.profile_cache.is_none());
        let action = astrid_approval::action::SensitiveAction::NetworkRequest {
            capsule_id: "test".into(),
            host: "127.0.0.1".into(),
            port: address.port(),
        };
        assert_eq!(
            state
                .allowance_store
                .as_ref()
                .unwrap()
                .find_matching(
                    &astrid_core::PrincipalId::new("alice").unwrap(),
                    &action,
                    None
                )
                .is_some(),
            streaming
        );
        let (line, host) = tokio::time::timeout(std::time::Duration::from_secs(8), peer)
            .await
            .expect("timed out waiting for the approved request")
            .unwrap();
        assert_eq!(line, "POST /v1/models?group=a%2Fb HTTP/1.1");
        assert_eq!(host.unwrap(), operator.await.unwrap());
    }
}

/// Retire each device during dispatch, body I/O admission, and a partial body read.
#[tokio::test(flavor = "multi_thread")]
async fn retiring_either_egress_device_cancels_an_admitted_http_send() {
    use crate::profile_cache::PrincipalProfileCache;
    use astrid_core::profile::{AuthMethod, DeviceKey, DeviceKeyId, DeviceScope};
    use astrid_core::{PrincipalId, PrincipalProfile, dirs::AstridHome};
    use std::time::Duration;

    #[derive(Clone, Copy)]
    enum Wait {
        Headers,
        BodyPermit,
        BodyChunk,
    }
    use Wait::{BodyChunk, BodyPermit, Headers};
    for (retire_responder, wait) in [false, true]
        .into_iter()
        .flat_map(|responder| [Headers, BodyPermit, BodyChunk].map(|wait| (responder, wait)))
    {
        let dir = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(dir.path());
        let principal = PrincipalId::new("alice").unwrap();
        let caller = DeviceKey::new("a".repeat(64), DeviceScope::Full, None, 0);
        let responder = DeviceKey::new("b".repeat(64), DeviceScope::Full, None, 0);
        let mut profile = PrincipalProfile::default();
        profile.auth.methods.push(AuthMethod::Keypair);
        profile.add_device(caller.clone());
        profile.add_device(responder.clone());
        profile.save(&home, &principal).unwrap();
        let mut state = minimal_host_state(tokio::runtime::Handle::current());
        state.profile_cache = Some(Arc::new(PrincipalProfileCache::with_home(home)));
        state.security = Some(Arc::new(AllowAllGate));
        state.allowance_store = Some(Arc::new(astrid_approval::AllowanceStore::new()));
        let owner = RequestOwnerId::generate();
        let mut context = IpcMessage::new(
            Topic::from_raw("test"),
            IpcPayload::Connect,
            uuid::Uuid::nil(),
        )
        .with_principal("alice")
        .with_origin(MessageOrigin::LocalSocket)
        .with_request_owner(owner);
        context.device_key_id = Some(caller.key_id.clone());
        context.device_registration_id = caller.registration_id.map(Into::into);
        state.caller_context = Some(context);
        let key = DeviceKeyId::new(if retire_responder {
            responder.key_id.clone()
        } else {
            caller.key_id.clone()
        })
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let operator = answer(
            state.event_bus.clone(),
            owner,
            address,
            "approve",
            Some(responder),
        );
        state.io_semaphore = Arc::new(tokio::sync::Semaphore::new(1));
        let io = state.io_semaphore.clone();
        let sessions = state.device_sessions.clone();
        let task = tokio::spawn(async move {
            let opts = super::super::options::ResolvedOptions::from_options(
                follow_opts(),
                &state.http_limits,
            );
            state
                .http_request_backend(get_request(format!("http://{address}/waiting")), opts)
                .await
        });
        tokio::time::timeout(Duration::from_secs(8), async {
            let (socket, _) = listener.accept().await.unwrap();
            let mut lines = BufReader::new(socket).lines();
            assert_eq!(
                lines.next_line().await.unwrap().unwrap(),
                "GET /waiting HTTP/1.1"
            );
            assert_eq!(operator.await.unwrap(), address.to_string());
            // Queue for the only I/O permit while send() is waiting for headers.
            // Receiving the permit proves the client has left its header wait.
            let mut body_barrier = None;
            if !matches!(wait, Headers) {
                let permit = io.acquire();
                tokio::pin!(permit);
                tokio::select! {
                    biased;
                    _ = &mut permit => panic!("send released its permit before response headers"),
                    () = std::future::ready(()) => {},
                }
                lines
                    .get_mut()
                    .get_mut()
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\na")
                    .await
                    .unwrap();
                body_barrier = Some(permit.await.unwrap());
                if matches!(wait, BodyChunk) {
                    drop(body_barrier.take());
                    // The HTTP task is the only other permit user. It now
                    // owns a body read that cannot finish with this prefix.
                    while io.available_permits() != 0 {
                        tokio::task::yield_now().await;
                    }
                }
            }
            sessions.retire(&principal, &key).await.unwrap();
            assert!(matches!(
                task.await.unwrap(),
                Err(super::super::ErrorCode::Closed)
            ));
            drop(body_barrier);
            drop(lines);
        })
        .await
        .expect("retirement must cancel the send before the peer responds");
    }
}
