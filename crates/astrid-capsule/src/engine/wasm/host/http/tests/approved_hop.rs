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
) -> tokio::task::JoinHandle<String> {
    let mut requests = bus.subscribe_topic(Topic::approval_request().as_str());
    tokio::spawn(async move {
        let event = requests.recv().await.unwrap();
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
        let response = IpcMessage::new(
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
        let operator = answer(state.event_bus.clone(), owner, address, approved);
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
        let (line, host) = peer.await.unwrap();
        assert_eq!(line, "POST /v1/models?group=a%2Fb HTTP/1.1");
        assert_eq!(host.unwrap(), operator.await.unwrap());
    }
}
