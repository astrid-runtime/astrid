use super::*;
use crate::engine::wasm::bindings::astrid::ipc::host::Host as IpcHost;
use crate::engine::wasm::test_fixtures::minimal_host_state;
use astrid_events::ipc::delivery_failure::{DeliveryFailureBinding, DeliveryId, FAILURE_NAMESPACE};

const ID: &str = "1234567890abcdef1234567890abcdef";

fn receipt(publisher: uuid::Uuid, principal: &str) -> InternalIpcMessage {
    let mut request = InternalIpcMessage::new(
        Topic::from_raw("arbitrary.v1.request"),
        IpcPayload::RawJson(serde_json::json!({})),
        publisher,
    )
    .with_principal(principal);
    request.delivery_id = DeliveryId::parse(ID);
    DeliveryFailureBinding::capture(&request)
        .expect("guest binding")
        .message("provider failed")
}

fn publish(bus: &astrid_events::EventBus, message: InternalIpcMessage) {
    bus.publish(AstridEvent::Ipc {
        message,
        metadata: EventMetadata::new("dispatcher-test"),
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn receipt_alias_is_publisher_and_principal_scoped_before_guest_delivery() {
    let mut state = minimal_host_state(tokio::runtime::Handle::current());
    state.principal = astrid_core::PrincipalId::new("alice").expect("principal");
    state.ipc_subscribe_patterns = vec![format!("{FAILURE_NAMESPACE}.*")];
    let sub = IpcHost::subscribe(&mut state, format!("{FAILURE_NAMESPACE}.{ID}")).expect("alias");
    publish(&state.event_bus, receipt(uuid::Uuid::new_v4(), "alice"));
    publish(&state.event_bus, receipt(state.capsule_uuid, "bob"));
    assert!(
        HostSubscription::poll(&mut state, Resource::new_borrow(sub.rep()))
            .expect("poll")
            .messages
            .is_empty()
    );
    publish(&state.event_bus, receipt(state.capsule_uuid, "alice"));
    let env =
        HostSubscription::poll(&mut state, Resource::new_borrow(sub.rep())).expect("own receipt");
    assert_eq!(env.messages.len(), 1);
    assert_eq!(env.messages[0].source_id, uuid::Uuid::nil().to_string());
    let peer_topic = receipt(uuid::Uuid::new_v4(), "alice").topic.to_string();
    assert!(matches!(
        IpcHost::subscribe(&mut state, peer_topic),
        Err(ErrorCode::CapabilityDenied)
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn broad_subscriptions_filter_peer_receipts_and_guests_cannot_publish_receipts() {
    let mut state = minimal_host_state(tokio::runtime::Handle::current());
    state.principal = astrid_core::PrincipalId::new("alice").expect("principal");
    state.ipc_subscribe_patterns = vec!["astrid.*".into()];
    state.ipc_publish_patterns = vec!["astrid.*".into()];
    let sub = IpcHost::subscribe(&mut state, "astrid.*".into()).expect("broad subscription");
    publish(&state.event_bus, receipt(uuid::Uuid::new_v4(), "alice"));
    assert!(
        HostSubscription::poll(&mut state, Resource::new_borrow(sub.rep()))
            .expect("filtered poll")
            .messages
            .is_empty()
    );
    let topic = receipt(state.capsule_uuid, "alice").topic.to_string();
    assert!(matches!(
        IpcHost::publish(&mut state, topic, "{}".into()).await,
        Err(ErrorCode::CapabilityDenied)
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn publish_captures_metadata_before_typed_payload_conversion() {
    let mut state = minimal_host_state(tokio::runtime::Handle::current());
    state.ipc_publish_patterns = vec!["tool.v1.execute.example".into()];
    let mut receiver = state.event_bus.subscribe_topic("tool.v1.execute.example");
    IpcHost::publish(&mut state, "tool.v1.execute.example".into(), serde_json::json!({
        "type":"tool_execute_request", "call_id":"call", "tool_name":"example", "arguments":{}, "_astrid_delivery_id":ID
    }).to_string()).await.expect("publish");
    let event = receiver.recv().await.expect("published");
    let AstridEvent::Ipc { message, .. } = event.as_ref() else {
        panic!("IPC")
    };
    assert_eq!(message.delivery_id, DeliveryId::parse(ID));
    assert_eq!(message.source_id, state.capsule_uuid);
    assert!(matches!(
        message.payload,
        IpcPayload::ToolExecuteRequest { .. }
    ));
    assert!(
        !String::from_utf8(message.payload.to_guest_bytes().expect("guest bytes"))
            .expect("UTF-8")
            .contains("_astrid_delivery_id")
    );
    assert!(matches!(
        IpcHost::publish(
            &mut state,
            "tool.v1.execute.example".into(),
            "{\"_astrid_delivery_id\":\"../other\"}".into()
        )
        .await,
        Err(ErrorCode::InvalidInput)
    ));
}
