//! Terminal denial reporting through the real reserved dispatcher path.

use super::*;
use astrid_events::ipc::{IpcMessage, MessageOrigin, RequestOwnerId};

const REQUEST: &str = "astrid.v1.request.example";
const REQ_ID: &str = "1234567890abcdef1234567890abcdef";

async fn exercise_terminal_denial(priorities: &[u32], expected_failure: bool) {
    let mut registry = CapsuleRegistry::new();
    let count = Arc::new(AtomicUsize::new(0));
    for (index, priority) in priorities.iter().enumerate() {
        let (mut capsule, _) =
            MockCapsule::with_priority(&format!("handler-{index}"), REQUEST, *priority, None);
        capsule.invoke_counter = Some(Arc::clone(&count));
        if index == 0 {
            capsule.result_override = Some(InterceptResult::Deny {
                reason: "invocation deadline exceeded".into(),
            });
        }
        register_system_test_capsule(&mut registry, Box::new(capsule));
    }
    let bus = Arc::new(EventBus::with_capacity(64));
    let mut failures = bus.subscribe_topic(format!("astrid.v1.response.failure.{REQ_ID}"));
    let dispatcher = EventDispatcher::new(Arc::new(RwLock::new(registry)), Arc::clone(&bus));
    let handle = tokio::spawn(dispatcher.run());
    tokio::task::yield_now().await;
    let owner = RequestOwnerId::generate();
    let message = IpcMessage::new(
        Topic::from_raw(REQUEST),
        IpcPayload::RawJson(serde_json::json!({"req_id": REQ_ID})),
        uuid::Uuid::nil(),
    )
    .with_principal("default")
    .with_request_owner(owner)
    .with_origin(MessageOrigin::LocalSocket);
    bus.reserve_publication(AstridEvent::Ipc {
        message,
        metadata: astrid_events::EventMetadata::new("native-test"),
    })
    .await
    .unwrap()
    .publish()
    .unwrap();

    let result = tokio::time::timeout(Duration::from_millis(300), failures.recv()).await;
    if expected_failure {
        let event = result
            .expect("terminal denial must be reported promptly")
            .unwrap();
        let AstridEvent::Ipc { message, .. } = event.as_ref() else {
            panic!("IPC failure")
        };
        assert_eq!(message.request_owner, Some(owner));
        assert_eq!(message.principal.as_deref(), Some("default"));
        assert!(message.source_id.is_nil());
        let IpcPayload::RawJson(payload) = &message.payload else {
            panic!("failure payload")
        };
        assert_eq!(payload["req_id"], REQ_ID);
        assert_eq!(payload["reason"], "invocation deadline exceeded");
        assert!(
            tokio::time::timeout(Duration::from_millis(20), failures.recv())
                .await
                .is_err(),
            "one failure only"
        );
        assert_eq!(
            count.load(Ordering::SeqCst),
            1,
            "ordered denial prevents subsequent execution"
        );
    } else {
        assert!(
            result.is_err(),
            "independent fan-out cannot terminate the request"
        );
        assert_eq!(count.load(Ordering::SeqCst), priorities.len());
    }
    handle.abort();
    let _ = handle.await;
}

#[tokio::test]
async fn terminal_denial_reports_sole_consumer_failure() {
    exercise_terminal_denial(&[100], true).await;
}

#[tokio::test]
async fn terminal_denial_reports_ordered_guard_failure() {
    exercise_terminal_denial(&[10, 100], true).await;
}

#[tokio::test]
async fn terminal_denial_does_not_fail_independent_fanout() {
    exercise_terminal_denial(&[100, 100], false).await;
}

/// A nested guest publication participates without borrowing native reply authority.
async fn exercise_guest_denial(priorities: &[u32], expected_failure: bool) {
    let mut registry = CapsuleRegistry::new();
    let count = Arc::new(AtomicUsize::new(0));
    for (index, priority) in priorities.iter().enumerate() {
        let (mut capsule, _) = MockCapsule::with_priority(
            &format!("provider-{index}"),
            "arbitrary.v1.request",
            *priority,
            None,
        );
        capsule.invoke_counter = Some(Arc::clone(&count));
        if index == 0 {
            capsule.result_override = Some(InterceptResult::Deny {
                reason: "interceptor execution failed".into(),
            });
        }
        register_system_test_capsule(&mut registry, Box::new(capsule));
    }
    let bus = Arc::new(EventBus::with_capacity(64));
    let publisher = uuid::Uuid::new_v4();
    let id = astrid_events::ipc::delivery_failure::DeliveryId::parse(REQ_ID).expect("canonical ID");
    let topic = astrid_events::ipc::delivery_failure::failure_topic(publisher, id);
    let mut failures = bus.subscribe_topic(topic.to_string());
    let mut native = bus.subscribe_topic(format!("astrid.v1.response.failure.{REQ_ID}"));
    let dispatcher = EventDispatcher::new(Arc::new(RwLock::new(registry)), Arc::clone(&bus));
    let handle = tokio::spawn(dispatcher.run());
    tokio::task::yield_now().await;
    let mut request = IpcMessage::new(
        Topic::from_raw("arbitrary.v1.request"),
        IpcPayload::RawJson(serde_json::json!({"anything": "payload"})),
        publisher,
    )
    .with_principal("default");
    request.delivery_id = Some(id);
    bus.reserve_publication(AstridEvent::Ipc {
        message: request,
        metadata: astrid_events::EventMetadata::new("guest-test"),
    })
    .await
    .expect("reserve")
    .publish()
    .expect("publish");
    let result = tokio::time::timeout(Duration::from_millis(300), failures.recv()).await;
    if !expected_failure {
        assert!(result.is_err(), "independent fan-out has no terminal owner");
        assert_eq!(count.load(Ordering::SeqCst), priorities.len());
        handle.abort();
        let _ = handle.await;
        return;
    }
    let event = result.expect("prompt delivery failure").expect("receipt");
    let AstridEvent::Ipc { message, .. } = event.as_ref() else {
        panic!("IPC receipt")
    };
    assert!(message.source_id.is_nil());
    assert_eq!(message.topic, topic);
    let IpcPayload::RawJson(payload) = &message.payload else {
        panic!("receipt JSON")
    };
    assert_eq!(payload["delivery_id"], REQ_ID);
    assert_eq!(payload["request_topic"], "arbitrary.v1.request");
    assert_eq!(payload["reason"], "interceptor execution failed");
    assert_eq!(count.load(Ordering::SeqCst), 1);
    assert!(
        tokio::time::timeout(Duration::from_millis(20), failures.recv())
            .await
            .is_err(),
        "one terminal receipt only"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(20), native.recv())
            .await
            .is_err()
    );
    handle.abort();
    let _ = handle.await;
}

#[tokio::test]
async fn guest_denial_reports_private_delivery_receipt() {
    exercise_guest_denial(&[100], true).await;
}

#[tokio::test]
async fn guest_denial_stops_ordered_handlers() {
    exercise_guest_denial(&[10, 100], true).await;
}

#[tokio::test]
async fn guest_denial_does_not_fail_independent_fanout() {
    exercise_guest_denial(&[100, 100], false).await;
}
