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
