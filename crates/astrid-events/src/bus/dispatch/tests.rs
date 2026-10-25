use super::*;
use crate::event::EventMetadata;
use crate::ipc::{IpcMessage, IpcPayload, Topic};
use crate::route::RouteAdmissionGate;
use std::time::Duration;
use uuid::Uuid;

fn event() -> Arc<AstridEvent> {
    let mut message = IpcMessage::new(
        Topic::from_raw("scale.request"),
        IpcPayload::RawJson(serde_json::json!({})),
        Uuid::nil(),
    );
    message.principal = Some("alice".into());
    Arc::new(AstridEvent::Ipc {
        metadata: EventMetadata::new("test"),
        message,
    })
}

#[test]
fn foreign_principals_do_not_enter_the_delivery_snapshot() {
    let bus = EventBus::new();
    let mut subscriptions = Vec::new();
    for ordinal in 0..10_000 {
        subscriptions.push(bus.subscribe_topic_routed_scoped(
            Uuid::new_v4(),
            "scale.*",
            "fixture",
            "test",
            Some(Some(format!("foreign-{ordinal}"))),
        ));
    }
    let _own = bus.subscribe_topic_routed_scoped(
        Uuid::new_v4(),
        "scale.*",
        "own",
        "test",
        Some(Some("alice".into())),
    );
    let _all = bus.subscribe_topic_routed(Uuid::new_v4(), "scale.*", "all", "test");
    let event = event();
    let matched = bus.matching_routes(&event, &Some("alice".into()));
    assert_eq!(
        matched.len(),
        2,
        "temporary route ownership must scale with admitted recipients"
    );
}

#[tokio::test]
async fn retirement_after_snapshot_skips_queue_and_wakeup() {
    let bus = EventBus::new();
    let gate = RouteAdmissionGate::published();
    let mut receiver = bus.subscribe_topic_routed_scoped_gated(
        Uuid::new_v4(),
        "scale.*",
        "retiring",
        "test",
        Some(Some("alice".into())),
        gate.clone(),
    );
    let event = event();
    let principal = Some("alice".into());
    let matched = bus.matching_routes(&event, &principal);
    assert_eq!(matched.len(), 1);
    let notify = Arc::clone(&matched[0].lock().notify);
    gate.retire();
    EventBus::enqueue_routes(matched, &event, &principal);
    assert!(receiver.try_drain(MAX_SUBSCRIPTION_BUDGET_BYTES).is_empty());
    assert!(
        tokio::time::timeout(Duration::from_millis(20), notify.notified())
            .await
            .is_err(),
        "retired route must not receive an empty wakeup"
    );
}

#[test]
fn staged_route_cannot_acquire_a_prepublication_snapshot() {
    let bus = EventBus::new();
    let gate = RouteAdmissionGate::staged();
    let mut receiver = bus.subscribe_topic_routed_scoped_gated(
        Uuid::new_v4(),
        "scale.*",
        "staged",
        "test",
        Some(Some("alice".into())),
        gate.clone(),
    );
    let event = event();
    let principal = Some("alice".into());
    let matched = bus.matching_routes(&event, &principal);
    assert!(matched.is_empty());
    gate.publish();
    EventBus::enqueue_routes(matched, &event, &principal);
    assert!(receiver.try_drain(MAX_SUBSCRIPTION_BUDGET_BYTES).is_empty());
    bus.publish((*event).clone());
    assert_eq!(receiver.try_drain(MAX_SUBSCRIPTION_BUDGET_BYTES).len(), 1);
}
