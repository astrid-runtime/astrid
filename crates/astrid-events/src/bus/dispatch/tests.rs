use super::*;
use crate::event::EventMetadata;
use crate::ipc::{IpcMessage, IpcPayload, RequestOwnerId, Topic};
use crate::route::RouteAdmissionGate;
use std::time::Duration;
use uuid::Uuid;

fn event_on(topic: &str, principal: Option<&str>) -> Arc<AstridEvent> {
    let mut message = IpcMessage::new(
        Topic::from_raw(topic),
        IpcPayload::RawJson(serde_json::json!({})),
        Uuid::nil(),
    );
    message.principal = principal.map(str::to_owned);
    Arc::new(AstridEvent::Ipc {
        metadata: EventMetadata::new("test"),
        message,
    })
}

fn event() -> Arc<AstridEvent> {
    event_on("scale.request", Some("alice"))
}

fn event_with_owner(topic: &str, principal: &str, owner: RequestOwnerId) -> Arc<AstridEvent> {
    let mut message = IpcMessage::new(
        Topic::from_raw(topic),
        IpcPayload::RawJson(serde_json::json!({})),
        Uuid::nil(),
    );
    message.principal = Some(principal.into());
    message.request_owner = Some(owner);
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
    let _ = bus.take_selection_visits();
    let matched = bus.matching_routes(&event, &Some("alice".into()));
    let visits = bus.take_selection_visits();
    assert_eq!(
        matched.len(),
        2,
        "temporary route ownership must scale with admitted recipients"
    );
    assert_eq!(
        visits, 2,
        "foreign-scope routes must not be locked during candidate selection"
    );
    drop(subscriptions);
}

#[tokio::test]
async fn public_publish_candidate_visits_ignore_foreign_scopes() {
    let bus = EventBus::new();
    let mut foreign = Vec::new();
    for ordinal in 0..10_000 {
        foreign.push(bus.subscribe_topic_routed_scoped(
            Uuid::new_v4(),
            "scale.*",
            "fixture",
            "test",
            Some(Some(format!("foreign-{ordinal}"))),
        ));
    }
    let mut own = bus.subscribe_topic_routed_scoped(
        Uuid::new_v4(),
        "scale.*",
        "own",
        "test",
        Some(Some("alice".into())),
    );
    let mut all = bus.subscribe_topic_routed(Uuid::new_v4(), "scale.*", "all", "test");
    let _ = bus.take_selection_visits();
    bus.publish((*event()).clone());
    assert_eq!(
        bus.take_selection_visits(),
        2,
        "public publish must not lock 10k foreign-scope routes"
    );
    assert_eq!(own.try_drain(MAX_SUBSCRIPTION_BUDGET_BYTES).len(), 1);
    assert_eq!(all.try_drain(MAX_SUBSCRIPTION_BUDGET_BYTES).len(), 1);
    drop(foreign);
}

#[test]
fn one_agent_exact_route_visits_only_itself() {
    let bus = EventBus::new();
    let _own = bus.subscribe_topic_routed_scoped(
        Uuid::new_v4(),
        "scale.*",
        "own",
        "test",
        Some(Some("alice".into())),
    );
    let _ = bus.take_selection_visits();
    let matched = bus.matching_routes(&event(), &Some("alice".into()));
    assert_eq!(matched.len(), 1);
    assert_eq!(
        bus.take_selection_visits(),
        1,
        "single exact route must not pay multi-partition scan overhead"
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
    let _ = bus.take_selection_visits();
    let matched = bus.matching_routes(&event, &principal);
    let visits = bus.take_selection_visits();
    assert!(matched.is_empty());
    assert_eq!(
        visits, 1,
        "staged same-scope routes remain candidates but fail accepts_event"
    );
    gate.publish();
    EventBus::enqueue_routes(matched, &event, &principal);
    assert!(receiver.try_drain(MAX_SUBSCRIPTION_BUDGET_BYTES).is_empty());
    bus.publish((*event).clone());
    assert_eq!(receiver.try_drain(MAX_SUBSCRIPTION_BUDGET_BYTES).len(), 1);
}

#[tokio::test]
async fn same_principal_different_request_owner_is_visited_but_not_delivered() {
    let bus = EventBus::new();
    let owner = RequestOwnerId::generate();
    let peer = RequestOwnerId::generate();
    let mut sub = bus.subscribe_topic_routed_for_request_owner(
        Uuid::new_v4(),
        "scale.*",
        "gateway",
        "test",
        "alice",
        owner,
    );
    let event = event_with_owner("scale.request", "alice", peer);
    let _ = bus.take_selection_visits();
    let matched = bus.matching_routes(&event, &Some("alice".into()));
    assert_eq!(bus.take_selection_visits(), 1);
    assert!(
        matched.is_empty(),
        "request-owner mismatch must fail accepts_event after scope selection"
    );
    bus.publish((*event).clone());
    assert!(sub.try_drain(MAX_SUBSCRIPTION_BUDGET_BYTES).is_empty());
    bus.publish((*event_with_owner("scale.request", "alice", owner)).clone());
    assert_eq!(sub.try_drain(MAX_SUBSCRIPTION_BUDGET_BYTES).len(), 1);
}

#[tokio::test]
async fn wildcard_topic_still_matches_after_scope_selection() {
    let bus = EventBus::new();
    let mut sub = bus.subscribe_topic_routed_scoped(
        Uuid::new_v4(),
        "scale.*",
        "own",
        "test",
        Some(Some("alice".into())),
    );
    bus.publish((*event_on("scale.request", Some("alice"))).clone());
    bus.publish((*event_on("other.request", Some("alice"))).clone());
    let drained = sub.try_drain(MAX_SUBSCRIPTION_BUDGET_BYTES);
    assert_eq!(drained.len(), 1);
    let AstridEvent::Ipc { message, .. } = &*drained[0] else {
        panic!("expected IPC");
    };
    assert_eq!(message.topic.as_str(), "scale.request");
}

#[tokio::test]
async fn unscoped_and_principal_or_system_receive_system_publish() {
    let bus = EventBus::new();
    let mut unscoped = bus.subscribe_topic_routed(Uuid::new_v4(), "scale.*", "all", "test");
    let mut runtime = bus.subscribe_topic_routed_principal_or_system(
        Uuid::new_v4(),
        "scale.*",
        "runtime",
        "test",
        "alice",
    );
    let mut exact = bus.subscribe_topic_routed_scoped(
        Uuid::new_v4(),
        "scale.*",
        "exact",
        "test",
        Some(Some("alice".into())),
    );
    let system = event_on("scale.request", None);
    let _ = bus.take_selection_visits();
    bus.publish((*system).clone());
    // exact(alice) is not a candidate for system; unscoped + every PoS are.
    assert_eq!(bus.take_selection_visits(), 2);
    assert_eq!(unscoped.try_drain(MAX_SUBSCRIPTION_BUDGET_BYTES).len(), 1);
    assert_eq!(runtime.try_drain(MAX_SUBSCRIPTION_BUDGET_BYTES).len(), 1);
    assert!(exact.try_drain(MAX_SUBSCRIPTION_BUDGET_BYTES).is_empty());
}

#[tokio::test]
async fn drop_removes_partition_membership_without_ghost_delivery() {
    let bus = EventBus::new();
    let first = bus.subscribe_topic_routed_scoped(
        Uuid::new_v4(),
        "scale.*",
        "first",
        "test",
        Some(Some("alice".into())),
    );
    assert_eq!(bus.routed_subscription_count(), 1);
    drop(first);
    assert_eq!(bus.routed_subscription_count(), 0);

    let mut replacement = bus.subscribe_topic_routed_scoped(
        Uuid::new_v4(),
        "scale.*",
        "replacement",
        "test",
        Some(Some("alice".into())),
    );
    bus.publish((*event()).clone());
    assert_eq!(
        replacement.try_drain(MAX_SUBSCRIPTION_BUDGET_BYTES).len(),
        1
    );
    drop(replacement);
    assert_eq!(bus.routed_subscription_count(), 0);
    let _ = bus.take_selection_visits();
    bus.publish((*event()).clone());
    assert_eq!(
        bus.take_selection_visits(),
        0,
        "dropped routes must leave no selectable candidates"
    );
}

#[tokio::test]
async fn peer_principal_or_system_is_not_a_candidate_for_foreign_publish() {
    let bus = EventBus::new();
    let mut alice = bus.subscribe_topic_routed_principal_or_system(
        Uuid::new_v4(),
        "scale.*",
        "alice-runtime",
        "test",
        "alice",
    );
    let mut bob = bus.subscribe_topic_routed_principal_or_system(
        Uuid::new_v4(),
        "scale.*",
        "bob-runtime",
        "test",
        "bob",
    );
    let _ = bus.take_selection_visits();
    bus.publish((*event_on("scale.request", Some("alice"))).clone());
    assert_eq!(bus.take_selection_visits(), 1);
    assert_eq!(alice.try_drain(MAX_SUBSCRIPTION_BUDGET_BYTES).len(), 1);
    assert!(bob.try_drain(MAX_SUBSCRIPTION_BUDGET_BYTES).is_empty());
}

#[test]
fn route_count_tracks_membership_without_scanning_principals() {
    let bus = EventBus::new();
    assert_eq!(bus.routed_subscription_count(), 0);
    let mut held = Vec::new();
    for ordinal in 0..128 {
        held.push(bus.subscribe_topic_routed_scoped(
            Uuid::new_v4(),
            "scale.*",
            "fixture",
            "test",
            Some(Some(format!("p-{ordinal}"))),
        ));
    }
    held.push(bus.subscribe_topic_routed(Uuid::new_v4(), "scale.*", "all", "test"));
    held.push(bus.subscribe_topic_routed_principal_or_system(
        Uuid::new_v4(),
        "scale.*",
        "runtime",
        "test",
        "alice",
    ));
    assert_eq!(bus.routed_subscription_count(), 130);
    assert_eq!(bus.routes.read().iter_all().count(), 130);
    held.truncate(10);
    assert_eq!(bus.routed_subscription_count(), 10);
    assert_eq!(bus.routes.read().iter_all().count(), 10);
}

#[test]
fn publish_selection_microbench_n1_and_10k_foreign() {
    use std::hint::black_box;
    use std::time::Instant;

    fn measure(label: &str, foreign: usize, iters: u32) {
        let bus = EventBus::new();
        let mut held = Vec::with_capacity(foreign.saturating_add(2));
        for ordinal in 0..foreign {
            held.push(bus.subscribe_topic_routed_scoped(
                Uuid::new_v4(),
                "scale.*",
                "fixture",
                "test",
                Some(Some(format!("foreign-{ordinal}"))),
            ));
        }
        let mut own = bus.subscribe_topic_routed_scoped(
            Uuid::new_v4(),
            "scale.*",
            "own",
            "test",
            Some(Some("alice".into())),
        );
        let event = (*event()).clone();
        // Warmup
        for _ in 0..32 {
            bus.publish(black_box(event.clone()));
            let _ = black_box(own.try_drain(MAX_SUBSCRIPTION_BUDGET_BYTES));
        }
        let start = Instant::now();
        for _ in 0..iters {
            bus.publish(black_box(event.clone()));
            let _ = black_box(own.try_drain(MAX_SUBSCRIPTION_BUDGET_BYTES));
        }
        let elapsed = start.elapsed();
        let per = elapsed / iters;
        println!(
            "publish_selection_microbench[{label}]: foreign={foreign} iters={iters} total={elapsed:?} per_publish={per:?}"
        );
        drop(held);
    }

    measure("n1", 0, 2_000);
    measure("n10000_foreign", 10_000, 200);
}
