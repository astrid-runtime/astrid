//! Ordered delivery under a provider burst, including the terminal event.

use super::*;

#[tokio::test]
async fn dispatcher_construction_refuses_unreserved_startup_publication() {
    let bus = Arc::new(EventBus::new());
    let registry = Arc::new(RwLock::new(CapsuleRegistry::new()));
    let dispatcher = EventDispatcher::new(registry, bus.clone());
    assert!(matches!(
        bus.reserve_publication(event("default", 0, uuid::Uuid::nil()))
            .await,
        Err(astrid_events::DeliveryAdmissionError::Closed)
    ));
    let mut run = Box::pin(dispatcher.run());
    std::future::poll_fn(|cx| {
        assert!(std::future::Future::poll(run.as_mut(), cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    assert!(
        bus.reserve_publication(event("default", 1, uuid::Uuid::nil()))
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn retired_generation_cannot_commit_reserved_delivery() {
    verify_retired_reservation(false).await;
}

#[tokio::test]
async fn retirement_during_capacity_wait_rejects_commit() {
    verify_retired_reservation(true).await;
}

async fn verify_retired_reservation(wait_for_capacity: bool) {
    let mut registry = CapsuleRegistry::new();
    let (capsule, _) = MockCapsule::new("retired-target", "llm.v1.stream.test-provider");
    let gate = capsule.delivery_gate.clone();
    let id = capsule.id().clone();
    register_system_test_capsule(&mut registry, Box::new(capsule));
    let runtime = registry
        .runtime_id_for(&astrid_core::PrincipalId::default(), &id)
        .unwrap();
    let (sender, mut receiver) = mpsc::channel(1);
    if wait_for_capacity {
        sender
            .try_send(InterceptorWork {
                action: "occupied".into(),
                payload: Arc::new(Vec::new()),
                topic: Arc::new("occupied".into()),
                ipc_message: None,
            })
            .unwrap();
    }
    let queues = Arc::new(parking_lot::Mutex::new(HashMap::from([(
        (runtime, Some("default".to_owned())),
        sender,
    )])));
    let bus = Arc::new(EventBus::new());
    let admitter: Arc<dyn astrid_events::EventDeliveryAdmitter> = Arc::new(admission::Admitter {
        registry: Arc::new(RwLock::new(registry)),
        event_bus: Arc::downgrade(&bus),
        queues,
        chain_locks: Arc::new(parking_lot::RwLock::new(HashMap::new())),
        access_resolver: None,
        waits: wait_graph::WaitGraph::default(),
    });
    assert!(bus.register_delivery_admitter(&admitter));
    let mut observed = bus.subscribe();
    let mut reservation = Box::pin(bus.reserve_publication(event("default", 0, uuid::Uuid::nil())));
    if wait_for_capacity {
        assert!(
            tokio::time::timeout(Duration::from_millis(10), &mut reservation)
                .await
                .is_err()
        );
        gate.retire();
        assert!(receiver.recv().await.is_some());
    }
    let reservation = reservation.await.expect("capacity reserved");
    gate.retire();
    assert_eq!(
        reservation.publish(),
        Err(astrid_events::DeliveryAdmissionError::Closed)
    );
    assert!(
        receiver.try_recv().is_err(),
        "retired queue receives no committed work"
    );
    assert!(
        observed.try_recv().is_none(),
        "failed commit is not broadcast"
    );
}

#[tokio::test]
async fn reserved_delivery_reports_ordinary_inbox_overflow() {
    let registry = Arc::new(RwLock::new(CapsuleRegistry::new()));
    let bus = Arc::new(EventBus::with_capacity(1));
    let dispatcher = EventDispatcher::new(registry.clone(), bus.clone());
    let mut run = Box::pin(dispatcher.run());
    std::future::poll_fn(|cx| {
        assert!(std::future::Future::poll(run.as_mut(), cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    let _ = bus
        .reserve_publication(event("default", 0, uuid::Uuid::nil()))
        .await
        .unwrap()
        .publish()
        .unwrap();
    // The inbox contains only reserved work; no later ordinary frame can
    // rescue the overflow notification.
    bus.publish(event("default", 1, uuid::Uuid::nil()));
    let mut notifications = bus.subscribe_topic("astrid.v1.event_bus.lagged");
    let task = tokio::spawn(run);
    let notification = tokio::time::timeout(Duration::from_secs(1), notifications.recv())
        .await
        .expect("overflow is reported on reserved delivery")
        .unwrap();
    task.abort();
    let AstridEvent::Ipc { message, .. } = &*notification else {
        panic!("IPC notification")
    };
    let IpcPayload::Custom { data } = &message.payload else {
        panic!("lag payload")
    };
    assert_eq!(data["lagged_count"], 1);
}

#[test]
fn circular_waits_are_rejected_and_cancelled_edges_are_released() {
    let mut registry = CapsuleRegistry::new();
    let principal = astrid_core::PrincipalId::default();
    let mut keys = Vec::new();
    for name in ["cycle-a", "cycle-b", "cycle-c"] {
        let (capsule, _) = MockCapsule::new(name, "cycle.topic");
        let id = capsule.id().clone();
        register_system_test_capsule(&mut registry, Box::new(capsule));
        keys.push((
            registry.runtime_id_for(&principal, &id).unwrap(),
            Some("default".to_owned()),
        ));
    }
    let graph = crate::dispatcher::wait_graph::WaitGraph::default();
    let first = graph
        .enter(keys[0].clone(), keys[1].clone())
        .expect("A to B");
    let duplicate = graph
        .enter(keys[0].clone(), keys[1].clone())
        .expect("second A to B waiter");
    let second = graph
        .enter(keys[1].clone(), keys[2].clone())
        .expect("B to C");
    assert!(
        graph.enter(keys[2].clone(), keys[0].clone()).is_none(),
        "C to A closes a cycle"
    );
    drop(first);
    assert!(
        graph.enter(keys[2].clone(), keys[0].clone()).is_none(),
        "remaining A to B waiter is still active"
    );
    drop(duplicate);
    let reverse = graph
        .enter(keys[2].clone(), keys[0].clone())
        .expect("cancel released dependency");
    drop(reverse);
    drop(second);
    assert!(
        graph.enter(keys[0].clone(), keys[0].clone()).is_none(),
        "self dependency is a cycle"
    );
}

fn event(principal: &str, index: usize, source: uuid::Uuid) -> AstridEvent {
    AstridEvent::Ipc {
        metadata: astrid_events::EventMetadata::new("test"),
        message: astrid_events::ipc::IpcMessage::new(
            Topic::from_raw("llm.v1.stream.test-provider"),
            IpcPayload::RawJson(serde_json::json!({"delta": index})),
            source,
        )
        .with_principal(principal),
    }
}

#[tokio::test]
async fn shared_fallback_queues_detect_cross_principal_wait_cycles() {
    let mut registry = CapsuleRegistry::new();
    let principal = astrid_core::PrincipalId::default();
    let mut identities = Vec::new();
    for (name, topic) in [("shared-a", "shared.a"), ("shared-b", "shared.b")] {
        let (capsule, _) = MockCapsule::new(name, topic);
        let id = capsule.id().clone();
        register_system_test_capsule(&mut registry, Box::new(capsule));
        for viewer in ["alice", "bob"] {
            let (capsule, _) = MockCapsule::new(name, topic);
            registry
                .register_system_runtime(
                    Box::new(capsule),
                    crate::registry::WasmHash::synthetic(id.as_str(), "test"),
                    &astrid_core::PrincipalId::new(viewer).unwrap(),
                )
                .unwrap();
        }
        identities.push((
            registry.runtime_id_for(&principal, &id).unwrap(),
            registry.source_id_for(&principal, &id).unwrap(),
        ));
    }
    let queues = Arc::new(parking_lot::Mutex::new(HashMap::new()));
    let mut receivers = Vec::new();
    for (runtime_id, _) in &identities {
        let (sender, receiver) = mpsc::channel(1);
        sender
            .try_send(InterceptorWork {
                action: "occupied".into(),
                payload: Arc::new(Vec::new()),
                topic: Arc::new("occupied".into()),
                ipc_message: None,
            })
            .unwrap();
        receivers.push(receiver);
        let mut guard = queues.lock();
        for index in 0..MAX_DISPATCHER_QUEUES_PER_CAPSULE {
            guard.insert(
                (runtime_id.clone(), Some(format!("existing-{index}"))),
                sender.clone(),
            );
        }
        guard.insert((runtime_id.clone(), None), sender);
    }
    let bus = Arc::new(EventBus::new());
    let admitter = admission::Admitter {
        registry: Arc::new(RwLock::new(registry)),
        event_bus: Arc::downgrade(&bus),
        queues,
        chain_locks: Arc::new(parking_lot::RwLock::new(HashMap::new())),
        access_resolver: None,
        waits: wait_graph::WaitGraph::default(),
    };
    let message = |principal: &str, topic: &str, source| AstridEvent::Ipc {
        metadata: astrid_events::EventMetadata::new("test"),
        message: astrid_events::ipc::IpcMessage::new(
            Topic::from_raw(topic),
            IpcPayload::RawJson(serde_json::json!({})),
            source,
        )
        .with_principal(principal),
    };
    use astrid_events::EventDeliveryAdmitter as _;
    let a_to_b = message("alice", "shared.b", identities[0].1);
    let mut pending = Box::pin(
        wait_graph::ACTIVE_CONSUMER
            .scope((identities[0].0.clone(), None), admitter.reserve(&a_to_b)),
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut pending)
            .await
            .is_err()
    );
    let b_to_a = message("bob", "shared.a", identities[1].1);
    let reverse = tokio::time::timeout(
        Duration::from_secs(1),
        wait_graph::ACTIVE_CONSUMER
            .scope((identities[1].0.clone(), None), admitter.reserve(&b_to_a)),
    )
    .await
    .expect("shared physical cycle must not hang");
    assert!(matches!(
        reverse,
        Err(astrid_events::DeliveryAdmissionError::SelfDependency)
    ));
    drop(pending);
    assert!(
        tokio::time::timeout(Duration::from_millis(20), admitter.reserve(&b_to_a))
            .await
            .is_err(),
        "dropping the pending admission removes the physical wait edge"
    );
    drop(receivers);
}

#[tokio::test(flavor = "current_thread")]
async fn full_consumer_queues_reject_a_cross_capsule_wait_cycle() {
    let mut registry = CapsuleRegistry::new();
    let principal = astrid_core::PrincipalId::default();
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    let mut sources = Vec::new();
    let mut keys = Vec::new();
    let mut started = Vec::new();
    for (name, topic) in [("cycle-a", "cycle.a"), ("cycle-b", "cycle.b")] {
        let (mut capsule, invoked) = MockCapsule::new(name, topic);
        capsule.blocked_principal = Some(("default".to_owned(), gate.clone()));
        let id = capsule.id().clone();
        register_system_test_capsule(&mut registry, Box::new(capsule));
        sources.push(registry.source_id_for(&principal, &id).unwrap());
        keys.push((
            registry.runtime_id_for(&principal, &id).unwrap(),
            Some("default".into()),
        ));
        started.push(invoked);
    }
    let bus = Arc::new(EventBus::with_capacity(2));
    let task =
        tokio::spawn(EventDispatcher::new(Arc::new(RwLock::new(registry)), bus.clone()).run());
    tokio::task::yield_now().await;
    let message = |topic: &str, source| AstridEvent::Ipc {
        metadata: astrid_events::EventMetadata::new("test"),
        message: astrid_events::ipc::IpcMessage::new(
            Topic::from_raw(topic),
            IpcPayload::RawJson(serde_json::json!({})),
            source,
        )
        .with_principal("default"),
    };
    for topic in ["cycle.a", "cycle.b"] {
        let _ = bus
            .reserve_publication(message(topic, uuid::Uuid::nil()))
            .await
            .unwrap()
            .publish()
            .unwrap();
    }
    tokio::time::timeout(Duration::from_secs(1), async {
        while started
            .iter()
            .any(|invoked| !invoked.load(Ordering::SeqCst))
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("both consumers started");
    for _ in 0..64 {
        for topic in ["cycle.a", "cycle.b"] {
            let _ = bus
                .reserve_publication(message(topic, uuid::Uuid::nil()))
                .await
                .unwrap()
                .publish()
                .unwrap();
        }
    }
    let mut a_to_b = Box::pin(wait_graph::ACTIVE_CONSUMER.scope(
        keys[0].clone(),
        bus.reserve_publication(message("cycle.b", sources[0])),
    ));
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut a_to_b)
            .await
            .is_err()
    );
    let reverse = tokio::time::timeout(
        Duration::from_secs(1),
        wait_graph::ACTIVE_CONSUMER.scope(
            keys[1].clone(),
            bus.reserve_publication(message("cycle.a", sources[1])),
        ),
    )
    .await
    .expect("cycle must be rejected, not hang");
    assert!(matches!(
        reverse,
        Err(astrid_events::DeliveryAdmissionError::SelfDependency)
    ));
    drop(a_to_b);
    assert!(
        tokio::time::timeout(
            Duration::from_millis(20),
            bus.reserve_publication(message("cycle.a", sources[1]))
        )
        .await
        .is_err(),
        "cancelled edge must no longer falsely reject the reverse wait"
    );
    gate.add_permits(130);
    task.abort();
}

#[tokio::test(flavor = "current_thread")]
async fn saturated_principal_yields_without_blocking_other_principals() {
    let (mut capsule, invoked) = MockCapsule::new("stream-consumer", "llm.v1.stream.*");
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    let observed = Arc::new(Mutex::new(Vec::new()));
    capsule.blocked_principal = Some(("default".to_owned(), Arc::clone(&gate)));
    capsule.payload_log = Some(Arc::clone(&observed));
    let id = capsule.id().clone();
    let mut registry = CapsuleRegistry::new();
    register_system_test_capsule(&mut registry, Box::new(capsule));
    let source = registry
        .source_id_for(&astrid_core::PrincipalId::default(), &id)
        .expect("registered source");
    let key = (
        registry
            .runtime_id_for(&astrid_core::PrincipalId::default(), &id)
            .unwrap(),
        Some("default".into()),
    );
    let bus = Arc::new(EventBus::with_capacity(2));
    let task =
        tokio::spawn(EventDispatcher::new(Arc::new(RwLock::new(registry)), Arc::clone(&bus)).run());
    tokio::task::yield_now().await;
    let _ = bus
        .reserve_publication(event("default", 0, uuid::Uuid::nil()))
        .await
        .expect("first event")
        .publish()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while !invoked.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("consumer started");
    for index in 1..=64 {
        let _ = bus
            .reserve_publication(event("default", index, uuid::Uuid::nil()))
            .await
            .expect("bounded queue space")
            .publish()
            .unwrap();
    }
    assert!(
        tokio::time::timeout(
            Duration::from_millis(20),
            bus.reserve_publication(event("default", 65, uuid::Uuid::nil()))
        )
        .await
        .is_err(),
        "publisher must wait when the 64 slots are occupied"
    );
    // A chain invocation with this source does not occupy the consumer. It
    // waits normally rather than inventing a dependency on its own queue.
    assert!(
        tokio::time::timeout(
            Duration::from_millis(20),
            bus.reserve_publication(event("default", 66, source)),
        )
        .await
        .is_err()
    );
    let recursive = wait_graph::ACTIVE_CONSUMER
        .scope(key, bus.reserve_publication(event("default", 66, source)))
        .await;
    assert!(
        matches!(
            recursive,
            Err(astrid_events::DeliveryAdmissionError::SelfDependency)
        ),
        "a recursive publisher must not wait for its own invocation"
    );
    let _ = bus
        .reserve_publication(event("bob", 100, uuid::Uuid::nil()))
        .await
        .expect("other principal remains usable")
        .publish()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while observed.lock().unwrap().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("other principal delivered");
    assert_eq!(
        observed.lock().unwrap()[0],
        serde_json::to_vec(&serde_json::json!({"delta":100})).unwrap()
    );
    gate.add_permits(65);
    tokio::time::timeout(Duration::from_secs(1), async {
        while observed.lock().unwrap().len() < 66 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("drained bounded queue");
    let actual = observed.lock().unwrap().clone();
    task.abort();
    assert_eq!(actual.len(), 66, "cancelled reservations must not publish");
    for index in 0..=64 {
        assert_eq!(
            actual[index + 1],
            serde_json::to_vec(&serde_json::json!({"delta":index})).unwrap()
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn reserved_delivery_cannot_overtake_an_earlier_ordinary_publication() {
    let (mut capsule, _) = MockCapsule::new("ordered-consumer", "llm.v1.stream.*");
    let observed = Arc::new(Mutex::new(Vec::new()));
    capsule.payload_log = Some(observed.clone());
    let mut registry = CapsuleRegistry::new();
    register_system_test_capsule(&mut registry, Box::new(capsule));
    let bus = Arc::new(EventBus::with_capacity(2));
    let dispatcher = EventDispatcher::new(Arc::new(RwLock::new(registry)), bus.clone());
    let task = tokio::spawn(dispatcher.run());
    tokio::task::yield_now().await;
    bus.publish(event("default", 0, uuid::Uuid::nil()));
    let _ = bus
        .reserve_publication(event("default", 1, uuid::Uuid::nil()))
        .await
        .unwrap()
        .publish()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while observed.lock().unwrap().len() < 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("both delivery classes invoked");
    let actual = observed.lock().unwrap().clone();
    task.abort();
    assert_eq!(
        actual,
        vec![
            serde_json::to_vec(&serde_json::json!({"delta":0})).unwrap(),
            serde_json::to_vec(&serde_json::json!({"delta":1})).unwrap(),
        ]
    );
}

#[tokio::test(flavor = "current_thread")]
async fn burst_preserves_every_payload_and_terminal_event() {
    let (mut capsule, _) = MockCapsule::new("stream-consumer", "llm.v1.stream.*");
    let observed = Arc::new(Mutex::new(Vec::new()));
    capsule.payload_log = Some(Arc::clone(&observed));
    let mut registry = CapsuleRegistry::new();
    register_system_test_capsule(&mut registry, Box::new(capsule));
    // Smaller than the burst: correctness must not depend on global broadcast
    // headroom, or raising only the downstream queue would move the loss here.
    let bus = Arc::new(EventBus::with_capacity(2));
    let dispatcher = EventDispatcher::new(Arc::new(RwLock::new(registry)), Arc::clone(&bus));
    let dispatcher_task = tokio::spawn(dispatcher.run());
    tokio::task::yield_now().await;
    let payloads: Vec<_> = (0..4096)
        .map(|index| serde_json::json!({"delta": index}))
        .chain(std::iter::once(serde_json::json!({"done": true})))
        .collect();
    let expected: Vec<Vec<u8>> = payloads
        .iter()
        .map(|payload| serde_json::to_vec(payload).expect("payload"))
        .collect();

    // No sleeps or manual producer yields. Admission itself must yield when
    // bounded capacity is occupied, without losing any frame or its terminal.
    for payload in payloads {
        let message = astrid_events::ipc::IpcMessage::new(
            Topic::from_raw("llm.v1.stream.test-provider"),
            IpcPayload::RawJson(payload),
            uuid::Uuid::nil(),
        )
        .with_principal("default");
        let publication = bus
            .reserve_publication(AstridEvent::Ipc {
                metadata: astrid_events::EventMetadata::new("test"),
                message,
            })
            .await
            .expect("admission");
        publication.publish().unwrap();
    }

    let completed = tokio::time::timeout(Duration::from_secs(1), async {
        while observed.lock().unwrap().len() < expected.len() {
            tokio::task::yield_now().await;
        }
    })
    .await;
    let actual = observed.lock().unwrap().clone();
    dispatcher_task.abort();
    assert!(
        completed.is_ok(),
        "received {} of {} events; terminal present: {}",
        actual.len(),
        expected.len(),
        actual.last() == expected.last(),
    );
    assert_eq!(actual, expected, "stream payloads must remain ordered");
}
