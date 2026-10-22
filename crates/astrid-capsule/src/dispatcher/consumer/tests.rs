use super::*;

fn work() -> InterceptorWork {
    InterceptorWork {
        action: "raced-command".into(),
        payload: Arc::new(Vec::new()),
        topic: Arc::new("test.command".into()),
        ipc_message: None,
    }
}

#[test]
fn idle_probe_preserves_work_arriving_after_timeout() {
    let key = (
        RuntimeId::for_test(CapsuleId::new("idle-probe").unwrap(), 1),
        None,
    );
    let (sender, mut receiver) = mpsc::channel(1);
    let generation = sender.downgrade();
    let queues = Arc::new(parking_lot::Mutex::new(HashMap::from([(
        key.clone(),
        sender,
    )])));
    // The timeout already happened. A dispatch commits just before cleanup
    // obtains the map lock; no cloned sender remains to postpone eviction.
    assert!(queues.lock()[&key].try_send(work()).is_ok());
    assert!(!try_evict_idle_consumer(
        &mut receiver,
        &queues,
        &key,
        &generation
    ));
    let received = receiver
        .try_recv()
        .expect("idle probe must retain accepted work");
    assert_eq!(received.action, "raced-command");
    assert!(queues.lock().contains_key(&key));
    assert!(try_evict_idle_consumer(
        &mut receiver,
        &queues,
        &key,
        &generation
    ));
    assert!(!queues.lock().contains_key(&key));
}

#[test]
fn in_flight_sender_or_owned_reservation_prevents_idle_eviction() {
    for reserved in [false, true] {
        let key = (
            RuntimeId::for_test(CapsuleId::new("idle-probe").unwrap(), 2),
            None,
        );
        let (sender, mut receiver) = mpsc::channel(1);
        let in_flight = sender.clone();
        let generation = sender.downgrade();
        let queues = Arc::new(parking_lot::Mutex::new(HashMap::from([(
            key.clone(),
            sender,
        )])));
        let permit = if reserved {
            Some(in_flight.clone().try_reserve_owned().unwrap())
        } else {
            None
        };
        assert!(!try_evict_idle_consumer(
            &mut receiver,
            &queues,
            &key,
            &generation
        ));
        drop(in_flight);
        if let Some(permit) = permit {
            assert!(!try_evict_idle_consumer(
                &mut receiver,
                &queues,
                &key,
                &generation
            ));
            drop(permit.send(work()));
        } else {
            assert!(queues.lock()[&key].try_send(work()).is_ok());
        }
        assert_eq!(receiver.try_recv().unwrap().action, "raced-command");
        assert!(try_evict_idle_consumer(
            &mut receiver,
            &queues,
            &key,
            &generation
        ));
    }
}

#[test]
fn old_consumer_cannot_evict_a_replacement_generation() {
    let key = (
        RuntimeId::for_test(CapsuleId::new("idle-probe").unwrap(), 3),
        None,
    );
    let (old_sender, mut old_receiver) = mpsc::channel(1);
    let generation = old_sender.downgrade();
    let (replacement, mut replacement_receiver) = mpsc::channel(1);
    let queues = Arc::new(parking_lot::Mutex::new(HashMap::from([(
        key.clone(),
        replacement,
    )])));
    // Exactly one sender remains for the old channel, but it is an in-flight
    // producer, not the map entry. The map belongs to the new channel.
    assert_eq!(old_receiver.sender_strong_count(), 1);
    assert!(!try_evict_idle_consumer(
        &mut old_receiver,
        &queues,
        &key,
        &generation
    ));
    assert!(old_sender.try_send(work()).is_ok());
    assert_eq!(old_receiver.try_recv().unwrap().action, "raced-command");
    assert!(queues.lock()[&key].try_send(work()).is_ok());
    assert_eq!(
        replacement_receiver.try_recv().unwrap().action,
        "raced-command"
    );
}
