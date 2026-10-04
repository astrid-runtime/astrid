use std::sync::{Arc, Mutex};

use super::*;
use crate::{EventMetadata, IpcMessage, IpcPayload, ipc::Topic};

#[derive(Debug)]
struct Admitter(Arc<Mutex<Vec<u64>>>);

struct Delivery(Arc<Mutex<Vec<u64>>>);

impl ReservedEventDelivery for Delivery {
    fn deliver(self: Box<Self>, event: &AstridEvent) {
        if let AstridEvent::Ipc { message, .. } = event {
            self.0.lock().unwrap().push(message.seq);
        }
    }
}

#[async_trait::async_trait]
impl EventDeliveryAdmitter for Admitter {
    async fn reserve(
        &self,
        _: &AstridEvent,
    ) -> Result<Box<dyn ReservedEventDelivery>, DeliveryAdmissionError> {
        Ok(Box::new(Delivery(Arc::clone(&self.0))))
    }
}

fn event() -> AstridEvent {
    AstridEvent::Ipc {
        metadata: EventMetadata::new("test"),
        message: IpcMessage::new(
            Topic::from_raw("test.delivery"),
            IpcPayload::RawJson(serde_json::json!({})),
            uuid::Uuid::nil(),
        ),
    }
}

#[tokio::test]
async fn unconfigured_reservation_cannot_bypass_newly_registered_delivery() {
    let bus = EventBus::new();
    let mut observer = bus.subscribe();
    let publication = bus.reserve_publication(event()).await.unwrap();
    let recorded = Arc::new(Mutex::new(Vec::new()));
    let admitter: Arc<dyn EventDeliveryAdmitter> = Arc::new(Admitter(recorded.clone()));
    assert!(bus.register_delivery_admitter(&admitter));
    assert_eq!(publication.publish(), Err(DeliveryAdmissionError::Closed));
    assert!(observer.try_recv().is_none());
    assert!(recorded.lock().unwrap().is_empty());
    assert!(
        bus.reserve_publication(event())
            .await
            .unwrap()
            .publish()
            .is_ok()
    );
    assert_eq!(recorded.lock().unwrap().len(), 1);
}

#[derive(Debug)]
struct FencedAdmitter(crate::RouteAdmissionGate);

#[tokio::test]
async fn reservation_before_ordered_inbox_cannot_skip_inbox_capacity() {
    let bus = EventBus::with_capacity(1);
    let recorded = Arc::new(Mutex::new(Vec::new()));
    let admitter: Arc<dyn EventDeliveryAdmitter> = Arc::new(Admitter(recorded.clone()));
    assert!(bus.register_delivery_admitter(&admitter));
    let publication = bus.reserve_publication(event()).await.unwrap();
    let mut inbox = bus.subscribe_ordered_delivery();
    let mut observer = bus.subscribe();
    bus.publish(event());
    assert!(observer.try_recv().is_some());
    assert_eq!(publication.publish(), Err(DeliveryAdmissionError::Closed));
    assert!(observer.try_recv().is_none());
    assert!(recorded.lock().unwrap().is_empty());
    assert!(inbox.recv().await.unwrap().into_unreserved().is_some());
    assert!(
        bus.reserve_publication(event())
            .await
            .unwrap()
            .publish()
            .is_ok()
    );
    assert!(inbox.recv().await.unwrap().into_unreserved().is_none());
    assert_eq!(recorded.lock().unwrap().len(), 1);
}

struct FencedDelivery(crate::RouteAdmissionGate);

impl ReservedEventDelivery for FencedDelivery {
    fn commit_guards(&self) -> Result<Vec<crate::RouteCommitGuard>, DeliveryAdmissionError> {
        Ok(vec![
            self.0
                .commit_guard()
                .ok_or(DeliveryAdmissionError::Closed)?,
        ])
    }

    fn deliver(self: Box<Self>, _: &AstridEvent) {}
}

#[async_trait::async_trait]
impl EventDeliveryAdmitter for FencedAdmitter {
    async fn reserve(
        &self,
        _: &AstridEvent,
    ) -> Result<Box<dyn ReservedEventDelivery>, DeliveryAdmissionError> {
        Ok(Box::new(FencedDelivery(self.0.clone())))
    }
}

struct RetiringObserver(crate::RouteAdmissionGate);

impl crate::subscriber::EventSubscriber for RetiringObserver {
    fn on_event(&self, _: &AstridEvent, _: &EventBus) {
        self.0.retire();
    }
}

#[tokio::test]
async fn commit_releases_generation_guard_before_synchronous_observation() {
    let bus = Arc::new(EventBus::new());
    let gate = crate::RouteAdmissionGate::published();
    let admitter: Arc<dyn EventDeliveryAdmitter> = Arc::new(FencedAdmitter(gate.clone()));
    assert!(bus.register_delivery_admitter(&admitter));
    bus.registry()
        .register(Arc::new(RetiringObserver(gate.clone())));
    let (finished_tx, finished_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let publication = bus.reserve_publication(event()).await.unwrap();
            finished_tx.send(publication.publish()).unwrap();
            drop(admitter);
        });
    });
    assert!(
        finished_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap()
            .is_ok()
    );
    assert!(!gate.is_published());
}

#[tokio::test]
async fn reservation_drop_is_invisible_and_commit_delivers_once_with_sequence() {
    let bus = EventBus::new();
    let recorded = Arc::new(Mutex::new(Vec::new()));
    let admitter: Arc<dyn EventDeliveryAdmitter> = Arc::new(Admitter(Arc::clone(&recorded)));
    assert!(bus.register_delivery_admitter(&admitter));
    assert!(!bus.register_delivery_admitter(&admitter));
    let mut observer = bus.subscribe();
    let mut legacy = bus.subscribe_unreserved_as("test-dispatcher");
    assert_eq!(bus.subscriber_count(), 2);
    drop(bus.reserve_publication(event()).await.unwrap());
    assert!(recorded.lock().unwrap().is_empty());
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(10), observer.recv())
            .await
            .is_err()
    );

    assert_eq!(
        bus.reserve_publication(event()).await.unwrap().publish(),
        Ok(1)
    );
    let committed = observer.recv().await.unwrap();
    let AstridEvent::Ipc { message, .. } = committed.as_ref() else {
        panic!("IPC expected")
    };
    assert_eq!(*recorded.lock().unwrap(), vec![message.seq]);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(10), legacy.recv())
            .await
            .is_err(),
        "reserved publication must not dispatch twice"
    );
    assert_eq!(bus.publish(event()), 2);
    let ordinary = legacy.recv().await.unwrap();
    let AstridEvent::Ipc {
        message: ordinary, ..
    } = ordinary.as_ref()
    else {
        panic!("IPC expected")
    };
    assert!(ordinary.seq > message.seq);
    assert_eq!(recorded.lock().unwrap().len(), 1);
    drop(admitter);
    assert!(
        matches!(
            bus.reserve_publication(event()).await,
            Err(DeliveryAdmissionError::Closed)
        ),
        "a stopped delivery owner must not silently lose admitted events"
    );
}

#[tokio::test]
async fn unconfigured_delivery_is_distinct_from_a_stopped_registered_lane() {
    let bus = EventBus::new();
    let mut observer = bus.subscribe();
    assert_eq!(
        bus.reserve_publication(event()).await.unwrap().publish(),
        Ok(1)
    );
    observer.recv().await.unwrap();
    let recorded = Arc::new(Mutex::new(Vec::new()));
    let admitter: Arc<dyn EventDeliveryAdmitter> = Arc::new(Admitter(Arc::clone(&recorded)));
    assert!(bus.register_delivery_admitter(&admitter));
    drop(admitter);
    assert!(matches!(
        bus.reserve_publication(event()).await,
        Err(DeliveryAdmissionError::Closed)
    ));
    assert!(
        observer.try_recv().is_none(),
        "failed admission is invisible"
    );
    let replacement: Arc<dyn EventDeliveryAdmitter> = Arc::new(Admitter(Arc::clone(&recorded)));
    assert!(bus.register_delivery_admitter(&replacement));
    bus.reserve_publication(event())
        .await
        .unwrap()
        .publish()
        .unwrap();
    observer.recv().await.unwrap();
    assert_eq!(recorded.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn dispatcher_retirement_rejects_uncommitted_reservation_without_publication() {
    let bus = EventBus::with_capacity(2);
    let inbox = bus.subscribe_ordered_delivery();
    let recorded = Arc::new(Mutex::new(Vec::new()));
    let admitter: Arc<dyn EventDeliveryAdmitter> = Arc::new(Admitter(recorded.clone()));
    assert!(bus.register_delivery_admitter(&admitter));
    let mut observer = bus.subscribe();
    let publication = bus.reserve_publication(event()).await.unwrap();
    drop(inbox);
    // Even replacing the lane must not revive an old reservation.
    let mut replacement = bus.subscribe_ordered_delivery();
    let result = publication.publish();
    assert!(observer.try_recv().is_none(), "failed commit is invisible");
    assert!(recorded.lock().unwrap().is_empty());
    assert_eq!(result, Err(DeliveryAdmissionError::Closed));
    bus.reserve_publication(event())
        .await
        .unwrap()
        .publish()
        .unwrap();
    assert!(
        replacement
            .recv()
            .await
            .unwrap()
            .into_unreserved()
            .is_none()
    );
    assert_eq!(*recorded.lock().unwrap(), vec![1]);
}

#[tokio::test]
async fn dispatcher_retirement_completes_committed_reservations_in_order() {
    let bus = EventBus::with_capacity(4);
    let inbox = bus.subscribe_ordered_delivery();
    let recorded = Arc::new(Mutex::new(Vec::new()));
    let admitter: Arc<dyn EventDeliveryAdmitter> = Arc::new(Admitter(recorded.clone()));
    assert!(bus.register_delivery_admitter(&admitter));
    bus.reserve_publication(event())
        .await
        .unwrap()
        .publish()
        .unwrap();
    bus.publish(event());
    bus.reserve_publication(event())
        .await
        .unwrap()
        .publish()
        .unwrap();
    let uncommitted = bus.reserve_publication(event()).await.unwrap();
    assert!(recorded.lock().unwrap().is_empty());
    drop(inbox);
    assert_eq!(*recorded.lock().unwrap(), vec![1, 3]);
    drop(uncommitted);
    assert_eq!(
        *recorded.lock().unwrap(),
        vec![1, 3],
        "no duplicate delivery"
    );
}

#[tokio::test]
async fn ordered_handoff_is_bounded_and_carries_reservations_in_sequence_order() {
    let bus = EventBus::with_capacity(2);
    let mut inbox = bus.subscribe_ordered_delivery();
    let recorded = Arc::new(Mutex::new(Vec::new()));
    let admitter: Arc<dyn EventDeliveryAdmitter> = Arc::new(Admitter(recorded.clone()));
    assert!(bus.register_delivery_admitter(&admitter));
    bus.publish(event());
    bus.reserve_publication(event())
        .await
        .unwrap()
        .publish()
        .unwrap();
    assert!(
        recorded.lock().unwrap().is_empty(),
        "no bypass of the ordered inbox"
    );
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(10),
            bus.reserve_publication(event())
        )
        .await
        .is_err(),
        "handoff capacity is bounded"
    );
    let ordinary = inbox.recv().await.unwrap().into_unreserved().unwrap();
    let AstridEvent::Ipc { message, .. } = &*ordinary else {
        panic!("IPC")
    };
    let first_seq = message.seq;
    let reserved = inbox.recv().await.unwrap();
    assert!(reserved.into_unreserved().is_none());
    assert!(recorded.lock().unwrap()[0] > first_seq);
    drop(bus.reserve_publication(event()).await.unwrap());
    bus.reserve_publication(event())
        .await
        .unwrap()
        .publish()
        .unwrap();
    assert!(inbox.recv().await.unwrap().into_unreserved().is_none());
    drop(inbox);
    assert!(matches!(
        bus.reserve_publication(event()).await,
        Err(DeliveryAdmissionError::Closed)
    ));
}

#[tokio::test]
async fn concurrent_dispatcher_retirement_accounts_for_every_commit() {
    let bus = EventBus::with_capacity(32);
    let inbox = bus.subscribe_ordered_delivery();
    let recorded = Arc::new(Mutex::new(Vec::new()));
    let admitter: Arc<dyn EventDeliveryAdmitter> = Arc::new(Admitter(recorded.clone()));
    assert!(bus.register_delivery_admitter(&admitter));
    let mut publications = Vec::new();
    for _ in 0..32 {
        publications.push(bus.reserve_publication(event()).await.unwrap());
    }
    let barrier = std::sync::Barrier::new(33);
    let accepted = std::thread::scope(|scope| {
        let handles: Vec<_> = publications
            .into_iter()
            .map(|publication| {
                let barrier = &barrier;
                scope.spawn(move || {
                    barrier.wait();
                    publication.publish().is_ok()
                })
            })
            .collect();
        barrier.wait();
        drop(inbox);
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .filter(|accepted| *accepted)
            .count()
    });
    let delivered = recorded.lock().unwrap();
    assert_eq!(delivered.len(), accepted);
    assert!(delivered.windows(2).all(|pair| pair[0] < pair[1]));
}
