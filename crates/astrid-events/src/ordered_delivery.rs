//! One bounded, sequence-ordered handoff for ordinary and reserved delivery.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::mpsc;

use crate::{AstridEvent, ReservedEventDelivery};

/// A published event with optional pre-reserved consumer capacity.
pub struct OrderedDelivery {
    pub(crate) event: Arc<AstridEvent>,
    pub(crate) reservation: Option<Box<dyn ReservedEventDelivery>>,
}

impl OrderedDelivery {
    /// Deliver a reserved event exactly once, or return an ordinary event for
    /// matching by the dispatcher. Call in inbox order, before the next recv.
    #[must_use]
    pub fn into_unreserved(self) -> Option<Arc<AstridEvent>> {
        if let Some(reservation) = self.reservation {
            reservation.deliver(&self.event);
            None
        } else {
            Some(self.event)
        }
    }
}

/// Exclusive bounded dispatcher inbox. Reserved publications wait for space;
/// synchronous publications retain best-effort, counted overflow semantics.
pub struct OrderedDeliveryReceiver {
    pub(crate) receiver: mpsc::Receiver<OrderedDelivery>,
    pub(crate) lagged: Arc<AtomicU64>,
    pub(crate) publish_order: Arc<parking_lot::ReentrantMutex<()>>,
}

impl OrderedDeliveryReceiver {
    /// Receive the next publication in bus sequence order.
    pub async fn recv(&mut self) -> Option<OrderedDelivery> {
        self.receiver.recv().await
    }

    /// Reset and return ordinary publications dropped at the inbox boundary.
    #[must_use]
    pub fn drain_lagged(&self) -> u64 {
        self.lagged.swap(0, Ordering::Relaxed)
    }
}

impl Drop for OrderedDeliveryReceiver {
    fn drop(&mut self) {
        // Commit and retirement share the bus's total order. Close first so
        // outstanding, uncommitted permits cannot enqueue behind this drain.
        // Publications already acknowledged must complete reserved delivery;
        // ordinary publications retain best-effort shutdown semantics.
        let _guard = self.publish_order.lock();
        self.receiver.close();
        while let Ok(delivery) = self.receiver.try_recv() {
            let _ = delivery.into_unreserved();
        }
    }
}

pub(crate) struct ReservedHandoff {
    pub(crate) sender: mpsc::Sender<OrderedDelivery>,
    pub(crate) permit: mpsc::OwnedPermit<OrderedDelivery>,
}

#[derive(Clone, Debug)]
pub(crate) struct OrderedSender {
    pub(crate) sender: mpsc::Sender<OrderedDelivery>,
    pub(crate) lagged: Arc<AtomicU64>,
}

pub(crate) type OrderedSlot = Arc<parking_lot::Mutex<Option<OrderedSender>>>;
