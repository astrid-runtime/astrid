//! Reservation-before-publication for bounded, ordered event delivery.

use std::sync::Weak;

use crate::{AstridEvent, EventBus};

/// Failure to reserve correctness-critical delivery capacity.
#[derive(Debug, Clone, Copy, Eq, PartialEq, thiserror::Error)]
pub enum DeliveryAdmissionError {
    /// The consumer disappeared before reservation completed.
    #[error("event delivery consumer closed")]
    Closed,
    /// Waiting would form a cycle involving the publishing invocation.
    #[error("event delivery would wait on its publisher")]
    SelfDependency,
    /// The event cannot be represented by the delivery consumer.
    #[error("invalid delivery event")]
    InvalidEvent,
}

/// An admission permit consumed exactly once, at publication time.
pub trait ReservedEventDelivery: Send {
    /// Acquire only short commit-time lifecycle fences, after all capacity
    /// waits. The bus releases them before notifying external observers.
    /// # Errors
    /// Returns `Closed` when a captured target generation retired.
    fn commit_guards(&self) -> Result<Vec<crate::RouteCommitGuard>, DeliveryAdmissionError> {
        Ok(Vec::new())
    }

    /// Enqueue the published, sequence-stamped event using already reserved space.
    fn deliver(self: Box<Self>, event: &AstridEvent);
}

/// Host-owned bounded delivery lane; no guest can register one.
#[async_trait::async_trait]
pub trait EventDeliveryAdmitter: std::fmt::Debug + Send + Sync {
    /// Reserve all required consumer capacity without publishing the event.
    /// Dropping the result must release every reservation without side effects.
    async fn reserve(
        &self,
        event: &AstridEvent,
    ) -> Result<Box<dyn ReservedEventDelivery>, DeliveryAdmissionError>;
}

/// A publication whose correctness-critical delivery capacity is reserved.
///
/// Dropping it cancels publication and releases capacity. This lets callers
/// recheck their invocation authority after a cancellable admission wait.
pub struct ReservedPublication<'a> {
    pub(crate) bus: &'a EventBus,
    pub(crate) event: AstridEvent,
    pub(crate) delivery: Option<Box<dyn ReservedEventDelivery>>,
    pub(crate) handoff: Option<crate::ordered_delivery::ReservedHandoff>,
}

impl ReservedPublication<'_> {
    /// Commit publication and its reservations in the bus's sequence order.
    /// # Errors
    /// Returns `Closed` if the dispatcher or a captured target retired after reservation.
    /// Failed commit publishes nothing and releases all reserved capacity.
    pub fn publish(self) -> Result<usize, DeliveryAdmissionError> {
        self.bus.commit_reserved(self)
    }
}

pub(crate) type AdmitterSlot =
    std::sync::Arc<parking_lot::RwLock<Option<Weak<dyn EventDeliveryAdmitter>>>>;

#[cfg(test)]
#[path = "admission_tests.rs"]
mod tests;
