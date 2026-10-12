//! Owner-scoped failure reporting for requests with one terminal consumer.

use std::sync::{Arc, Weak};

use astrid_events::ipc::{IpcMessage, request_failure::RequestFailureBinding};
use astrid_events::{AstridEvent, EventBus, EventMetadata};

pub(super) struct TerminalFailure {
    bus: Weak<EventBus>,
    binding: RequestFailureBinding,
}

impl TerminalFailure {
    pub(super) fn capture(bus: &Arc<EventBus>, message: Option<&IpcMessage>) -> Option<Self> {
        Some(Self {
            bus: Arc::downgrade(bus),
            binding: RequestFailureBinding::capture(message?)?,
        })
    }

    pub(super) fn report(&self, reason: &str) {
        if let Some(bus) = self.bus.upgrade() {
            bus.publish(AstridEvent::Ipc {
                message: self.binding.message(reason),
                metadata: EventMetadata::new("dispatcher"),
            });
        }
    }
}
