//! Owner-scoped failure reporting for requests with one terminal consumer.

use std::sync::{Arc, Weak};

use astrid_events::ipc::{
    IpcMessage, delivery_failure::DeliveryFailureBinding, request_failure::RequestFailureBinding,
};
use astrid_events::{AstridEvent, EventBus, EventMetadata};

pub(super) struct TerminalFailure {
    bus: Weak<EventBus>,
    binding: FailureBinding,
}

enum FailureBinding {
    Native(RequestFailureBinding),
    Guest(DeliveryFailureBinding),
}

impl TerminalFailure {
    pub(super) fn capture(bus: &Arc<EventBus>, message: Option<&IpcMessage>) -> Option<Self> {
        Some(Self {
            bus: Arc::downgrade(bus),
            binding: RequestFailureBinding::capture(message?)
                .map(FailureBinding::Native)
                .or_else(|| DeliveryFailureBinding::capture(message?).map(FailureBinding::Guest))?,
        })
    }

    pub(super) fn report(&self, reason: &str) {
        if let Some(bus) = self.bus.upgrade() {
            bus.publish(AstridEvent::Ipc {
                message: match &self.binding {
                    FailureBinding::Native(binding) => binding.message(reason),
                    FailureBinding::Guest(binding) => binding.message(reason),
                },
                metadata: EventMetadata::new("dispatcher"),
            });
        }
    }
}
