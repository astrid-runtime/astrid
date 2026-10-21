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
                    FailureBinding::Guest(binding) => binding.message(guest_reason(reason)),
                },
                metadata: EventMetadata::new("dispatcher"),
            });
        }
    }
}

/// Guest receipts expose only fixed classifications, never backend, overlay,
/// lookup or guest-authored denial diagnostics. Native receipts retain their
/// existing diagnostic contract. Exact matching prevents appended secrets.
fn guest_reason(reason: &str) -> &'static str {
    match reason {
        "interceptor exhausted its fuel budget" => "interceptor exhausted its fuel budget",
        "interceptor exceeded its execution deadline" => {
            "interceptor exceeded its execution deadline"
        },
        "interceptor execution failed: wasm unreachable instruction executed" => {
            "interceptor execution failed: wasm unreachable instruction executed"
        },
        _ => "interceptor execution failed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use astrid_events::ipc::{IpcPayload, Topic, delivery_failure::DeliveryId};

    #[test]
    fn stable_trap_classifications_survive_sanitization() {
        for reason in [
            "interceptor exhausted its fuel budget",
            "interceptor exceeded its execution deadline",
            "interceptor execution failed: wasm unreachable instruction executed",
        ] {
            assert_eq!(guest_reason(reason), reason);
        }
    }

    #[tokio::test]
    async fn guest_receipt_does_not_reflect_pre_invocation_or_denial_diagnostics() {
        let bus = Arc::new(EventBus::new());
        let mut replies = bus.subscribe();
        let mut request = IpcMessage::new(
            Topic::from_raw("arbitrary.v1.request"),
            IpcPayload::RawJson(serde_json::json!({})),
            uuid::Uuid::new_v4(),
        )
        .with_principal("alice");
        request.delivery_id = DeliveryId::parse("123456781234123412341234567890ab");
        let failure = TerminalFailure::capture(&bus, Some(&request)).unwrap();
        for diagnostic in [
            "backend unavailable: secret=/private/host/credential",
            "overlay failed: private operator config",
            "function lookup failed: host internal details",
            "denied: secret guest argument",
            "interceptor execution failed: wasm unreachable instruction executed; secret",
        ] {
            failure.report(diagnostic);
            let event = replies.recv().await.unwrap();
            let AstridEvent::Ipc { message, .. } = event.as_ref() else {
                panic!("IPC");
            };
            let IpcPayload::RawJson(payload) = &message.payload else {
                panic!("JSON");
            };
            assert_eq!(payload["reason"], "interceptor execution failed");
        }
    }
}
