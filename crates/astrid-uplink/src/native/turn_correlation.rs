//! Bounded correlation for autonomous completion of an admitted chat turn.
//!
//! A producer first binds a nonce with a normally host-owned nonterminal
//! response. Later callbacks may lack that invocation owner, but must still
//! match this producer and nonce. Conversation identity alone is insufficient.

use astrid_events::ipc::{IpcMessage, RequestOwnerId};
use astrid_types::ipc::IpcPayload;
use uuid::Uuid;

#[derive(Clone, Copy)]
pub(super) struct ResponseCorrelation {
    producer: Uuid,
    nonce: Uuid,
}

fn nonce(message: &IpcMessage) -> Option<Uuid> {
    let (IpcPayload::Custom { data: value } | IpcPayload::RawJson(value)) = &message.payload else {
        return None;
    };
    Uuid::parse_str(value.get("request_id")?.as_str()?)
        .ok()
        .filter(|id| !id.is_nil())
}

pub(super) fn owner_allows(
    message: &IpcMessage,
    owner: RequestOwnerId,
    binding: &mut Option<ResponseCorrelation>,
    completed: bool,
) -> bool {
    if message.request_owner == Some(owner) {
        if !completed
            && binding.is_none()
            && !message.source_id.is_nil()
            && let Some(nonce) = nonce(message)
        {
            *binding = Some(ResponseCorrelation {
                producer: message.source_id,
                nonce,
            });
        }
        return true;
    }
    // A foreign explicit owner never falls back to autonomous correlation.
    message.request_owner.is_none()
        && completed
        && binding.as_ref().is_some_and(|binding| {
            message.source_id == binding.producer && nonce(message) == Some(binding.nonce)
        })
}

pub(super) fn bind_terminal(message: &mut IpcMessage, owner: Option<RequestOwnerId>) {
    message.request_owner = owner;
    // The bus needs the nonce-bearing raw payload, but typed native clients
    // need the response discriminator. Normalize only this validated copy.
    if let IpcPayload::Custom { data } | IpcPayload::RawJson(data) = &mut message.payload
        && let Some(object) = data.as_object_mut()
    {
        object.insert("type".into(), serde_json::json!("agent_response"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::egress::{Registry, TryRecvError};
    use astrid_events::{AstridEvent, EventBus, EventMetadata};
    use astrid_types::Topic;
    use std::sync::Arc;

    #[test]
    fn autonomous_timeout_requires_bound_producer_and_current_nonce() {
        let bus = Arc::new(EventBus::new());
        let registry = Registry::install(&bus);
        let mut receiver = registry.subscribe("alice".into(), None, RequestOwnerId::generate());
        let producer = Uuid::new_v4();
        let nonce = Uuid::new_v4();
        assert!(receiver.begin_turn("conversation"));
        let owner = receiver.turn_owner().unwrap();
        let publish = |producer, nonce, owner, is_final| {
            let mut message = IpcMessage::new(
                Topic::from_raw("agent.v1.response"),
                IpcPayload::RawJson(serde_json::json!({
                    "text": if is_final { "Request timed out" } else { "" },
                    "is_final": is_final, "session_id": "conversation",
                    "request_id": nonce,
                })),
                producer,
            )
            .with_principal("alice");
            message.request_owner = owner;
            bus.publish(AstridEvent::Ipc {
                metadata: EventMetadata::new("capsule"),
                message,
            });
        };
        publish(producer, nonce, None, true);
        assert!(matches!(receiver.try_recv(), Err(TryRecvError::Empty)));
        publish(producer, nonce, Some(owner), false);
        receiver
            .try_recv()
            .expect("owned response binds original turn");
        for (source, nonce, claimed_owner) in [
            (Uuid::new_v4(), nonce, None),
            (producer, Uuid::new_v4(), None),
            (producer, nonce, Some(RequestOwnerId::generate())),
        ] {
            publish(source, nonce, claimed_owner, true);
            assert!(matches!(receiver.try_recv(), Err(TryRecvError::Empty)));
            assert_eq!(receiver.turn_owner(), Some(owner));
        }
        publish(producer, nonce, None, true);
        let terminal = receiver
            .try_recv()
            .expect("bound autonomous timeout reaches client");
        assert!(matches!(&*terminal, AstridEvent::Ipc { message, .. }
            if message.request_owner == Some(owner)));
        let AstridEvent::Ipc { message, .. } = &*terminal else {
            panic!("terminal IPC");
        };
        let wire = super::super::message_frame(message).unwrap();
        let typed: astrid_types::ipc::IpcMessage = serde_json::from_value(wire)
            .expect("typed native client can decode the validated timeout");
        assert!(matches!(
            typed.payload,
            IpcPayload::AgentResponse { is_final: true, .. }
        ));
        assert_eq!(receiver.session(), None);
        assert!(receiver.begin_turn("conversation"));
        let next_owner = receiver.turn_owner().unwrap();
        publish(producer, Uuid::new_v4(), Some(next_owner), false);
        receiver
            .try_recv()
            .expect("new turn establishes its own binding");
        publish(producer, nonce, None, true);
        assert!(matches!(receiver.try_recv(), Err(TryRecvError::Empty)));
        assert_eq!(receiver.turn_owner(), Some(next_owner));
    }
}
