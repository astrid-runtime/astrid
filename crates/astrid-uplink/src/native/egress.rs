//! Per-connection egress queues for the native local transport.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock, Weak};

use astrid_events::{AstridEvent, EventBus};

use super::{CLIENT_EGRESS_CAPACITY, EVENT_SOURCE, event_topic, routing};

struct ClientQueue {
    principal: String,
    device_key_id: Option<String>,
    session: Arc<RwLock<Option<String>>>,
    sender: tokio::sync::broadcast::Sender<Arc<AstridEvent>>,
}

/// Registry consulted synchronously while events are published.
///
/// Each connection owns a distinct bounded queue. Filtering before enqueueing
/// means traffic for one principal cannot advance another principal's cursor
/// or cause an unrelated connection to report lag.
pub(super) struct Registry {
    clients: Mutex<HashMap<uuid::Uuid, ClientQueue>>,
}

pub(super) struct Subscription {
    id: uuid::Uuid,
    registry: Weak<Registry>,
    session: Arc<RwLock<Option<String>>>,
    receiver: tokio::sync::broadcast::Receiver<Arc<AstridEvent>>,
}

impl Registry {
    pub(super) fn install(event_bus: &Arc<EventBus>) -> Arc<Self> {
        let registry = Arc::new(Self {
            clients: Mutex::new(HashMap::new()),
        });
        let weak_registry = Arc::downgrade(&registry);
        event_bus.observe_permanently(EVENT_SOURCE, move |event| {
            let Some(registry) = weak_registry.upgrade() else {
                return;
            };
            let Some(message) = event_message(event) else {
                return;
            };
            if !routing::egress_allowed(event_topic(event).unwrap_or_default()) {
                return;
            }

            let event = Arc::new(event.clone());
            let clients = registry
                .clients
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for client in clients.values() {
                let session = client
                    .session
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if routing::should_deliver(
                    message,
                    &client.principal,
                    client.device_key_id.as_deref(),
                    session.as_deref(),
                ) {
                    let _ = client.sender.send(Arc::clone(&event));
                }
            }
        });
        registry
    }

    pub(super) fn subscribe(
        self: &Arc<Self>,
        principal: String,
        device_key_id: Option<String>,
    ) -> Subscription {
        let id = uuid::Uuid::new_v4();
        let session = Arc::new(RwLock::new(None));
        let (sender, receiver) = tokio::sync::broadcast::channel(CLIENT_EGRESS_CAPACITY);
        self.clients
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(
                id,
                ClientQueue {
                    principal,
                    device_key_id,
                    session: Arc::clone(&session),
                    sender,
                },
            );
        Subscription {
            id,
            registry: Arc::downgrade(self),
            session,
            receiver,
        }
    }
}

impl Subscription {
    pub(super) fn set_session(&self, session: Option<String>) {
        *self
            .session
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = session;
    }

    pub(super) fn session(&self) -> Option<String> {
        self.session
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    pub(super) async fn recv(
        &mut self,
    ) -> Result<Arc<AstridEvent>, tokio::sync::broadcast::error::RecvError> {
        self.receiver.recv().await
    }

    pub(super) fn try_recv(
        &mut self,
    ) -> Result<Arc<AstridEvent>, tokio::sync::broadcast::error::TryRecvError> {
        self.receiver.try_recv()
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        let Some(registry) = self.registry.upgrade() else {
            return;
        };
        registry
            .clients
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.id);
    }
}

fn event_message(event: &AstridEvent) -> Option<&astrid_types::ipc::IpcMessage> {
    let AstridEvent::Ipc { message, .. } = event else {
        return None;
    };
    Some(message)
}
