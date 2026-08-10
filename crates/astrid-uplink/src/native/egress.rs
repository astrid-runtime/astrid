//! Per-connection egress queues for the native local transport.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex, RwLock, Weak};

use astrid_events::{AstridEvent, EventBus};

use super::{CLIENT_EGRESS_CAPACITY, EVENT_SOURCE, MAX_PAYLOAD_BYTES, event_topic, routing};

const CLIENT_EGRESS_BYTE_BUDGET: usize = 4 * MAX_PAYLOAD_BYTES;

struct QueuedEvent {
    event: Arc<AstridEvent>,
    bytes: usize,
}

#[derive(Default)]
struct QueueState {
    events: VecDeque<QueuedEvent>,
    bytes: usize,
    overflowed: bool,
}

struct EgressQueue {
    state: Mutex<QueueState>,
    ready: tokio::sync::Notify,
}

#[derive(Debug, Eq, PartialEq)]
pub(super) enum RecvError {
    Lagged,
}

#[derive(Debug, Eq, PartialEq)]
pub(super) enum TryRecvError {
    Empty,
    Lagged,
}

struct ClientQueue {
    principal: String,
    device_key_id: Option<String>,
    session: Arc<RwLock<Option<String>>>,
    queue: Arc<EgressQueue>,
}

/// Registry consulted synchronously while events are published.
///
/// Each connection owns a distinct bounded queue. Filtering before enqueueing
/// means traffic for one principal cannot advance another principal's cursor
/// or cause an unrelated connection to report lag.
pub(super) struct Registry {
    clients: Mutex<HashMap<uuid::Uuid, ClientQueue>>,
    active_turns: Mutex<HashSet<(String, String)>>,
}

pub(super) struct Subscription {
    id: uuid::Uuid,
    registry: Weak<Registry>,
    principal: String,
    session: Arc<RwLock<Option<String>>>,
    queue: Arc<EgressQueue>,
}

impl Registry {
    pub(super) fn install(event_bus: &Arc<EventBus>) -> Arc<Self> {
        let registry = Arc::new(Self {
            clients: Mutex::new(HashMap::new()),
            active_turns: Mutex::new(HashSet::new()),
        });
        let weak_registry = Arc::downgrade(&registry);
        event_bus.observe_permanently(EVENT_SOURCE, move |event| {
            let Some(registry) = weak_registry.upgrade() else {
                return;
            };
            let Some(message) = event_message(event) else {
                return;
            };
            if let (Some(principal), Some(session)) = (
                message.principal.as_deref(),
                routing::completed_chat_session(message),
            ) {
                registry
                    .active_turns
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .remove(&(principal.to_owned(), session.to_owned()));
            }
            if !routing::egress_allowed(event_topic(event).unwrap_or_default()) {
                return;
            }

            // Match the bare frame written by `write_message` rather than the
            // richer internal envelope (whose tagged RawJson representation
            // is intentionally not the local wire shape). The fixed overhead
            // conservatively covers topic, principal, source UUID, and JSON
            // field syntax.
            let event_bytes = message
                .payload
                .to_guest_bytes()
                .map_or(usize::MAX, |bytes| {
                    bytes
                        .len()
                        .saturating_add(message.topic.as_str().len())
                        .saturating_add(message.principal.as_deref().map_or(0, str::len))
                        .saturating_add(1024)
                });
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
                    client.queue.enqueue(Arc::clone(&event), event_bytes);
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
        let queue = Arc::new(EgressQueue::new());
        self.clients
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(
                id,
                ClientQueue {
                    principal: principal.clone(),
                    device_key_id,
                    session: Arc::clone(&session),
                    queue: Arc::clone(&queue),
                },
            );
        Subscription {
            id,
            registry: Arc::downgrade(self),
            principal,
            session,
            queue,
        }
    }
}

impl Subscription {
    pub(super) fn begin_turn(&self, session: &str) -> bool {
        let Some(registry) = self.registry.upgrade() else {
            return false;
        };
        registry
            .active_turns
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert((self.principal.clone(), session.to_owned()))
    }

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

    pub(super) async fn recv(&mut self) -> Result<Arc<AstridEvent>, RecvError> {
        self.queue.recv().await
    }

    pub(super) fn try_recv(&mut self) -> Result<Arc<AstridEvent>, TryRecvError> {
        self.queue.try_recv()
    }
}

impl EgressQueue {
    fn new() -> Self {
        Self {
            state: Mutex::new(QueueState::default()),
            ready: tokio::sync::Notify::new(),
        }
    }

    fn enqueue(&self, event: Arc<AstridEvent>, bytes: usize) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.overflowed {
            return;
        }
        if state.events.len() >= CLIENT_EGRESS_CAPACITY
            || bytes > CLIENT_EGRESS_BYTE_BUDGET.saturating_sub(state.bytes)
        {
            // Release retained frames immediately. The affected connection
            // observes Lagged and fail-closes; other clients have independent
            // queues and remain available.
            state.events.clear();
            state.bytes = 0;
            state.overflowed = true;
            drop(state);
            self.ready.notify_one();
            return;
        }
        state.bytes = state.bytes.saturating_add(bytes);
        state.events.push_back(QueuedEvent { event, bytes });
        drop(state);
        self.ready.notify_one();
    }

    async fn recv(&self) -> Result<Arc<AstridEvent>, RecvError> {
        loop {
            // Register before inspecting state so a publisher cannot notify
            // between the empty check and this task beginning to wait.
            let ready = self.ready.notified();
            {
                let mut state = self
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if state.overflowed {
                    return Err(RecvError::Lagged);
                }
                if let Some(queued) = state.events.pop_front() {
                    state.bytes = state.bytes.saturating_sub(queued.bytes);
                    return Ok(queued.event);
                }
            }
            ready.await;
        }
    }

    fn try_recv(&self) -> Result<Arc<AstridEvent>, TryRecvError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.overflowed {
            return Err(TryRecvError::Lagged);
        }
        let Some(queued) = state.events.pop_front() else {
            return Err(TryRecvError::Empty);
        };
        state.bytes = state.bytes.saturating_sub(queued.bytes);
        Ok(queued.event)
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

#[cfg(test)]
mod tests {
    use astrid_events::EventMetadata;
    use astrid_types::Topic;
    use astrid_types::ipc::{IpcMessage, IpcPayload};

    use super::*;

    fn event() -> Arc<AstridEvent> {
        Arc::new(AstridEvent::Ipc {
            metadata: EventMetadata::new("test"),
            message: IpcMessage::new(
                Topic::from_raw("astrid.v1.response.test"),
                IpcPayload::RawJson(serde_json::json!({"ok": true})),
                uuid::Uuid::nil(),
            )
            .with_principal("alice"),
        })
    }

    #[tokio::test]
    async fn byte_budget_fail_closes_and_releases_retained_events() {
        let queue = EgressQueue::new();
        queue.enqueue(event(), CLIENT_EGRESS_BYTE_BUDGET);
        queue.enqueue(event(), 1);

        assert!(matches!(queue.recv().await, Err(RecvError::Lagged)));
        let state = queue
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(state.events.is_empty());
        assert_eq!(state.bytes, 0);
    }

    #[test]
    fn one_turn_per_principal_session_until_terminal_publication() {
        let bus = Arc::new(EventBus::new());
        let registry = Registry::install(&bus);
        let first = registry.subscribe("alice".to_owned(), None);
        let second = registry.subscribe("alice".to_owned(), None);

        assert!(first.begin_turn("session-1"));
        assert!(!second.begin_turn("session-1"));
        assert!(second.begin_turn("session-2"));

        bus.publish(AstridEvent::Ipc {
            metadata: EventMetadata::new("test"),
            message: IpcMessage::new(
                Topic::from_raw("agent.v1.response"),
                IpcPayload::AgentResponse {
                    text: "done".to_owned(),
                    is_final: true,
                    session_id: "session-1".to_owned(),
                },
                uuid::Uuid::nil(),
            )
            .with_principal("alice"),
        });

        assert!(second.begin_turn("session-1"));
    }
}
