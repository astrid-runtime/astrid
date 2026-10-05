//! Per-connection egress queues for the native local transport.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, RwLock, Weak};

use astrid_events::ipc::{IpcMessage, RequestOwnerId, Topic};
use astrid_events::{AstridEvent, EventBus};

use super::{CLIENT_EGRESS_CAPACITY, EVENT_SOURCE, MAX_PAYLOAD_BYTES, event_topic, routing};

const CLIENT_EGRESS_BYTE_BUDGET: usize = 4 * MAX_PAYLOAD_BYTES;

struct QueuedEvent {
    event: Arc<AstridEvent>,
    bytes: usize,
}

fn request_owner_allows(message: &IpcMessage, client_owner: RequestOwnerId) -> bool {
    if message.topic == Topic::approval_request() {
        let expected_owner = client_owner.to_string();
        return match &message.payload {
            astrid_types::ipc::IpcPayload::ApprovalRequired { request_owner, .. }
            | astrid_types::ipc::IpcPayload::GrantRequired { request_owner, .. } => {
                message.source_id == uuid::Uuid::nil()
                    && message.request_owner == Some(client_owner)
                    && request_owner.as_str() == expected_owner.as_str()
            },
            _ => false,
        };
    }
    message
        .request_owner
        .is_none_or(|owner| owner == client_owner)
}

#[derive(Default)]
struct QueueState {
    events: VecDeque<QueuedEvent>,
    human_replies: HashMap<ReplyKey, RequestOwnerId>,
    claimed_replies: std::collections::HashSet<ReplyKey>,
    human_reply_bytes: usize,
    bytes: usize,
    overflowed: bool,
}

#[derive(Clone, Hash, Eq, PartialEq)]
pub(super) struct ReplyKey {
    topic: Topic,
    selection_id: Option<String>,
}

impl ReplyKey {
    pub(super) fn from_reply(message: &IpcMessage) -> Self {
        let selection_id = if message.topic.as_str().starts_with("registry.v1.selection.") {
            match &message.payload {
                astrid_types::ipc::IpcPayload::Custom { data }
                | astrid_types::ipc::IpcPayload::RawJson(data) => data
                    .get("request_id")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned),
                _ => None,
            }
        } else {
            None
        };
        Self {
            topic: message.topic.clone(),
            selection_id,
        }
    }

    fn bytes(&self) -> usize {
        self.topic
            .as_str()
            .len()
            .saturating_add(self.selection_id.as_ref().map_or(0, String::len))
    }
}

pub(super) struct EgressQueue {
    state: Mutex<QueueState>,
    ready: tokio::sync::Notify,
}

fn connection_owned_elicitation(
    event: &Arc<AstridEvent>,
    owner: RequestOwnerId,
) -> Arc<AstridEvent> {
    let Some(message) = event_message(event) else {
        return Arc::clone(event);
    };
    if message.request_owner.is_none()
        && message.source_id.is_nil()
        && message.topic == Topic::elicit_request()
        && matches!(
            message.payload,
            astrid_types::ipc::IpcPayload::ElicitRequest { .. }
        )
    {
        let mut delivered = (**event).clone();
        if let AstridEvent::Ipc { message, .. } = &mut delivered {
            message.request_owner = Some(owner);
        }
        Arc::new(delivered)
    } else {
        Arc::clone(event)
    }
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
    request_owner: RequestOwnerId,
    session: Arc<RwLock<Option<ActiveTurn>>>,
    queue: Arc<EgressQueue>,
}

struct ActiveTurn {
    session_id: String,
    request_owner: RequestOwnerId,
    correlation: Option<super::turn_correlation::ResponseCorrelation>,
}

impl ClientQueue {
    fn owner_allows(
        &self,
        session: &mut Option<ActiveTurn>,
        message: &IpcMessage,
        chat: bool,
        completed: bool,
    ) -> bool {
        if chat {
            return session.as_mut().is_some_and(|turn| {
                super::turn_correlation::owner_allows(
                    message,
                    turn.request_owner,
                    &mut turn.correlation,
                    completed,
                )
            });
        }
        request_owner_allows(message, self.request_owner)
            || session
                .as_ref()
                .is_some_and(|turn| request_owner_allows(message, turn.request_owner))
    }
}

/// Registry consulted synchronously while events are published.
///
/// Each connection owns a distinct bounded queue. Filtering before enqueueing
/// means traffic for one principal cannot advance another principal's cursor
/// or cause an unrelated connection to report lag.
pub(super) struct Registry {
    clients: Mutex<HashMap<uuid::Uuid, ClientQueue>>,
    active_turns: Mutex<HashMap<(String, String), uuid::Uuid>>,
}

pub(super) struct Subscription {
    id: uuid::Uuid,
    registry: Weak<Registry>,
    principal: String,
    session: Arc<RwLock<Option<ActiveTurn>>>,
    queue: Arc<EgressQueue>,
}

pub(super) struct HumanReplyClaim<'a> {
    receiver: &'a Subscription,
    key: ReplyKey,
    pub(super) owner: RequestOwnerId,
    completed: bool,
}

impl HumanReplyClaim<'_> {
    pub(super) fn complete(mut self) {
        self.receiver.complete_human_reply(&self.key, self.owner);
        self.completed = true;
    }
}

impl Drop for HumanReplyClaim<'_> {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        self.receiver
            .queue
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .claimed_replies
            .remove(&self.key);
    }
}

impl Registry {
    pub(super) fn install(event_bus: &Arc<EventBus>) -> Arc<Self> {
        let registry = Arc::new(Self {
            clients: Mutex::new(HashMap::new()),
            active_turns: Mutex::new(HashMap::new()),
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

            let turn_key = message.principal.as_deref().and_then(|principal| {
                routing::outbound_session(message)
                    .map(|session| (principal.to_owned(), session.to_owned()))
            });
            let turn_owner = turn_key.as_ref().and_then(|key| {
                registry
                    .active_turns
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .get(key)
                    .copied()
            });
            let completed = routing::completed_chat_session(message).is_some();

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
            let mut finished_owner = None;
            for (id, client) in clients.iter() {
                if turn_key.is_some() && turn_owner != Some(*id) {
                    continue;
                }
                let mut session = client
                    .session
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if !routing::should_deliver(
                    message,
                    &client.principal,
                    client.device_key_id.as_deref(),
                    session.as_ref().map(|turn| turn.session_id.as_str()),
                ) {
                    continue;
                }
                let active_owner = session.as_ref().map(|turn| turn.request_owner);
                // Ordinary chat frames require the host-stamped turn owner.
                // Autonomous completion additionally needs a nonce bound by
                // that owner and the same authenticated capsule producer.
                let owner_allowed =
                    client.owner_allows(&mut session, message, turn_key.is_some(), completed);
                if !owner_allowed {
                    continue;
                }
                // Legacy kernel elicitation has principal authority but
                // no invocation owner. Bind its delivered copy to this
                // authenticated connection, never to an unrelated chat.
                let mut delivered = connection_owned_elicitation(&event, client.request_owner);
                if turn_key.is_some()
                    && message.request_owner.is_none()
                    && let AstridEvent::Ipc { message, .. } = Arc::make_mut(&mut delivered)
                {
                    super::turn_correlation::bind_terminal(message, active_owner);
                }
                client.queue.enqueue(delivered, event_bytes);
                if completed {
                    finished_owner = Some(*id);
                }
            }
            if completed
                && let Some(owner) = finished_owner
                && let Some(client) = clients.get(&owner)
            {
                *client
                    .session
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
            }
            drop(clients);
            if completed && let (Some(key), Some(owner)) = (turn_key, finished_owner) {
                let mut active = registry
                    .active_turns
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if active.get(&key) == Some(&owner) {
                    active.remove(&key);
                }
            }
        });
        registry
    }

    pub(super) fn subscribe(
        self: &Arc<Self>,
        principal: String,
        device_key_id: Option<String>,
        request_owner: RequestOwnerId,
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
                    request_owner,
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
    pub(super) fn claim_human_reply(
        &self,
        message: &IpcMessage,
    ) -> Result<Option<HumanReplyClaim<'_>>, &'static str> {
        let Some(owner) = self.human_reply_owner(message)? else {
            return Ok(None);
        };
        let key = ReplyKey::from_reply(message);
        let mut state = self
            .queue
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.overflowed
            || state.human_replies.get(&key) != Some(&owner)
            || !state.claimed_replies.insert(key.clone())
        {
            return Err("human reply is no longer available on this connection");
        }
        Ok(Some(HumanReplyClaim {
            receiver: self,
            key,
            owner,
            completed: false,
        }))
    }

    pub(super) fn human_reply_owner(
        &self,
        message: &IpcMessage,
    ) -> Result<Option<RequestOwnerId>, &'static str> {
        use astrid_types::ipc::IpcPayload;
        let topic = message.topic.as_str();
        if topic.starts_with("registry.v1.selection.") {
            let state = self
                .queue
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let key = ReplyKey::from_reply(message);
            let Some(owner) = state.human_replies.get(&key) else {
                return if key.selection_id.is_some() {
                    Err("selection reply does not match a request on this connection")
                } else {
                    Ok(None) // Standalone model-selection command.
                };
            };
            if state.overflowed || state.claimed_replies.contains(&key) {
                return Err("selection reply does not match the delivered request");
            }
            return Ok(Some(*owner));
        }
        if !topic.starts_with("astrid.v1.approval.response.")
            && !topic.starts_with("astrid.v1.elicit.response.")
        {
            return Ok(None);
        }
        let expected = match &message.payload {
            IpcPayload::ApprovalResponse { request_id, .. } => Topic::approval_response(request_id),
            IpcPayload::ElicitResponse { request_id, .. } => Topic::elicit_response(*request_id),
            _ => return Err("human reply requires a typed response"),
        };
        if expected != message.topic {
            return Err("human reply request ID does not match its topic");
        }
        let state = self
            .queue
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.overflowed {
            return Err("human request delivery overflowed");
        }
        if state
            .claimed_replies
            .contains(&ReplyKey::from_reply(message))
        {
            return Err("human reply is already awaiting runtime delivery");
        }
        state
            .human_replies
            .get(&ReplyKey {
                topic: expected,
                selection_id: None,
            })
            .copied()
            .map(Some)
            .ok_or("human reply does not match a request on this connection")
    }

    pub(super) fn complete_human_reply(&self, key: &ReplyKey, owner: RequestOwnerId) {
        let mut state = self
            .queue
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state
            .human_replies
            .get(key)
            .is_some_and(|existing| *existing == owner)
            && state.human_replies.remove(key).is_some()
        {
            state.human_reply_bytes = state.human_reply_bytes.saturating_sub(key.bytes());
            state.claimed_replies.remove(key);
        }
    }

    pub(super) fn egress_queue(&self) -> Arc<EgressQueue> {
        Arc::clone(&self.queue)
    }
    pub(super) fn begin_turn(&self, session: &str) -> bool {
        let Some(registry) = self.registry.upgrade() else {
            return false;
        };
        let mut current = self
            .session
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if current.is_some() {
            return false;
        }
        let inserted = match registry
            .active_turns
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry((self.principal.clone(), session.to_owned()))
        {
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(self.id);
                true
            },
            std::collections::hash_map::Entry::Occupied(_) => false,
        };
        if inserted {
            *current = Some(ActiveTurn {
                session_id: session.to_owned(),
                request_owner: RequestOwnerId::generate(),
                correlation: None,
            });
        }
        inserted
    }

    pub(super) fn session(&self) -> Option<String> {
        self.session
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map(|turn| turn.session_id.clone())
    }

    /// Roll back a turn whose input was never published. The captured owner
    /// prevents a cancelled reservation from clearing a later turn.
    pub(super) fn abandon_unpublished_turn(&self, owner: RequestOwnerId) {
        let Some(registry) = self.registry.upgrade() else {
            return;
        };
        let mut current = self
            .session
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if current
            .as_ref()
            .is_some_and(|turn| turn.request_owner == owner)
        {
            let turn = current.take().expect("matched turn");
            let mut active = registry
                .active_turns
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let key = (self.principal.clone(), turn.session_id);
            if active.get(&key) == Some(&self.id) {
                active.remove(&key);
            }
        }
    }

    pub(super) fn turn_owner(&self) -> Option<RequestOwnerId> {
        self.session
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map(|turn| turn.request_owner)
    }

    #[cfg(test)]
    pub(super) async fn recv(&mut self) -> Result<Arc<AstridEvent>, RecvError> {
        self.queue.recv().await
    }

    #[cfg(test)]
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
        let human_reply = event_message(&event).and_then(|message| {
            use astrid_types::ipc::IpcPayload;
            let owner = message.request_owner?;
            let mut selection_id = None;
            let topic = match &message.payload {
                IpcPayload::ApprovalRequired { request_id, .. }
                | IpcPayload::GrantRequired { request_id, .. }
                    if message.topic == Topic::approval_request() =>
                {
                    Topic::approval_response(request_id)
                },
                IpcPayload::ElicitRequest { request_id, .. }
                    if message.topic == Topic::elicit_request() =>
                {
                    Topic::elicit_response(*request_id)
                },
                IpcPayload::SelectionRequired {
                    request_id,
                    callback_topic,
                    ..
                } if callback_topic
                    .as_str()
                    .starts_with("registry.v1.selection.") =>
                {
                    selection_id = Some(request_id.clone());
                    callback_topic.clone()
                },
                _ => return None,
            };
            Some((
                ReplyKey {
                    topic,
                    selection_id,
                },
                owner,
            ))
        });
        let reply_overflow = human_reply.as_ref().is_some_and(|(topic, owner)| {
            state
                .human_replies
                .get(topic)
                .is_some_and(|existing| existing != owner)
                || (!state.human_replies.contains_key(topic)
                    && (state.human_replies.len() >= CLIENT_EGRESS_CAPACITY
                        || topic.bytes()
                            > CLIENT_EGRESS_BYTE_BUDGET.saturating_sub(state.human_reply_bytes)))
        });
        if state.events.len() >= CLIENT_EGRESS_CAPACITY
            || bytes > CLIENT_EGRESS_BYTE_BUDGET.saturating_sub(state.bytes)
            || reply_overflow
        {
            // Release retained frames immediately. The affected connection
            // observes Lagged and fail-closes; other clients have independent
            // queues and remain available.
            state.events.clear();
            state.human_replies.clear();
            state.claimed_replies.clear();
            state.human_reply_bytes = 0;
            state.bytes = 0;
            state.overflowed = true;
            drop(state);
            self.ready.notify_one();
            return;
        }
        if let Some((topic, owner)) = human_reply {
            if !state.human_replies.contains_key(&topic) {
                state.human_reply_bytes = state.human_reply_bytes.saturating_add(topic.bytes());
            }
            state.human_replies.insert(topic, owner);
        }
        state.bytes = state.bytes.saturating_add(bytes);
        state.events.push_back(QueuedEvent { event, bytes });
        drop(state);
        self.ready.notify_one();
    }

    pub(super) async fn recv(&self) -> Result<Arc<AstridEvent>, RecvError> {
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

    pub(super) fn try_recv(&self) -> Result<Arc<AstridEvent>, TryRecvError> {
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
        if let Some(session) = self.session() {
            let key = (self.principal.clone(), session);
            let mut active = registry
                .active_turns
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if active.get(&key) == Some(&self.id) {
                active.remove(&key);
            }
        }
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

    #[test]
    fn unanswered_human_requests_have_a_bounded_lifetime_on_the_connection() {
        let queue = EgressQueue::new();
        let owner = RequestOwnerId::generate();
        for index in 0..=CLIENT_EGRESS_CAPACITY {
            queue.enqueue(
                Arc::new(AstridEvent::Ipc {
                    metadata: EventMetadata::new("test"),
                    message: IpcMessage::new(
                        Topic::approval_request(),
                        IpcPayload::GrantRequired {
                            request_id: index.to_string(),
                            request_owner: owner.to_string(),
                            principal: "alice".to_owned(),
                            capsule_id: "test".to_owned(),
                        },
                        uuid::Uuid::nil(),
                    )
                    .with_principal("alice")
                    .with_request_owner(owner),
                }),
                1,
            );
            if index < CLIENT_EGRESS_CAPACITY {
                assert!(queue.try_recv().is_ok());
            }
        }
        assert_eq!(queue.try_recv().err(), Some(TryRecvError::Lagged));
        let state = queue.state.lock().expect("state");
        assert!(state.human_replies.is_empty());
        assert_eq!(state.human_reply_bytes, 0);
    }

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
    fn request_owned_event_reaches_only_the_originating_connection() {
        let bus = Arc::new(EventBus::new());
        let registry = Registry::install(&bus);
        let owner = RequestOwnerId::generate();
        let other_owner = RequestOwnerId::generate();
        let mut origin = registry.subscribe("alice".to_owned(), None, owner);
        let mut peer = registry.subscribe("alice".to_owned(), None, other_owner);

        bus.publish(AstridEvent::Ipc {
            metadata: EventMetadata::new("test"),
            message: IpcMessage::new(
                Topic::from_raw("astrid.v1.approval"),
                IpcPayload::ApprovalRequired {
                    request_id: "request-1".to_owned(),
                    request_owner: owner.to_string(),
                    action: "run".to_owned(),
                    resource: "command".to_owned(),
                    reason: "test".to_owned(),
                },
                uuid::Uuid::nil(),
            )
            .with_principal("alice")
            .with_request_owner(owner),
        });

        assert!(origin.try_recv().is_ok());
        assert!(matches!(peer.try_recv(), Err(TryRecvError::Empty)));
    }

    #[test]
    fn ownerless_approval_reaches_no_native_connection() {
        let bus = Arc::new(EventBus::new());
        let registry = Registry::install(&bus);
        let owner = RequestOwnerId::generate();
        let mut client = registry.subscribe("alice".to_owned(), None, owner);

        bus.publish(AstridEvent::Ipc {
            metadata: EventMetadata::new("test"),
            message: IpcMessage::new(
                Topic::from_raw("astrid.v1.approval"),
                IpcPayload::ApprovalRequired {
                    request_id: "request-1".to_owned(),
                    request_owner: owner.to_string(),
                    action: "run".to_owned(),
                    resource: "command".to_owned(),
                    reason: "test".to_owned(),
                },
                uuid::Uuid::nil(),
            )
            .with_principal("alice"),
        });

        assert!(matches!(client.try_recv(), Err(TryRecvError::Empty)));
    }

    #[test]
    fn forged_or_internally_inconsistent_approval_reaches_no_native_connection() {
        let bus = Arc::new(EventBus::new());
        let registry = Registry::install(&bus);
        let owner = RequestOwnerId::generate();
        let mut client = registry.subscribe("alice".to_owned(), None, owner);

        for (source_id, payload_owner) in [
            (uuid::Uuid::new_v4(), owner.to_string()),
            (uuid::Uuid::nil(), RequestOwnerId::generate().to_string()),
        ] {
            bus.publish(AstridEvent::Ipc {
                metadata: EventMetadata::new("test"),
                message: IpcMessage::new(
                    Topic::from_raw("astrid.v1.approval"),
                    IpcPayload::ApprovalRequired {
                        request_id: "request-1".to_owned(),
                        request_owner: payload_owner,
                        action: "run".to_owned(),
                        resource: "command".to_owned(),
                        reason: "test".to_owned(),
                    },
                    source_id,
                )
                .with_principal("alice")
                .with_request_owner(owner),
            });
        }

        assert!(matches!(client.try_recv(), Err(TryRecvError::Empty)));
    }

    #[test]
    fn malformed_typed_approval_reaches_no_native_connection() {
        let bus = Arc::new(EventBus::new());
        let registry = Registry::install(&bus);
        let owner = RequestOwnerId::generate();
        let mut client = registry.subscribe("alice".to_owned(), None, owner);

        bus.publish(AstridEvent::Ipc {
            metadata: EventMetadata::new("test"),
            message: IpcMessage::new(
                Topic::approval_request(),
                IpcPayload::Custom {
                    data: serde_json::json!({
                        "type": "approval_required",
                        "request_id": "request-1",
                        "action": "run",
                        "resource": "command",
                        "reason": "missing payload owner"
                    }),
                },
                uuid::Uuid::nil(),
            )
            .with_principal("alice")
            .with_request_owner(owner),
        });

        assert!(matches!(client.try_recv(), Err(TryRecvError::Empty)));
    }

    #[test]
    fn one_turn_per_principal_session_until_terminal_publication() {
        let bus = Arc::new(EventBus::new());
        let registry = Registry::install(&bus);
        let mut first = registry.subscribe("alice".to_owned(), None, RequestOwnerId::generate());
        let mut second = registry.subscribe("alice".to_owned(), None, RequestOwnerId::generate());

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
            .with_principal("alice")
            .with_request_owner(first.turn_owner().expect("first turn owner")),
        });

        assert_eq!(first.session(), None);
        assert!(!second.begin_turn("session-1"));
        assert!(first.try_recv().is_ok(), "owner receives its terminal");

        bus.publish(AstridEvent::Ipc {
            metadata: EventMetadata::new("test"),
            message: IpcMessage::new(
                Topic::from_raw("agent.v1.response"),
                IpcPayload::AgentResponse {
                    text: "done".to_owned(),
                    is_final: true,
                    session_id: "session-2".to_owned(),
                },
                uuid::Uuid::nil(),
            )
            .with_principal("alice")
            .with_request_owner(second.turn_owner().expect("second turn owner")),
        });
        assert_eq!(second.session(), None);
        assert!(
            second.try_recv().is_ok(),
            "second owner receives its terminal"
        );
        assert!(second.begin_turn("session-1"));

        bus.publish(AstridEvent::Ipc {
            metadata: EventMetadata::new("test"),
            message: IpcMessage::new(
                Topic::from_raw("agent.v1.stream.delta"),
                IpcPayload::RawJson(serde_json::json!({
                    "session_id": "session-1",
                    "delta": "new"
                })),
                uuid::Uuid::nil(),
            )
            .with_principal("alice")
            .with_request_owner(second.turn_owner().expect("new turn owner")),
        });
        assert!(matches!(first.try_recv(), Err(TryRecvError::Empty)));
        assert!(
            second.try_recv().is_ok(),
            "only the new owner receives deltas"
        );
    }

    #[test]
    fn dropping_turn_owner_releases_only_its_admission() {
        let bus = Arc::new(EventBus::new());
        let registry = Registry::install(&bus);
        let first = registry.subscribe("alice".to_owned(), None, RequestOwnerId::generate());
        let second = registry.subscribe("alice".to_owned(), None, RequestOwnerId::generate());

        assert!(first.begin_turn("session-1"));
        drop(first);
        assert!(second.begin_turn("session-1"));
    }
}
