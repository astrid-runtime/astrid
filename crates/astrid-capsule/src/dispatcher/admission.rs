//! Reserve bounded consumer slots before guest IPC publication.

use super::*;
use astrid_events::{DeliveryAdmissionError, EventDeliveryAdmitter, ReservedEventDelivery};

/// Registered before the inbox is visible, but closed until `run` activates
/// the final builder configuration. This avoids admitting through a temporary
/// access-resolver-free configuration during dispatcher construction.
#[derive(Debug, Default)]
pub(super) struct DeferredAdmitter {
    pub active: std::sync::OnceLock<Admitter>,
}

#[async_trait::async_trait]
impl EventDeliveryAdmitter for DeferredAdmitter {
    async fn reserve(
        &self,
        event: &AstridEvent,
    ) -> Result<Box<dyn ReservedEventDelivery>, DeliveryAdmissionError> {
        self.active
            .get()
            .ok_or(DeliveryAdmissionError::Closed)?
            .reserve(event)
            .await
    }
}

pub(super) struct Admitter {
    pub registry: Arc<RwLock<CapsuleRegistry>>,
    pub event_bus: std::sync::Weak<EventBus>,
    pub queues: CapsuleQueues,
    pub chain_locks: ChainLocks,
    pub access_resolver: Option<CapsuleAccessResolver>,
    pub waits: super::wait_graph::WaitGraph,
}

impl std::fmt::Debug for Admitter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CapsuleDeliveryAdmitter")
            .finish_non_exhaustive()
    }
}

struct CommittedDelivery {
    delivery: Delivery,
    grants: Vec<String>,
    principal: Option<String>,
    owner: Option<astrid_events::ipc::RequestOwnerId>,
    resolver: Option<CapsuleAccessResolver>,
    bus: std::sync::Weak<EventBus>,
    gates: Vec<astrid_events::RouteAdmissionGate>,
}

impl ReservedEventDelivery for CommittedDelivery {
    fn commit_guards(
        &self,
    ) -> Result<Vec<astrid_events::RouteCommitGuard>, DeliveryAdmissionError> {
        self.gates
            .iter()
            .map(|gate| gate.commit_guard().ok_or(DeliveryAdmissionError::Closed))
            .collect()
    }

    fn deliver(self: Box<Self>, event: &AstridEvent) {
        let Self {
            delivery,
            grants,
            principal,
            owner,
            resolver,
            bus,
            gates: _,
        } = *self;
        Box::new(delivery).deliver(event);
        if !grants.is_empty()
            && let Some(principal) = principal
            && let Some(bus) = bus.upgrade()
        {
            // Only committed events may ask the human for a grant. Batch these
            // infrequent prompts; normal streaming delivery spawns no task.
            tokio::spawn(async move {
                for capsule in grants {
                    crate::access::emit_grant_required(
                        &bus,
                        resolver.as_ref(),
                        &principal,
                        capsule,
                        owner,
                    )
                    .await;
                }
            });
        }
    }
}

enum Delivery {
    Queues(Vec<(mpsc::OwnedPermit<InterceptorWork>, InterceptorWork)>),
    Chain {
        queues: CapsuleQueues,
        locks: ChainLocks,
        matches: InterceptorMatches,
        topic: Arc<String>,
        payload: Arc<Vec<u8>>,
    },
}

impl ReservedEventDelivery for Delivery {
    fn deliver(self: Box<Self>, event: &AstridEvent) {
        let message = match event {
            AstridEvent::Ipc { message, .. } => Some(Arc::new(message.clone())),
            _ => None,
        };
        match *self {
            Self::Queues(work) => {
                for (permit, mut work) in work {
                    work.ipc_message.clone_from(&message);
                    permit.send(work);
                }
            },
            Self::Chain {
                queues,
                locks,
                matches,
                topic,
                payload,
            } => {
                dispatch_to_capsule_queues(&queues, &locks, matches, topic, payload, message);
            },
        }
    }
}

#[async_trait::async_trait]
impl EventDeliveryAdmitter for Admitter {
    async fn reserve(
        &self,
        event: &AstridEvent,
    ) -> Result<Box<dyn ReservedEventDelivery>, DeliveryAdmissionError> {
        let bus = self
            .event_bus
            .upgrade()
            .ok_or(DeliveryAdmissionError::Closed)?;
        let (topic, payload, message) = match event {
            AstridEvent::Ipc { message, .. } => (
                message.topic.to_string(),
                message
                    .payload
                    .to_guest_bytes()
                    .map_err(|_| DeliveryAdmissionError::InvalidEvent)?,
                Some(message),
            ),
            other => (
                other.event_type().to_owned(),
                serde_json::to_vec(other).map_err(|_| DeliveryAdmissionError::InvalidEvent)?,
                None,
            ),
        };
        let principal = message.and_then(|message| message.principal.as_deref());
        let (matches, grants) = collect_matching_interceptors(
            &self.registry,
            &topic,
            principal,
            message.and_then(|message| message.device_key_id.as_deref()),
            self.access_resolver.as_ref(),
        )
        .await;
        // Capture each runtime once even if several of its handlers match.
        // These gates are not locked until commit, after every capacity wait.
        let mut seen = std::collections::HashSet::new();
        let gates = matches
            .iter()
            .filter_map(|(runtime, capsule, _, _)| {
                seen.insert(runtime.clone())
                    .then(|| capsule.delivery_admission_gate())
                    .flatten()
            })
            .collect();
        let committed = |delivery| -> Box<dyn ReservedEventDelivery> {
            Box::new(CommittedDelivery {
                delivery,
                grants,
                principal: principal.map(str::to_owned),
                owner: message.and_then(|message| message.request_owner),
                resolver: self.access_resolver.clone(),
                bus: Arc::downgrade(&bus),
                gates,
            })
        };
        let topic = Arc::new(topic);
        let payload = Arc::new(payload);
        if matches
            .first()
            .is_some_and(|first| matches.iter().any(|entry| entry.3 != first.3))
        {
            // Preserve the existing ordered middleware-chain semantics.
            return Ok(committed(Delivery::Chain {
                queues: Arc::clone(&self.queues),
                locks: Arc::clone(&self.chain_locks),
                matches,
                topic,
                payload,
            }));
        }
        let source_key = if let Some(message) = message {
            let registry = self.registry.read().await;
            let principal_id =
                principal.and_then(|value| astrid_core::PrincipalId::new(value).ok());
            principal_id.and_then(|principal_id| {
                let capsule =
                    registry.find_instance_by_uuid_for(&principal_id, &message.source_id)?;
                let runtime_id = registry.runtime_id_for(&principal_id, capsule.id())?;
                if let Ok(active) = super::wait_graph::ACTIVE_CONSUMER.try_with(Clone::clone)
                    && active.0 == runtime_id
                {
                    return Some(active);
                }
                // Middleware chains do not occupy a FIFO consumer. Merely
                // having a source capsule does not mean that queue is blocked.
                None
            })
        } else {
            None
        };
        let mut reservations = Vec::with_capacity(matches.len());
        for (runtime_id, capsule, action, _) in matches {
            let requested = (runtime_id, principal.map(str::to_owned));
            let (key, sender) = get_or_spawn_consumer(&self.queues, &capsule, requested);
            let permit = match sender.try_reserve_owned() {
                Ok(permit) => permit,
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    return Err(DeliveryAdmissionError::Closed);
                },
                Err(mpsc::error::TrySendError::Full(sender)) => {
                    // Waiting A→B while B already waits on A would strand both
                    // invocations. Cancelled waits release their graph edges.
                    let _wait = source_key
                        .as_ref()
                        .map(|source| {
                            self.waits
                                .enter(source.clone(), key)
                                .ok_or(DeliveryAdmissionError::SelfDependency)
                        })
                        .transpose()?;
                    sender
                        .reserve_owned()
                        .await
                        .map_err(|_| DeliveryAdmissionError::Closed)?
                },
            };
            reservations.push((
                permit,
                InterceptorWork {
                    action,
                    payload: Arc::clone(&payload),
                    topic: Arc::clone(&topic),
                    ipc_message: None,
                },
            ));
        }
        Ok(committed(Delivery::Queues(reservations)))
    }
}
