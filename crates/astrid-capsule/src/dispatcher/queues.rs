//! Owned queue admission and shutdown for dispatcher consumers.

use super::*;
use astrid_events::RouteAdmissionGate;

type QueueMap = HashMap<(RuntimeId, PrincipalKey), mpsc::Sender<InterceptorWork>>;

#[derive(Default)]
pub(super) struct ConsumerQueues {
    entries: parking_lot::Mutex<QueueMap>,
    stopping: RouteAdmissionGate,
    pub(super) resolver: std::sync::OnceLock<CapsuleAccessResolver>,
}

impl ConsumerQueues {
    pub(super) fn lock(&self) -> parking_lot::MutexGuard<'_, QueueMap> {
        self.entries.lock()
    }

    pub(super) fn stopping(&self) -> &RouteAdmissionGate {
        &self.stopping
    }

    /// Recheck the registration after the FIFO or chain wait, immediately before
    /// handing the event to the selected capsule.
    pub(super) async fn invoke(
        &self,
        capsule: &dyn Capsule,
        action: &str,
        payload: &[u8],
        caller: Option<&astrid_events::IpcMessage>,
    ) -> crate::error::CapsuleResult<crate::capsule::InterceptResult> {
        if let Some(message) = caller {
            let device = message.device_stamp();
            if device.fingerprint.is_some() || device.registration.is_some() {
                let access = self.resolver.get().and_then(|resolver| {
                    resolver.resolve_access(message.principal.as_deref(), device)
                });
                if !access.is_some_and(|access| {
                    !crate::access::is_user_invocable_surface(message.topic.as_str())
                        || access.is_capsule_allowed(capsule.id())
                }) {
                    return Ok(crate::capsule::InterceptResult::Deny {
                        reason: "device authority unavailable at invocation".into(),
                    });
                }
            }
        }
        capsule.invoke_interceptor(action, payload, caller).await
    }

    fn stop(&self) {
        // Retire before taking the admission lock: publishers may hold a
        // commit guard, so stop must never invert their future lock order.
        // A consumer already inside the map lock observes retirement before
        // enqueue, or starts and immediately drains on the retired gate.
        self.stopping.retire();
        self.entries.lock().clear();
    }
}

/// Close dispatcher admission and wake idle consumers without abandoning
/// active invocations or already-committed deliveries. Capsule unload still
/// waits for those users to release their generation references.
#[derive(Clone)]
pub struct DispatcherControl(Arc<ConsumerQueues>);

impl DispatcherControl {
    pub(super) fn new(queues: Arc<ConsumerQueues>) -> Self {
        Self(queues)
    }

    /// Permanently stop dispatch admission and begin ordered consumer drain.
    pub fn stop(&self) {
        self.0.stop();
    }
}
