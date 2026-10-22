//! Owned queue admission and shutdown for dispatcher consumers.

use super::*;
use astrid_events::RouteAdmissionGate;

type QueueMap = HashMap<(RuntimeId, PrincipalKey), mpsc::Sender<InterceptorWork>>;

#[derive(Default)]
pub(super) struct ConsumerQueues {
    entries: parking_lot::Mutex<QueueMap>,
    stopping: RouteAdmissionGate,
}

impl ConsumerQueues {
    pub(super) fn lock(&self) -> parking_lot::MutexGuard<'_, QueueMap> {
        self.entries.lock()
    }

    pub(super) fn stopping(&self) -> &RouteAdmissionGate {
        &self.stopping
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
