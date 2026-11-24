//! Counts admitted operations until retirement can reclaim principal state.

use std::sync::Arc;

mod state;
use state::PrincipalInvocation;

#[derive(Default)]
pub(in crate::engine) struct PrincipalInvocationTracker {
    state:
        std::sync::Mutex<std::collections::HashMap<astrid_core::PrincipalId, PrincipalInvocation>>,
    changed: tokio::sync::Notify,
}

pub(crate) struct PrincipalInvocationGuard {
    tracker: Arc<PrincipalInvocationTracker>,
    principal: astrid_core::PrincipalId,
}

#[cfg(test)]
pub(crate) struct QuiescenceObservationHook {
    pub(crate) observed: tokio::sync::oneshot::Sender<()>,
    pub(crate) resume: tokio::sync::oneshot::Receiver<()>,
}

impl PrincipalInvocationTracker {
    pub(super) fn begin(
        self: &Arc<Self>,
        principal: &astrid_core::PrincipalId,
    ) -> Option<PrincipalInvocationGuard> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !state
            .entry(principal.clone())
            .or_insert_with(PrincipalInvocation::new)
            .begin()
        {
            return None;
        }
        Some(PrincipalInvocationGuard {
            tracker: Arc::clone(self),
            principal: principal.clone(),
        })
    }

    pub(super) fn retire(&self, principal: &astrid_core::PrincipalId) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(principal.clone())
            .or_insert_with(PrincipalInvocation::new)
            .retire();
    }

    pub(super) fn resume(&self, principal: &astrid_core::PrincipalId) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(entry) = state.get_mut(principal) {
            entry.resume();
            if entry.discardable() {
                state.remove(principal);
            }
        }
    }

    pub(super) fn active(&self, principal: &astrid_core::PrincipalId) -> usize {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(principal)
            .map_or(0, PrincipalInvocation::active)
    }

    pub(super) async fn wait_for_quiescence(&self, principal: &astrid_core::PrincipalId) {
        self.wait_for_quiescence_inner(
            principal,
            #[cfg(test)]
            None,
        )
        .await;
    }

    async fn wait_for_quiescence_inner(
        &self,
        principal: &astrid_core::PrincipalId,
        #[cfg(test)] mut observation_hook: Option<QuiescenceObservationHook>,
    ) {
        loop {
            let notified = self.changed.notified();
            tokio::pin!(notified);
            // notify_waiters does not retain a permit for a future that has
            // not registered yet. Register before sampling active, otherwise
            // the final guard can drop between the sample and first poll and
            // leave retirement asleep after the principal is already drained.
            notified.as_mut().enable();
            let active = self.active(principal);
            #[cfg(test)]
            if let Some(hook) = observation_hook.take() {
                let _ = hook.observed.send(());
                let _ = hook.resume.await;
            }
            if active == 0 {
                return;
            }
            notified.await;
        }
    }

    #[cfg(test)]
    pub(crate) async fn wait_for_quiescence_with_observation_hook(
        &self,
        principal: &astrid_core::PrincipalId,
        hook: QuiescenceObservationHook,
    ) {
        self.wait_for_quiescence_inner(principal, Some(hook)).await;
    }
}

impl PrincipalInvocationGuard {
    pub(super) fn belongs_to(
        &self,
        tracker: &Arc<PrincipalInvocationTracker>,
        principal: &astrid_core::PrincipalId,
    ) -> bool {
        Arc::ptr_eq(&self.tracker, tracker) && &self.principal == principal
    }
}

impl Drop for PrincipalInvocationGuard {
    fn drop(&mut self) {
        let mut state = self
            .tracker
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(entry) = state.get_mut(&self.principal) {
            entry.finish();
            if entry.discardable() {
                state.remove(&self.principal);
            }
        }
        drop(state);
        self.tracker.changed.notify_waiters();
    }
}
