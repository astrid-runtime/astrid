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
    principal: Option<astrid_core::PrincipalId>,
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
        let principal = state::acquire(&mut state, principal)?;
        Some(PrincipalInvocationGuard {
            tracker: Arc::clone(self),
            principal: Some(principal),
        })
    }

    pub(super) fn retire(&self, principal: &astrid_core::PrincipalId) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state::retire_locked(&mut state, principal.clone());
    }

    pub(super) fn resume(&self, principal: &astrid_core::PrincipalId) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state::drain_locked(&mut state, principal.clone(), state::DrainAction::Resume);
    }

    pub(super) fn active(&self, principal: &astrid_core::PrincipalId) -> usize {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state::active_locked(&state, principal)
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
        state::covers(
            &self.tracker,
            self.principal.as_ref(),
            tracker,
            principal,
            Arc::ptr_eq,
        )
    }
}

impl Drop for PrincipalInvocationGuard {
    fn drop(&mut self) {
        let Some(principal) = self.principal.take() else {
            return;
        };
        let mut state = self
            .tracker
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state::drain_locked(&mut state, principal, state::DrainAction::Finish);
        drop(state);
        self.tracker.changed.notify_waiters();
    }
}
