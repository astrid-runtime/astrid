//! Close admission, then join already admitted kernel lifecycle work.

use std::sync::{Mutex, MutexGuard};
use tokio::sync::Notify;

#[derive(Default)]
struct State {
    closing: bool,
    active: usize,
}

#[derive(Default)]
pub(crate) struct RuntimeWork {
    state: Mutex<State>,
    drained: Notify,
}

pub(crate) struct WorkPermit<'a>(&'a RuntimeWork);

impl RuntimeWork {
    fn state(&self) -> MutexGuard<'_, State> {
        // Only scalar updates occur while held. A panic cannot leave a partial
        // external publication; admission still observes the closing fence.
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(crate) fn admit(&self) -> Option<WorkPermit<'_>> {
        let mut state = self.state();
        if state.closing {
            return None;
        }
        state.active = state.active.strict_add(1);
        Some(WorkPermit(self))
    }

    pub(crate) async fn close(&self) {
        self.state().closing = true;
        loop {
            // Register before testing the count so the last drop cannot be lost.
            let notified = self.drained.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.state().active == 0 {
                return;
            }
            notified.await;
        }
    }
}

impl Drop for WorkPermit<'_> {
    fn drop(&mut self) {
        let mut state = self.0.state();
        state.active = state.active.strict_sub(1);
        if state.active == 0 {
            self.0.drained.notify_waiters();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RuntimeWork;

    #[tokio::test]
    async fn close_waits_for_work_and_rejects_new_and_nested_admission() {
        let work = RuntimeWork::default();
        let first = work.admit().unwrap();
        let nested = work.admit().unwrap();
        let mut close = Box::pin(work.close());
        assert!(
            std::future::Future::poll(
                close.as_mut(),
                &mut std::task::Context::from_waker(std::task::Waker::noop())
            )
            .is_pending()
        );
        assert!(work.admit().is_none());
        drop(nested);
        assert!(
            std::future::Future::poll(
                close.as_mut(),
                &mut std::task::Context::from_waker(std::task::Waker::noop())
            )
            .is_pending()
        );
        drop(first);
        close.await;
        assert!(work.admit().is_none());
        work.close().await;
    }
}
