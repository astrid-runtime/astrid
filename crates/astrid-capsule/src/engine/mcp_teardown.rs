use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::Notify;
use tracing::warn;

use astrid_mcp::SecureMcpClient;

#[async_trait]
trait DisconnectOps: Send + Sync {
    async fn disconnect(&self, server_id: &str) -> Result<(), String>;
    async fn is_running(&self, server_id: &str) -> bool;
}

#[async_trait]
impl DisconnectOps for SecureMcpClient {
    async fn disconnect(&self, server_id: &str) -> Result<(), String> {
        SecureMcpClient::disconnect(self, server_id)
            .await
            .map_err(|error| error.to_string())
    }

    async fn is_running(&self, server_id: &str) -> bool {
        self.inner().is_server_running(server_id).await
    }
}

struct TeardownState {
    ops: Arc<dyn DisconnectOps>,
    server_id: Mutex<Option<String>>,
    started: AtomicBool,
    done: AtomicBool,
    /// True while activation still holds the registration returned by
    /// [`McpTeardown::register`]. Cleanup may already be elected, but it must
    /// not treat the name as absent until this is cleared. Clearing it does
    /// not elect cleanup.
    activation_held: AtomicBool,
    completed: Notify,
    activation_released: Notify,
    #[cfg(test)]
    activation_parked: AtomicBool,
}

/// Durable, shared ownership of one MCP server's teardown.
///
/// The cleanup task owns this state, rather than borrowing the capsule engine,
/// so a timed-out unload or a lingering `Arc<Capsule>` cannot orphan the child.
#[derive(Clone)]
pub(super) struct McpTeardown {
    state: Arc<TeardownState>,
}

/// Holds one registered server name until that activation attempt settles.
///
/// Dropping the guard, or calling [`ActivationGuard::settle`], releases cleanup
/// that is already waiting. Neither starts teardown. The holder has to release
/// the guard before waiting for cleanup, or that wait cannot finish.
#[must_use]
pub(super) struct ActivationGuard {
    state: Arc<TeardownState>,
    active: bool,
}

impl ActivationGuard {
    pub(super) fn settle(&mut self) {
        if !self.active {
            return;
        }
        self.active = false;
        self.state.activation_held.store(false, Ordering::Release);
        self.state.activation_released.notify_waiters();
    }
}

impl Drop for ActivationGuard {
    fn drop(&mut self) {
        self.settle();
    }
}

impl McpTeardown {
    pub(super) fn new(client: SecureMcpClient) -> Self {
        Self::with_ops(Arc::new(client))
    }

    fn with_ops(ops: Arc<dyn DisconnectOps>) -> Self {
        Self {
            state: Arc::new(TeardownState {
                ops,
                server_id: Mutex::new(None),
                started: AtomicBool::new(false),
                done: AtomicBool::new(false),
                activation_held: AtomicBool::new(false),
                completed: Notify::new(),
                activation_released: Notify::new(),
                #[cfg(test)]
                activation_parked: AtomicBool::new(false),
            }),
        }
    }

    /// Records `server_id` and holds cleanup until the returned guard settles.
    ///
    /// Returns `None` when retirement has already been elected, or when another
    /// activation guard is still outstanding. A later registration must not
    /// release the hold that the first guard still owns.
    #[must_use]
    pub(super) fn register(&self, server_id: String) -> Option<ActivationGuard> {
        let mut owned_id = self
            .state
            .server_id
            .lock()
            .expect("MCP server id lock poisoned");
        if self.state.started.load(Ordering::Acquire)
            || self.state.activation_held.load(Ordering::Acquire)
        {
            return None;
        }
        *owned_id = Some(server_id);
        self.state.activation_held.store(true, Ordering::Release);
        Some(ActivationGuard {
            state: Arc::clone(&self.state),
            active: true,
        })
    }

    pub(super) fn server_id(&self) -> Option<String> {
        self.state
            .server_id
            .lock()
            .expect("MCP server id lock poisoned")
            .clone()
    }

    pub(super) fn retirement_started(&self) -> bool {
        self.state.started.load(Ordering::Acquire)
    }

    #[cfg(test)]
    fn activation_is_parked(&self) -> bool {
        self.state.activation_parked.load(Ordering::Acquire)
    }

    pub(super) fn start(&self) {
        if self
            .state
            .started
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }

        let state = Arc::clone(&self.state);
        astrid_runtime::spawn(async move {
            retire_registered_server(state).await;
        });
    }

    pub(super) async fn wait(&self) {
        self.start();
        loop {
            let completed = self.state.completed.notified();
            if self.state.done.load(Ordering::Acquire) {
                return;
            }
            completed.await;
        }
    }
}

async fn retire_registered_server(state: Arc<TeardownState>) {
    wait_for_activation_guard(&state).await;
    // Drop the registration lock before `finish`. A `let`-`else` would keep the
    // guard alive into that branch, and `finish` locks the same mutex.
    let server_id = state
        .server_id
        .lock()
        .expect("MCP server id lock poisoned")
        .clone();
    let Some(server_id) = server_id else {
        finish(&state, None);
        return;
    };
    disconnect_until_absent(&state, &server_id).await;
    finish(&state, Some(&server_id));
}

/// Parks until the activation attempt that owns `state` has settled.
///
/// The registration mutex is held only for the flag check. Subscribing to the
/// release notification first closes the gap where the guard settles between
/// the check and the wait.
async fn wait_for_activation_guard(state: &TeardownState) {
    loop {
        let released = state.activation_released.notified();
        let held = {
            let registration = state.server_id.lock().expect("MCP server id lock poisoned");
            let held = state.activation_held.load(Ordering::Acquire);
            drop(registration);
            held
        };
        if !held {
            return;
        }
        #[cfg(test)]
        state.activation_parked.store(true, Ordering::Release);
        released.await;
        #[cfg(test)]
        state.activation_parked.store(false, Ordering::Release);
    }
}

async fn disconnect_until_absent(state: &TeardownState, server_id: &str) {
    let mut retry_delay = Duration::from_millis(25);
    loop {
        match state.ops.disconnect(server_id).await {
            Ok(()) => break,
            Err(_error) if !state.ops.is_running(server_id).await => break,
            Err(error) => {
                warn!(
                    server = %server_id,
                    %error,
                    "MCP teardown failed while server is still present; retrying"
                );
                tokio::time::sleep(retry_delay).await;
                retry_delay = retry_delay
                    .checked_mul(2)
                    .unwrap_or(Duration::from_secs(1))
                    .min(Duration::from_secs(1));
            },
        }
    }
}

fn finish(state: &TeardownState, server_id: Option<&str>) {
    let mut owned_id = state.server_id.lock().expect("MCP server id lock poisoned");
    if server_id.is_none() || owned_id.as_deref() == server_id {
        *owned_id = None;
    }
    drop(owned_id);
    state.done.store(true, Ordering::Release);
    state.completed.notify_waiters();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    struct FailingOnceDisconnect {
        attempts: AtomicUsize,
        first_attempt: Notify,
        release_first: Notify,
        running: AtomicBool,
    }

    #[async_trait]
    impl DisconnectOps for FailingOnceDisconnect {
        async fn disconnect(&self, _server_id: &str) -> Result<(), String> {
            if self.attempts.fetch_add(1, Ordering::AcqRel) == 0 {
                self.first_attempt.notify_one();
                self.release_first.notified().await;
                Err("injected transient failure".to_string())
            } else {
                self.running.store(false, Ordering::Release);
                Ok(())
            }
        }

        async fn is_running(&self, _server_id: &str) -> bool {
            self.running.load(Ordering::Acquire)
        }
    }

    struct AbsentDisconnect {
        disconnects: AtomicUsize,
        running: AtomicBool,
    }

    #[async_trait]
    impl DisconnectOps for AbsentDisconnect {
        async fn disconnect(&self, server_id: &str) -> Result<(), String> {
            assert_eq!(server_id, "capsule:held");
            self.disconnects.fetch_add(1, Ordering::AcqRel);
            self.running.store(false, Ordering::Release);
            Err("registration is not in the manager".to_string())
        }

        async fn is_running(&self, server_id: &str) -> bool {
            assert_eq!(server_id, "capsule:held");
            self.running.load(Ordering::Acquire)
        }
    }

    #[tokio::test]
    async fn cancellation_retries_to_absence_and_remains_awaitable_after_owner_drop() {
        let ops = Arc::new(FailingOnceDisconnect {
            attempts: AtomicUsize::new(0),
            first_attempt: Notify::new(),
            release_first: Notify::new(),
            running: AtomicBool::new(true),
        });
        let teardown = McpTeardown::with_ops(ops.clone());
        drop(
            teardown
                .register("capsule:test".to_string())
                .expect("registration precedes cancellation"),
        );
        let waiter = teardown.clone();
        teardown.start();

        ops.first_attempt.notified().await;
        drop(teardown);
        ops.release_first.notify_one();

        tokio::time::timeout(Duration::from_secs(1), waiter.wait())
            .await
            .expect("durable cleanup should complete");
        assert_eq!(ops.attempts.load(Ordering::Acquire), 2);
        assert!(!ops.running.load(Ordering::Acquire));
        assert_eq!(waiter.server_id(), None);
    }

    #[tokio::test]
    async fn retirement_before_register_keeps_the_late_name_unconnected() {
        let ops = Arc::new(AbsentDisconnect {
            disconnects: AtomicUsize::new(0),
            running: AtomicBool::new(false),
        });
        let teardown = McpTeardown::with_ops(ops.clone());
        teardown.start();
        assert!(teardown.register("capsule:held".to_string()).is_none());
        teardown.wait().await;
        assert_eq!(ops.disconnects.load(Ordering::Acquire), 0);
        assert_eq!(teardown.server_id(), None);
    }

    #[tokio::test]
    async fn dropping_the_activation_guard_does_not_start_cleanup() {
        let ops = Arc::new(AbsentDisconnect {
            disconnects: AtomicUsize::new(0),
            running: AtomicBool::new(false),
        });
        let teardown = McpTeardown::with_ops(ops.clone());
        drop(
            teardown
                .register("capsule:held".to_string())
                .expect("activation owns the registration"),
        );
        assert!(!teardown.retirement_started());
        assert_eq!(teardown.server_id().as_deref(), Some("capsule:held"));
        assert_eq!(ops.disconnects.load(Ordering::Acquire), 0);

        teardown.wait().await;
        assert_eq!(ops.disconnects.load(Ordering::Acquire), 1);
        assert_eq!(teardown.server_id(), None);
    }

    #[tokio::test]
    async fn cleanup_parks_while_activation_holds_an_absent_registration() {
        let ops = Arc::new(AbsentDisconnect {
            disconnects: AtomicUsize::new(0),
            running: AtomicBool::new(false),
        });
        let teardown = McpTeardown::with_ops(ops.clone());
        let guard = teardown
            .register("capsule:held".to_string())
            .expect("activation owns the registration");
        assert!(!teardown.retirement_started());
        let waiter = teardown.clone();
        teardown.start();
        assert!(teardown.retirement_started());

        while !teardown.activation_is_parked() {
            assert_eq!(
                ops.disconnects.load(Ordering::Acquire),
                0,
                "cleanup disconnected while activation still held the registration"
            );
            tokio::task::yield_now().await;
        }
        assert!(
            teardown.register("other-server".to_string()).is_none(),
            "a later registration must not replace or release the held name"
        );
        assert_eq!(teardown.server_id().as_deref(), Some("capsule:held"));
        assert_eq!(ops.disconnects.load(Ordering::Acquire), 0);

        drop(guard);
        waiter.wait().await;
        assert_eq!(ops.disconnects.load(Ordering::Acquire), 1);
        assert!(!ops.running.load(Ordering::Acquire));
        assert_eq!(waiter.server_id(), None);
        waiter.wait().await;
        assert_eq!(ops.disconnects.load(Ordering::Acquire), 1);
    }
}
