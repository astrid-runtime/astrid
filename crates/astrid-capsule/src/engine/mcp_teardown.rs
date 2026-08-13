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
    completed: Notify,
}

/// Durable, shared ownership of one MCP server's teardown.
///
/// The cleanup task owns this state, rather than borrowing the capsule engine,
/// so a timed-out unload or a lingering `Arc<Capsule>` cannot orphan the child.
#[derive(Clone)]
pub(super) struct McpTeardown {
    state: Arc<TeardownState>,
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
                completed: Notify::new(),
            }),
        }
    }

    pub(super) fn register(&self, server_id: String) -> bool {
        let mut owned_id = self
            .state
            .server_id
            .lock()
            .expect("MCP server id lock poisoned");
        if self.state.started.load(Ordering::Acquire) {
            return false;
        }
        *owned_id = Some(server_id);
        true
    }

    pub(super) fn server_id(&self) -> Option<String> {
        self.state
            .server_id
            .lock()
            .expect("MCP server id lock poisoned")
            .clone()
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
            let Some(server_id) = state
                .server_id
                .lock()
                .expect("MCP server id lock poisoned")
                .clone()
            else {
                finish(&state, None);
                return;
            };

            let mut retry_delay = Duration::from_millis(25);
            loop {
                match state.ops.disconnect(&server_id).await {
                    Ok(()) => break,
                    Err(_error) if !state.ops.is_running(&server_id).await => break,
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
            finish(&state, Some(&server_id));
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

    #[tokio::test]
    async fn cancellation_retries_to_absence_and_remains_awaitable_after_owner_drop() {
        let ops = Arc::new(FailingOnceDisconnect {
            attempts: AtomicUsize::new(0),
            first_attempt: Notify::new(),
            release_first: Notify::new(),
            running: AtomicBool::new(true),
        });
        let teardown = McpTeardown::with_ops(ops.clone());
        assert!(teardown.register("capsule:test".to_string()));
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
}
