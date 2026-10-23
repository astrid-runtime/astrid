//! Ordered retirement of producers before durable store finalization.

use super::Kernel;
use std::sync::Arc;

enum ShutdownMode {
    Close,
    #[cfg(not(target_family = "wasm"))]
    Transfer,
}

enum ShutdownOutcome {
    Complete,
    #[cfg(not(target_family = "wasm"))]
    Retirement(astrid_storage::principal_state::RuntimeRetirement),
}

impl Kernel {
    /// Gracefully shut down the kernel.
    ///
    /// Stop lifecycle admission and join admitted operations before draining
    /// capsule producers. Publish the final projection and close durable stores
    /// after producers stop, then remove the Unix socket file.
    pub async fn shutdown(&self, reason: Option<String>) {
        if let Err(error) = self.shutdown_inner(reason, ShutdownMode::Close).await {
            tracing::error!(%error, "kernel shutdown did not finish durable ownership");
        }
    }

    /// Stop runtime producers and close their handles, retaining a distinct
    /// durable owner for packing after the host joins its task runtime.
    ///
    /// # Errors
    /// Returns publication, handoff, or close failures without claiming that
    /// the surviving projection was successfully retired.
    #[cfg(not(target_family = "wasm"))]
    pub async fn shutdown_for_finalization(
        &self,
        reason: Option<String>,
    ) -> astrid_storage::StorageResult<Option<astrid_storage::principal_state::RuntimeRetirement>>
    {
        match self.shutdown_inner(reason, ShutdownMode::Transfer).await? {
            ShutdownOutcome::Complete => Ok(None),
            ShutdownOutcome::Retirement(owner) => Ok(Some(owner)),
        }
    }

    async fn shutdown_inner(
        &self,
        reason: Option<String>,
        mode: ShutdownMode,
    ) -> astrid_storage::StorageResult<ShutdownOutcome> {
        tracing::info!(reason = ?reason, "Kernel shutting down");
        self.shutdown_tx.send_replace(true);
        self.runtime_work.close().await;
        tracing::info!("Kernel lifecycle work quiesced");

        // 1. Notify all subscribers so capsules can react.
        let _ = self
            .event_bus
            .publish(astrid_events::AstridEvent::KernelShutdown {
                metadata: astrid_events::EventMetadata::new("kernel"),
                reason: reason.clone(),
            });

        // Clear every principal's session-only state in one sweep. Belt-
        // and-suspenders for a process that is exiting anyway, but load-
        // bearing the moment session allowances are ever persisted
        // (Layer 7) — without this call a persisted-allowance layer would
        // inherit stale per-session grants from the previous process.
        self.allowance_store.clear_all_session_allowances();
        if let Err(e) = self.capabilities.clear_session() {
            tracing::warn!(error = %e, "failed to clear capability session on shutdown");
        }

        // Drain the registry so the dispatcher cannot hand out new Arc clones,
        // then unload each capsule CONCURRENTLY. MCP engine unload is critical —
        // it calls `mcp_client.disconnect()` to gracefully terminate child
        // processes; without explicit unload they orphan. `drain()` returns one
        // Arc per DISTINCT runtime (views are cleared first), so no two unload
        // tasks contend on the same runtime's `Arc::get_mut`. Concurrency bounds
        // retry delay to one shared budget instead of N sequential budgets.
        // The process watchdog remains the hard bound for stuck unload work.
        //
        // The `EventDispatcher` temporarily clones `Arc<dyn Capsule>` into
        // spawned interceptor tasks. After draining, no new clones can be
        // created, but in-flight tasks may still hold one; each unload task
        // `request_cancel`s to unblock them, then retries `Arc::get_mut` with
        // brief yields.
        self.drain_shutdown_capsules().await;

        // No admitted load/admin work or capsule producer may write after
        // the final audit flush and projection publication.
        #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
        self.audit_sink.shutdown();
        let mut outcome = Ok(ShutdownOutcome::Complete);
        #[cfg(not(target_family = "wasm"))]
        if let Some(store) = self.principal_store.as_ref() {
            outcome = store
                .publish_runtime_projection(&self.astrid_home)
                .map(|()| ShutdownOutcome::Complete);
            if outcome.is_ok() && matches!(mode, ShutdownMode::Transfer) {
                outcome = store
                    .handoff_for_retirement(&self.astrid_home)
                    .map(ShutdownOutcome::Retirement);
            }
        }
        #[cfg(target_family = "wasm")]
        let _ = mode;
        // A successful transfer has already closed the old engine. Closing
        // this old KV view also releases its read cache; no new owner is closed.
        if let Err(error) = self.kv.close().await {
            tracing::warn!(%error, "Failed to close KV store during shutdown");
            record_close_error(&mut outcome, error);
        }
        if let Err(error) = self.audit_log.close().await {
            tracing::warn!(%error, "Failed to close audit log during shutdown");
            record_close_error(
                &mut outcome,
                astrid_storage::StorageError::Internal(format!(
                    "close shutdown audit log: {error}"
                )),
            );
        }

        tracing::info!("Kernel durable stores closed");

        // Remove the socket and token files so stale-socket detection works
        // on next boot and the auth token doesn't persist on disk after shutdown.
        // This runs AFTER the capsule drain, which is the correct order: MCP
        // child processes communicate via stdio pipes (not this Unix socket), so
        // they have already been drained. The socket is only used for
        // CLI-to-kernel IPC. Unix-only: the `socket` module (and the on-disk
        // socket/PID/readiness files it manages) exist only on that profile.
        #[cfg(unix)]
        {
            let socket_path = crate::socket::kernel_socket_path();
            let _ = astrid_core::local_transport::remove_endpoint(&socket_path);
            let _ = std::fs::remove_file(&self.token_path);
            crate::socket::remove_readiness_file();
            crate::socket::remove_pid_file();
        }

        tracing::info!("Kernel shutdown complete");
        outcome
    }
    async fn drain_shutdown_capsules(&self) {
        let capsules = {
            let mut reg = self.capsules.write().await;
            reg.drain()
        };
        for capsule in &capsules {
            capsule.retire();
            capsule.request_cancel();
        }
        if let Some(dispatcher) = self.dispatcher_control.get() {
            dispatcher.stop();
        }
        let mut drain_set = tokio::task::JoinSet::new();
        for mut arc in capsules {
            drain_set.spawn(async move {
                let id = arc.id().clone();

                let mut retries = 0_u32;
                loop {
                    if let Some(capsule) = Arc::get_mut(&mut arc) {
                        if let Err(e) = capsule.unload().await {
                            tracing::warn!(
                                capsule_id = %id,
                                error = %e,
                                "Failed to unload capsule during shutdown"
                            );
                        }
                        break;
                    }
                    retries = retries.saturating_add(1);
                    if retries == 20 {
                        tracing::warn!(
                            capsule_id = %id,
                            strong_count = Arc::strong_count(&arc),
                            "Waiting for cancelled capsule users before closing durable stores"
                        );
                    }
                    astrid_runtime::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            });
        }
        // Await every unload task. A task that panicked or was cancelled would
        // otherwise be swallowed silently, leaving its capsule un-unloaded (and
        // its MCP subprocess possibly orphaned) with no diagnostic — so log the
        // join failure. A stuck unload retains stores until its users stop;
        // the OS-thread watchdog is the hard backstop.
        while let Some(res) = drain_set.join_next().await {
            if let Err(err) = res {
                if err.is_panic() {
                    tracing::error!("A capsule unload task panicked during shutdown");
                } else {
                    tracing::error!(error = %err, "A capsule unload task failed to join during shutdown");
                }
            }
        }
    }
}

// A transferred owner is custody, not a success flag that an ancillary close
// error may replace. Report the error only after that owner has packed/closed.
fn record_close_error(
    outcome: &mut astrid_storage::StorageResult<ShutdownOutcome>,
    error: astrid_storage::StorageError,
) {
    match outcome {
        Ok(ShutdownOutcome::Complete) => *outcome = Err(error),
        #[cfg(not(target_family = "wasm"))]
        Ok(ShutdownOutcome::Retirement(owner)) => owner.record_shutdown_error(error),
        Err(_) => {},
    }
}

#[cfg(all(test, not(target_family = "wasm")))]
mod tests;
