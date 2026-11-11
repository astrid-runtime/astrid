//! Ordered retirement of producers before durable store finalization.

use super::Kernel;
use std::sync::Arc;

#[cfg(not(target_family = "wasm"))]
use astrid_storage::principal_state::{PendingRuntimeFinalization, RuntimeFinalization};

#[derive(Clone, Copy)]
enum StoreShutdown {
    Close,
    #[cfg(not(target_family = "wasm"))]
    RetainForFinalization,
    #[cfg(not(target_family = "wasm"))]
    RetainPending,
}

#[cfg(not(target_family = "wasm"))]
enum ShutdownCustody {
    None,
    Immediate(RuntimeFinalization),
    Pending(PendingRuntimeFinalization),
}

#[cfg(target_family = "wasm")]
enum ShutdownCustody {
    None,
}

impl Kernel {
    /// Gracefully shut down the kernel.
    ///
    /// Stop lifecycle admission and join admitted operations before draining
    /// capsule producers. Publish the final projection and close durable stores
    /// after producers stop, then remove the Unix socket file.
    pub async fn shutdown(&self, reason: Option<String>) {
        let _ = self.shutdown_ordered(reason, StoreShutdown::Close).await;
    }

    /// Stop producers and immediately hand off the open store for finalization.
    ///
    /// Prefer [`Self::shutdown_retain_pending`] for daemon retained shutdown so
    /// handoff runs after the original task runtime drops and joins blocking
    /// work. Ordinary callers should use [`Self::shutdown`] to close storage.
    ///
    /// # Errors
    /// Returns a storage error when native storage is unavailable or exclusive
    /// handoff fails. Ancillary close errors stay with the returned token and
    /// are reported after final packing. Producer-drain failures retain their
    /// existing log and audit-health reporting.
    /// Projection validation and publication are deferred to the finalizer.
    #[cfg(not(target_family = "wasm"))]
    pub async fn shutdown_for_finalization(
        &self,
        reason: Option<String>,
    ) -> astrid_storage::StorageResult<RuntimeFinalization> {
        match self
            .shutdown_ordered(reason, StoreShutdown::RetainForFinalization)
            .await?
        {
            ShutdownCustody::Immediate(finalization) => Ok(finalization),
            ShutdownCustody::Pending(_) | ShutdownCustody::None => {
                Err(astrid_storage::StorageError::Internal(
                    "kernel has no native principal store".into(),
                ))
            },
        }
    }

    /// Stop producers while retaining open-store custody for deferred handoff.
    ///
    /// Does not hand off or close the authoritative engine. The host must drop
    /// the original task runtime (joining `spawn_blocking` work), then call
    /// [`PendingRuntimeFinalization::handoff_for_finalization`] before packing.
    ///
    /// # Errors
    /// Returns a storage error when native storage is unavailable or retention
    /// validation fails. Producer-drain failures retain their existing log and
    /// audit-health reporting.
    #[cfg(not(target_family = "wasm"))]
    pub async fn shutdown_retain_pending(
        &self,
        reason: Option<String>,
    ) -> astrid_storage::StorageResult<PendingRuntimeFinalization> {
        match self
            .shutdown_ordered(reason, StoreShutdown::RetainPending)
            .await?
        {
            ShutdownCustody::Pending(pending) => Ok(pending),
            ShutdownCustody::Immediate(_) | ShutdownCustody::None => {
                Err(astrid_storage::StorageError::Internal(
                    "kernel has no native principal store".into(),
                ))
            },
        }
    }

    async fn shutdown_ordered(
        &self,
        reason: Option<String>,
        mode: StoreShutdown,
    ) -> astrid_storage::StorageResult<ShutdownCustody> {
        self.drain_shutdown_producers(reason).await;
        let custody = self.finish_shutdown_storage(mode).await;
        self.remove_shutdown_endpoints();
        tracing::info!("Kernel shutdown complete");
        custody
    }

    async fn drain_shutdown_producers(&self, reason: Option<String>) {
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
        // closing its audit projection. Retained mode publishes the final host
        // projection only after the host task runtime has stopped.
        #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
        self.audit_sink.shutdown();
    }

    fn remove_shutdown_endpoints(&self) {
        // Remove the socket and token files so stale-socket detection works
        // on next boot and the auth token doesn't persist on disk after shutdown.
        // This runs AFTER the capsule drain, which is the correct order: MCP
        // child processes communicate via stdio pipes (not this Unix socket), so
        // they have already been drained. The socket is only used for
        // CLI-to-kernel IPC. Unix-only: the `socket` module (and the on-disk
        // socket/PID/readiness files it manages) exist only on that profile.
        #[cfg(unix)]
        {
            use astrid_core::dirs::AstridHome;

            // The token captures the admitted runtime directory at boot. Never
            // resolve process-wide environment paths again during teardown: an
            // embedded kernel or changed override may refer to another runtime.
            let socket_path = self.token_path.with_file_name(AstridHome::SOCKET_FILE_NAME);
            let _ = astrid_core::local_transport::remove_endpoint(&socket_path);
            let _ = std::fs::remove_file(&self.token_path);
            let _ =
                std::fs::remove_file(self.token_path.with_file_name(AstridHome::READY_FILE_NAME));
            let _ = std::fs::remove_file(self.token_path.with_file_name(AstridHome::PID_FILE_NAME));
        }
    }

    async fn finish_shutdown_storage(
        &self,
        mode: StoreShutdown,
    ) -> astrid_storage::StorageResult<ShutdownCustody> {
        let mut custody = Ok(ShutdownCustody::None);
        #[cfg(not(target_family = "wasm"))]
        if let Some(store) = self.principal_store.as_ref() {
            custody = match mode {
                StoreShutdown::Close => store
                    .publish_runtime_projection(&self.astrid_home)
                    .map(|()| ShutdownCustody::None),
                StoreShutdown::RetainForFinalization => store
                    .handoff_for_finalization(&self.astrid_home)
                    .map(ShutdownCustody::Immediate),
                StoreShutdown::RetainPending => store
                    .retain_for_finalization(&self.astrid_home)
                    .map(ShutdownCustody::Pending),
            };
            if let Err(error) = &custody {
                tracing::error!(%error, "failed to finalize runtime storage during shutdown");
            }
        }

        // Pending custody must keep the authoritative engine open across the
        // original runtime drop so in-flight spawn_blocking commits can finish.
        // Always run the close helper: it alone decides whether to poll KV close.
        // Independent audit backends must still flush/close under RetainPending;
        // NativeAuditSystemNamespace::close remains a no-op on the shared engine.
        close_shutdown_projections(mode, &mut custody, self.kv.close(), self.audit_log.close())
            .await;
        tracing::info!("Kernel durable stores quiesced");
        custody
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

// A transferred or pending owner is custody. An ancillary close error must not
// discard it before late host writes can be packed after the runtime joins.
/// Apply durable-projection closes after custody is established.
///
/// Invoked unconditionally from [`Kernel::finish_shutdown_storage`]. Under
/// native pending mode the KV close future must not be polled so
/// the authoritative engine stays open across the original runtime drop.
/// Audit close always runs so ancillary flush/close errors remain observable.
async fn close_shutdown_projections(
    mode: StoreShutdown,
    custody: &mut astrid_storage::StorageResult<ShutdownCustody>,
    kv_close: impl std::future::Future<Output = astrid_storage::StorageResult<()>>,
    audit_close: impl std::future::Future<Output = astrid_audit::AuditResult<()>>,
) {
    #[cfg(not(target_family = "wasm"))]
    let close_kv = !matches!(mode, StoreShutdown::RetainPending);
    #[cfg(target_family = "wasm")]
    let close_kv = {
        let _ = mode;
        true
    };

    if close_kv {
        // A successful immediate handoff leaves the old engine permanently
        // closed. Closing this projection releases its read cache without
        // unlocking or closing the distinct finalization owner.
        if let Err(error) = kv_close.await {
            tracing::warn!(%error, "Failed to flush KV store during shutdown");
            record_close_error(custody, error);
        }
    } else {
        // Constructed at the call site only; never poll while pending custody
        // still owns the authoritative engine.
        drop(kv_close);
    }

    if let Err(error) = audit_close.await {
        tracing::warn!(%error, "Failed to close audit log during shutdown");
        record_close_error(
            custody,
            astrid_storage::StorageError::Internal(format!(
                "close audit log during shutdown: {error}"
            )),
        );
    }
}

fn record_close_error(
    outcome: &mut astrid_storage::StorageResult<ShutdownCustody>,
    error: astrid_storage::StorageError,
) {
    match outcome {
        #[cfg(not(target_family = "wasm"))]
        Ok(ShutdownCustody::Immediate(owner)) => owner.record_shutdown_error(error),
        #[cfg(not(target_family = "wasm"))]
        Ok(ShutdownCustody::Pending(owner)) => owner.record_shutdown_error(error),
        Ok(ShutdownCustody::None) => *outcome = Err(error),
        Err(previous) => {
            *previous = astrid_storage::StorageError::Internal(format!(
                "{previous}; additionally: {error}"
            ));
        },
    }
}

#[cfg(all(test, not(target_family = "wasm")))]
mod tests;
