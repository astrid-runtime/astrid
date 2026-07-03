//! Kernel-response publishing + the long-request keepalive pinger.
//!
//! Split out of `kernel_router/mod.rs` to keep that file under the 1000-line CI
//! threshold. Holds the canonical response envelope helpers and the RAII
//! [`KeepalivePinger`] that emits [`KernelResponse::Working`] frames while a slow
//! handler is in flight. The dispatcher in `mod.rs` re-exports these so every
//! existing call site is unchanged.

use std::sync::Arc;
use std::time::Duration;

use astrid_events::ipc::{IpcMessage, IpcPayload, Topic};
use astrid_events::kernel_api::KernelResponse;
use serde::Serialize;

pub(crate) fn publish_response<R: Serialize>(
    kernel: &Arc<crate::Kernel>,
    response_topic: Topic,
    res: R,
) {
    if let Ok(val) = serde_json::to_value(res) {
        publish_response_value(kernel, response_topic, val);
    }
}

/// Publish an already-serialized response body on `response_topic` using the
/// canonical kernel-response envelope (`RawJson` payload, kernel session id,
/// `"kernel_router"` metadata source).
///
/// Single-sourced so the periodic [`KernelResponse::Working`] keepalive lands
/// on the response topic with the **identical** envelope the uplink already
/// reads for the terminal response — the uplink can't tell a keepalive frame
/// apart from a real one by envelope shape, only by the inner variant.
pub(crate) fn publish_response_value(
    kernel: &Arc<crate::Kernel>,
    response_topic: Topic,
    val: serde_json::Value,
) {
    let msg = IpcMessage::new(
        response_topic,
        IpcPayload::RawJson(val),
        kernel.session_id.0,
    );
    let _ = kernel.event_bus.publish(astrid_events::AstridEvent::Ipc {
        metadata: astrid_events::EventMetadata::new("kernel_router"),
        message: msg,
    });
}

/// Interval between [`KernelResponse::Working`] keepalive frames the kernel
/// emits on a long-running request's response topic.
///
/// Chosen so a fast request finishes and drops the [`KeepalivePinger`] guard
/// *before* the first sleep elapses — a fast op emits **zero** keepalive frames
/// and adds no extra bus traffic (the guard still spawns + aborts a task, but no
/// frame is published). Only a genuinely slow handler (one running longer than
/// this interval) ever gets pinged. The uplink's inactivity timeout is set to a
/// small multiple of this (see `astrid-uplink`'s `DEFAULT_TIMEOUT`) so it
/// tolerates a couple of missed pings before giving up.
pub(crate) const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(5);

/// RAII guard around the background keepalive task for one in-flight request.
///
/// Mirrors `EpochTickerGuard` (`astrid-capsule`): while alive it publishes a
/// [`KernelResponse::Working`] frame on the request's response topic every
/// [`KEEPALIVE_INTERVAL`], resetting each waiting uplink's inactivity window so
/// a slow-but-live handler is never mistaken for a dead one. Dropping the guard
/// aborts the task. The dispatch drops it *after* the handler produces its
/// terminal result and *before* the terminal response is published, so the
/// terminal frame is not preceded by a redundant late ping. A `Working` that
/// still races out after the terminal is harmless — the uplink skips it.
pub(crate) struct KeepalivePinger {
    handle: astrid_runtime::JoinHandle<()>,
}

impl KeepalivePinger {
    /// Spawn the keepalive task for `response_topic`. The first `Working` frame
    /// is emitted only after the first [`KEEPALIVE_INTERVAL`] sleep, so a
    /// handler that completes sooner produces none.
    pub(crate) fn spawn(kernel: &Arc<crate::Kernel>, response_topic: Topic) -> Self {
        Self::spawn_with_interval(kernel, response_topic, KEEPALIVE_INTERVAL)
    }

    /// [`spawn`](Self::spawn) with an explicit interval. Production passes
    /// [`KEEPALIVE_INTERVAL`]; tests pass a short interval so the ping/stop
    /// behaviour is observable without a multi-second wait.
    fn spawn_with_interval(
        kernel: &Arc<crate::Kernel>,
        response_topic: Topic,
        interval: Duration,
    ) -> Self {
        let kernel = Arc::clone(kernel);
        let handle = astrid_runtime::spawn(async move {
            loop {
                astrid_runtime::time::sleep(interval).await;
                let Ok(val) = serde_json::to_value(KernelResponse::Working) else {
                    return;
                };
                publish_response_value(&kernel, response_topic.clone(), val);
            }
        });
        Self { handle }
    }
}

impl Drop for KeepalivePinger {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The keepalive pinger publishes `KernelResponse::Working` frames on the
    /// response topic while a slow handler is in flight, and STOPS the moment its
    /// RAII guard drops. Drives `KeepalivePinger` directly with a short interval so
    /// the ping/stop behaviour is observable without a multi-second wait.
    ///
    /// Proves: (1) a handler outliving the interval yields >=1 `Working`; (2) after
    /// the guard drops (handler done, terminal about to publish), no further
    /// `Working` arrives — so the terminal frame is never preceded by a late ping.
    #[tokio::test(flavor = "multi_thread")]
    async fn keepalive_pinger_emits_working_then_stops_on_drop() {
        let dir = tempfile::tempdir().expect("tempdir");
        let home = astrid_core::dirs::AstridHome::from_path(dir.path());
        let kernel = crate::test_kernel_with_home(home).await;

        let response_topic = Topic::kernel_response("keepalive_probe.probe");
        let mut rx = kernel.event_bus.subscribe_topic(response_topic.as_str());

        let interval = std::time::Duration::from_millis(40);
        let pinger =
            KeepalivePinger::spawn_with_interval(&kernel, response_topic.clone(), interval);

        // Count Working frames over ~5 intervals while the guard is alive.
        let deadline = astrid_runtime::time::Instant::now() + std::time::Duration::from_millis(220);
        let mut working_seen = 0u32;
        loop {
            let remaining =
                deadline.saturating_duration_since(astrid_runtime::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            match astrid_runtime::time::timeout(remaining, rx.recv()).await {
                Ok(Some(event)) => {
                    if let astrid_events::AstridEvent::Ipc { message, .. } = &*event
                        && let IpcPayload::RawJson(val) = &message.payload
                        && let Ok(KernelResponse::Working) =
                            serde_json::from_value::<KernelResponse>(val.clone())
                    {
                        working_seen += 1;
                    }
                },
                Ok(None) | Err(_) => break,
            }
        }
        assert!(
            working_seen >= 1,
            "a handler outliving the keepalive interval must emit >=1 Working (saw {working_seen})"
        );

        // Drop the guard: the pinger must stop. A `Working` racing the abort may
        // still land right after the drop — harmless by construction (the uplink
        // `continue`s past a stray late ping). Allow a grace window for such a
        // straggler and drain it, then assert the stream goes SILENT: no fresh ping
        // arrives across several further intervals, proving the loop task stopped.
        drop(pinger);
        let grace_deadline = astrid_runtime::time::Instant::now() + interval * 2;
        loop {
            let remaining =
                grace_deadline.saturating_duration_since(astrid_runtime::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            // Drain stragglers during the grace window; stop early on silence.
            if astrid_runtime::time::timeout(remaining, rx.recv())
                .await
                .is_err()
            {
                break;
            }
        }

        let after = astrid_runtime::time::timeout(interval * 4, rx.recv()).await;
        assert!(
            after.is_err(),
            "no Working frame may arrive after the pinger guard is dropped, got {after:?}"
        );
    }
}
