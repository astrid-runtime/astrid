//! Principal-scoped MCP broker readiness.
//!
//! The daemon deliberately becomes globally ready after loading only the
//! default principal's boot-critical capsules. Persisted non-default
//! principals warm in the background, so an authenticated `mcp serve` uplink
//! can connect before that principal's broker capsule has subscribed to
//! [`TOOLS_LIST_TOPIC`]. Publishing the MCP client's first `tools/list` in that
//! window drops the request (the event bus is not a durable queue), leaving the
//! shim to wait out its full request deadline for a reply that can never exist.
//!
//! Before stdio is exposed, this module proves the generic broker path is live
//! with an idempotent `tools/list` round trip. A principal-scoped
//! `astrid.v1.capsules_loaded` broadcast or a bounded retry interval reissues a
//! dropped probe. No product capsule name is hardcoded: readiness means the
//! broker front-door topic actually answered for this authenticated principal.

use std::collections::HashSet;
use std::time::Duration;

use anyhow::{Context, Result};
use astrid_core::PrincipalId;
use astrid_types::ipc::{IpcMessage, IpcPayload};
use serde_json::{Value, json};
use tokio::time::Instant;
use tracing::{debug, info};
use uuid::Uuid;

use crate::socket_client::SocketClient;

use super::server::{TOOLS_LIST_TOPIC, new_req_id};

const CAPSULES_LOADED_TOPIC: &str = "astrid.v1.capsules_loaded";

/// Total startup budget for proving that the principal's broker front door is
/// responsive. This matches the normal broker round-trip budget: a genuinely
/// slow describe drain gets the same headroom, while an absent broker fails
/// startup loudly instead of accepting MCP and hanging the client's first
/// request.
const BROKER_READY_DEADLINE: Duration = Duration::from_secs(55);

/// Fallback retry cadence when a legacy daemon does not deliver a
/// `capsules_loaded` broadcast to the newly-bound uplink. It exceeds the
/// broker's normal 2.5 s cold discovery drain, avoiding a duplicate fan-out on
/// a healthy but cold broker while still recovering a request dropped before
/// subscription registration.
const PROBE_RETRY_INTERVAL: Duration = Duration::from_secs(3);

/// Minimal transport seam for a deterministic cold-start regression test.
/// Production uses [`SocketClient`]; tests model the first probe being dropped,
/// the principal load completing, and the replay receiving a response.
#[allow(async_fn_in_trait)]
trait ReadinessIo {
    async fn send_message(&mut self, message: IpcMessage) -> Result<()>;
    async fn read_raw_frame(&mut self) -> Result<Option<Vec<u8>>>;
}

impl ReadinessIo for SocketClient {
    async fn send_message(&mut self, message: IpcMessage) -> Result<()> {
        SocketClient::send_message(self, message).await
    }

    async fn read_raw_frame(&mut self) -> Result<Option<Vec<u8>>> {
        SocketClient::read_raw_frame(self).await
    }
}

/// Wait until the principal-scoped MCP broker answers a real `tools/list`
/// round trip.
pub(super) async fn wait_for_broker(
    client: &mut SocketClient,
    principal: &PrincipalId,
) -> Result<()> {
    wait_for_broker_on(
        client,
        principal,
        BROKER_READY_DEADLINE,
        PROBE_RETRY_INTERVAL,
    )
    .await
}

async fn wait_for_broker_on<I: ReadinessIo>(
    io: &mut I,
    principal: &PrincipalId,
    ready_deadline: Duration,
    retry_interval: Duration,
) -> Result<()> {
    let deadline = Instant::now()
        .checked_add(ready_deadline)
        .unwrap_or_else(Instant::now);
    let mut outstanding = HashSet::new();

    send_probe(io, principal, &mut outstanding).await?;
    let mut retry_at = Instant::now()
        .checked_add(retry_interval)
        .unwrap_or(deadline);

    loop {
        let now = Instant::now();
        if now >= deadline {
            anyhow::bail!(
                "MCP broker did not become ready for principal '{principal}' within {}s; no capsule answered {TOOLS_LIST_TOPIC}",
                ready_deadline.as_secs()
            );
        }
        if now >= retry_at {
            debug!(%principal, "MCP broker readiness probe interval elapsed; retrying idempotent tools/list");
            send_probe(io, principal, &mut outstanding).await?;
            retry_at = Instant::now()
                .checked_add(retry_interval)
                .unwrap_or(deadline);
            continue;
        }

        let wake_at = retry_at.min(deadline);
        let frame = match tokio::time::timeout_at(wake_at, io.read_raw_frame()).await {
            Ok(Ok(Some(frame))) => frame,
            Ok(Ok(None)) => {
                anyhow::bail!(
                    "daemon connection closed while waiting for the MCP broker for principal '{principal}'"
                )
            },
            Ok(Err(error)) => {
                return Err(error).with_context(|| {
                    format!(
                        "daemon connection failed while waiting for the MCP broker for principal '{principal}'"
                    )
                });
            },
            Err(_) => {
                if Instant::now() >= deadline {
                    anyhow::bail!(
                        "MCP broker did not become ready for principal '{principal}' within {}s; no capsule answered {TOOLS_LIST_TOPIC}",
                        ready_deadline.as_secs()
                    );
                }
                debug!(%principal, "MCP broker readiness probe unanswered; retrying idempotent tools/list");
                send_probe(io, principal, &mut outstanding).await?;
                retry_at = Instant::now()
                    .checked_add(retry_interval)
                    .unwrap_or(deadline);
                continue;
            },
        };

        let Ok(raw) = serde_json::from_slice::<Value>(&frame) else {
            continue;
        };
        if frame_principal_mismatches(&raw, principal) {
            continue;
        }

        let topic = raw.get("topic").and_then(Value::as_str);
        if topic.is_some_and(|topic| outstanding.contains(topic)) {
            info!(%principal, "MCP broker readiness confirmed");
            return Ok(());
        }

        if topic == Some(CAPSULES_LOADED_TOPIC) {
            debug!(%principal, "principal capsule load completed; reproving MCP broker readiness");
            send_probe(io, principal, &mut outstanding).await?;
            retry_at = Instant::now()
                .checked_add(retry_interval)
                .unwrap_or(deadline);
        }
    }
}

async fn send_probe<I: ReadinessIo>(
    io: &mut I,
    principal: &PrincipalId,
    outstanding: &mut HashSet<String>,
) -> Result<()> {
    let req_id = new_req_id();
    let response_topic = astrid_types::Topic::kernel_response(&req_id).to_string();
    let message = IpcMessage::new(
        astrid_types::Topic::from_raw(TOOLS_LIST_TOPIC),
        IpcPayload::RawJson(json!({ "req_id": req_id })),
        Uuid::nil(),
    )
    .with_principal(principal.to_string());

    io.send_message(message)
        .await
        .context("failed to publish MCP broker readiness probe")?;
    outstanding.insert(response_topic);
    Ok(())
}

/// A connection is principal-bound by the first probe and the proxy filters
/// later delivery, but retain an explicit check as defense in depth. Legacy
/// frames without a top-level principal remain acceptable on that bound
/// connection.
fn frame_principal_mismatches(raw: &Value, principal: &PrincipalId) -> bool {
    raw.get("principal")
        .and_then(Value::as_str)
        .is_some_and(|frame_principal| frame_principal != principal.as_str())
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;

    struct ColdStartIo {
        frames: VecDeque<Vec<u8>>,
        sends: usize,
        principal: PrincipalId,
        drop_first_probe: bool,
        continuous_noise: bool,
    }

    impl ColdStartIo {
        fn new(principal: PrincipalId, drop_first_probe: bool) -> Self {
            Self {
                frames: VecDeque::new(),
                sends: 0,
                principal,
                drop_first_probe,
                continuous_noise: false,
            }
        }

        fn noisy(principal: PrincipalId) -> Self {
            Self {
                continuous_noise: true,
                ..Self::new(principal, true)
            }
        }

        fn raw_frame(value: &Value) -> Vec<u8> {
            serde_json::to_vec(value).expect("serialize test frame")
        }
    }

    impl ReadinessIo for ColdStartIo {
        async fn send_message(&mut self, message: IpcMessage) -> Result<()> {
            self.sends = self.sends.checked_add(1).expect("test send count overflow");
            let req_id = match message.payload {
                IpcPayload::RawJson(body) => body
                    .get("req_id")
                    .and_then(Value::as_str)
                    .expect("probe req_id")
                    .to_string(),
                other => panic!("unexpected probe payload: {other:?}"),
            };

            if self.drop_first_probe && self.sends == 1 {
                // Exact cold-start race: the event-bus request had no broker
                // subscriber, then the principal's capsule view completed.
                if !self.continuous_noise {
                    self.frames.push_back(Self::raw_frame(&json!({
                        "topic": CAPSULES_LOADED_TOPIC,
                        "principal": self.principal.to_string(),
                        "payload": { "status": "ready", "capsules": [] }
                    })));
                }
            } else {
                self.frames.push_back(Self::raw_frame(&json!({
                    "topic": astrid_types::Topic::kernel_response(&req_id).to_string(),
                    "principal": self.principal.to_string(),
                    "payload": {
                        "type": "raw_json",
                        "value": { "kind": "tools.list", "req_id": req_id, "tools": [] }
                    }
                })));
            }
            Ok(())
        }

        async fn read_raw_frame(&mut self) -> Result<Option<Vec<u8>>> {
            match self.frames.pop_front() {
                Some(frame) => Ok(Some(frame)),
                None if self.continuous_noise => Ok(Some(Self::raw_frame(&json!({
                    "topic": "astrid.v1.unrelated",
                    "principal": self.principal.to_string(),
                    "payload": {}
                })))),
                None => std::future::pending().await,
            }
        }
    }

    #[tokio::test]
    async fn cold_start_replays_probe_after_principal_capsules_load() {
        let principal = PrincipalId::new("codex-code").expect("principal");
        let mut io = ColdStartIo::new(principal.clone(), true);

        wait_for_broker_on(
            &mut io,
            &principal,
            Duration::from_secs(1),
            Duration::from_millis(50),
        )
        .await
        .expect("broker becomes ready after principal warm");

        assert_eq!(io.sends, 2, "dropped first probe must be replayed once");
    }

    #[tokio::test]
    async fn warm_broker_needs_only_one_probe() {
        let principal = PrincipalId::new("codex-code").expect("principal");
        let mut io = ColdStartIo::new(principal.clone(), false);

        wait_for_broker_on(
            &mut io,
            &principal,
            Duration::from_secs(1),
            Duration::from_millis(50),
        )
        .await
        .expect("warm broker answers first probe");

        assert_eq!(io.sends, 1);
    }

    #[tokio::test]
    async fn unrelated_frames_cannot_starve_retry_interval() {
        let principal = PrincipalId::new("codex-code").expect("principal");
        let mut io = ColdStartIo::noisy(principal.clone());

        wait_for_broker_on(
            &mut io,
            &principal,
            Duration::from_millis(100),
            Duration::from_millis(10),
        )
        .await
        .expect("wall-clock retry fires despite continuously ready noise");

        assert_eq!(io.sends, 2, "noise must not starve the fallback retry");
    }

    #[test]
    fn mismatched_principal_frame_is_rejected() {
        let principal = PrincipalId::new("codex-code").expect("principal");
        assert!(frame_principal_mismatches(
            &json!({ "principal": "claude-code" }),
            &principal
        ));
        assert!(!frame_principal_mismatches(
            &json!({ "principal": "codex-code" }),
            &principal
        ));
        assert!(!frame_principal_mismatches(&json!({}), &principal));
    }
}
