//! Hot-reload bridge from kernel hints to MCP `tools/list_changed`.
//!
//! A dedicated watcher uplink uses the same principal authentication policy
//! as request traffic. Initial enumeration establishes a complete baseline;
//! failed enumeration leaves it unknown rather than inventing an empty list.
//!
//! `capsules_loaded` broadcasts are hints, never tool authority. Each hint
//! triggers a full `tools/list` snapshot on this uplink. Malformed snapshots
//! retain the previous state; only a valid snapshot can replace its epoch and
//! tool names. Changed names notify the stdio peer, request subscription, or
//! gateway peers through one shared loop. Schema-only changes retain the
//! existing name-based notification behavior.
//!
//! Gateway cancellation drops pending connection, enumeration and notification
//! work. Peer-map locks are released before network notifications. This task
//! writes diagnostics only to tracing; stdout belongs to MCP transport.

use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rmcp::service::{Peer, RoleServer};
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::socket_client::SocketClient;

use super::server::{
    TOOLS_LIST_TOPIC, new_req_id, snapshot_tool_names, unwrap_reply_payload,
    unwrap_reply_payload_ref,
};

/// Kernel broadcast emitted once every capsule (re)load completes.
const CAPSULES_LOADED_TOPIC: &str = "astrid.v1.capsules_loaded";

/// Deadline for a single re-enumeration round trip on the watcher's own
/// uplink. Matches the request-path deadline so a slow broker drain
/// surfaces as a logged miss rather than wedging the watch loop.
const ENUMERATE_DEADLINE: Duration = Duration::from_secs(55);

/// Run the hot-reload watch loop until its uplink closes.
///
/// `peer` is the held server peer used to push `tools/list_changed`.
/// `principal` is stamped on the watcher's own outbound enumerate request
/// so the kernel scopes discovery to the same identity as the request
/// handlers. The function owns a freshly-connected [`SocketClient`] and
/// drives it to EOF; it returns when the daemon closes the watch uplink.
pub(super) async fn run(peer: Peer<RoleServer>, principal: String, daemon_root: PathBuf) {
    run_with_sink(ChangeSink::Legacy(peer), principal, daemon_root).await;
}

/// The 2026 subscription is request-scoped on both stdio and HTTP. Cancelling
/// it drops its watcher uplink; it never owns the shared broker connection.
pub(super) async fn run_subscription(
    context: rmcp::service::SubscriptionContext,
    principal: String,
    daemon_root: PathBuf,
) {
    tokio::select! {
        () = context.cancelled() => {},
        () = run_with_sink(ChangeSink::Subscription(context.sink().clone()), principal, daemon_root) => {},
    }
}

enum ChangeSink {
    Legacy(Peer<RoleServer>),
    Subscription(rmcp::service::SubscriptionSink),
    Many(Arc<Mutex<HashMap<String, Peer<RoleServer>>>>),
}

impl ChangeSink {
    async fn notify(&self) -> anyhow::Result<()> {
        match self {
            Self::Legacy(peer) => peer.notify_tool_list_changed().await?,
            Self::Subscription(sink) => sink.notify_tool_list_changed().await?,
            Self::Many(peers) => notify_peers(peers).await,
        }
        Ok(())
    }
}

/// Share one authenticated, epoch-aware watcher across gateway sessions.
/// Cancelling the gateway drops its pending connection/read and notification work.
pub(super) async fn run_many(
    peers: Arc<Mutex<HashMap<String, Peer<RoleServer>>>>,
    principal: String,
    daemon_root: PathBuf,
    shutdown: CancellationToken,
) {
    tokio::select! {
        () = shutdown.cancelled() => {},
        () = run_with_sink(ChangeSink::Many(peers), principal, daemon_root) => {},
    }
}

async fn notify_peers(peers: &Arc<Mutex<HashMap<String, Peer<RoleServer>>>>) {
    // Do not hold the map lock across network notifications. Snapshot the
    // keyed peers, notify independently, then remove only sessions whose
    // transport has closed. An attach that reaches stdin EOF is therefore
    // unregistered on the next reload signal without disturbing other peers.
    let snapshot = peers
        .lock()
        .await
        .iter()
        .map(|(id, peer)| (id.clone(), peer.clone()))
        .collect::<Vec<_>>();
    let mut closed = Vec::new();
    for (id, peer) in snapshot {
        if peer.notify_tool_list_changed().await.is_err() {
            closed.push(id);
        }
    }
    if !closed.is_empty() {
        let mut guard = peers.lock().await;
        for id in closed {
            guard.remove(&id);
        }
    }
}

async fn run_with_sink(sink: ChangeSink, principal: String, daemon_root: PathBuf) {
    // The watch uplink's session id is ephemeral — it only keys this
    // transport's frames. Bind the connection to the SAME principal the
    // request handlers use: the native uplink binds that principal during the
    // signed connection handshake, before any enumerate request is sent.
    let caller = match astrid_core::PrincipalId::new(&principal) {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, %principal, "MCP hot-reload watcher: invalid principal; live tool-reload pushes disabled");
            return;
        },
    };
    let session = astrid_core::SessionId::from_uuid(Uuid::new_v4());
    let mut watch_client = match crate::socket_client::connect_for_workspace(
        session,
        caller.clone(),
        Some(daemon_root.as_path()),
    )
    .await
    {
        Ok(c) => c,
        Err(e) => {
            // Non-fatal: the server still serves tools; clients just won't
            // get live `list_changed` pushes. Log and bow out.
            warn!(error = %e, "MCP hot-reload watcher: failed to open watch uplink; live tool-reload pushes disabled");
            return;
        },
    };

    if let Err(error) =
        super::require_authenticated_unless_anonymous(&caller, watch_client.is_authenticated())
    {
        warn!(%error, %principal, "MCP hot-reload watcher: authentication policy refused uplink");
        return;
    }

    info!("MCP hot-reload watcher: watching for {CAPSULES_LOADED_TOPIC} broadcasts");

    // A valid empty snapshot is meaningful authority. Failed enumeration
    // remains unknown, so the first later valid snapshot can notify peers.
    let mut last_known = match enumerate_on(&mut watch_client, &principal).await {
        Ok(state) => Some(state),
        Err(e) => {
            warn!(error = %e, "MCP hot-reload watcher: baseline seed failed; waiting for a valid resnapshot");
            None
        },
    };

    loop {
        let frame = match watch_client.read_raw_frame().await {
            Ok(Some(bytes)) => bytes,
            Ok(None) => {
                debug!("MCP hot-reload watcher: watch uplink closed; stopping");
                return;
            },
            Err(e) => {
                warn!(error = %e, "MCP hot-reload watcher: watch uplink read failed; stopping");
                return;
            },
        };

        // Match the topic on the raw frame rather than deserializing a typed
        // `IpcMessage` — the same tactic `SocketClient::read_until_topic`
        // uses. (A typed parse would work too — `IpcPayload` is
        // `#[serde(tag = "type")]` with a `raw_json` variant — but raw-frame
        // matching keeps the watcher independent of the payload schema.)
        let Ok(raw) = serde_json::from_slice::<Value>(&frame) else {
            continue;
        };
        if raw.get("topic").and_then(Value::as_str) != Some(CAPSULES_LOADED_TOPIC) {
            continue;
        }

        // `capsules_loaded` is a payload-light hint.  Its epoch is useful only
        // for anomaly detection; the authoritative tools and epoch come from a
        // fresh full `tools/list` snapshot on this same authenticated uplink.
        let hint = unwrap_reply_payload_ref(&raw);
        let hint_epoch = hint.get("epoch").and_then(Value::as_u64);
        let expected = last_known
            .as_ref()
            .and_then(|state| state.epoch.checked_add(1));
        let valid_next = valid_next_epoch(last_known.as_ref(), hint_epoch);
        if !valid_next {
            debug!(
                hint_epoch = ?hint_epoch,
                expected = ?expected,
                "MCP hot-reload watcher: malformed, stale, reordered, missed, or overflow hint; forcing full resnapshot"
            );
        }

        let refreshed = match enumerate_on(&mut watch_client, &principal).await {
            Ok(state) => state,
            Err(error) => {
                warn!(%error, "MCP hot-reload watcher: full resnapshot failed; retaining prior authority");
                continue;
            },
        };
        let changed = last_known
            .as_ref()
            .is_none_or(|previous| previous.names != refreshed.names);
        last_known = Some(refreshed);
        if !changed {
            debug!("MCP hot-reload watcher: tool set unchanged; suppressing notification");
            continue;
        }

        if let Err(e) = sink.notify().await {
            // Peer channel closed -> the transport is gone; stop.
            warn!(error = %e, "MCP hot-reload watcher: notify failed (peer closed); stopping");
            return;
        }
        info!(
            "MCP hot-reload watcher: valid resnapshot changed tool set; pushed tools/list_changed"
        );
    }
}

/// One complete authority snapshot held by the watcher.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SnapshotState {
    epoch: u64,
    names: BTreeSet<String>,
}

fn valid_next_epoch(last_known: Option<&SnapshotState>, hint_epoch: Option<u64>) -> bool {
    let Some(expected) = last_known.and_then(|state| state.epoch.checked_add(1)) else {
        return false;
    };
    hint_epoch == Some(expected)
}

/// Send a `tools.list` request on the given uplink and parse a complete,
/// epoch-bearing kernel snapshot. A malformed response is an error; callers
/// retain no synthetic empty authority state.
async fn enumerate_on(client: &mut SocketClient, principal: &str) -> anyhow::Result<SnapshotState> {
    let req_id = new_req_id();
    let reply_topic = astrid_types::Topic::kernel_response(&req_id);
    let body = json!({ "req_id": req_id });

    let msg = astrid_types::ipc::IpcMessage::new(
        astrid_types::Topic::from_raw(TOOLS_LIST_TOPIC),
        astrid_types::ipc::IpcPayload::RawJson(body),
        Uuid::nil(),
    )
    .with_principal(principal.to_string());

    client.send_message(msg).await?;

    let raw = client
        .read_until_topic(&reply_topic, ENUMERATE_DEADLINE)
        .await?;
    let (epoch, names) = snapshot_tool_names(&unwrap_reply_payload(&raw))
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    Ok(SnapshotState { epoch, names })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(names: &[&str], epoch: u64) -> Value {
        json!({
            "epoch": epoch,
            "tools": names.iter().map(|name| json!({
                "name": name,
                "description": "",
                "inputSchema": {},
            })).collect::<Vec<_>>(),
        })
    }

    #[test]
    fn valid_snapshot_accepts_empty_tools_only_with_epoch() {
        let (_, names) = snapshot_tool_names(&snapshot(&[], 1)).expect("valid empty snapshot");
        assert!(names.is_empty());
        assert!(snapshot_tool_names(&json!({ "tools": [] })).is_err());
    }

    #[test]
    fn malformed_snapshot_is_an_error_not_empty() {
        assert!(snapshot_tool_names(&json!({})).is_err());
        assert!(snapshot_tool_names(&json!({ "epoch": 2, "tools": "nope" })).is_err());
        assert!(
            snapshot_tool_names(&json!({
                "epoch": 2,
                "tools": [{ "name": "broken", "inputSchema": null }]
            }))
            .is_err()
        );
    }

    #[test]
    fn duplicate_stale_reordered_missed_and_overflow_hints_require_resnapshot() {
        let current = SnapshotState {
            epoch: 7,
            names: BTreeSet::from(["a".to_string()]),
        };
        for hint in [None, Some(0), Some(7), Some(6), Some(9)] {
            assert!(!valid_next_epoch(Some(&current), hint));
        }
        assert!(valid_next_epoch(Some(&current), Some(8)));
        let overflow = SnapshotState {
            epoch: u64::MAX,
            names: BTreeSet::new(),
        };
        assert!(!valid_next_epoch(Some(&overflow), Some(u64::MAX)));
    }

    #[test]
    fn disjoint_name_sets_remain_disjoint_after_resnapshot() {
        let (_, alice) = snapshot_tool_names(&snapshot(&["a"], 1)).expect("alice");
        let (_, bob) = snapshot_tool_names(&snapshot(&["b"], 1)).expect("bob");
        assert_eq!(alice, BTreeSet::from(["a".to_string()]));
        assert_eq!(bob, BTreeSet::from(["b".to_string()]));
        assert!(alice.is_disjoint(&bob));
    }
}
