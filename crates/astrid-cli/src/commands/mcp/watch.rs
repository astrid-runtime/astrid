//! Hot-reload bridge: kernel `capsules_loaded` -> MCP `tools/list_changed`.
//!
//! The kernel broadcasts [`CAPSULES_LOADED_TOPIC`] whenever it finishes a
//! (re)load of the capsule set — e.g. after `astrid refresh` installs or
//! swaps a capsule that contributes tools. An MCP client that connected
//! earlier holds a stale `tools/list`; the MCP spec lets the server push
//! `notifications/tools/list_changed` to invite a re-fetch.
//!
//! The kernel stamps that broadcast with the affected **principal**, and the
//! cli-proxy delivers a principal-stamped event only to uplinks BOUND to that
//! principal. A connection binds on the first ingress message it *sends* — so a
//! watch uplink that only ever READ would stay unbound and never be delivered
//! the broadcast at all. The watcher therefore seeds its baseline by
//! enumerating ON the watch uplink (that first `tools/list` request binds the
//! connection), and only then falls into a pure read loop.
//!
//! The `capsules_loaded` payload already carries each capsule's described tool
//! surface (`meta.tools`, injected kernel-side — see
//! [`astrid_kernel::capsules_loaded`]), so the watcher reads the new tool set
//! straight from the broadcast rather than issuing a second broker round trip.
//! That is the signal's intended contract ("a sandboxed consumer derives a
//! deterministic tool surface from this signal, instead of a racy describe
//! fan-out") and it means a reload never depends on a follow-up request that
//! could time out while the broker is busy. It pushes a `tools/list_changed`
//! notification through the held [`Peer<RoleServer>`] **only when the
//! tool-name set actually changed**, diffing against a baseline seeded from
//! the live surface at startup (so the first post-connect reload is not
//! swallowed).
//!
//! ## Why a coarse signal
//!
//! The MCP notification carries no payload — it is a pure "re-fetch" hint.
//! We diff the set of tool *names* (a cheap, order-insensitive signature)
//! to suppress no-op notifications when a reload doesn't touch the tool
//! surface. Schema-only edits that keep every name identical are not
//! detected; that is acceptable for a coarse reload hint, and the client
//! always re-fetches the full, authoritative list when it does react.
//!
//! ## stdout discipline
//!
//! This task never touches stdout — that channel belongs to the MCP
//! transport. Every diagnostic goes through `tracing` (stderr).

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::Duration;

use rmcp::service::{Peer, RoleServer};
use serde_json::{Value, json};
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
        caller,
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

    info!("MCP hot-reload watcher: watching for {CAPSULES_LOADED_TOPIC} broadcasts");

    // Seed the baseline from the live surface NOW — AND bind this uplink. Two
    // jobs in one round trip:
    //
    //  1. Baseline: capture the current tool-name set so the FIRST reload after
    //     the client connected is diffed against reality and pushed when it
    //     changed, rather than swallowed as a synthetic baseline.
    //  2. Bind: the cli-proxy binds a connection to its principal on the first
    //     ingress message the connection *sends*, and delivers a
    //     principal-stamped `capsules_loaded` only to uplinks bound to that
    //     principal. Running the seed enumeration ON `watch_client` sends that
    //     first message, so this uplink is bound and later broadcasts actually
    //     reach the read loop below. Seeding on a *separate* uplink (as an
    //     earlier version did) left this one unbound — and silently starved of
    //     every broadcast, so no `tools/list_changed` ever fired.
    //
    // A failed seed leaves the baseline unknown.  Keep that distinction: an
    // empty set is authority-bearing only after a valid epoch and complete
    // snapshot have been received.
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

        if let Err(e) = peer.notify_tool_list_changed().await {
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
