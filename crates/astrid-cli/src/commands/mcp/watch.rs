//! Hot-reload bridge: kernel `capsules_loaded` -> MCP `tools/list_changed`.
//!
//! The kernel broadcasts [`CAPSULES_LOADED_TOPIC`] whenever it finishes a
//! (re)load of the capsule set — e.g. after `astrid refresh` installs or
//! swaps a capsule that contributes tools. An MCP client that connected
//! earlier holds a stale `tools/list`; the MCP spec lets the server push
//! `notifications/tools/list_changed` to invite a re-fetch.
//!
//! The kernel auto-broadcasts that topic to **every** uplink (no explicit
//! subscribe — the same delivery the TUI relies on), so this task just reads
//! frames off its watch uplink and filters for it. Tool re-enumeration runs
//! on a **separate, short-lived** uplink per delivery, so a reload broadcast
//! arriving mid-enumeration can never be consumed (and discarded) by the
//! reply drain on the watch uplink. It pushes a `tools/list_changed`
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
use std::time::Duration;

use rmcp::service::{Peer, RoleServer};
use serde_json::{Value, json};
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::socket_client::SocketClient;

use super::server::{RESPONSE_PREFIX, TOOLS_LIST_TOPIC, new_req_id, unwrap_reply_payload};

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
pub(super) async fn run(peer: Peer<RoleServer>, principal: String) {
    // The watch uplink's session id is ephemeral — it only keys this
    // transport's frames. Work is attributed via the per-message
    // `principal`, not the session (same as the request-path uplink).
    // The connection's principal binding is the fallback for messages
    // that omit one; this watcher always stamps `principal` explicitly
    // (below), so bind the default and let the explicit stamp win.
    let session = astrid_core::SessionId::from_uuid(Uuid::new_v4());
    let mut watch_client = match SocketClient::connect(session, astrid_core::PrincipalId::default())
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

    // `astrid.v1.capsules_loaded` is auto-broadcast to every uplink (no
    // explicit subscribe — the same path the TUI uses), so the watch uplink
    // receives it just by reading frames.
    info!("MCP hot-reload watcher: watching for {CAPSULES_LOADED_TOPIC} broadcasts");

    // Seed the baseline from the live surface NOW, so the FIRST reload after
    // the client connected is diffed against reality and pushed when it
    // changed — rather than swallowed as a synthetic baseline. On a seed
    // failure, fall back to the empty set: the first successful enumeration
    // then over-notifies once (the client harmlessly re-fetches) rather than
    // under-notifying.
    let mut last_known: BTreeSet<String> = match enumerate_tool_names(&principal).await {
        Ok(names) => names,
        Err(e) => {
            warn!(error = %e, "MCP hot-reload watcher: baseline seed failed; starting from empty set");
            BTreeSet::new()
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
        // uses, and all this loop needs is the topic string. (A typed parse
        // would work too — `IpcPayload` is `#[serde(tag = "type")]` with a
        // `raw_json` variant — but raw-frame matching keeps the watcher
        // independent of the payload schema.)
        let Ok(raw) = serde_json::from_slice::<Value>(&frame) else {
            continue;
        };
        if raw.get("topic").and_then(Value::as_str) != Some(CAPSULES_LOADED_TOPIC) {
            continue;
        }

        debug!("MCP hot-reload watcher: capsules_loaded received; re-enumerating tools");

        let names = match enumerate_tool_names(&principal).await {
            Ok(names) => names,
            Err(e) => {
                warn!(error = %e, "MCP hot-reload watcher: tool re-enumeration failed; keeping last-known set");
                continue;
            },
        };

        if names == last_known {
            debug!("MCP hot-reload watcher: tool set unchanged; suppressing notification");
            continue;
        }

        if let Err(e) = peer.notify_tool_list_changed().await {
            // Peer channel closed -> the transport is gone; stop.
            warn!(error = %e, "MCP hot-reload watcher: notify failed (peer closed); stopping");
            return;
        }
        info!(
            tools = names.len(),
            "MCP hot-reload watcher: tool set changed; pushed tools/list_changed"
        );
        last_known = names;
    }
}

/// Publish a `tools.list` request on a **fresh, short-lived** uplink and
/// collect the set of tool names from the broker reply.
///
/// The dedicated connection is the point: the watch loop's own uplink only
/// ever reads the `capsules_loaded` broadcast, so a reload frame arriving
/// while this round trip is draining its reply can never be consumed (and
/// silently discarded) by `read_until_topic` here — nor raced against an
/// in-flight `tools/list` / `tools/call` on the request handlers' client.
/// Reloads are infrequent, so a connect-per-enumeration is cheap.
async fn enumerate_tool_names(principal: &str) -> anyhow::Result<BTreeSet<String>> {
    let session = astrid_core::SessionId::from_uuid(Uuid::new_v4());
    let mut client = SocketClient::connect(session, astrid_core::PrincipalId::default()).await?;
    let req_id = new_req_id();
    let reply_topic = format!("{RESPONSE_PREFIX}{req_id}");
    let body = json!({ "req_id": req_id });

    let msg = astrid_types::ipc::IpcMessage::new(
        TOOLS_LIST_TOPIC,
        astrid_types::ipc::IpcPayload::RawJson(body),
        Uuid::nil(),
    )
    .with_principal(principal.to_string());

    client.send_message(msg).await?;

    let raw = client
        .read_until_topic(&reply_topic, ENUMERATE_DEADLINE)
        .await?;
    let reply = unwrap_reply_payload(&raw);

    let names = reply
        .get("tools")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|t| t.get("name").and_then(Value::as_str))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();

    Ok(names)
}
