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
use std::time::Duration;

use rmcp::service::{Peer, RoleServer};
use serde_json::{Value, json};
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::socket_client::SocketClient;

use super::server::{TOOLS_LIST_TOPIC, new_req_id, unwrap_reply_payload, unwrap_reply_payload_ref};

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
    // transport's frames. Bind the connection to the SAME principal the
    // request handlers use: the proxy pins the first principal it sees per
    // connection and DROPS any message stamped with a different one, so a
    // `default`-bound uplink would have this watcher's explicitly-stamped
    // enumerate requests silently dropped whenever the principal is not
    // `default`.
    let caller = match astrid_core::PrincipalId::new(&principal) {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, %principal, "MCP hot-reload watcher: invalid principal; live tool-reload pushes disabled");
            return;
        },
    };
    let session = astrid_core::SessionId::from_uuid(Uuid::new_v4());
    let mut watch_client = match SocketClient::connect(session, caller).await {
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
    // On a seed failure, fall back to the empty set: the first successful
    // re-enumeration then over-notifies once (the client harmlessly re-fetches)
    // rather than under-notifying. The bind still took effect as long as the
    // request was sent, so the read loop remains live.
    let mut last_known: BTreeSet<String> = match enumerate_on(&mut watch_client, &principal).await {
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
        // uses. (A typed parse would work too — `IpcPayload` is
        // `#[serde(tag = "type")]` with a `raw_json` variant — but raw-frame
        // matching keeps the watcher independent of the payload schema.)
        let Ok(raw) = serde_json::from_slice::<Value>(&frame) else {
            continue;
        };
        if raw.get("topic").and_then(Value::as_str) != Some(CAPSULES_LOADED_TOPIC) {
            continue;
        }

        // Read the new tool surface straight from the broadcast PAYLOAD — the
        // kernel already injected each capsule's described tools into it (see
        // `astrid_kernel::capsules_loaded`). This is the intended contract: "a
        // sandboxed consumer derives a deterministic tool surface from this
        // signal, instead of a racy describe fan-out". An earlier version
        // re-enumerated over a fresh broker round trip here; that round trip
        // could time out precisely when a reload was in flight (the broker busy
        // with its own describe fan-out), silently swallowing the notification.
        // Reading the payload removes that dependency and fires immediately.
        debug!(
            "MCP hot-reload watcher: capsules_loaded received; reading tool surface from payload"
        );
        let names = tool_names_from_capsules_loaded(unwrap_reply_payload_ref(&raw), &principal);

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

/// Send a `tools.list` request on the GIVEN uplink and collect the set of tool
/// names from the broker reply.
///
/// Sending the request is load-bearing beyond enumeration: it also BINDS this
/// uplink's principal in the cli-proxy (which binds a connection on the first
/// ingress message it sends). Only a bound uplink is delivered the kernel's
/// per-principal `capsules_loaded` broadcast, so the watch loop must run at
/// least one enumeration on its OWN uplink — the baseline seed — or it would
/// never receive a single reload signal. The request is stamped with
/// `principal`; the proxy pins the first principal per connection and drops
/// mismatched stamps, so binding to the request's principal (not `default`)
/// keeps a non-`default` watcher's later broadcasts flowing.
async fn enumerate_on(
    client: &mut SocketClient,
    principal: &str,
) -> anyhow::Result<BTreeSet<String>> {
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
    Ok(tool_names_from_reply(&unwrap_reply_payload(&raw)))
}

/// Extract the set of tool names from a broker `tools.list` reply
/// (`{ "tools": [{ "name": ... }, ...] }`).
///
/// A stable, order-insensitive signature of the tool surface: the watcher
/// diffs successive sets to suppress no-op `tools/list_changed` notifications
/// (equal sets ⇒ quiet). A missing or misshapen reply yields the empty set
/// rather than an error, so a degraded broker reply diffs cleanly instead of
/// wedging the loop.
fn tool_names_from_reply(reply: &Value) -> BTreeSet<String> {
    reply
        .get("tools")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|t| t.get("name").and_then(Value::as_str))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Extract the set of tool names from an `astrid.v1.capsules_loaded` payload
/// (`{ "status", "capsules": [{ "principal", "name", "meta": { "tools": [...] } }] }`),
/// keeping only entries whose per-capsule `principal` matches `principal`.
///
/// The kernel injects each capsule's described tool surface into `meta.tools`
/// (see `astrid_kernel::capsules_loaded`), so the loaded set rides along with
/// the signal and the watcher never needs a second broker round trip. The
/// broadcast is already principal-scoped by the cli-proxy, but the payload
/// carries an explicit per-entry `principal` — honouring it is defense in depth:
/// a stray cross-principal entry can never widen this watcher's view. Any
/// missing/`null`/misshapen field degrades to the empty set (never an error),
/// so a partially-described reload diffs cleanly instead of wedging the loop.
fn tool_names_from_capsules_loaded(payload: &Value, principal: &str) -> BTreeSet<String> {
    payload
        .get("capsules")
        .and_then(Value::as_array)
        .map(|caps| {
            caps.iter()
                .filter(|c| c.get("principal").and_then(Value::as_str) == Some(principal))
                .filter_map(|c| {
                    c.get("meta")
                        .and_then(|m| m.get("tools"))
                        .and_then(Value::as_array)
                })
                .flatten()
                .filter_map(|t| t.get("name").and_then(Value::as_str))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Names are extracted and collected into an order-insensitive set.
    #[test]
    fn tool_names_are_extracted_as_a_set() {
        let reply = json!({ "tools": [
            { "name": "read_file" },
            { "name": "write_file" },
            { "name": "grep_search" },
        ] });
        assert_eq!(
            tool_names_from_reply(&reply),
            BTreeSet::from([
                "grep_search".to_string(),
                "read_file".to_string(),
                "write_file".to_string(),
            ])
        );
    }

    /// A nameless descriptor, a missing `tools` key, and a wrong-typed `tools`
    /// all degrade to a clean set rather than erroring — a malformed reply must
    /// never wedge or panic the watch loop.
    #[test]
    fn malformed_replies_degrade_to_a_clean_set() {
        let mixed = json!({ "tools": [{ "name": "a" }, { "description": "no name" }, {}] });
        assert_eq!(
            tool_names_from_reply(&mixed),
            BTreeSet::from(["a".to_string()])
        );
        assert!(tool_names_from_reply(&json!({})).is_empty());
        assert!(tool_names_from_reply(&json!({ "tools": "nope" })).is_empty());
    }

    /// The diff the watcher keys on: adding or removing a tool changes the set
    /// (fires a notification), while a pure reorder of the same names does not
    /// (stays quiet). This is the "quiet when unchanged" contract.
    #[test]
    fn set_diff_detects_membership_not_order() {
        let before = tool_names_from_reply(&json!({ "tools": [{ "name": "a" }, { "name": "b" }] }));
        let added = tool_names_from_reply(
            &json!({ "tools": [{ "name": "a" }, { "name": "b" }, { "name": "c" }] }),
        );
        let removed = tool_names_from_reply(&json!({ "tools": [{ "name": "a" }] }));
        let reordered =
            tool_names_from_reply(&json!({ "tools": [{ "name": "b" }, { "name": "a" }] }));

        assert_ne!(before, added, "an added tool must be a detected change");
        assert_ne!(before, removed, "a removed tool must be a detected change");
        assert_eq!(
            before, reordered,
            "reordering identical names must stay quiet"
        );
    }

    /// Tool names are read from `capsules[].meta.tools[].name` across every
    /// capsule entry that belongs to the watcher's principal.
    #[test]
    fn capsules_loaded_collects_tools_across_capsules() {
        let payload = json!({
            "status": "ready",
            "capsules": [
                { "principal": "default", "name": "astrid-capsule-system",
                  "meta": { "tools": [{ "name": "system_status" }] } },
                { "principal": "default", "name": "astrid-capsule-fs",
                  "meta": { "tools": [{ "name": "read_file" }, { "name": "write_file" }] } },
            ]
        });
        assert_eq!(
            tool_names_from_capsules_loaded(&payload, "default"),
            BTreeSet::from([
                "read_file".to_string(),
                "system_status".to_string(),
                "write_file".to_string(),
            ])
        );
    }

    /// Only entries stamped with the watcher's principal count — a
    /// cross-principal entry can never widen the view.
    #[test]
    fn capsules_loaded_filters_by_principal() {
        let payload = json!({
            "capsules": [
                { "principal": "default", "name": "a", "meta": { "tools": [{ "name": "mine" }] } },
                { "principal": "bob", "name": "b", "meta": { "tools": [{ "name": "theirs" }] } },
            ]
        });
        assert_eq!(
            tool_names_from_capsules_loaded(&payload, "default"),
            BTreeSet::from(["mine".to_string()])
        );
    }

    /// A `null` meta, a meta with no `tools`, a nameless descriptor, and a
    /// missing/misshapen `capsules` all degrade to the empty set rather than
    /// erroring — a partially-described reload must never wedge the loop.
    #[test]
    fn capsules_loaded_degrades_on_missing_fields() {
        let ragged = json!({
            "capsules": [
                { "principal": "default", "name": "a", "meta": null },
                { "principal": "default", "name": "b", "meta": { "version": "1.0.0" } },
                { "principal": "default", "name": "c", "meta": { "tools": [{ "no": "name" }] } },
            ]
        });
        assert!(tool_names_from_capsules_loaded(&ragged, "default").is_empty());
        assert!(tool_names_from_capsules_loaded(&json!({}), "default").is_empty());
        assert!(
            tool_names_from_capsules_loaded(&json!({ "capsules": "nope" }), "default").is_empty()
        );
    }

    /// End-to-end diff contract: installing a capsule (its tools appear in the
    /// next broadcast) is a detected change; unloading one (its tools vanish)
    /// is too. This is exactly the signal the watch loop keys its
    /// `tools/list_changed` push on.
    #[test]
    fn capsules_loaded_diff_tracks_install_and_unload() {
        let base = tool_names_from_capsules_loaded(
            &json!({ "capsules": [
                { "principal": "default", "name": "sys", "meta": { "tools": [{ "name": "system_status" }] } }
            ] }),
            "default",
        );
        let after_install = tool_names_from_capsules_loaded(
            &json!({ "capsules": [
                { "principal": "default", "name": "sys", "meta": { "tools": [{ "name": "system_status" }] } },
                { "principal": "default", "name": "fs", "meta": { "tools": [{ "name": "read_file" }] } }
            ] }),
            "default",
        );
        assert_ne!(
            base, after_install,
            "a newly installed capsule's tools must register as a change"
        );
        // Unload returns to the base surface — also a change from `after_install`.
        assert_ne!(
            after_install, base,
            "an unloaded capsule's tools vanishing must register as a change"
        );
    }
}
