//! Live-load nudge — make a fresh `astrid capsule install` / `update` usable
//! without a daemon restart.
//!
//! Installing a capsule writes it to disk through a deliberately standalone,
//! daemon-independent path (it must work with no daemon running). This module
//! adds the *optional* second half: when a daemon is up, ask it to hot-load —
//! or hot-swap — the just-installed capsule(s) so they're immediately usable. It
//! is kept separate from `install.rs` (source resolution) because activating a
//! running daemon over IPC is a distinct concern from resolving a source.

/// After a manual `astrid capsule install` / `update`, ask a running daemon to
/// hot-load each just-installed capsule so it becomes usable WITHOUT a restart.
///
/// For each id, sends `KernelRequest::ReloadCapsule { id }`, which the daemon
/// resolves as add-or-restart: an already-loaded capsule is hot-swapped to the
/// new on-disk bytes (a live upgrade), otherwise it is loaded fresh. Either way
/// the daemon publishes `astrid.v1.capsules_loaded`, which the `astrid mcp serve`
/// shim turns into an MCP `notifications/tools/list_changed`, so a connected
/// agent sees the change live.
///
/// Best-effort and non-fatal by design. The on-disk install is standalone, so a
/// missing/unreachable daemon is silent (the capsule activates on the next daemon
/// start) and a declined/timed-out reload only prints a note. Never changes the
/// install's exit status.
pub(crate) async fn nudge_daemon_reload(capsule_ids: &[String]) {
    use astrid_core::kernel_api::{KernelRequest, KernelResponse};

    if capsule_ids.is_empty() {
        return;
    }
    // No socket file => no daemon to nudge. Stay silent: the standalone install
    // already reported success, and the capsule loads on the next daemon start.
    if !crate::socket_client::proxy_socket_path().exists() {
        return;
    }

    // One fresh session UUID, used for BOTH the connection's SessionId and each
    // message source_id, so these requests are attributed to a real client
    // session — never the reserved nil UUID, which is SYSTEM_SESSION_UUID.
    let session_uuid = uuid::Uuid::new_v4();
    let session = astrid_core::SessionId::from_uuid(session_uuid);
    let Ok(mut client) =
        crate::socket_client::SocketClient::connect(session, crate::principal::current()).await
    else {
        // Socket present but unreachable (e.g. a hung/stale daemon). Leave the
        // install standalone rather than failing it.
        return;
    };

    for id in capsule_ids {
        let Ok(val) = serde_json::to_value(KernelRequest::ReloadCapsule { id: id.clone() }) else {
            continue;
        };
        // Per-request correlation suffix: the kernel router mirrors the
        // request-topic suffix onto the response topic, so a slow or timed-out
        // reload's late response can never be mis-read as the next capsule's
        // response in this loop.
        let correlation = uuid::Uuid::new_v4().simple().to_string();
        let request_topic = astrid_types::Topic::reload_capsule_request(&correlation);
        let response_topic = astrid_types::Topic::reload_capsule_response(&correlation);
        let msg = astrid_types::ipc::IpcMessage::new(
            request_topic,
            astrid_types::ipc::IpcPayload::RawJson(val),
            session_uuid,
        );
        if client.send_message(msg).await.is_err() {
            continue;
        }

        // Confirm the daemon reloaded (it replies only after the load completes),
        // so the line we print is truthful. A timeout is non-fatal.
        let Ok(raw) = client
            .read_until_topic(response_topic.as_str(), std::time::Duration::from_secs(15))
            .await
        else {
            eprintln!(
                "Note: installed '{id}' to disk, but the running daemon didn't confirm a live reload in time — it will load on the next daemon start."
            );
            continue;
        };

        match crate::socket_client::SocketClient::extract_kernel_response(&raw) {
            Some(KernelResponse::Success(_)) => {
                eprintln!("Live: the running daemon loaded '{id}' — no restart needed.");
            },
            Some(KernelResponse::Error(reason)) => {
                eprintln!(
                    "Note: installed '{id}' to disk, but the daemon declined a live reload ({reason}); it will load on the next daemon start."
                );
            },
            _ => {
                eprintln!(
                    "Note: installed '{id}' to disk, but couldn't confirm a live reload; it will load on the next daemon start."
                );
            },
        }
    }
}

/// After a manual `astrid capsule remove`, ask a running daemon to unload the
/// just-removed capsule so it leaves the live tool surface WITHOUT a restart.
///
/// Sends `KernelRequest::UnloadCapsule { id }`, which unregisters the capsule
/// from the running daemon and publishes `astrid.v1.capsules_loaded`; the
/// `astrid mcp serve` shim turns that into an MCP `notifications/tools/list_changed`,
/// so a connected agent sees the capsule's tools disappear live.
///
/// Best-effort and non-fatal by design, mirroring [`nudge_daemon_reload`]. The
/// on-disk removal is authoritative and already done (and dependency-checked),
/// so a missing/unreachable daemon is silent, a capsule that was never loaded
/// live is a quiet no-op, and a declined/timed-out unload only prints a note.
/// Never changes the remove's exit status.
pub(crate) async fn nudge_daemon_unload(capsule_id: &str) {
    use astrid_core::kernel_api::{KernelRequest, KernelResponse};

    if capsule_id.is_empty() {
        return;
    }
    // No socket file => no daemon to nudge. Stay silent: the standalone remove
    // already reported success and there is no live instance to unload.
    if !crate::socket_client::proxy_socket_path().exists() {
        return;
    }

    // One fresh session UUID, used for BOTH the connection's SessionId and the
    // message source_id, so this request is attributed to a real client session
    // — never the reserved nil UUID, which is SYSTEM_SESSION_UUID.
    let session_uuid = uuid::Uuid::new_v4();
    let session = astrid_core::SessionId::from_uuid(session_uuid);
    let Ok(mut client) =
        crate::socket_client::SocketClient::connect(session, crate::principal::current()).await
    else {
        // Socket present but unreachable (e.g. a hung/stale daemon). Leave the
        // remove standalone rather than failing it.
        return;
    };

    let Ok(val) = serde_json::to_value(KernelRequest::UnloadCapsule {
        id: capsule_id.to_string(),
    }) else {
        return;
    };
    // Per-request correlation suffix: the kernel router mirrors the request-topic
    // suffix onto the response topic, so a slow or timed-out unload's late
    // response can't be mis-read as some other request's response.
    let correlation = uuid::Uuid::new_v4().simple().to_string();
    let request_topic =
        astrid_types::Topic::kernel_request(format!("unload_capsule.{correlation}"));
    let response_topic =
        astrid_types::Topic::kernel_response(format!("unload_capsule.{correlation}"));
    let msg = astrid_types::ipc::IpcMessage::new(
        request_topic,
        astrid_types::ipc::IpcPayload::RawJson(val),
        session_uuid,
    );
    if client.send_message(msg).await.is_err() {
        return;
    }

    // Confirm the daemon processed the unload (it replies only after the unload
    // completes), so the line we print is truthful. A timeout is non-fatal.
    let Ok(raw) = client
        .read_until_topic(response_topic.as_str(), std::time::Duration::from_secs(15))
        .await
    else {
        eprintln!(
            "Note: removed '{capsule_id}' from disk, but the running daemon didn't confirm a live unload in time — restart it to drop the capsule from the live tool surface."
        );
        return;
    };

    match crate::socket_client::SocketClient::extract_kernel_response(&raw) {
        Some(KernelResponse::Success(data)) => {
            // The daemon distinguishes a real unload ("unloaded") from a no-op
            // ("not_loaded": removed from disk but never loaded live). Only the
            // former changed live state, so only announce that one — a no-op
            // needs no line.
            if data.get("status").and_then(serde_json::Value::as_str) == Some("unloaded") {
                eprintln!("Live: the running daemon unloaded '{capsule_id}' — no restart needed.");
            }
        },
        Some(KernelResponse::Error(reason)) => {
            eprintln!(
                "Note: removed '{capsule_id}' from disk, but the daemon declined a live unload ({reason}); restart it to drop the capsule from the live tool surface."
            );
        },
        _ => {
            eprintln!(
                "Note: removed '{capsule_id}' from disk, but couldn't confirm a live unload; restart it to drop the capsule from the live tool surface."
            );
        },
    }
}
