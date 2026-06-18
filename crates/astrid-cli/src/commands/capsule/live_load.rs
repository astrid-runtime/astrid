//! Live-load nudge — make a fresh `astrid capsule install` usable without a
//! daemon restart.
//!
//! Installing a capsule writes it to disk through a deliberately standalone,
//! daemon-independent path (it must work with no daemon running). This module
//! adds the *optional* second half: when a daemon happens to be up, ask it to
//! hot-load the just-installed capsule so it's immediately usable. It is kept
//! separate from `install.rs` (source resolution) because activating a running
//! daemon over IPC is a distinct concern from resolving and unpacking a source.

/// After a manual `astrid capsule install`, ask a running daemon to hot-load the
/// just-installed capsule so it becomes usable WITHOUT a restart.
///
/// Best-effort and non-fatal by design. The on-disk install is standalone, so
/// this only adds live activation when a daemon is reachable:
///
/// * No daemon socket / unreachable daemon -> do nothing, silently. The capsule
///   activates on the next daemon start.
/// * Reachable daemon -> send `KernelRequest::ReloadCapsules`, which re-scans the
///   install directory and loads any newly-present capsule. Loading publishes
///   `astrid.v1.capsules_loaded`, which the `astrid mcp serve` shim turns into an
///   MCP `notifications/tools/list_changed`, so a connected agent sees the new
///   tools live.
///
/// Scope: this loads a newly-installed capsule. Re-installing a capsule that is
/// already loaded (same id) is skipped by the loader's already-registered guard,
/// so swapping an already-loaded capsule's code still needs a restart — in-place
/// live upgrade is a separate, later change. Never changes the install's exit
/// status — a failed nudge leaves a successful on-disk install.
pub(crate) async fn nudge_daemon_reload() {
    use astrid_core::kernel_api::{KernelRequest, KernelResponse};

    // No socket file => no daemon to nudge. Stay silent: the standalone install
    // already reported success, and the capsule loads on the next daemon start.
    if !crate::socket_client::proxy_socket_path().exists() {
        return;
    }

    // One fresh session UUID, used for BOTH the connection's SessionId and the
    // message source_id, so this request is attributed to a real client session
    // — never the reserved nil UUID, which is SYSTEM_SESSION_UUID (internal /
    // daemon messages). A client-initiated, capability-gated request must not
    // claim the system session.
    let session_uuid = uuid::Uuid::new_v4();
    let session = astrid_core::SessionId::from_uuid(session_uuid);
    let Ok(mut client) =
        crate::socket_client::SocketClient::connect(session, crate::principal::current()).await
    else {
        // Socket present but unreachable (e.g. a hung/stale daemon). Leave the
        // install standalone rather than failing it.
        return;
    };

    let Ok(val) = serde_json::to_value(KernelRequest::ReloadCapsules) else {
        return;
    };
    let msg = astrid_types::ipc::IpcMessage::new(
        "astrid.v1.request.reload_capsules",
        astrid_types::ipc::IpcPayload::RawJson(val),
        session_uuid,
    );
    if client.send_message(msg).await.is_err() {
        return;
    }

    // Confirm the daemon actually reloaded (it replies only after the load
    // completes), so the line we print is truthful. A timeout is non-fatal.
    let Ok(raw) = client
        .read_until_topic(
            "astrid.v1.response.reload_capsules",
            std::time::Duration::from_secs(15),
        )
        .await
    else {
        eprintln!(
            "Note: installed to disk, but the running daemon didn't confirm a live reload in time — the capsule will load on the next daemon start."
        );
        return;
    };

    match crate::socket_client::SocketClient::extract_kernel_response(&raw) {
        Some(KernelResponse::Success(_)) => {
            eprintln!("Live: the running daemon picked up the new capsule — no restart needed.");
        },
        Some(KernelResponse::Error(reason)) => {
            eprintln!(
                "Note: installed to disk, but the daemon declined a live reload ({reason}); the capsule will load on the next daemon start."
            );
        },
        _ => {
            eprintln!(
                "Note: installed to disk, but couldn't confirm a live reload; the capsule will load on the next daemon start."
            );
        },
    }
}
