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
    // A stale socket is still an offline install. Probe reachability without an
    // authenticated handshake before the workspace checks so missing readiness
    // metadata cannot turn an unreachable daemon into a 60-second wait.
    if !daemon_socket_reachable().await {
        return;
    }
    // One fresh session UUID, used for BOTH the connection's SessionId and each
    // message source_id, so these requests are attributed to a real client
    // session — never the reserved nil UUID, which is SYSTEM_SESSION_UUID.
    let session_uuid = uuid::Uuid::new_v4();
    let session = astrid_core::SessionId::from_uuid(session_uuid);
    let mut client = match classify_live_client(
        crate::socket_client::connect_for_workspace(session, crate::principal::current(), None)
            .await,
    ) {
        Ok(Some(client)) => client,
        Ok(None) => return,
        Err(error) => {
            eprintln!("Note: installed capsules to disk, but skipped live reload because {error}.");
            return;
        },
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LiveUnload {
    NoDaemon,
    NotLoaded,
    Unloaded,
}

/// Ask a running daemon to unload `capsule_id`.
///
/// Missing or unreachable daemon sockets return [`LiveUnload::NoDaemon`] so
/// offline local removal still works. Once connected, the daemon must
/// authorize and confirm the unload before the caller can delete disk state.
pub(crate) async fn try_daemon_unload(capsule_id: &str) -> anyhow::Result<LiveUnload> {
    use anyhow::{Context, bail};
    use astrid_core::kernel_api::{KernelRequest, KernelResponse};

    if capsule_id.is_empty() || !daemon_socket_reachable().await {
        return Ok(LiveUnload::NoDaemon);
    }
    let session_uuid = uuid::Uuid::new_v4();
    let session = astrid_core::SessionId::from_uuid(session_uuid);
    let Some(mut client) = classify_live_client(
        crate::socket_client::connect_for_workspace(session, crate::principal::current(), None)
            .await,
    )
    .context("refusing to unload from a daemon with a different workspace selection")?
    else {
        return Ok(LiveUnload::NoDaemon);
    };

    let val = serde_json::to_value(KernelRequest::UnloadCapsule {
        id: capsule_id.to_string(),
    })
    .context("failed to encode live capsule unload request")?;
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
    client
        .send_message(msg)
        .await
        .context("failed to send live capsule unload request")?;

    let raw = client
        .read_until_topic(response_topic.as_str(), std::time::Duration::from_secs(15))
        .await
        .context("running daemon did not confirm live capsule unload")?;

    match crate::socket_client::SocketClient::extract_kernel_response(&raw) {
        Some(KernelResponse::Success(data)) => {
            match data.get("status").and_then(serde_json::Value::as_str) {
                Some("unloaded") => Ok(LiveUnload::Unloaded),
                Some("not_loaded") => Ok(LiveUnload::NotLoaded),
                Some(other) => bail!("running daemon returned unknown unload status {other:?}"),
                None => bail!("running daemon returned unload success without a status"),
            }
        },
        Some(KernelResponse::Error(reason)) => {
            bail!("running daemon declined live capsule unload: {reason}")
        },
        _ => bail!("running daemon returned a malformed live capsule unload response"),
    }
}

async fn daemon_socket_reachable() -> bool {
    let path = crate::socket_client::proxy_socket_path();
    path.exists() && tokio::net::UnixStream::connect(path).await.is_ok()
}

fn classify_live_client<T>(
    result: crate::socket_client::WorkspaceConnectionResult<T>,
) -> anyhow::Result<Option<T>> {
    match result {
        Ok(client) => Ok(Some(client)),
        Err(crate::socket_client::WorkspaceConnectionError::Connect(_)) => Ok(None),
        Err(crate::socket_client::WorkspaceConnectionError::Selection(error)) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::classify_live_client;
    use crate::socket_client::WorkspaceConnectionError;

    #[test]
    fn live_client_classification_keeps_offline_and_mismatch_distinct() {
        assert!(
            classify_live_client::<()>(Err(WorkspaceConnectionError::Connect(anyhow::anyhow!(
                "unreachable socket"
            ))))
            .unwrap()
            .is_none()
        );
        assert!(
            classify_live_client::<()>(Err(WorkspaceConnectionError::Selection(anyhow::anyhow!(
                "workspace mismatch"
            ))))
            .is_err()
        );
    }
}
