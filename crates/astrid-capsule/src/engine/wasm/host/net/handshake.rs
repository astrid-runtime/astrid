//! Inbound socket handshake: protocol-version + session-token verification
//! and peer-UID credential check. Used by `net-accept` / `net-poll-accept`
//! before an authenticated stream is exposed to the WASM guest.

use astrid_core::session_token::{
    HandshakeRequest, HandshakeResponse, PROTOCOL_VERSION, SessionToken,
};

/// Timeout for individual handshake read/write operations (server-side).
pub(super) const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Maximum allowed size of a handshake request payload (bytes).
const MAX_HANDSHAKE_SIZE: usize = 4096;

/// Validate the client handshake: read the `HandshakeRequest`, verify the token
/// and protocol version, then send back a `HandshakeResponse`.
///
/// Returns `Ok(())` on success or `Err(reason)` with a human-readable rejection
/// reason.
pub(super) async fn validate_handshake(
    stream: &mut tokio::net::UnixStream,
    expected_token: &SessionToken,
) -> Result<(), String> {
    use tokio::io::AsyncReadExt;

    // 1. Read the handshake request (length-prefixed JSON, same wire format).
    let mut len_buf = [0u8; 4];
    tokio::time::timeout(HANDSHAKE_TIMEOUT, stream.read_exact(&mut len_buf))
        .await
        .map_err(|_| "handshake timed out (5s)".to_string())?
        .map_err(|e| format!("handshake read error: {e}"))?;

    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_HANDSHAKE_SIZE {
        return Err(format!("handshake too large: {len} bytes"));
    }

    let mut payload = vec![0u8; len];
    tokio::time::timeout(HANDSHAKE_TIMEOUT, stream.read_exact(&mut payload))
        .await
        .map_err(|_| "handshake payload timed out".to_string())?
        .map_err(|e| format!("handshake payload read error: {e}"))?;

    let request: HandshakeRequest =
        serde_json::from_slice(&payload).map_err(|e| format!("invalid handshake JSON: {e}"))?;

    // 2. Validate protocol version FIRST - this check reveals no information
    // about token validity. Checking version before token prevents an oracle
    // where a "protocol mismatch" response confirms the token was correct.
    if request.protocol_version != PROTOCOL_VERSION {
        let reason = format!(
            "Protocol version mismatch (client={}, server={}). \
             Restart the daemon with `astrid daemon restart`.",
            request.protocol_version, PROTOCOL_VERSION,
        );
        if let Err(e) =
            send_handshake_response_timed(stream, &HandshakeResponse::error(&reason)).await
        {
            tracing::warn!(error = %e, "Failed to send handshake error response for protocol mismatch");
        }
        return Err(reason);
    }

    // 3. Validate token (constant-time comparison).
    // Send a uniform error response on both malformed-hex and wrong-token
    // paths to prevent an oracle that distinguishes the two failure modes.
    let client_token = match SessionToken::from_hex(&request.token) {
        Ok(t) => t,
        Err(_) => {
            if let Err(e) = send_handshake_response_timed(
                stream,
                &HandshakeResponse::error("authentication failed"),
            )
            .await
            {
                tracing::warn!(error = %e, "Failed to send handshake error response");
            }
            return Err("invalid session token".to_string());
        },
    };

    if !expected_token.ct_eq(&client_token) {
        if let Err(e) = send_handshake_response_timed(
            stream,
            &HandshakeResponse::error("authentication failed"),
        )
        .await
        {
            tracing::warn!(error = %e, "Failed to send handshake error response");
        }
        return Err("invalid session token".to_string());
    }

    // 4. All checks passed - send success response.
    send_handshake_response_timed(stream, &HandshakeResponse::ok())
        .await
        .map_err(|e| format!("failed to send handshake response: {e}"))?;

    // Truncate client_version to prevent log injection from oversized values.
    // Use chars().take() to avoid panicking on multi-byte UTF-8 boundaries.
    let safe_version: String = request.client_version.chars().take(64).collect();
    tracing::info!(
        client_version = %safe_version,
        "Socket handshake succeeded"
    );
    Ok(())
}

/// Send a length-prefixed JSON handshake response with a 5s write timeout.
///
/// Wraps [`send_handshake_response`] with a timeout to prevent a stalled
/// client from holding the accept loop hostage during the response write.
async fn send_handshake_response_timed(
    stream: &mut tokio::net::UnixStream,
    response: &HandshakeResponse,
) -> Result<(), std::io::Error> {
    tokio::time::timeout(HANDSHAKE_TIMEOUT, send_handshake_response(stream, response))
        .await
        .map_err(|_| std::io::Error::other("handshake response write timed out (5s)"))?
}

/// Send a length-prefixed JSON handshake response.
async fn send_handshake_response(
    stream: &mut tokio::net::UnixStream,
    response: &HandshakeResponse,
) -> Result<(), std::io::Error> {
    use tokio::io::AsyncWriteExt;

    let bytes = serde_json::to_vec(response)
        .map_err(|e| std::io::Error::other(format!("serialize handshake response: {e}")))?;
    let len = u32::try_from(bytes.len())
        .map_err(|_| std::io::Error::other("handshake response too large"))?;

    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(&bytes).await?;
    stream.flush().await?;
    Ok(())
}

/// Verify that the connecting process runs as the same UID as the daemon.
/// Returns `Err(reason)` if the UID does not match or credentials cannot
/// be retrieved.
#[cfg(unix)]
pub(super) fn verify_peer_credentials(stream: &tokio::net::UnixStream) -> Result<(), String> {
    match stream.peer_cred() {
        Ok(cred) => {
            let peer_uid = cred.uid();
            let my_uid = nix::unistd::geteuid().as_raw();
            if peer_uid != my_uid {
                Err(format!(
                    "peer UID {peer_uid} does not match daemon UID {my_uid}"
                ))
            } else {
                Ok(())
            }
        },
        Err(e) => Err(format!("failed to check peer credentials: {e}")),
    }
}
