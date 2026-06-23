//! Inbound socket handshake: protocol-version + session-token verification,
//! peer-UID credential check, and the OPTIONAL per-connection principal
//! challenge-response (issue #45/#852). Used by `net-accept` /
//! `net-poll-accept` before an authenticated stream is exposed to the WASM
//! guest.
//!
//! ## Two-frame principal authentication (additive)
//!
//! The base handshake is a single round trip: the client sends a
//! [`HandshakeRequest`] with the session token, the daemon replies with a
//! [`HandshakeResponse`]. A client that wants to authenticate as a specific
//! principal sets [`HandshakeRequest::claimed_principal`] on that first
//! frame (no signature yet). The daemon then:
//!
//! 1. validates protocol version + token on the first frame (unchanged);
//! 2. if a principal was claimed, generates a random nonce and sends it back
//!    in [`HandshakeResponse::challenge`] — an intermediate `Ok` response;
//! 3. reads a SECOND request frame carrying
//!    [`HandshakeRequest::signature`] over
//!    `astrid-principal-auth:v1:{principal}:{nonce_hex}`;
//! 4. verifies the signature against a key registered in the claimed
//!    principal's `AuthConfig.public_keys`, then sends the final response.
//!
//! A first frame WITHOUT `claimed_principal` skips steps 2–4 entirely and
//! completes in the legacy single round trip with NO verified principal —
//! so legacy clients and legacy daemons keep interoperating.
//!
//! Fail-closed: a claimed principal with an INVALID (or absent-second-frame)
//! signature FAILS the handshake. A bad signature is an attack, not a
//! fallback to unauthenticated.

use astrid_core::principal::PrincipalId;
use astrid_core::profile::DeviceKey;
use astrid_core::session_token::{
    HandshakeRequest, HandshakeResponse, PRINCIPAL_AUTH_NONCE_LEN, PROTOCOL_VERSION, SessionToken,
    principal_auth_challenge_message,
};

/// Timeout for individual handshake read/write operations (server-side).
pub(super) const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Maximum allowed size of a handshake request payload (bytes).
const MAX_HANDSHAKE_SIZE: usize = 4096;

/// Validate the client handshake: read the [`HandshakeRequest`], verify the
/// token and protocol version, optionally run the principal
/// challenge-response, then send back a [`HandshakeResponse`].
///
/// `home` is where the claimed principal's profile (and its registered
/// keys) is loaded from — passed in rather than resolved internally so the
/// challenge path is unit-testable against a tempdir-backed home (the crate
/// is `#![deny(unsafe_code)]`, so env mutation in tests is impossible).
///
/// Returns `Ok(Some((principal, key_id)))` when the client signed a valid
/// challenge for a registered key (`key_id` is the matched [`DeviceKey`]'s
/// fingerprint, carried forward so the cap-gate can apply that device's
/// scope), `Ok(None)` for a legacy/unauthenticated handshake, or
/// `Err(reason)` with a human-readable rejection reason.
pub(super) async fn validate_handshake(
    stream: &mut tokio::net::UnixStream,
    expected_token: &SessionToken,
    home: &astrid_core::dirs::AstridHome,
) -> Result<Option<(PrincipalId, String)>, String> {
    let request = read_handshake_request(stream).await?;

    // 1. Validate protocol version FIRST - this check reveals no information
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

    // 2. Validate token (constant-time comparison).
    // Send a uniform error response on both malformed-hex and wrong-token
    // paths to prevent an oracle that distinguishes the two failure modes.
    let client_token = match SessionToken::from_hex(&request.token) {
        Ok(t) => t,
        Err(_) => {
            send_auth_failed(stream).await;
            return Err("invalid session token".to_string());
        },
    };

    if !expected_token.ct_eq(&client_token) {
        send_auth_failed(stream).await;
        return Err("invalid session token".to_string());
    }

    // 3. Optional per-connection principal challenge-response. A claimed
    // principal restructures the flow into two frames; absence keeps the
    // legacy single round trip.
    let verified_principal = match request.claimed_principal.clone() {
        Some(claimed) => Some(run_principal_challenge(stream, &claimed, home).await?),
        None => None,
    };

    // 4. All checks passed - send the final success response.
    send_handshake_response_timed(stream, &HandshakeResponse::ok())
        .await
        .map_err(|e| format!("failed to send handshake response: {e}"))?;

    // Truncate client_version to prevent log injection from oversized values.
    // Use chars().take() to avoid panicking on multi-byte UTF-8 boundaries.
    let safe_version: String = request.client_version.chars().take(64).collect();
    tracing::info!(
        client_version = %safe_version,
        authenticated = verified_principal.is_some(),
        "Socket handshake succeeded"
    );
    Ok(verified_principal)
}

/// Read one length-prefixed JSON [`HandshakeRequest`] frame off the stream.
async fn read_handshake_request(
    stream: &mut tokio::net::UnixStream,
) -> Result<HandshakeRequest, String> {
    use tokio::io::AsyncReadExt;

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

    serde_json::from_slice(&payload).map_err(|e| format!("invalid handshake JSON: {e}"))
}

/// Run the challenge-response for a client that claimed `claimed` as its
/// principal: issue a random nonce, read the signed second frame, and verify
/// the signature against a registered key.
///
/// Returns the verified [`PrincipalId`] paired with the `key_id` of the
/// matched [`DeviceKey`] on success, or `Err(reason)` on any failure
/// (unknown/disabled principal, missing/invalid signature). Sends an
/// `authentication failed` response before returning an error so the client
/// observes a uniform rejection. The `key_id` carries the matched device's
/// identity forward so the cap-gate can apply that device's scope.
async fn run_principal_challenge(
    stream: &mut tokio::net::UnixStream,
    claimed: &str,
    home: &astrid_core::dirs::AstridHome,
) -> Result<(PrincipalId, String), String> {
    // Validate the principal id shape before touching disk so a malformed
    // claim never reaches the filesystem.
    let principal = match PrincipalId::new(claimed) {
        Ok(p) => p,
        Err(e) => {
            send_auth_failed(stream).await;
            return Err(format!("invalid claimed principal: {e}"));
        },
    };

    // Issue the challenge nonce. Source straight from the OS CSPRNG, matching
    // `sys::random_bytes` and `SessionToken::generate`.
    let nonce_hex = match generate_nonce_hex() {
        Ok(n) => n,
        Err(e) => {
            send_auth_failed(stream).await;
            return Err(format!("challenge nonce generation failed: {e}"));
        },
    };
    send_handshake_response_timed(stream, &HandshakeResponse::challenge(nonce_hex.clone()))
        .await
        .map_err(|e| format!("failed to send challenge: {e}"))?;

    // Read the second frame carrying the signature.
    let signed = read_handshake_request(stream).await?;
    let Some(signature_hex) = signed.signature else {
        send_auth_failed(stream).await;
        return Err("missing signature in second handshake frame".to_string());
    };

    // Verify against a key registered on the claimed principal's profile.
    // On success this yields the matched device's `key_id` so the connection
    // can be scoped to that device at the cap-gate.
    let key_id = match verify_principal_signature(&principal, &nonce_hex, &signature_hex, home) {
        Ok(key_id) => key_id,
        Err(reason) => {
            send_auth_failed(stream).await;
            return Err(reason);
        },
    };

    Ok((principal, key_id))
}

/// Verify `signature_hex` over the challenge message for `principal` against
/// a public key registered in that principal's `AuthConfig.public_keys`.
///
/// Loads the principal's profile from the resolved [`AstridHome`] and
/// delegates the pure check to [`verify_signature_against_keys`].
///
/// Returns `Ok(key_id)` — the matched [`DeviceKey`]'s fingerprint — if any
/// registered `ed25519:<hex>` key verifies the signature, `Err(reason)`
/// otherwise. Fail-closed: an unreadable profile, a disabled principal, a
/// principal with no registered keys, or a malformed signature all reject.
fn verify_principal_signature(
    principal: &PrincipalId,
    nonce_hex: &str,
    signature_hex: &str,
    home: &astrid_core::dirs::AstridHome,
) -> Result<String, String> {
    let profile = astrid_core::PrincipalProfile::load(home, principal)
        .map_err(|e| format!("cannot load principal profile: {e}"))?;

    if !profile.enabled {
        return Err(format!("principal {principal} is disabled"));
    }

    verify_signature_against_keys(
        principal,
        &profile.auth.public_keys,
        nonce_hex,
        signature_hex,
    )
}

/// Pure signature check: does `signature_hex` verify the challenge message for
/// `principal` against any registered [`DeviceKey`] in `public_keys`?
///
/// Returns the matched [`DeviceKey::key_id`] on success so the caller can bind
/// the connection to that specific device for scope attenuation at the
/// cap-gate. Separated from profile/disk loading so it is unit-testable
/// without an `AstridHome` or environment. We do NOT short-circuit on the
/// first key whose hex fails to parse — a malformed entry must not block a
/// later valid one. The per-device scope is not consulted here: this gate
/// establishes *which key authenticated the connection*; the scope is applied
/// later at the capability gate once the matched device is known.
fn verify_signature_against_keys(
    principal: &PrincipalId,
    public_keys: &[DeviceKey],
    nonce_hex: &str,
    signature_hex: &str,
) -> Result<String, String> {
    let signature = astrid_crypto::Signature::from_hex(signature_hex)
        .map_err(|e| format!("malformed signature: {e}"))?;

    let message = principal_auth_challenge_message(principal.as_str(), nonce_hex);
    let message_bytes = message.as_bytes();

    let mut saw_key = false;
    for key in public_keys {
        saw_key = true;
        let Ok(public_key) = astrid_crypto::PublicKey::from_hex(&key.pubkey) else {
            continue;
        };
        if public_key.verify(message_bytes, &signature).is_ok() {
            return Ok(key.key_id.clone());
        }
    }

    if saw_key {
        Err(format!(
            "signature did not verify against any registered key for {principal}"
        ))
    } else {
        Err(format!(
            "principal {principal} has no registered ed25519 key"
        ))
    }
}

/// Generate a fresh hex-encoded challenge nonce from the OS CSPRNG.
fn generate_nonce_hex() -> Result<String, String> {
    use rand::RngCore;
    let mut nonce = [0u8; PRINCIPAL_AUTH_NONCE_LEN];
    rand::rngs::OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|e| format!("entropy source unavailable: {e}"))?;
    Ok(hex::encode(nonce))
}

/// Send the uniform `authentication failed` response, logging a write error.
async fn send_auth_failed(stream: &mut tokio::net::UnixStream) {
    if let Err(e) =
        send_handshake_response_timed(stream, &HandshakeResponse::error("authentication failed"))
            .await
    {
        tracing::warn!(error = %e, "Failed to send handshake error response");
    }
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

#[cfg(test)]
#[path = "handshake_tests.rs"]
mod tests;
