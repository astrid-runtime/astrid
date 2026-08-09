//! Server side of the local-transport authentication protocol.

use astrid_core::PrincipalId;
use astrid_core::dirs::AstridHome;
use astrid_core::local_transport::{self, LocalStream};
use astrid_core::profile::DeviceKey;
use astrid_core::session_token::{
    HandshakeRequest, HandshakeResponse, PRINCIPAL_AUTH_NONCE_LEN, PROTOCOL_VERSION, SessionToken,
    principal_auth_challenge_message,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const MAX_HANDSHAKE_SIZE: usize = 4096;

/// Identity established for one accepted local connection.
#[derive(Debug, Clone)]
pub struct AuthenticatedIdentity {
    /// Cryptographically verified principal, or `anonymous` for the legacy
    /// token-only handshake.
    pub principal: PrincipalId,
    /// Fingerprint of the device key that signed the challenge.
    pub device_key_id: Option<String>,
}

impl AuthenticatedIdentity {
    /// Whether this connection proved a principal key rather than only
    /// possession of the daemon's session token.
    #[must_use]
    pub fn is_principal_verified(&self) -> bool {
        self.device_key_id.is_some()
    }
}

/// Authenticate an accepted host-local stream.
///
/// Same-user peer credentials are mandatory. The session token is checked in
/// constant time and an optional principal claim must complete the existing
/// signed challenge protocol. A token-only legacy peer is deliberately bound
/// to the no-capability `anonymous` principal.
pub async fn authenticate(
    stream: &mut LocalStream,
    expected_token: &SessionToken,
    home: &AstridHome,
) -> Result<AuthenticatedIdentity, String> {
    verify_peer_credentials(stream)?;
    let verified = validate_handshake(stream, expected_token, home).await?;
    Ok(match verified {
        Some((principal, device_key_id)) => AuthenticatedIdentity {
            principal,
            device_key_id: Some(device_key_id),
        },
        None => AuthenticatedIdentity {
            principal: PrincipalId::anonymous(),
            device_key_id: None,
        },
    })
}

async fn validate_handshake<S>(
    stream: &mut S,
    expected_token: &SessionToken,
    home: &AstridHome,
) -> Result<Option<(PrincipalId, String)>, String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = read_request(stream).await?;
    if request.protocol_version != PROTOCOL_VERSION {
        let reason = format!(
            "Protocol version mismatch (client={}, server={}). Restart the daemon with `astrid restart`.",
            request.protocol_version, PROTOCOL_VERSION,
        );
        let _ = send_response(stream, &HandshakeResponse::error(&reason)).await;
        return Err(reason);
    }

    let Ok(client_token) = SessionToken::from_hex(&request.token) else {
        send_auth_failed(stream).await;
        return Err("invalid session token".to_string());
    };
    if !expected_token.ct_eq(&client_token) {
        send_auth_failed(stream).await;
        return Err("invalid session token".to_string());
    }

    let verified = match request.claimed_principal.as_deref() {
        Some(claimed) => Some(run_principal_challenge(stream, claimed, home).await?),
        None => None,
    };
    send_response(stream, &HandshakeResponse::ok())
        .await
        .map_err(|error| format!("failed to send handshake response: {error}"))?;
    let safe_version: String = request.client_version.chars().take(64).collect();
    tracing::info!(
        client_version = %safe_version,
        authenticated = verified.is_some(),
        "Socket handshake succeeded"
    );
    Ok(verified)
}

async fn read_request<S>(stream: &mut S) -> Result<HandshakeRequest, String>
where
    S: AsyncRead + Unpin,
{
    let mut len_buf = [0_u8; 4];
    tokio::time::timeout(HANDSHAKE_TIMEOUT, stream.read_exact(&mut len_buf))
        .await
        .map_err(|_| "handshake timed out (5s)".to_string())?
        .map_err(|error| format!("handshake read error: {error}"))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_HANDSHAKE_SIZE {
        return Err(format!("handshake too large: {len} bytes"));
    }
    let mut payload = vec![0_u8; len];
    tokio::time::timeout(HANDSHAKE_TIMEOUT, stream.read_exact(&mut payload))
        .await
        .map_err(|_| "handshake payload timed out".to_string())?
        .map_err(|error| format!("handshake payload read error: {error}"))?;
    serde_json::from_slice(&payload).map_err(|error| format!("invalid handshake JSON: {error}"))
}

async fn run_principal_challenge<S>(
    stream: &mut S,
    claimed: &str,
    home: &AstridHome,
) -> Result<(PrincipalId, String), String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let principal = match PrincipalId::new(claimed) {
        Ok(principal) => principal,
        Err(error) => {
            send_auth_failed(stream).await;
            return Err(format!("invalid claimed principal: {error}"));
        },
    };
    let nonce_hex = generate_nonce_hex()?;
    send_response(stream, &HandshakeResponse::challenge(nonce_hex.clone()))
        .await
        .map_err(|error| format!("failed to send challenge: {error}"))?;

    let signed = read_request(stream).await?;
    if signed.claimed_principal.as_deref() != Some(principal.as_str()) {
        send_auth_failed(stream).await;
        return Err("principal changed during handshake".to_string());
    }
    let Some(signature_hex) = signed.signature else {
        send_auth_failed(stream).await;
        return Err("missing signature in second handshake frame".to_string());
    };
    match verify_signature(&principal, &nonce_hex, &signature_hex, home) {
        Ok(key_id) => Ok((principal, key_id)),
        Err(reason) => {
            send_auth_failed(stream).await;
            Err(reason)
        },
    }
}

fn verify_signature(
    principal: &PrincipalId,
    nonce_hex: &str,
    signature_hex: &str,
    home: &AstridHome,
) -> Result<String, String> {
    let profile = astrid_core::PrincipalProfile::load(home, principal)
        .map_err(|error| format!("cannot load principal profile: {error}"))?;
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

fn verify_signature_against_keys(
    principal: &PrincipalId,
    public_keys: &[DeviceKey],
    nonce_hex: &str,
    signature_hex: &str,
) -> Result<String, String> {
    let signature = astrid_crypto::Signature::from_hex(signature_hex)
        .map_err(|error| format!("malformed signature: {error}"))?;
    let message = principal_auth_challenge_message(principal.as_str(), nonce_hex);
    for key in public_keys {
        let Ok(pubkey) = key.typed_pubkey() else {
            continue;
        };
        let Ok(public_key) = astrid_crypto::PublicKey::from_hex(pubkey.as_str()) else {
            continue;
        };
        if public_key.verify(message.as_bytes(), &signature).is_ok() {
            return Ok(key.key_id.clone());
        }
    }
    if public_keys.is_empty() {
        Err(format!(
            "principal {principal} has no registered ed25519 key"
        ))
    } else {
        Err(format!(
            "signature did not verify against any registered key for {principal}"
        ))
    }
}

fn generate_nonce_hex() -> Result<String, String> {
    use rand::{TryRng, rngs::SysRng};
    let mut nonce = [0_u8; PRINCIPAL_AUTH_NONCE_LEN];
    SysRng
        .try_fill_bytes(&mut nonce)
        .map_err(|error| format!("entropy source unavailable: {error}"))?;
    Ok(hex::encode(nonce))
}

async fn send_auth_failed<S>(stream: &mut S)
where
    S: AsyncWrite + Unpin,
{
    if let Err(error) =
        send_response(stream, &HandshakeResponse::error("authentication failed")).await
    {
        tracing::warn!(%error, "failed to send handshake error response");
    }
}

async fn send_response<S>(
    stream: &mut S,
    response: &HandshakeResponse,
) -> Result<(), std::io::Error>
where
    S: AsyncWrite + Unpin,
{
    tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        let bytes = serde_json::to_vec(response)
            .map_err(|error| std::io::Error::other(format!("serialize handshake: {error}")))?;
        let len = u32::try_from(bytes.len())
            .map_err(|_| std::io::Error::other("handshake response too large"))?;
        stream.write_all(&len.to_be_bytes()).await?;
        stream.write_all(&bytes).await?;
        stream.flush().await
    })
    .await
    .map_err(|_| std::io::Error::other("handshake response write timed out (5s)"))?
}

fn verify_peer_credentials(stream: &LocalStream) -> Result<(), String> {
    match local_transport::peer_is_current_user(stream) {
        Ok(true) => Ok(()),
        Ok(false) => Err("peer operating-system user does not match daemon user".to_string()),
        Err(error) => Err(format!("failed to check peer credentials: {error}")),
    }
}

#[cfg(test)]
mod tests {
    use astrid_core::profile::DeviceScope;
    use astrid_core::session_token::principal_auth_challenge_message;
    use tokio::io::{AsyncRead, AsyncWrite};

    use super::*;

    fn full_device(keypair: &astrid_crypto::KeyPair) -> DeviceKey {
        DeviceKey::new(
            keypair.export_public_key().to_hex(),
            DeviceScope::Full,
            None,
            0,
        )
    }

    fn home_with_key(
        principal: &PrincipalId,
        keypair: &astrid_crypto::KeyPair,
    ) -> (tempfile::TempDir, AstridHome) {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = AstridHome::from_path(temp.path());
        let mut profile = astrid_core::PrincipalProfile::default();
        profile.auth.public_keys.push(full_device(keypair));
        profile
            .auth
            .methods
            .push(astrid_core::profile::AuthMethod::Keypair);
        let path = astrid_core::PrincipalProfile::path_for(&home, principal);
        std::fs::create_dir_all(path.parent().expect("profile parent"))
            .expect("create profile dir");
        profile.save_to_path(&path).expect("save profile");
        (temp, home)
    }

    async fn exchange<S>(stream: &mut S, request: &HandshakeRequest) -> HandshakeResponse
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let bytes = serde_json::to_vec(request).expect("serialize request");
        let len = u32::try_from(bytes.len()).expect("bounded request");
        stream
            .write_all(&len.to_be_bytes())
            .await
            .expect("write len");
        stream.write_all(&bytes).await.expect("write request");
        stream.flush().await.expect("flush request");
        let mut len_buf = [0_u8; 4];
        stream.read_exact(&mut len_buf).await.expect("read len");
        let mut response = vec![0_u8; u32::from_be_bytes(len_buf) as usize];
        stream
            .read_exact(&mut response)
            .await
            .expect("read response");
        serde_json::from_slice(&response).expect("parse response")
    }

    #[tokio::test]
    async fn signed_handshake_returns_principal_and_device() {
        let principal = PrincipalId::new("alice").expect("principal");
        let keypair = astrid_crypto::KeyPair::generate();
        let (_temp, home) = home_with_key(&principal, &keypair);
        let token = SessionToken::generate();
        let token_hex = token.to_hex();
        let (mut server, mut client) = tokio::io::duplex(16 * 1024);
        let task =
            tokio::spawn(async move { validate_handshake(&mut server, &token, &home).await });

        let first = HandshakeRequest {
            token: token_hex.clone(),
            protocol_version: PROTOCOL_VERSION,
            client_version: "test".to_owned(),
            claimed_principal: Some(principal.to_string()),
            signature: None,
        };
        let challenge = exchange(&mut client, &first)
            .await
            .challenge
            .expect("challenge");
        let signed_message = principal_auth_challenge_message(principal.as_str(), &challenge);
        let second = HandshakeRequest {
            token: token_hex,
            protocol_version: PROTOCOL_VERSION,
            client_version: "test".to_owned(),
            claimed_principal: Some(principal.to_string()),
            signature: Some(keypair.sign(signed_message.as_bytes()).to_hex()),
        };
        assert!(exchange(&mut client, &second).await.is_ok());
        let identity = task.await.expect("server task").expect("valid handshake");
        assert_eq!(identity, Some((principal, full_device(&keypair).key_id)));
    }

    #[tokio::test]
    async fn principal_cannot_change_between_handshake_frames() {
        let principal = PrincipalId::new("alice").expect("principal");
        let keypair = astrid_crypto::KeyPair::generate();
        let (_temp, home) = home_with_key(&principal, &keypair);
        let token = SessionToken::generate();
        let token_hex = token.to_hex();
        let (mut server, mut client) = tokio::io::duplex(16 * 1024);
        let task =
            tokio::spawn(async move { validate_handshake(&mut server, &token, &home).await });
        let first = HandshakeRequest {
            token: token_hex.clone(),
            protocol_version: PROTOCOL_VERSION,
            client_version: "test".to_owned(),
            claimed_principal: Some(principal.to_string()),
            signature: None,
        };
        let challenge = exchange(&mut client, &first)
            .await
            .challenge
            .expect("challenge");
        let signed_message = principal_auth_challenge_message(principal.as_str(), &challenge);
        let second = HandshakeRequest {
            token: token_hex,
            protocol_version: PROTOCOL_VERSION,
            client_version: "test".to_owned(),
            claimed_principal: Some("bob".to_owned()),
            signature: Some(keypair.sign(signed_message.as_bytes()).to_hex()),
        };
        assert!(!exchange(&mut client, &second).await.is_ok());
        assert!(task.await.expect("server task").is_err());
    }
}
