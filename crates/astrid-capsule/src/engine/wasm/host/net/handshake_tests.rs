//! Tests for the inbound socket handshake, including the optional
//! per-connection principal challenge-response (issue #45/#852).
//!
//! The protocol tests drive a transport-neutral in-memory byte-stream pair:
//! one half is fed to [`validate_handshake`] (the server), the other is
//! driven by a minimal in-test client that mirrors the production framing in
//! `astrid-uplink`. The claimed principal's profile is written to a
//! tempdir-backed [`AstridHome`] passed explicitly into the handshake, so no
//! process-environment mutation is needed (the crate is
//! `#![deny(unsafe_code)]`).

use super::*;

use astrid_core::dirs::AstridHome;
use astrid_core::profile::{DeviceKey, DeviceScope};
use astrid_core::session_token::{
    HandshakeRequest, HandshakeResponse, PROTOCOL_VERSION, principal_auth_challenge_message,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Build a Full-scope [`DeviceKey`] from a keypair's exported public key for
/// the signature-verification tests (the scope is irrelevant to the pure
/// signature check, which only consults the registered pubkey).
fn full_device(keypair: &astrid_crypto::KeyPair) -> DeviceKey {
    DeviceKey::new(
        keypair.export_public_key().to_hex(),
        DeviceScope::Full,
        None,
        0,
    )
}

// ── Crypto-core: challenge-message sign/verify round trip ──────────────

#[test]
fn challenge_signature_verifies_against_registered_key() {
    let principal = PrincipalId::new("alice").expect("valid principal");
    let nonce_hex = hex::encode([7u8; PRINCIPAL_AUTH_NONCE_LEN]);

    let keypair = astrid_crypto::KeyPair::generate();
    let registered = full_device(&keypair);

    let message = principal_auth_challenge_message(principal.as_str(), &nonce_hex);
    let signature = keypair.sign(message.as_bytes()).to_hex();

    // A registered key over the exact challenge message verifies, returning
    // THAT device's key_id so the connection can be scoped to it.
    assert_eq!(
        verify_signature_against_keys(
            &principal,
            std::slice::from_ref(&registered),
            &nonce_hex,
            &signature
        )
        .as_deref(),
        Ok(registered.key_id.as_str()),
        "valid signature must verify and return the matched device key_id"
    );

    // A DIFFERENT key fails.
    let other = astrid_crypto::KeyPair::generate();
    let other_registered = full_device(&other);
    assert!(
        verify_signature_against_keys(&principal, &[other_registered], &nonce_hex, &signature)
            .is_err(),
        "signature must not verify against a different key"
    );

    // A TAMPERED nonce fails (the daemon would verify the issued nonce, not
    // whatever the client signed).
    let tampered_nonce = hex::encode([9u8; PRINCIPAL_AUTH_NONCE_LEN]);
    assert!(
        verify_signature_against_keys(
            &principal,
            std::slice::from_ref(&registered),
            &tampered_nonce,
            &signature
        )
        .is_err(),
        "signature over the wrong nonce must not verify"
    );

    // No registered ed25519 key at all → reject.
    assert!(
        verify_signature_against_keys(&principal, &[], &nonce_hex, &signature).is_err(),
        "a principal with no registered key must reject"
    );
}

// ── End-to-end handshake over a socket pair ────────────────────────────

/// Tempdir-backed home with a profile for `principal` registering
/// `keypair`'s public key.
fn home_with_registered_key(
    principal: &PrincipalId,
    keypair: &astrid_crypto::KeyPair,
) -> (tempfile::TempDir, AstridHome) {
    let dir = tempfile::tempdir().expect("tempdir");
    let home = AstridHome::from_path(dir.path());
    let mut profile = astrid_core::PrincipalProfile::default();
    profile.auth.public_keys.push(full_device(keypair));
    profile
        .auth
        .methods
        .push(astrid_core::profile::AuthMethod::Keypair);
    let path = astrid_core::PrincipalProfile::path_for(&home, principal);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    profile.save_to_path(&path).expect("save profile");
    (dir, home)
}

/// Write one length-prefixed JSON value, then read one back.
async fn client_send_recv<T, R, S>(stream: &mut S, value: &T) -> R
where
    T: serde::Serialize,
    R: serde::de::DeserializeOwned,
    S: AsyncRead + AsyncWrite + Unpin,
{
    let bytes = serde_json::to_vec(value).unwrap();
    let len = u32::try_from(bytes.len()).unwrap();
    stream.write_all(&len.to_be_bytes()).await.unwrap();
    stream.write_all(&bytes).await.unwrap();
    stream.flush().await.unwrap();

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await.unwrap();
    let resp_len = u32::from_be_bytes(len_buf) as usize;
    let mut payload = vec![0u8; resp_len];
    stream.read_exact(&mut payload).await.unwrap();
    serde_json::from_slice(&payload).unwrap()
}

fn token() -> SessionToken {
    SessionToken::generate()
}

#[tokio::test]
async fn handshake_unsigned_returns_no_principal() {
    let (mut server, mut client) = tokio::io::duplex(16 * 1024);
    let tok = token();
    let dir = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(dir.path());

    let tok_hex = tok.to_hex();
    let server_task =
        tokio::spawn(async move { validate_handshake(&mut server, &tok, &home).await });

    // Legacy single-frame client: no claimed_principal, no signature.
    let request = HandshakeRequest {
        token: tok_hex,
        protocol_version: PROTOCOL_VERSION,
        client_version: "test".to_string(),
        claimed_principal: None,
        signature: None,
    };
    let response: HandshakeResponse = client_send_recv(&mut client, &request).await;
    assert!(response.is_ok(), "unauthenticated handshake must succeed");
    assert!(response.challenge.is_none(), "no challenge without a claim");

    let verified = server_task.await.unwrap().expect("handshake ok");
    assert_eq!(
        verified, None,
        "unsigned handshake yields no verified principal"
    );
}

#[tokio::test]
async fn handshake_signed_returns_verified_principal() {
    let principal = PrincipalId::new("alice").expect("valid principal");
    let keypair = astrid_crypto::KeyPair::generate();
    let (_dir, home) = home_with_registered_key(&principal, &keypair);

    let (mut server, mut client) = tokio::io::duplex(16 * 1024);
    let tok = token();
    let tok_hex = tok.to_hex();
    let server_task =
        tokio::spawn(async move { validate_handshake(&mut server, &tok, &home).await });

    // Frame 1: claim the principal, no signature → expect a challenge back.
    let first = HandshakeRequest {
        token: tok_hex.clone(),
        protocol_version: PROTOCOL_VERSION,
        client_version: "test".to_string(),
        claimed_principal: Some(principal.to_string()),
        signature: None,
    };
    let challenge_resp: HandshakeResponse = client_send_recv(&mut client, &first).await;
    let nonce_hex = challenge_resp
        .challenge
        .expect("daemon must issue a challenge");

    // Frame 2: sign the challenge → expect final OK.
    let message = principal_auth_challenge_message(principal.as_str(), &nonce_hex);
    let signature = keypair.sign(message.as_bytes()).to_hex();
    let second = HandshakeRequest {
        token: tok_hex,
        protocol_version: PROTOCOL_VERSION,
        client_version: "test".to_string(),
        claimed_principal: Some(principal.to_string()),
        signature: Some(signature),
    };
    let final_resp: HandshakeResponse = client_send_recv(&mut client, &second).await;
    assert!(final_resp.is_ok(), "signed handshake must succeed");

    let verified = server_task.await.unwrap().expect("handshake ok");
    let expected_key_id = full_device(&keypair).key_id;
    assert_eq!(
        verified,
        Some((principal, expected_key_id)),
        "a valid signed handshake yields the verified principal and matched device key_id"
    );
}

#[tokio::test]
async fn handshake_bad_signature_fails_closed() {
    let principal = PrincipalId::new("alice").expect("valid principal");
    let keypair = astrid_crypto::KeyPair::generate();
    let (_dir, home) = home_with_registered_key(&principal, &keypair);

    let (mut server, mut client) = tokio::io::duplex(16 * 1024);
    let tok = token();
    let tok_hex = tok.to_hex();
    let server_task =
        tokio::spawn(async move { validate_handshake(&mut server, &tok, &home).await });

    let first = HandshakeRequest {
        token: tok_hex.clone(),
        protocol_version: PROTOCOL_VERSION,
        client_version: "test".to_string(),
        claimed_principal: Some(principal.to_string()),
        signature: None,
    };
    let challenge_resp: HandshakeResponse = client_send_recv(&mut client, &first).await;
    let nonce_hex = challenge_resp
        .challenge
        .expect("daemon must issue a challenge");

    // Sign with a DIFFERENT (unregistered) key → must fail closed.
    let attacker = astrid_crypto::KeyPair::generate();
    let message = principal_auth_challenge_message(principal.as_str(), &nonce_hex);
    let bad_signature = attacker.sign(message.as_bytes()).to_hex();
    let second = HandshakeRequest {
        token: tok_hex,
        protocol_version: PROTOCOL_VERSION,
        client_version: "test".to_string(),
        claimed_principal: Some(principal.to_string()),
        signature: Some(bad_signature),
    };
    let final_resp: HandshakeResponse = client_send_recv(&mut client, &second).await;
    assert!(!final_resp.is_ok(), "bad signature must be rejected");

    let result = server_task.await.unwrap();
    assert!(
        result.is_err(),
        "a bad signature must fail the handshake, never fall back to unauthenticated"
    );
}
