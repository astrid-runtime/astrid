//! Session token for Unix socket authentication.
//!
//! The daemon generates a random 256-bit token at startup and writes it to
//! `~/.astrid/run/system.token` with 0o600 permissions. The CLI reads
//! this token and sends it as the first message after connecting. The daemon
//! validates the token with constant-time comparison and rejects connections
//! that fail.
//!
//! This follows the same pattern used by Jupyter notebooks and Docker.

use std::fmt;
use std::io;
use std::path::Path;

use rand::RngCore;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

/// Current wire protocol version. Bumped when the handshake or IPC message
/// format changes in a backwards-incompatible way.
pub const PROTOCOL_VERSION: u8 = 1;

/// Domain-separation prefix for the per-connection principal-auth
/// challenge (issue #45/#852).
///
/// The signed message is `{PRINCIPAL_AUTH_CHALLENGE_PREFIX}{principal}:{nonce_hex}`.
/// The version segment is bumped if the challenge construction changes so a
/// signature minted under one scheme can never be replayed under another.
pub const PRINCIPAL_AUTH_CHALLENGE_PREFIX: &str = "astrid-principal-auth:v1:";

/// Length of the principal-auth challenge nonce in bytes.
pub const PRINCIPAL_AUTH_NONCE_LEN: usize = 32;

/// Build the exact message bytes a client signs (and the daemon verifies)
/// for the per-connection principal-auth challenge.
///
/// `nonce_hex` is the hex-encoded challenge the daemon issued in
/// [`HandshakeResponse::challenge`]. Both sides MUST construct the message
/// identically — this helper is the single source of truth so they cannot
/// drift.
#[must_use]
pub fn principal_auth_challenge_message(principal: &str, nonce_hex: &str) -> String {
    format!("{PRINCIPAL_AUTH_CHALLENGE_PREFIX}{principal}:{nonce_hex}")
}

/// A 256-bit random session token for socket authentication.
pub struct SessionToken([u8; 32]);

impl SessionToken {
    /// Generate a new random session token from the OS CSPRNG.
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Hex-encode the token for file storage and wire transmission.
    #[must_use]
    pub fn to_hex(&self) -> String {
        let mut hex = String::with_capacity(64);
        for byte in &self.0 {
            use fmt::Write;
            let _ = write!(hex, "{byte:02x}");
        }
        hex
    }

    /// Decode a hex-encoded token string.
    ///
    /// # Errors
    ///
    /// Returns an error if the hex string is not exactly 64 characters or
    /// contains invalid hex digits.
    pub fn from_hex(hex: &str) -> Result<Self, io::Error> {
        if hex.len() != 64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("session token hex must be 64 chars, got {}", hex.len()),
            ));
        }
        let mut bytes = [0u8; 32];
        for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
            let hi = hex_digit(chunk[0])?;
            let lo = hex_digit(chunk[1])?;
            bytes[i] = (hi << 4) | lo;
        }
        Ok(Self(bytes))
    }

    /// Write the token to a file with owner-only permissions (0o600).
    ///
    /// On Unix, this uses write-then-rename atomicity: writes to a temporary
    /// file at 0o600 (via `OpenOptions::mode` to avoid a TOCTOU permissions
    /// window), then atomically renames it to the target path. This prevents
    /// a racing `read_from_file` from seeing a truncated/empty file during
    /// daemon restarts.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be written or permissions cannot be set.
    pub fn write_to_file(&self, path: &Path) -> io::Result<()> {
        let hex = self.to_hex();

        #[cfg(unix)]
        {
            use io::Write;
            use std::os::unix::fs::OpenOptionsExt;

            let tmp_path = path.with_extension(format!("{}.tmp", std::process::id()));
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp_path)?;
            f.write_all(hex.as_bytes())?;
            f.sync_all()?;
            drop(f);

            // Atomic rename on the same filesystem. Clean up temp file on
            // failure to avoid orphaned secret-containing files.
            if let Err(e) = std::fs::rename(&tmp_path, path) {
                let _ = std::fs::remove_file(&tmp_path);
                return Err(e);
            }
        }

        // Non-Unix fallback: no atomic rename, no explicit permissions.
        // The token file will inherit the process umask (likely 0o644).
        // Windows is not a supported daemon platform; this exists only
        // for compilation and test compatibility.
        #[cfg(not(unix))]
        {
            std::fs::write(path, hex.as_bytes())?;
        }

        Ok(())
    }

    /// Read and decode a token from a file.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or contains invalid hex.
    pub fn read_from_file(path: &Path) -> io::Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        Self::from_hex(contents.trim())
    }

    /// Constant-time comparison. Returns `true` if the tokens are equal.
    #[must_use]
    pub fn ct_eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl fmt::Debug for SessionToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionToken([REDACTED])")
    }
}

/// Decode a single hex digit, returning an error for invalid characters.
///
/// The match arms guarantee the subtraction cannot overflow.
#[expect(clippy::arithmetic_side_effects)]
fn hex_digit(byte: u8) -> io::Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid hex digit: {byte:#04x}"),
        )),
    }
}

/// First message sent by the CLI after connecting to the daemon socket.
///
/// The optional [`claimed_principal`](Self::claimed_principal) /
/// [`signature`](Self::signature) fields carry the per-connection
/// principal challenge-response (issue #45/#852). Both are
/// `#[serde(default)]` so legacy clients (which never set them) and
/// legacy daemons (which never read them) keep interoperating: an
/// unauthenticated handshake is exactly the old single-round-trip flow.
#[derive(Debug, Serialize, Deserialize)]
pub struct HandshakeRequest {
    /// Hex-encoded session token.
    pub token: String,
    /// Wire protocol version supported by this client.
    pub protocol_version: u8,
    /// Semantic version of the client binary (e.g. "0.1.1").
    pub client_version: String,
    /// Principal this connection wishes to authenticate as.
    ///
    /// When present, the daemon replies with a challenge nonce in
    /// [`HandshakeResponse::challenge`] and expects a second frame
    /// carrying [`signature`](Self::signature) over that nonce. Absent
    /// → the connection is unauthenticated (legacy single round trip).
    #[serde(default)]
    pub claimed_principal: Option<String>,
    /// Hex-encoded ed25519 signature over the challenge message
    /// `astrid-principal-auth:v1:{claimed_principal}:{nonce_hex}`.
    ///
    /// Sent in the SECOND request frame, after the daemon's challenge.
    /// `None` in the first frame and for unauthenticated handshakes.
    #[serde(default)]
    pub signature: Option<String>,
}

/// Typed status for handshake responses. Using an enum instead of a raw
/// string prevents typo-induced mismatches between client and server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HandshakeStatus {
    /// Handshake succeeded.
    Ok,
    /// Handshake failed.
    Error,
}

/// Response sent by the daemon after validating the handshake.
#[derive(Debug, Serialize, Deserialize)]
pub struct HandshakeResponse {
    /// Whether the handshake succeeded or failed.
    pub status: HandshakeStatus,
    /// Wire protocol version of the daemon.
    pub protocol_version: u8,
    /// Semantic version of the daemon binary.
    pub server_version: String,
    /// Human-readable reason for rejection (only set when status is `Error`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Hex-encoded 32-byte challenge nonce for principal authentication
    /// (issue #45/#852).
    ///
    /// Set on the INTERMEDIATE response the daemon sends when a client's
    /// first frame carried a [`HandshakeRequest::claimed_principal`]: the
    /// client signs `astrid-principal-auth:v1:{principal}:{nonce_hex}` and
    /// returns the signature in a second request frame. `None` on the
    /// final success/error response and for unauthenticated handshakes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,
}

impl HandshakeResponse {
    /// Create a successful handshake response.
    #[must_use]
    pub fn ok() -> Self {
        Self {
            status: HandshakeStatus::Ok,
            protocol_version: PROTOCOL_VERSION,
            server_version: env!("CARGO_PKG_VERSION").to_string(),
            reason: None,
            challenge: None,
        }
    }

    /// Create an error handshake response.
    #[must_use]
    pub fn error(reason: impl Into<String>) -> Self {
        Self {
            status: HandshakeStatus::Error,
            protocol_version: PROTOCOL_VERSION,
            server_version: env!("CARGO_PKG_VERSION").to_string(),
            reason: Some(reason.into()),
            challenge: None,
        }
    }

    /// Create an intermediate handshake response carrying a principal-auth
    /// challenge nonce (issue #45/#852).
    ///
    /// `status` is [`HandshakeStatus::Ok`] — the token has already been
    /// accepted; this response asks the client to sign the nonce and send
    /// a second frame. The final success/error response follows after the
    /// signature is verified.
    #[must_use]
    pub fn challenge(nonce_hex: impl Into<String>) -> Self {
        Self {
            status: HandshakeStatus::Ok,
            protocol_version: PROTOCOL_VERSION,
            server_version: env!("CARGO_PKG_VERSION").to_string(),
            reason: None,
            challenge: Some(nonce_hex.into()),
        }
    }

    /// Returns `true` if the handshake succeeded.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.status == HandshakeStatus::Ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_produces_unique_tokens() {
        let a = SessionToken::generate();
        let b = SessionToken::generate();
        assert!(!a.ct_eq(&b), "two generated tokens must differ");
    }

    #[test]
    fn hex_round_trip() {
        let token = SessionToken::generate();
        let hex = token.to_hex();
        assert_eq!(hex.len(), 64);
        let decoded = SessionToken::from_hex(&hex).expect("valid hex");
        assert!(token.ct_eq(&decoded));
    }

    #[test]
    fn from_hex_rejects_wrong_length() {
        let err = SessionToken::from_hex("abcd").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("64 chars"));
    }

    #[test]
    fn from_hex_rejects_invalid_chars() {
        let bad = "zz".repeat(32);
        let err = SessionToken::from_hex(&bad).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("invalid hex digit"));
    }

    #[test]
    fn constant_time_eq_matches() {
        let token = SessionToken::generate();
        let same = SessionToken::from_hex(&token.to_hex()).expect("valid");
        assert!(token.ct_eq(&same));
    }

    #[test]
    fn constant_time_eq_rejects_different() {
        let a = SessionToken::generate();
        let b = SessionToken::generate();
        assert!(!a.ct_eq(&b));
    }

    #[test]
    fn file_round_trip() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let path = dir.path().join("test.token");

        let token = SessionToken::generate();
        token.write_to_file(&path).expect("write");

        let loaded = SessionToken::read_from_file(&path).expect("read");
        assert!(token.ct_eq(&loaded));

        // Verify 0600 permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::metadata(&path).expect("metadata").permissions();
            assert_eq!(perms.mode() & 0o777, 0o600);
        }
    }

    #[test]
    fn debug_redacts_token() {
        let token = SessionToken::generate();
        let debug = format!("{token:?}");
        assert_eq!(debug, "SessionToken([REDACTED])");
        assert!(!debug.contains(&token.to_hex()));
    }

    #[test]
    fn handshake_response_ok_serializes() {
        let resp = HandshakeResponse::ok();
        assert_eq!(resp.status, HandshakeStatus::Ok);
        assert!(resp.is_ok());
        assert_eq!(resp.protocol_version, PROTOCOL_VERSION);
        assert!(resp.reason.is_none());

        let json = serde_json::to_value(&resp).expect("serialize");
        assert_eq!(json["status"], "ok");
        assert!(json.get("reason").is_none(), "reason should be skipped");
    }

    #[test]
    fn handshake_response_error_serializes() {
        let resp = HandshakeResponse::error("bad token");
        assert_eq!(resp.status, HandshakeStatus::Error);
        assert!(!resp.is_ok());
        assert_eq!(resp.reason.as_deref(), Some("bad token"));

        let json = serde_json::to_value(&resp).expect("serialize");
        assert_eq!(json["status"], "error");
        assert_eq!(json["reason"], "bad token");
    }

    #[test]
    fn legacy_handshake_request_without_auth_fields_parses() {
        // A frame from a pre-#45 client carries no claimed_principal /
        // signature. `#[serde(default)]` must let it deserialize to `None`.
        let legacy = r#"{"token":"ab","protocol_version":1,"client_version":"0.1.0"}"#;
        let req: HandshakeRequest = serde_json::from_str(legacy).expect("parse legacy request");
        assert_eq!(req.claimed_principal, None);
        assert_eq!(req.signature, None);
    }

    #[test]
    fn legacy_handshake_response_without_challenge_parses() {
        // A response from a pre-#45 daemon carries no challenge field.
        let legacy = r#"{"status":"ok","protocol_version":1,"server_version":"0.1.0"}"#;
        let resp: HandshakeResponse = serde_json::from_str(legacy).expect("parse legacy response");
        assert!(resp.is_ok());
        assert_eq!(resp.challenge, None);
    }

    #[test]
    fn challenge_response_carries_nonce_and_is_ok() {
        // The intermediate challenge response is status=ok with a nonce — the
        // token is already accepted; the client must still sign the nonce.
        let resp = HandshakeResponse::challenge("deadbeef");
        assert!(resp.is_ok());
        assert_eq!(resp.challenge.as_deref(), Some("deadbeef"));

        let json = serde_json::to_value(&resp).expect("serialize");
        assert_eq!(json["challenge"], "deadbeef");
    }

    #[test]
    fn challenge_message_binds_principal_and_nonce() {
        let m = principal_auth_challenge_message("alice", "00ff");
        assert_eq!(m, "astrid-principal-auth:v1:alice:00ff");
        // Different principal or nonce ⇒ different message (no cross-replay).
        assert_ne!(m, principal_auth_challenge_message("bob", "00ff"));
        assert_ne!(m, principal_auth_challenge_message("alice", "ff00"));
    }
}
