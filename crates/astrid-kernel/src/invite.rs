//! Persistent invite-token store (issue #756 / Layer 6 gateway).
//!
//! Invite tokens are short opaque secrets that grant a one-time-ish
//! right to mint a principal. The kernel never stores the raw token —
//! it stores SHA-256 of the URL-safe base64 form. Redemption hashes
//! the incoming token and compares against the persisted set.
//!
//! ## On-disk layout
//!
//! `$ASTRID_HOME/etc/invites.toml`:
//!
//! ```toml
//! [[invite]]
//! token_hash = "..."         # hex(sha256(token)) — 64 hex chars
//! group = "agent"
//! remaining_uses = 1
//! expires_at_epoch = 1234567890
//! issued_at_epoch = 1234560000
//! metadata = "alice's tablet"
//! ```
//!
//! Atomic writes via write-then-rename. The file is owned by the
//! daemon UID and chmod 0600 — same posture as
//! `~/.astrid/run/system.token`.
//!
//! ## Threat model
//!
//! * **Read-only leak**: an attacker who reads `invites.toml` sees
//!   token *hashes*, not tokens. They cannot redeem.
//! * **Write leak**: an attacker who can write `invites.toml` wins
//!   anyway — they can plant a hash whose pre-image they know. This
//!   matches the existing `groups.toml` / `profile.toml` threat model
//!   (operator-trusted system files; file-system perms gate access).
//! * **Replay**: each redemption decrements `remaining_uses`; reaching
//!   zero removes the entry under the kernel's `admin_write_lock`.
//! * **Wall-clock expiry**: enforced at redeem time. Expired entries
//!   are removed lazily (next `prune`) — no background sweeper is
//!   spun up for what is at most a few-hundred-entry file.
//! * **Side-channel on lookup**: the redeem path uses
//!   constant-time comparison on the hash bytes.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use astrid_core::dirs::AstridHome;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Length of the random token portion in bytes (192 bits → 32 chars
/// URL-safe base64, comfortably exceeding the 128-bit work factor we
/// need against online brute force given the per-IP redeem rate-limit
/// at the gateway).
pub const TOKEN_RAW_LEN: usize = 24;

/// Hard cap on a single token's lifetime. Mirrors the issue's
/// "max 30 days" guidance; longer-lived invites should issue a fresh
/// token rather than carry one forever.
pub const MAX_EXPIRY_SECS: u64 = 60 * 60 * 24 * 30;

/// On-disk persisted invite record. The raw token is NEVER stored —
/// only its SHA-256.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Invite {
    /// Hex-encoded SHA-256 of the URL-safe base64 token (64 hex chars).
    pub token_hash: String,
    /// Group new redeemers join.
    pub group: String,
    /// Remaining redemptions. Zero means "consumed; pending prune".
    pub remaining_uses: u32,
    /// Wall-clock Unix epoch at which this invite expires. `None` = no
    /// expiry (max-uses is the only stop).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_epoch: Option<u64>,
    /// Wall-clock Unix epoch at which this invite was issued.
    pub issued_at_epoch: u64,
    /// Operator-supplied label (e.g. "alice's tablet").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<String>,
}

/// File-backed invite store. Read-modify-write with atomic rename;
/// concurrent mutators must serialise externally (the kernel uses
/// `admin_write_lock`).
#[derive(Debug)]
pub struct InviteStore {
    path: PathBuf,
}

impl InviteStore {
    /// Construct a store backed by `path`. The file does not need to
    /// exist — empty/missing reads return an empty list.
    #[must_use]
    pub const fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Convenience: build the canonical path under `$ASTRID_HOME/etc`.
    #[must_use]
    pub fn path_for(home: &AstridHome) -> PathBuf {
        home.etc_dir().join("invites.toml")
    }

    /// Read the persisted list. Missing file → empty Vec (single-tenant
    /// deployments never call invite-issue).
    ///
    /// # Errors
    /// Returns an error if the file exists but is unreadable or malformed.
    pub fn load(&self) -> Result<Vec<Invite>, InviteStoreError> {
        let bytes = match std::fs::read(&self.path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(InviteStoreError::Io(e)),
        };
        let text = std::str::from_utf8(&bytes).map_err(|e| {
            InviteStoreError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        })?;
        if text.trim().is_empty() {
            return Ok(Vec::new());
        }
        let parsed: PersistedFile = toml::from_str(text).map_err(InviteStoreError::Toml)?;
        Ok(parsed.invite)
    }

    /// Write the supplied list atomically (write-then-rename, 0600
    /// permissions). An empty list is persisted as an empty TOML file
    /// rather than deleting — keeps the file-permission invariant
    /// observable to ops tooling.
    ///
    /// # Errors
    /// Returns an error if the file cannot be written.
    pub fn save(&self, invites: &[Invite]) -> Result<(), InviteStoreError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(InviteStoreError::Io)?;
        }
        let body = PersistedFile {
            invite: invites.to_vec(),
        };
        let text = toml::to_string_pretty(&body).map_err(InviteStoreError::TomlSer)?;

        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let tmp_path = self
                .path
                .with_extension(format!("{}.tmp", std::process::id()));
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp_path)
                .map_err(InviteStoreError::Io)?;
            f.write_all(text.as_bytes()).map_err(InviteStoreError::Io)?;
            f.sync_all().map_err(InviteStoreError::Io)?;
            drop(f);
            if let Err(e) = std::fs::rename(&tmp_path, &self.path) {
                let _ = std::fs::remove_file(&tmp_path);
                return Err(InviteStoreError::Io(e));
            }
        }
        #[cfg(not(unix))]
        {
            std::fs::write(&self.path, text.as_bytes()).map_err(InviteStoreError::Io)?;
        }
        Ok(())
    }
}

/// Errors surfaced by [`InviteStore`] operations.
#[derive(Debug)]
pub enum InviteStoreError {
    /// File-system IO error.
    Io(std::io::Error),
    /// `invites.toml` failed to parse.
    Toml(toml::de::Error),
    /// `invites.toml` failed to serialise.
    TomlSer(toml::ser::Error),
}

impl std::fmt::Display for InviteStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "invite store io: {e}"),
            Self::Toml(e) => write!(f, "invite store parse: {e}"),
            Self::TomlSer(e) => write!(f, "invite store serialise: {e}"),
        }
    }
}

impl std::error::Error for InviteStoreError {}

#[derive(Debug, Default, Serialize, Deserialize)]
struct PersistedFile {
    #[serde(default)]
    invite: Vec<Invite>,
}

/// Generate a random URL-safe-base64 token. Uses the OS CSPRNG.
#[must_use]
pub fn generate_token() -> String {
    use rand::{TryRng, rngs::SysRng};
    let mut bytes = [0u8; TOKEN_RAW_LEN];
    SysRng
        .try_fill_bytes(&mut bytes)
        .expect("OS CSPRNG unavailable while generating invite token");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Hash a token for storage / lookup. Hex-encoded SHA-256.
#[must_use]
pub fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

/// Constant-time hash comparison. Both inputs must be hex-encoded
/// SHA-256 (64 hex chars). Returns `false` on any length mismatch
/// without leaking the position via short-circuit.
#[must_use]
pub fn ct_hash_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

/// Current wall-clock as seconds since Unix epoch. Saturating on the
/// (impossible) pre-1970 case so the returned `u64` never wraps.
#[must_use]
pub fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Borrow-checked helper: prune the in-place list, returning the count
/// removed. Expired entries (wall-clock expiry passed) and consumed
/// entries (`remaining_uses == 0`) both go.
pub fn prune_expired(invites: &mut Vec<Invite>) -> usize {
    let now = now_epoch();
    let before = invites.len();
    invites.retain(|i| {
        if i.remaining_uses == 0 {
            return false;
        }
        i.expires_at_epoch.is_none_or(|exp| exp > now)
    });
    before.saturating_sub(invites.len())
}

/// Same conventions as `prune_expired` but keyed on `path` — used by
/// the handlers under the admin write lock.
///
/// # Errors
/// Propagates [`InviteStoreError`] from the read-modify-write cycle.
pub fn prune_file(store: &InviteStore) -> Result<usize, InviteStoreError> {
    let mut invites = store.load()?;
    let removed = prune_expired(&mut invites);
    if removed > 0 {
        store.save(&invites)?;
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_round_trip_is_random_and_url_safe() {
        let a = generate_token();
        let b = generate_token();
        assert_ne!(a, b, "two tokens must differ");
        assert!(
            a.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
        // base64-url-no-pad of 24 bytes is 32 chars.
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn hash_token_is_deterministic_hex_sha256() {
        let h = hash_token("hello");
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(h, hash_token("hello"));
        assert_ne!(h, hash_token("world"));
    }

    #[test]
    fn ct_hash_eq_rejects_length_mismatch() {
        assert!(!ct_hash_eq("abc", "abcd"));
        assert!(ct_hash_eq("abc", "abc"));
        assert!(!ct_hash_eq("abc", "abd"));
    }

    #[test]
    fn prune_removes_expired_and_consumed() {
        let mut v = vec![
            Invite {
                token_hash: "a".into(),
                group: "agent".into(),
                remaining_uses: 1,
                expires_at_epoch: Some(now_epoch().saturating_add(60)),
                issued_at_epoch: 0,
                metadata: None,
            },
            Invite {
                token_hash: "b".into(),
                group: "agent".into(),
                remaining_uses: 0,
                expires_at_epoch: None,
                issued_at_epoch: 0,
                metadata: None,
            },
            Invite {
                token_hash: "c".into(),
                group: "agent".into(),
                remaining_uses: 1,
                expires_at_epoch: Some(now_epoch().saturating_sub(60)),
                issued_at_epoch: 0,
                metadata: None,
            },
        ];
        let removed = prune_expired(&mut v);
        assert_eq!(removed, 2);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].token_hash, "a");
    }

    #[test]
    fn save_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let store = InviteStore::new(dir.path().join("invites.toml"));
        let now = now_epoch();
        let invite = Invite {
            token_hash: "deadbeef".into(),
            group: "agent".into(),
            remaining_uses: 2,
            expires_at_epoch: Some(now.saturating_add(3600)),
            issued_at_epoch: now,
            metadata: Some("alice".into()),
        };
        store.save(std::slice::from_ref(&invite)).unwrap();
        let loaded = store.load().unwrap();
        assert_eq!(loaded, vec![invite]);
    }

    #[test]
    fn empty_file_loads_as_empty_vec() {
        let dir = tempfile::tempdir().unwrap();
        let store = InviteStore::new(dir.path().join("invites.toml"));
        // Missing file → empty
        assert_eq!(store.load().unwrap(), Vec::<Invite>::new());
        // Touch empty file → empty
        std::fs::write(&store.path, "").unwrap();
        assert_eq!(store.load().unwrap(), Vec::<Invite>::new());
    }

    #[cfg(unix)]
    #[test]
    fn save_writes_0600_perms() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let store = InviteStore::new(dir.path().join("invites.toml"));
        store.save(&[]).unwrap();
        let perms = std::fs::metadata(&store.path).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o600);
    }
}
