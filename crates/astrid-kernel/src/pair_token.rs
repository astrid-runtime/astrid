//! Persistent pair-device token store (issue #756).
//!
//! Mirrors [`crate::invite`]'s shape but targets adding a NEW key
//! to an EXISTING principal (the "pair device" flow) instead of
//! minting a fresh principal.
//!
//! ## On-disk layout
//!
//! `$ASTRID_HOME/etc/pair-tokens.toml`:
//!
//! ```toml
//! [[pair_token]]
//! token_hash = "..."           # hex(sha256(token)) — 64 hex chars
//! principal = "alice"          # the principal the new key will bind to
//! expires_at_epoch = 1234567890
//! issued_at_epoch = 1234560000
//! label = "alice's phone"      # optional
//! ```
//!
//! ## Threat model
//!
//! Same posture as the invite store: hashes on disk, atomic
//! write-then-rename, 0600 perms, constant-time hash comparison on
//! redeem. Pair-tokens are single-use only (no `remaining_uses`
//! field) — a redeemed token is removed immediately.
//!
//! Lifetime is capped at one hour (`MAX_EXPIRY_SECS`) — pair-tokens
//! are meant for immediate use on a neighbouring device. Longer
//! sharing windows are deliberately unsupported; if a user really
//! wants a multi-day window they should redeem a separate invite
//! (different principal) instead.

use std::path::PathBuf;

use astrid_core::DeviceScope;
use astrid_core::PrincipalId;
use astrid_core::dirs::AstridHome;
use base64::Engine;
use rand::{TryRng, rngs::SysRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Length of the random token portion in bytes (192 bits → 32 chars
/// URL-safe base64). Same sizing as invite tokens.
pub const TOKEN_RAW_LEN: usize = 24;

/// Hard cap on a single pair-token's lifetime. Pair-tokens are
/// intended for immediate use ("scan this QR with your phone, now")
/// — a longer window is deliberately unsupported.
pub const MAX_EXPIRY_SECS: u64 = 60 * 60;

/// On-disk persisted pair-token record. Raw token is never stored —
/// only its SHA-256.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairToken {
    /// Hex-encoded SHA-256 of the URL-safe base64 token.
    pub token_hash: String,
    /// Principal the new device's key will attach to.
    pub principal: PrincipalId,
    /// Wall-clock Unix-epoch at which this token expires.
    pub expires_at_epoch: u64,
    /// Wall-clock Unix-epoch at which the token was issued.
    pub issued_at_epoch: u64,
    /// Operator-supplied label (e.g. "alice's phone"). Persisted
    /// alongside the new key entry once the token is redeemed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Capability scope the redeemed device will authenticate under,
    /// resolved + validated at issue time. Redeem stamps this onto the new
    /// [`DeviceKey`](astrid_core::DeviceKey) so the paired device is
    /// attenuated to exactly this scope on every transport. Defaults to
    /// [`DeviceScope::Full`] when absent so any pre-scope on-disk token (and
    /// older serialized records) round-trips as an unattenuated device,
    /// preserving the prior behaviour.
    #[serde(default = "default_full_scope")]
    pub scope: DeviceScope,
}

/// Serde default for [`PairToken::scope`] — `Full`, so an on-disk record
/// written before scoping existed loads as an unattenuated device.
fn default_full_scope() -> DeviceScope {
    DeviceScope::Full
}

/// File-backed pair-token store. Read-modify-write with atomic
/// rename; concurrent mutators serialise on the kernel's
/// `admin_write_lock`.
#[derive(Debug)]
pub struct PairTokenStore {
    path: PathBuf,
}

impl PairTokenStore {
    /// Construct a store backed by `path`. Missing file → empty list.
    #[must_use]
    pub const fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Convenience: canonical path under `$ASTRID_HOME/etc`.
    #[must_use]
    pub fn path_for(home: &AstridHome) -> PathBuf {
        home.etc_dir().join("pair-tokens.toml")
    }

    /// Read the persisted list. Missing file → empty Vec.
    ///
    /// # Errors
    /// Returns an error if the file exists but is unreadable or
    /// malformed.
    pub fn load(&self) -> Result<Vec<PairToken>, PairTokenStoreError> {
        let bytes = match std::fs::read(&self.path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(PairTokenStoreError::Io(e)),
        };
        let text = std::str::from_utf8(&bytes).map_err(|e| {
            PairTokenStoreError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        })?;
        if text.trim().is_empty() {
            return Ok(Vec::new());
        }
        let parsed: PersistedFile = toml::from_str(text).map_err(PairTokenStoreError::Toml)?;
        Ok(parsed.pair_token)
    }

    /// Write the supplied list atomically (write-then-rename, 0600
    /// perms). Empty list persists as an empty TOML file.
    ///
    /// # Errors
    /// Returns an error if the file cannot be written.
    pub fn save(&self, tokens: &[PairToken]) -> Result<(), PairTokenStoreError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(PairTokenStoreError::Io)?;
        }
        let body = PersistedFile {
            pair_token: tokens.to_vec(),
        };
        let text = toml::to_string_pretty(&body).map_err(PairTokenStoreError::TomlSer)?;

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
                .map_err(PairTokenStoreError::Io)?;
            f.write_all(text.as_bytes())
                .map_err(PairTokenStoreError::Io)?;
            f.sync_all().map_err(PairTokenStoreError::Io)?;
            drop(f);
            if let Err(e) = std::fs::rename(&tmp_path, &self.path) {
                let _ = std::fs::remove_file(&tmp_path);
                return Err(PairTokenStoreError::Io(e));
            }
        }
        #[cfg(not(unix))]
        {
            std::fs::write(&self.path, text.as_bytes()).map_err(PairTokenStoreError::Io)?;
        }
        Ok(())
    }
}

/// Errors surfaced by [`PairTokenStore`] operations.
#[derive(Debug)]
pub enum PairTokenStoreError {
    /// File-system IO error.
    Io(std::io::Error),
    /// `pair-tokens.toml` failed to parse.
    Toml(toml::de::Error),
    /// `pair-tokens.toml` failed to serialise.
    TomlSer(toml::ser::Error),
}

impl std::fmt::Display for PairTokenStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "pair-token store io: {e}"),
            Self::Toml(e) => write!(f, "pair-token store parse: {e}"),
            Self::TomlSer(e) => write!(f, "pair-token store serialise: {e}"),
        }
    }
}

impl std::error::Error for PairTokenStoreError {}

#[derive(Debug, Default, Serialize, Deserialize)]
struct PersistedFile {
    #[serde(default)]
    pair_token: Vec<PairToken>,
}

/// Generate a random URL-safe-base64 token from the OS CSPRNG.
///
/// # Panics
///
/// Panics if the OS CSPRNG is unavailable.
#[must_use]
pub fn generate_token() -> String {
    let mut bytes = [0u8; TOKEN_RAW_LEN];
    SysRng
        .try_fill_bytes(&mut bytes)
        .expect("OS CSPRNG unavailable while generating pair token");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Hash a token for storage / lookup. Hex-encoded SHA-256.
#[must_use]
pub fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

/// Constant-time hash comparison.
#[must_use]
pub fn ct_hash_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

/// Current wall-clock seconds since Unix epoch.
#[must_use]
pub fn now_epoch() -> u64 {
    astrid_runtime::clock::now_epoch_secs()
}

/// Prune expired pair-tokens in place. Returns the count removed.
pub fn prune_expired(tokens: &mut Vec<PairToken>) -> usize {
    let now = now_epoch();
    let before = tokens.len();
    tokens.retain(|t| t.expires_at_epoch > now);
    before.saturating_sub(tokens.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_is_random_and_short() {
        let a = generate_token();
        let b = generate_token();
        assert_ne!(a, b);
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn hash_is_deterministic_hex() {
        let h = hash_token("hello");
        assert_eq!(h.len(), 64);
        assert_eq!(h, hash_token("hello"));
        assert_ne!(h, hash_token("world"));
    }

    #[test]
    fn round_trip_save_load() {
        let dir = tempfile::tempdir().unwrap();
        let store = PairTokenStore::new(dir.path().join("pair-tokens.toml"));
        let token = PairToken {
            token_hash: "abc".into(),
            principal: PrincipalId::new("alice").unwrap(),
            expires_at_epoch: 9_999_999_999,
            issued_at_epoch: 1,
            label: Some("phone".into()),
            scope: DeviceScope::Scoped {
                allow: vec!["self:*".into()],
                deny: vec!["self:auth:pair".into()],
            },
        };
        store.save(std::slice::from_ref(&token)).unwrap();
        let loaded = store.load().unwrap();
        assert_eq!(loaded, vec![token]);
    }

    #[test]
    fn legacy_token_without_scope_loads_as_full() {
        // A pair-token record written before the `scope` field existed has no
        // `scope` key on disk; it must load as a Full-scope (unattenuated)
        // device so the round-trip preserves the prior behaviour.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pair-tokens.toml");
        let legacy = "[[pair_token]]\n\
            token_hash = \"abc\"\n\
            principal = \"alice\"\n\
            expires_at_epoch = 9999999999\n\
            issued_at_epoch = 1\n";
        std::fs::write(&path, legacy).unwrap();
        let loaded = PairTokenStore::new(path).load().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].scope, DeviceScope::Full);
    }

    #[test]
    fn prune_drops_expired() {
        let now = now_epoch();
        let mut v = vec![
            PairToken {
                token_hash: "a".into(),
                principal: PrincipalId::default(),
                expires_at_epoch: now.saturating_add(60),
                issued_at_epoch: now,
                label: None,
                scope: DeviceScope::Full,
            },
            PairToken {
                token_hash: "b".into(),
                principal: PrincipalId::default(),
                expires_at_epoch: now.saturating_sub(60),
                issued_at_epoch: now.saturating_sub(120),
                label: None,
                scope: DeviceScope::Full,
            },
        ];
        assert_eq!(prune_expired(&mut v), 1);
        assert_eq!(v.len(), 1);
    }
}
