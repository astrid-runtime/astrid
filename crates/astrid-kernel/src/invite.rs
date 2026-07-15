//! Persistent invite-token store (issue #756 / Layer 6 gateway).
//!
//! Invite tokens are short opaque secrets that grant a one-time-ish
//! right to mint a principal. The kernel never stores the raw token —
//! it stores a domain-separated BLAKE3 identifier of the complete typed
//! bearer string (`astrid_inv_` plus its URL-safe base64 secret). Redemption
//! hashes the incoming token and compares against the persisted set.
//!
//! ## On-disk layout
//!
//! `$ASTRID_HOME/etc/invites.toml`:
//!
//! ```toml
//! schema_version = 1
//!
//! [[invite]]
//! token_hash = "blake3:..."  # domain-separated BLAKE3 identifier
//! group = "agent"
//! remaining_uses = 1
//! expires_at_epoch = 1234567890
//! issued_at_epoch = 1234560000
//! metadata = "alice's tablet"
//! ```
//!
//! Unix writes use write-then-rename. The file is owned by the
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

use astrid_core::dirs::AstridHome;
use astrid_crypto::IdentifierHash;
use base64::Engine;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
use tracing::warn;

const STORE_SCHEMA_VERSION: u32 = 1;
const TOKEN_HASH_CONTEXT: &str = "astrid.runtime.invite-token.identifier.v1";

/// Type prefix carried by every raw invite bearer token.
pub const TOKEN_PREFIX: &str = "astrid_inv_";

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
/// only its domain-separated BLAKE3 identifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Invite {
    /// `blake3:<hex>` identifier of the complete `astrid_inv_` bearer token.
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

/// File-backed invite store. Read-modify-write uses atomic rename on Unix; all
/// loads and mutators must serialise externally because a load can migrate
/// legacy state (the kernel uses `admin_write_lock`).
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
    /// deployments never call invite-issue). A schema-0 store is invalidated
    /// because its SHA-256 token identifiers cannot be converted
    /// without the raw tokens.
    ///
    /// # Errors
    /// Returns an error if the file exists but is unreadable or malformed.
    pub fn load(&self) -> Result<Vec<Invite>, InviteStoreError> {
        // Invite persistence is native-only; the browser store is in-memory
        // (always empty) and never reads disk.
        #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
        {
            let _ = &self.path;
            return Ok(Vec::new());
        }
        #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
        {
            self.load_from_disk()
        }
    }

    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    fn load_from_disk(&self) -> Result<Vec<Invite>, InviteStoreError> {
        let bytes = match std::fs::read(&self.path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(InviteStoreError::Io(e)),
        };
        let text = std::str::from_utf8(&bytes).map_err(|e| {
            InviteStoreError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        })?;
        if text.trim().is_empty() {
            if let Err(error) = self.save_to_disk(&[]) {
                warn!(
                    path = %self.path.display(),
                    %error,
                    "could not normalize empty invite store"
                );
            }
            return Ok(Vec::new());
        }
        let probe: SchemaProbe = toml::from_str(text).map_err(InviteStoreError::Toml)?;
        if probe.schema_version > STORE_SCHEMA_VERSION {
            return Err(InviteStoreError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "invite store schema {} is newer than supported schema {STORE_SCHEMA_VERSION}",
                    probe.schema_version
                ),
            )));
        }
        let parsed: PersistedFile = toml::from_str(text).map_err(InviteStoreError::Toml)?;
        if probe.schema_version == 0 {
            let invalidated = parsed.invite.len();
            self.save_to_disk(&[])?;
            warn!(
                path = %self.path.display(),
                invalidated,
                "invalidated legacy SHA-256 invite-token store"
            );
            return Ok(Vec::new());
        }
        Ok(parsed.invite)
    }

    /// Write the supplied list with write-then-rename and 0600 permissions on
    /// Unix. An empty list retains the versioned TOML envelope rather than
    /// deleting the file, keeping the file-permission invariant observable to
    /// ops tooling.
    ///
    /// # Errors
    /// Returns an error if the file cannot be written.
    pub fn save(&self, invites: &[Invite]) -> Result<(), InviteStoreError> {
        // Invite persistence is native-only; the browser store is in-memory
        // and silently drops writes rather than touching disk.
        #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
        {
            let _ = (&self.path, invites);
            return Ok(());
        }
        #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
        {
            self.save_to_disk(invites)
        }
    }

    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    fn save_to_disk(&self, invites: &[Invite]) -> Result<(), InviteStoreError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(InviteStoreError::Io)?;
        }
        let body = PersistedFile {
            schema_version: STORE_SCHEMA_VERSION,
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

#[derive(Debug, Default, Deserialize)]
struct SchemaProbe {
    #[serde(default)]
    schema_version: u32,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct PersistedFile {
    #[serde(default)]
    schema_version: u32,
    #[serde(default)]
    invite: Vec<Invite>,
}

/// Generate a typed token with a random URL-safe-base64 secret. Uses the OS CSPRNG.
///
/// # Panics
///
/// Panics if the OS CSPRNG is unavailable.
#[must_use]
pub fn generate_token() -> String {
    use rand::{TryRng, rngs::SysRng};
    let mut bytes = [0u8; TOKEN_RAW_LEN];
    SysRng
        .try_fill_bytes(&mut bytes)
        .expect("OS CSPRNG unavailable while generating invite token");
    format!(
        "{TOKEN_PREFIX}{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    )
}

/// Derive a token identifier for storage and lookup.
#[must_use]
pub fn hash_token(token: &str) -> String {
    IdentifierHash::derive(TOKEN_HASH_CONTEXT, token.as_bytes()).to_prefixed_hex()
}

/// Constant-time hash comparison. Both inputs must be `blake3:<hex>`
/// identifiers. Returns `false` on any length mismatch
/// without leaking the position via short-circuit.
#[must_use]
pub fn ct_hash_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

/// Canonicalize a copied token identifier.
///
/// Returns `None` unless `value` is exactly one `blake3:<64 hex>` identifier.
/// Generated raw invite tokens carry [`TOKEN_PREFIX`], so the two accepted
/// revoke-input forms are unambiguous.
#[must_use]
pub fn canonical_token_fingerprint(value: &str) -> Option<String> {
    let (algorithm, digest) = value.split_once(':')?;
    (algorithm.eq_ignore_ascii_case("blake3")
        && digest.len() == 64
        && digest.chars().all(|c| c.is_ascii_hexdigit()))
    .then(|| format!("blake3:{}", digest.to_ascii_lowercase()))
}

/// Current wall-clock as seconds since Unix epoch. Saturating on the
/// (impossible) pre-1970 case so the returned `u64` never wraps.
#[must_use]
pub fn now_epoch() -> u64 {
    astrid_runtime::clock::now_epoch_secs()
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
        assert!(a.starts_with(TOKEN_PREFIX));
        let secret = a.strip_prefix(TOKEN_PREFIX).unwrap();
        assert!(
            secret
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
        // base64-url-no-pad of 24 bytes is 32 chars.
        assert_eq!(secret.len(), 32);
    }

    #[test]
    fn hash_token_is_domain_separated_blake3() {
        let h = hash_token("hello");
        assert_eq!(
            h,
            "blake3:d39676568f815c5ec571111d4563251442758032b79ed8d01c97518b4e2630d2"
        );
        assert_eq!(h.len(), 71);
        assert_eq!(h, hash_token("hello"));
        assert_ne!(h, hash_token("world"));
    }

    #[test]
    fn ct_hash_eq_rejects_length_mismatch() {
        let expected = hash_token("hello");
        assert!(ct_hash_eq(&expected, &expected));
        for index in [7, expected.len() / 2, expected.len() - 1] {
            let mut different = expected.clone().into_bytes();
            different[index] = if different[index] == b'0' { b'1' } else { b'0' };
            assert!(!ct_hash_eq(
                &expected,
                std::str::from_utf8(&different).unwrap()
            ));
        }
        assert!(!ct_hash_eq(&expected, &expected[..70]));
        assert!(!ct_hash_eq(&expected, &format!("{expected}0")));
    }

    #[test]
    fn copied_fingerprint_is_canonicalized() {
        let expected = hash_token("hello");
        assert_eq!(
            canonical_token_fingerprint(&expected.to_ascii_uppercase()),
            Some(expected)
        );
        assert_eq!(canonical_token_fingerprint("raw-token"), None);
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
            token_hash: hash_token("alice invite"),
            group: "agent".into(),
            remaining_uses: 2,
            expires_at_epoch: Some(now.saturating_add(3600)),
            issued_at_epoch: now,
            metadata: Some("alice".into()),
        };
        store.save(std::slice::from_ref(&invite)).unwrap();
        assert!(
            std::fs::read_to_string(&store.path)
                .unwrap()
                .contains("schema_version = 1")
        );
        let loaded = store.load().unwrap();
        assert_eq!(loaded, vec![invite]);
    }

    #[test]
    fn legacy_sha256_store_is_invalidated_and_rewritten() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("invites.toml");
        let legacy = "[[invite]]\n\
            token_hash = \"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824\"\n\
            group = \"agent\"\n\
            remaining_uses = 1\n\
            issued_at_epoch = 1\n";
        std::fs::write(&path, legacy).unwrap();

        let store = InviteStore::new(path.clone());
        assert!(store.load().unwrap().is_empty());
        let rewritten = std::fs::read_to_string(&path).unwrap();
        assert!(rewritten.contains("schema_version = 1"));
        assert!(!rewritten.contains("[[invite]]"));
        assert!(store.load().unwrap().is_empty());
    }

    #[test]
    fn future_store_is_rejected_without_rewrite() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("invites.toml");
        let future = "schema_version = 2\nfuture_field = \"preserve me\"\n";
        std::fs::write(&path, future).unwrap();

        let err = InviteStore::new(path.clone()).load().unwrap_err();
        assert!(err.to_string().contains("schema 2 is newer"));
        assert_eq!(std::fs::read_to_string(path).unwrap(), future);
    }

    #[test]
    fn malformed_store_is_rejected_without_rewrite() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("invites.toml");
        let malformed = "schema_version = [not valid\n";
        std::fs::write(&path, malformed).unwrap();

        assert!(InviteStore::new(path.clone()).load().is_err());
        assert_eq!(std::fs::read_to_string(path).unwrap(), malformed);
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
        assert!(
            std::fs::read_to_string(&store.path)
                .unwrap()
                .contains("schema_version = 1")
        );
    }

    #[cfg(unix)]
    #[test]
    fn read_only_empty_file_still_loads_as_empty_vec() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let store = InviteStore::new(dir.path().join("invites.toml"));
        std::fs::write(&store.path, "").unwrap();

        let original = std::fs::metadata(dir.path()).unwrap().permissions();
        let mut read_only = original.clone();
        read_only.set_mode(0o500);
        std::fs::set_permissions(dir.path(), read_only).unwrap();
        let loaded = store.load();
        std::fs::set_permissions(dir.path(), original).unwrap();

        assert_eq!(loaded.unwrap(), Vec::<Invite>::new());
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
