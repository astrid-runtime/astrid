//! Persistent invite-token store (issue #756 / Layer 6 gateway).
//!
//! Invite tokens are short opaque secrets that grant a one-time-ish
//! right to mint a principal. The kernel never stores the raw token —
//! it stores a domain-separated BLAKE3 identifier of the complete typed
//! bearer string (`astrid_inv_` plus its URL-safe base64 secret). Redemption
//! hashes the incoming token and compares against the persisted set.
//!
//! Durable records live in the fixed `system:control:invites` namespace.
//! Issuance, redemption, revocation, and pruning use one-owner atomic KV
//! batches. `$ASTRID_HOME/etc/invites.toml` is accepted only by the bounded
//! boot migration and is retired after receipt-bound readback.
//!
//! ## Threat model
//!
//! * **Read-only leak**: an attacker who reads the durable namespace sees
//!   token *hashes*, not tokens. They cannot redeem.
//! * **Write authority**: only the kernel's system-owner control projection
//!   can mutate records; a host file is never live token authority.
//! * **Replay**: each redemption decrements `remaining_uses`; reaching
//!   zero removes the entry under the kernel's `admin_write_lock`.
//! * **Wall-clock expiry**: enforced at redeem time. Expired entries
//!   are removed lazily on the next bounded `prune`.
//! * **Side-channel on lookup**: the redeem path uses
//!   constant-time comparison on the hash bytes.

use std::path::PathBuf;
use std::sync::Arc;

use astrid_core::dirs::AstridHome;
use astrid_crypto::IdentifierHash;
use base64::Engine;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
use tracing::warn;

mod durable_reservation;
mod storage_migration;
use storage_migration::{read_legacy_source, retire_legacy_file};

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

/// Fixed host-only namespace used for invite state.  This is deliberately a
/// constant rather than an alias-derived namespace: invite records are daemon
/// control state, not principal state.
pub const SYSTEM_KV_NAMESPACE: &str = "system:control:invites";
const LEGACY_RECEIPT_KEY: &str = "migration:legacy-v1";
const RECORD_PREFIX: &str = "record:";
const MAX_RECORDS: usize = 4096;
const MAX_RECORD_BYTES: usize = 16 * 1024;
const MAX_LEGACY_BYTES: u64 = 4 * 1024 * 1024;

/// Storage-backed invite state.  Every mutating operation is one conditional
/// KV batch, so two daemons cannot consume the same token even if an outer
/// process lock is lost.
#[derive(Clone)]
pub struct DurableInviteStore {
    backend: Arc<dyn astrid_storage::KvStore>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyImportReceipt {
    schema: u32,
    source_digest: String,
    record_count: u64,
}

impl DurableInviteStore {
    /// Bind the fixed system-control projection.
    ///
    /// # Errors
    ///
    /// Returns a storage error if the backend rejects the fixed invite
    /// namespace.
    pub fn new(backend: Arc<dyn astrid_storage::KvStore>) -> astrid_storage::StorageResult<Self> {
        // Validate the fixed namespace at construction time so a future edit
        // cannot accidentally widen this helper to an arbitrary scope.
        astrid_storage::kv::ScopedKvStore::new(Arc::clone(&backend), SYSTEM_KV_NAMESPACE)?;
        Ok(Self { backend })
    }

    fn key(hash: &str) -> String {
        format!("{RECORD_PREFIX}{hash}")
    }

    fn validate_record(invite: &Invite) -> astrid_storage::StorageResult<()> {
        if canonical_token_fingerprint(&invite.token_hash).as_deref() != Some(&invite.token_hash) {
            return Err(astrid_storage::StorageError::Serialization(
                "invite record has a non-canonical token identifier".to_owned(),
            ));
        }
        if invite.group.is_empty() || invite.group.len() > 256 || invite.remaining_uses == 0 {
            return Err(astrid_storage::StorageError::Serialization(
                "invite record is outside its bounded schema".to_owned(),
            ));
        }
        if invite
            .metadata
            .as_ref()
            .is_some_and(|value| value.len() > 4096)
        {
            return Err(astrid_storage::StorageError::Serialization(
                "invite metadata exceeds its bounded schema".to_owned(),
            ));
        }
        Ok(())
    }

    fn encode(invite: &Invite) -> astrid_storage::StorageResult<Vec<u8>> {
        Self::validate_record(invite)?;
        let value = serde_json::to_vec(invite)
            .map_err(|error| astrid_storage::StorageError::Serialization(error.to_string()))?;
        if value.len() > MAX_RECORD_BYTES {
            return Err(astrid_storage::StorageError::Serialization(
                "invite record exceeds its bounded size".to_owned(),
            ));
        }
        Ok(value)
    }

    fn decode(bytes: &[u8]) -> astrid_storage::StorageResult<Invite> {
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(astrid_storage::StorageError::Serialization(
                "invite record exceeds its bounded size".to_owned(),
            ));
        }
        let invite: Invite = serde_json::from_slice(bytes).map_err(|_| {
            astrid_storage::StorageError::Serialization("invalid invite record".to_owned())
        })?;
        Self::validate_record(&invite)?;
        Ok(invite)
    }

    async fn apply(
        &self,
        conditions: Vec<astrid_storage::KvBatchCondition>,
        mutations: Vec<astrid_storage::KvBatchMutation>,
    ) -> astrid_storage::StorageResult<bool> {
        if !self.backend.supports_atomic_batch() {
            return Err(astrid_storage::StorageError::Internal(
                "invite storage requires an atomic KV backend".to_owned(),
            ));
        }
        let batch = astrid_storage::KvMutationBatch::new(conditions, mutations)?;
        Ok(self.backend.apply_batch(&batch).await?.applied)
    }

    /// Ensure a released native invite file has been imported exactly once.
    /// The source is validated and parsed before any durable mutation.  A
    /// durable receipt makes restart idempotent; retirement happens only after
    /// record and receipt read-back succeeds.
    ///
    /// # Errors
    ///
    /// Returns a storage error if the legacy source is unsafe or malformed,
    /// conflicts with durable state, or cannot be durably imported.
    pub async fn ensure_legacy_import(
        &self,
        home: &AstridHome,
    ) -> astrid_storage::StorageResult<()> {
        let path = InviteStore::path_for(home);
        let source = read_legacy_source(&path)?;
        let receipt = self
            .backend
            .get(SYSTEM_KV_NAMESPACE, LEGACY_RECEIPT_KEY)
            .await?;
        if let Some(bytes) = receipt {
            let receipt: LegacyImportReceipt = serde_json::from_slice(&bytes).map_err(|_| {
                astrid_storage::StorageError::Internal(
                    "invite migration receipt is invalid".to_owned(),
                )
            })?;
            if receipt.schema != 1 {
                return Err(astrid_storage::StorageError::Internal(
                    "invite migration receipt schema is unsupported".to_owned(),
                ));
            }
            if let Some((source_bytes, _)) = &source {
                let digest = format!("blake3:{}", blake3::hash(source_bytes).to_hex());
                if digest != receipt.source_digest {
                    return Err(astrid_storage::StorageError::Internal(
                        "legacy invite source conflicts with durable migration state".to_owned(),
                    ));
                }
            }
            self.verify_count(receipt.record_count).await?;
            if source.is_some() {
                retire_legacy_file(&path, &receipt.source_digest)?;
            }
            return Ok(());
        }

        let Some((source_bytes, invites)) = source else {
            return Ok(());
        };
        if invites.len() > MAX_RECORDS || invites.len() > 500 {
            return Err(astrid_storage::StorageError::Serialization(
                "legacy invite store exceeds the bounded migration limit".to_owned(),
            ));
        }
        let existing = self
            .backend
            .list_keys_with_prefix(SYSTEM_KV_NAMESPACE, RECORD_PREFIX)
            .await?;
        if !existing.is_empty() {
            return Err(astrid_storage::StorageError::Internal(
                "legacy invite source conflicts with existing durable state".to_owned(),
            ));
        }
        let digest = format!("blake3:{}", blake3::hash(&source_bytes).to_hex());
        let receipt = LegacyImportReceipt {
            schema: 1,
            source_digest: digest.clone(),
            record_count: invites.len() as u64,
        };
        let receipt_bytes = serde_json::to_vec(&receipt)
            .map_err(|error| astrid_storage::StorageError::Serialization(error.to_string()))?;
        let mut conditions = vec![astrid_storage::KvBatchCondition::ValueEquals {
            key: astrid_storage::KvEntryKey::new(SYSTEM_KV_NAMESPACE, LEGACY_RECEIPT_KEY)?,
            expected: None,
        }];
        let mut mutations = vec![astrid_storage::KvBatchMutation::Set {
            key: astrid_storage::KvEntryKey::new(SYSTEM_KV_NAMESPACE, LEGACY_RECEIPT_KEY)?,
            value: receipt_bytes,
        }];
        for invite in &invites {
            let value = Self::encode(invite)?;
            let key = Self::key(&invite.token_hash);
            conditions.push(astrid_storage::KvBatchCondition::ValueEquals {
                key: astrid_storage::KvEntryKey::new(SYSTEM_KV_NAMESPACE, &key)?,
                expected: None,
            });
            mutations.push(astrid_storage::KvBatchMutation::Set {
                key: astrid_storage::KvEntryKey::new(SYSTEM_KV_NAMESPACE, &key)?,
                value,
            });
        }
        if !self.apply(conditions, mutations).await? {
            return Err(astrid_storage::StorageError::Internal(
                "legacy invite migration raced with another durable writer".to_owned(),
            ));
        }
        self.verify_count(invites.len() as u64).await?;
        retire_legacy_file(&path, &digest)?;
        Ok(())
    }

    async fn verify_count(&self, expected: u64) -> astrid_storage::StorageResult<()> {
        let keys = self
            .backend
            .list_keys_with_prefix(SYSTEM_KV_NAMESPACE, RECORD_PREFIX)
            .await?;
        if keys.len() as u64 != expected || keys.len() > MAX_RECORDS {
            return Err(astrid_storage::StorageError::Internal(
                "durable invite migration read-back count mismatch".to_owned(),
            ));
        }
        for key in keys {
            let Some(value) = self.backend.get(SYSTEM_KV_NAMESPACE, &key).await? else {
                return Err(astrid_storage::StorageError::Internal(
                    "durable invite migration read-back was incomplete".to_owned(),
                ));
            };
            Self::decode(&value)?;
        }
        Ok(())
    }

    /// Load all current records in deterministic token-identifier order.
    ///
    /// # Errors
    ///
    /// Returns a storage error if records cannot be listed or decoded.
    pub async fn list(&self) -> astrid_storage::StorageResult<Vec<Invite>> {
        let mut keys = self
            .backend
            .list_keys_with_prefix(SYSTEM_KV_NAMESPACE, RECORD_PREFIX)
            .await?;
        if keys.len() > MAX_RECORDS {
            return Err(astrid_storage::StorageError::Internal(
                "invite storage exceeds its bounded record limit".to_owned(),
            ));
        }
        keys.sort_unstable();
        let mut records = Vec::with_capacity(keys.len());
        for key in keys {
            let Some(value) = self.backend.get(SYSTEM_KV_NAMESPACE, &key).await? else {
                return Err(astrid_storage::StorageError::Internal(
                    "invite record disappeared during read".to_owned(),
                ));
            };
            records.push(Self::decode(&value)?);
        }
        records.sort_by(|left, right| left.token_hash.cmp(&right.token_hash));
        Ok(records)
    }

    /// Insert one invite iff its identifier is absent.
    ///
    /// # Errors
    ///
    /// Returns a storage error if the conditional batch cannot be applied.
    pub async fn issue(&self, invite: &Invite) -> astrid_storage::StorageResult<bool> {
        let value = Self::encode(invite)?;
        let key = Self::key(&invite.token_hash);
        self.apply(
            vec![astrid_storage::KvBatchCondition::ValueEquals {
                key: astrid_storage::KvEntryKey::new(SYSTEM_KV_NAMESPACE, &key)?,
                expected: None,
            }],
            vec![astrid_storage::KvBatchMutation::Set {
                key: astrid_storage::KvEntryKey::new(SYSTEM_KV_NAMESPACE, &key)?,
                value,
            }],
        )
        .await
    }

    /// Atomically consume one invite.  Only one concurrent caller can win.
    ///
    /// # Errors
    ///
    /// Returns a storage error if the record cannot be read, decoded, or
    /// conditionally removed.
    pub async fn redeem(&self, token_hash: &str) -> astrid_storage::StorageResult<Option<Invite>> {
        let key = Self::key(token_hash);
        let Some(value) = self.backend.get(SYSTEM_KV_NAMESPACE, &key).await? else {
            return Ok(None);
        };
        let invite = Self::decode(&value)?;
        let now = now_epoch();
        if invite.remaining_uses == 0
            || invite
                .expires_at_epoch
                .is_some_and(|expires| expires <= now)
        {
            let _ = self
                .apply(
                    vec![astrid_storage::KvBatchCondition::ValueEquals {
                        key: astrid_storage::KvEntryKey::new(SYSTEM_KV_NAMESPACE, &key)?,
                        expected: Some(value),
                    }],
                    vec![astrid_storage::KvBatchMutation::Delete {
                        key: astrid_storage::KvEntryKey::new(SYSTEM_KV_NAMESPACE, &key)?,
                    }],
                )
                .await?;
            return Ok(None);
        }
        let mut consumed = invite.clone();
        consumed.remaining_uses = consumed.remaining_uses.saturating_sub(1);
        let mutation = if consumed.remaining_uses == 0 {
            astrid_storage::KvBatchMutation::Delete {
                key: astrid_storage::KvEntryKey::new(SYSTEM_KV_NAMESPACE, &key)?,
            }
        } else {
            astrid_storage::KvBatchMutation::Set {
                key: astrid_storage::KvEntryKey::new(SYSTEM_KV_NAMESPACE, &key)?,
                value: Self::encode(&consumed)?,
            }
        };
        if self
            .apply(
                vec![astrid_storage::KvBatchCondition::ValueEquals {
                    key: astrid_storage::KvEntryKey::new(SYSTEM_KV_NAMESPACE, &key)?,
                    expected: Some(value),
                }],
                vec![mutation],
            )
            .await?
        {
            Ok(Some(invite))
        } else {
            Ok(None)
        }
    }

    /// Remove one invite by its canonical fingerprint.
    ///
    /// # Errors
    ///
    /// Returns a storage error if the conditional delete cannot be applied.
    pub async fn revoke(&self, token_hash: &str) -> astrid_storage::StorageResult<bool> {
        let key = Self::key(token_hash);
        let Some(value) = self.backend.get(SYSTEM_KV_NAMESPACE, &key).await? else {
            return Ok(false);
        };
        Self::decode(&value)?;
        self.apply(
            vec![astrid_storage::KvBatchCondition::ValueEquals {
                key: astrid_storage::KvEntryKey::new(SYSTEM_KV_NAMESPACE, &key)?,
                expected: Some(value),
            }],
            vec![astrid_storage::KvBatchMutation::Delete {
                key: astrid_storage::KvEntryKey::new(SYSTEM_KV_NAMESPACE, &key)?,
            }],
        )
        .await
    }

    /// Prune expired and exhausted records using conditional deletes.
    ///
    /// # Errors
    ///
    /// Returns a storage error if records cannot be read or a conditional
    /// delete cannot be applied.
    pub async fn prune(&self) -> astrid_storage::StorageResult<usize> {
        let records = self.list().await?;
        let now = now_epoch();
        let mut removed = 0usize;
        for invite in records {
            if invite.remaining_uses > 0
                && invite.expires_at_epoch.is_none_or(|expires| expires > now)
            {
                continue;
            }
            let key = Self::key(&invite.token_hash);
            let Some(value) = self.backend.get(SYSTEM_KV_NAMESPACE, &key).await? else {
                continue;
            };
            if self
                .apply(
                    vec![astrid_storage::KvBatchCondition::ValueEquals {
                        key: astrid_storage::KvEntryKey::new(SYSTEM_KV_NAMESPACE, &key)?,
                        expected: Some(value),
                    }],
                    vec![astrid_storage::KvBatchMutation::Delete {
                        key: astrid_storage::KvEntryKey::new(SYSTEM_KV_NAMESPACE, &key)?,
                    }],
                )
                .await?
            {
                removed = removed.saturating_add(1);
            }
        }
        Ok(removed)
    }
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

    #[cfg(unix)]
    #[test]
    fn read_only_legacy_sha256_store_fails_closed_without_rewrite() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("invites.toml");
        let legacy = "[[invite]]\n\
            token_hash = \"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824\"\n\
            group = \"agent\"\n\
            remaining_uses = 1\n\
            issued_at_epoch = 1\n";
        std::fs::write(&path, legacy).unwrap();

        let original = std::fs::metadata(dir.path()).unwrap().permissions();
        let mut read_only = original.clone();
        read_only.set_mode(0o500);
        std::fs::set_permissions(dir.path(), read_only).unwrap();
        let loaded = InviteStore::new(path.clone()).load();
        std::fs::set_permissions(dir.path(), original).unwrap();

        assert!(loaded.is_err());
        assert_eq!(std::fs::read_to_string(path).unwrap(), legacy);
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
