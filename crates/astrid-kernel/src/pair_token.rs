//! Persistent pair-device token store (issue #756).
//!
//! Mirrors [`crate::invite`]'s shape but targets adding a NEW key
//! to an EXISTING principal (the "pair device" flow) instead of
//! minting a fresh principal.
//!
//! Durable records live in the fixed `system:control:pair-tokens` namespace,
//! bound to immutable principal UIDs. `$ASTRID_HOME/etc/pair-tokens.toml` is
//! accepted only by the bounded boot migration and is retired after verified
//! readback.
//!
//! ## Threat model
//!
//! Same posture as the invite store: only domain-separated hashes are stored,
//! redemption compares hashes in constant time, and mutation uses atomic
//! system-owner KV batches. Pair-tokens are single-use only (no
//! `remaining_uses` field). Redemption first claims an exact record with a
//! durable reservation, performs the profile update, and then commits the
//! deletion; a preparation failure releases only that reservation.
//!
//! Lifetime is capped at one hour (`MAX_EXPIRY_SECS`) — pair-tokens
//! are meant for immediate use on a neighbouring device. Longer
//! sharing windows are deliberately unsupported; if a user really
//! wants a multi-day window they should redeem a separate invite
//! (different principal) instead.

use std::path::PathBuf;
use std::sync::Arc;

use astrid_core::DeviceScope;
use astrid_core::PrincipalId;
use astrid_core::dirs::AstridHome;
use astrid_core::identity::PrincipalUid;
use astrid_crypto::IdentifierHash;
use base64::Engine;
use rand::{TryRng, rngs::SysRng};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
use tracing::warn;

#[path = "pair_token_storage_migration.rs"]
mod storage_migration;
use storage_migration::{read_legacy_source, retire_legacy_file};

#[path = "pair_token/token_hash.rs"]
mod token_hash;
use token_hash::TokenHash;

mod durable_reservation;

const STORE_SCHEMA_VERSION: u32 = 1;
const TOKEN_HASH_CONTEXT: &str = "astrid.runtime.pair-device-token.identifier.v1";

/// Type prefix carried by every raw device-pairing bearer token.
pub const TOKEN_PREFIX: &str = "astrid_pair_";

/// Length of the random token portion in bytes (192 bits → 32 chars
/// URL-safe base64). Same sizing as invite tokens.
pub const TOKEN_RAW_LEN: usize = 24;

/// Hard cap on a single pair-token's lifetime. Pair-tokens are
/// intended for immediate use ("scan this QR with your phone, now")
/// — a longer window is deliberately unsupported.
pub const MAX_EXPIRY_SECS: u64 = 60 * 60;

/// On-disk persisted pair-token record. Raw token is never stored —
/// only its domain-separated BLAKE3 identifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairToken {
    /// `blake3:<hex>` identifier of the complete `astrid_pair_` bearer token.
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

/// Fixed host-only namespace for pair-device authority.  Records are keyed by
/// token identifier and bind the immutable principal UID, never a mutable
/// alias or alias-derived namespace.
pub const SYSTEM_KV_NAMESPACE: &str = "system:control:pair-tokens";
const LEGACY_RECEIPT_KEY: &str = "migration:legacy-v1";
const RECORD_PREFIX: &str = "record:";
const MAX_RECORDS: usize = 4096;
const MAX_RECORD_BYTES: usize = 16 * 1024;
const MAX_LEGACY_BYTES: u64 = 4 * 1024 * 1024;

/// Durable UID-bound pair-token record.  The public [`PairToken`] remains the
/// legacy-file compatibility type; runtime handlers use this record so alias
/// renames cannot retarget an outstanding pairing authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurablePairToken {
    /// Canonical BLAKE3 identifier of the raw bearer token.
    pub token_hash: String,
    /// Immutable principal identity receiving the paired key.
    pub principal_uid: PrincipalUid,
    /// Wall-clock expiration.
    pub expires_at_epoch: u64,
    /// Wall-clock issuance time.
    pub issued_at_epoch: u64,
    /// Optional operator label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Capability scope stamped onto the paired device.
    pub scope: DeviceScope,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyImportReceipt {
    schema: u32,
    source_digest: String,
    record_count: u64,
}

/// Storage-backed pair-token state with atomic conditional issue/consume/
/// revoke operations and strict one-time legacy import.
#[derive(Clone)]
pub struct DurablePairTokenStore {
    backend: Arc<dyn astrid_storage::KvStore>,
}

impl DurablePairTokenStore {
    /// Bind the fixed system-control projection.
    ///
    /// # Errors
    ///
    /// Returns a storage error if the backend rejects the fixed pair-token
    /// namespace.
    pub fn new(backend: Arc<dyn astrid_storage::KvStore>) -> astrid_storage::StorageResult<Self> {
        astrid_storage::ScopedKvStore::new(Arc::clone(&backend), SYSTEM_KV_NAMESPACE)?;
        Ok(Self { backend })
    }

    fn key(hash: &TokenHash) -> String {
        format!("{RECORD_PREFIX}{}", hash.as_str())
    }

    fn validate_record(token: &DurablePairToken) -> astrid_storage::StorageResult<()> {
        let _ = TokenHash::parse(&token.token_hash)?;
        if token.expires_at_epoch <= token.issued_at_epoch
            || token.expires_at_epoch.saturating_sub(token.issued_at_epoch) > MAX_EXPIRY_SECS
            || token.label.as_ref().is_some_and(|label| label.len() > 4096)
        {
            return Err(astrid_storage::StorageError::Serialization(
                "pair-token record is outside its bounded schema".to_owned(),
            ));
        }
        Ok(())
    }

    fn encode(token: &DurablePairToken) -> astrid_storage::StorageResult<Vec<u8>> {
        Self::validate_record(token)?;
        let value = serde_json::to_vec(token)
            .map_err(|error| astrid_storage::StorageError::Serialization(error.to_string()))?;
        if value.len() > MAX_RECORD_BYTES {
            return Err(astrid_storage::StorageError::Serialization(
                "pair-token record exceeds its bounded size".to_owned(),
            ));
        }
        Ok(value)
    }

    fn decode(bytes: &[u8]) -> astrid_storage::StorageResult<DurablePairToken> {
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(astrid_storage::StorageError::Serialization(
                "pair-token record exceeds its bounded size".to_owned(),
            ));
        }
        let token: DurablePairToken = serde_json::from_slice(bytes).map_err(|_| {
            astrid_storage::StorageError::Serialization("invalid pair-token record".to_owned())
        })?;
        Self::validate_record(&token)?;
        Ok(token)
    }

    async fn apply(
        &self,
        conditions: Vec<astrid_storage::KvBatchCondition>,
        mutations: Vec<astrid_storage::KvBatchMutation>,
    ) -> astrid_storage::StorageResult<bool> {
        if !self.backend.supports_atomic_batch() {
            return Err(astrid_storage::StorageError::Internal(
                "pair-token storage requires an atomic KV backend".to_owned(),
            ));
        }
        let batch = astrid_storage::KvMutationBatch::new(conditions, mutations)?;
        Ok(self.backend.apply_batch(&batch).await?.applied)
    }

    /// Import the released alias-bearing TOML exactly once, resolving each
    /// alias through the live immutable principal directory before mutation.
    ///
    /// # Errors
    ///
    /// Returns a storage error if the legacy source is unsafe or malformed,
    /// contains an unknown alias, conflicts with durable state, or cannot be
    /// durably imported.
    pub async fn ensure_legacy_import(
        &self,
        home: &AstridHome,
        principals: &astrid_storage::PrincipalDirectory,
    ) -> astrid_storage::StorageResult<()> {
        let path = PairTokenStore::path_for(home);
        let source = read_legacy_source(&path, principals)?;
        let receipt = self
            .backend
            .get(SYSTEM_KV_NAMESPACE, LEGACY_RECEIPT_KEY)
            .await?;
        if let Some(bytes) = receipt {
            let receipt: LegacyImportReceipt = serde_json::from_slice(&bytes).map_err(|_| {
                astrid_storage::StorageError::Internal(
                    "pair-token migration receipt is invalid".to_owned(),
                )
            })?;
            if receipt.schema != 1 {
                return Err(astrid_storage::StorageError::Internal(
                    "pair-token migration receipt schema is unsupported".to_owned(),
                ));
            }
            if let Some((source_bytes, _)) = &source {
                let digest = format!("blake3:{}", blake3::hash(source_bytes).to_hex());
                if digest != receipt.source_digest {
                    return Err(astrid_storage::StorageError::Internal(
                        "legacy pair-token source conflicts with durable migration state"
                            .to_owned(),
                    ));
                }
            }
            self.verify_count(receipt.record_count).await?;
            if source.is_some() {
                retire_legacy_file(&path, &receipt.source_digest)?;
            }
            return Ok(());
        }

        let Some((source_bytes, tokens)) = source else {
            return Ok(());
        };
        if tokens.len() > MAX_RECORDS || tokens.len() > 500 {
            return Err(astrid_storage::StorageError::Serialization(
                "legacy pair-token store exceeds the bounded migration limit".to_owned(),
            ));
        }
        let existing = self
            .backend
            .list_keys_with_prefix(SYSTEM_KV_NAMESPACE, RECORD_PREFIX)
            .await?;
        if !existing.is_empty() {
            return Err(astrid_storage::StorageError::Internal(
                "legacy pair-token source conflicts with existing durable state".to_owned(),
            ));
        }
        let digest = format!("blake3:{}", blake3::hash(&source_bytes).to_hex());
        let receipt = LegacyImportReceipt {
            schema: 1,
            source_digest: digest.clone(),
            record_count: tokens.len() as u64,
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
        for token in &tokens {
            let durable = DurablePairToken {
                token_hash: token.token_hash.clone(),
                principal_uid: principals.uid_for(&token.principal).map_err(|_| {
                    astrid_storage::StorageError::Internal(
                        "legacy pair-token principal is not an admitted immutable identity"
                            .to_owned(),
                    )
                })?,
                expires_at_epoch: token.expires_at_epoch,
                issued_at_epoch: token.issued_at_epoch,
                label: token.label.clone(),
                scope: token.scope.clone(),
            };
            let value = Self::encode(&durable)?;
            let key = Self::key(&TokenHash::parse(&durable.token_hash)?);
            conditions.push(astrid_storage::KvBatchCondition::ValueEquals {
                key: astrid_storage::KvEntryKey::new(SYSTEM_KV_NAMESPACE, &key)?,
                expected: None,
            });
            mutations.push(astrid_storage::KvBatchMutation::Set {
                key: astrid_storage::KvEntryKey::new(SYSTEM_KV_NAMESPACE, key)?,
                value,
            });
        }
        if !self.apply(conditions, mutations).await? {
            return Err(astrid_storage::StorageError::Internal(
                "legacy pair-token migration raced with another durable writer".to_owned(),
            ));
        }
        self.verify_count(tokens.len() as u64).await?;
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
                "durable pair-token migration read-back count mismatch".to_owned(),
            ));
        }
        for key in keys {
            let Some(value) = self.backend.get(SYSTEM_KV_NAMESPACE, &key).await? else {
                return Err(astrid_storage::StorageError::Internal(
                    "durable pair-token migration read-back was incomplete".to_owned(),
                ));
            };
            Self::decode(&value)?;
        }
        Ok(())
    }

    /// List current UID-bound records in deterministic order.
    ///
    /// # Errors
    ///
    /// Returns a storage error if records cannot be listed or decoded.
    pub async fn list(&self) -> astrid_storage::StorageResult<Vec<DurablePairToken>> {
        let mut keys = self
            .backend
            .list_keys_with_prefix(SYSTEM_KV_NAMESPACE, RECORD_PREFIX)
            .await?;
        if keys.len() > MAX_RECORDS {
            return Err(astrid_storage::StorageError::Internal(
                "pair-token storage exceeds its bounded record limit".to_owned(),
            ));
        }
        keys.sort_unstable();
        let mut records = Vec::with_capacity(keys.len());
        for key in keys {
            let Some(value) = self.backend.get(SYSTEM_KV_NAMESPACE, &key).await? else {
                return Err(astrid_storage::StorageError::Internal(
                    "pair-token record disappeared during read".to_owned(),
                ));
            };
            records.push(Self::decode(&value)?);
        }
        records.sort_by(|left, right| left.token_hash.cmp(&right.token_hash));
        Ok(records)
    }

    /// Insert a UID-bound token iff its identifier is absent.
    ///
    /// # Errors
    ///
    /// Returns a storage error if the conditional batch cannot be applied.
    pub async fn issue(&self, token: &DurablePairToken) -> astrid_storage::StorageResult<bool> {
        let value = Self::encode(token)?;
        let hash = TokenHash::parse(&token.token_hash)?;
        let key = Self::key(&hash);
        self.apply(
            vec![astrid_storage::KvBatchCondition::ValueEquals {
                key: astrid_storage::KvEntryKey::new(SYSTEM_KV_NAMESPACE, &key)?,
                expected: None,
            }],
            vec![astrid_storage::KvBatchMutation::Set {
                key: astrid_storage::KvEntryKey::new(SYSTEM_KV_NAMESPACE, key)?,
                value,
            }],
        )
        .await
    }

    /// Atomically consume one token; only one concurrent redeemer wins.
    ///
    /// # Errors
    ///
    /// Returns a storage error if the record cannot be read, decoded, or
    /// conditionally removed.
    pub async fn redeem(
        &self,
        token_hash: &str,
    ) -> astrid_storage::StorageResult<Option<DurablePairToken>> {
        let hash = TokenHash::parse(token_hash)?;
        let key = Self::key(&hash);
        let Some(value) = self.backend.get(SYSTEM_KV_NAMESPACE, &key).await? else {
            return Ok(None);
        };
        let token = Self::decode(&value)?;
        if token.expires_at_epoch <= now_epoch() {
            let _ = self
                .apply(
                    vec![astrid_storage::KvBatchCondition::ValueEquals {
                        key: astrid_storage::KvEntryKey::new(SYSTEM_KV_NAMESPACE, &key)?,
                        expected: Some(value),
                    }],
                    vec![astrid_storage::KvBatchMutation::Delete {
                        key: astrid_storage::KvEntryKey::new(SYSTEM_KV_NAMESPACE, key)?,
                    }],
                )
                .await?;
            return Ok(None);
        }
        if self
            .apply(
                vec![astrid_storage::KvBatchCondition::ValueEquals {
                    key: astrid_storage::KvEntryKey::new(SYSTEM_KV_NAMESPACE, &key)?,
                    expected: Some(value),
                }],
                vec![astrid_storage::KvBatchMutation::Delete {
                    key: astrid_storage::KvEntryKey::new(SYSTEM_KV_NAMESPACE, key)?,
                }],
            )
            .await?
        {
            Ok(Some(token))
        } else {
            Ok(None)
        }
    }
}

fn canonical_fingerprint(value: &str) -> Option<String> {
    let (algorithm, digest) = value.split_once(':')?;
    (algorithm == "blake3"
        && digest.len() == 64
        && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        && digest == digest.to_ascii_lowercase())
    .then(|| value.to_owned())
}

/// Serde default for [`PairToken::scope`] — `Full`, so an on-disk record
/// written before scoping existed loads as an unattenuated device.
fn default_full_scope() -> DeviceScope {
    DeviceScope::Full
}

/// File-backed pair-token store. Read-modify-write uses atomic rename on Unix;
/// all loads and mutators serialise on the kernel's `admin_write_lock` because
/// a load can migrate legacy state.
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

    /// Read the persisted list. Missing file → empty Vec. A schema-0 store is
    /// invalidated because its SHA-256 token identifiers cannot be
    /// converted without the raw tokens.
    ///
    /// # Errors
    /// Returns an error if the file exists but is unreadable or
    /// malformed.
    pub fn load(&self) -> Result<Vec<PairToken>, PairTokenStoreError> {
        // Pairing persistence is native-only; the browser store is in-memory
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
    fn load_from_disk(&self) -> Result<Vec<PairToken>, PairTokenStoreError> {
        let bytes = match std::fs::read(&self.path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(PairTokenStoreError::Io(e)),
        };
        let text = std::str::from_utf8(&bytes).map_err(|e| {
            PairTokenStoreError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        })?;
        if text.trim().is_empty() {
            if let Err(error) = self.save_to_disk(&[]) {
                warn!(
                    path = %self.path.display(),
                    %error,
                    "could not normalize empty pair-token store"
                );
            }
            return Ok(Vec::new());
        }
        let probe: SchemaProbe = toml::from_str(text).map_err(PairTokenStoreError::Toml)?;
        if probe.schema_version > STORE_SCHEMA_VERSION {
            return Err(PairTokenStoreError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "pair-token store schema {} is newer than supported schema {STORE_SCHEMA_VERSION}",
                    probe.schema_version
                ),
            )));
        }
        let parsed: PersistedFile = toml::from_str(text).map_err(PairTokenStoreError::Toml)?;
        if probe.schema_version == 0 {
            let invalidated = parsed.pair_token.len();
            self.save_to_disk(&[])?;
            warn!(
                path = %self.path.display(),
                invalidated,
                "invalidated legacy SHA-256 pair-token store"
            );
            return Ok(Vec::new());
        }
        Ok(parsed.pair_token)
    }

    /// Write the supplied list with write-then-rename and 0600 permissions on
    /// Unix. An empty list retains the versioned TOML envelope.
    ///
    /// # Errors
    /// Returns an error if the file cannot be written.
    pub fn save(&self, tokens: &[PairToken]) -> Result<(), PairTokenStoreError> {
        // Pairing persistence is native-only; the browser store is in-memory
        // and silently drops writes rather than touching disk.
        #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
        {
            let _ = (&self.path, tokens);
            return Ok(());
        }
        #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
        {
            self.save_to_disk(tokens)
        }
    }

    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    fn save_to_disk(&self, tokens: &[PairToken]) -> Result<(), PairTokenStoreError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(PairTokenStoreError::Io)?;
        }
        let body = PersistedFile {
            schema_version: STORE_SCHEMA_VERSION,
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
    pair_token: Vec<PairToken>,
}

/// Generate a typed token with a random URL-safe-base64 secret from the OS CSPRNG.
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
        assert!(a.starts_with(TOKEN_PREFIX));
        assert_eq!(a.strip_prefix(TOKEN_PREFIX).unwrap().len(), 32);
    }

    #[test]
    fn hash_is_domain_separated_blake3() {
        let h = hash_token("hello");
        assert_eq!(
            h,
            "blake3:4e8275107b87254c5236647be8785404cdf3388d1ec2e149df1054de5a01e7a4"
        );
        assert_eq!(h.len(), 71);
        assert_eq!(h, hash_token("hello"));
        assert_ne!(h, hash_token("world"));
        assert_ne!(h, crate::invite::hash_token("hello"));
    }

    #[test]
    fn ct_hash_eq_checks_the_full_identifier_shape() {
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
    fn round_trip_save_load() {
        let dir = tempfile::tempdir().unwrap();
        let store = PairTokenStore::new(dir.path().join("pair-tokens.toml"));
        let token = PairToken {
            token_hash: hash_token("pair alice phone"),
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
        assert!(
            std::fs::read_to_string(&store.path)
                .unwrap()
                .contains("schema_version = 1")
        );
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
        let legacy = "schema_version = 1\n\
            [[pair_token]]\n\
            token_hash = \"blake3:4e8275107b87254c5236647be8785404cdf3388d1ec2e149df1054de5a01e7a4\"\n\
            principal = \"alice\"\n\
            expires_at_epoch = 9999999999\n\
            issued_at_epoch = 1\n";
        std::fs::write(&path, legacy).unwrap();
        let loaded = PairTokenStore::new(path).load().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].scope, DeviceScope::Full);
    }

    #[test]
    fn legacy_sha256_store_is_invalidated_and_rewritten() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pair-tokens.toml");
        let legacy = "[[pair_token]]\n\
            token_hash = \"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824\"\n\
            principal = \"alice\"\n\
            expires_at_epoch = 9999999999\n\
            issued_at_epoch = 1\n";
        std::fs::write(&path, legacy).unwrap();

        let store = PairTokenStore::new(path.clone());
        assert!(store.load().unwrap().is_empty());
        let rewritten = std::fs::read_to_string(&path).unwrap();
        assert!(rewritten.contains("schema_version = 1"));
        assert!(!rewritten.contains("[[pair_token]]"));
        assert!(store.load().unwrap().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn read_only_legacy_sha256_store_fails_closed_without_rewrite() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pair-tokens.toml");
        let legacy = "[[pair_token]]\n\
            token_hash = \"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824\"\n\
            principal = \"alice\"\n\
            expires_at_epoch = 9999999999\n\
            issued_at_epoch = 1\n";
        std::fs::write(&path, legacy).unwrap();

        let original = std::fs::metadata(dir.path()).unwrap().permissions();
        let mut read_only = original.clone();
        read_only.set_mode(0o500);
        std::fs::set_permissions(dir.path(), read_only).unwrap();
        let loaded = PairTokenStore::new(path.clone()).load();
        std::fs::set_permissions(dir.path(), original).unwrap();

        assert!(loaded.is_err());
        assert_eq!(std::fs::read_to_string(path).unwrap(), legacy);
    }

    #[test]
    fn future_store_is_rejected_without_rewrite() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pair-tokens.toml");
        let future = "schema_version = 2\nfuture_field = \"preserve me\"\n";
        std::fs::write(&path, future).unwrap();

        let err = PairTokenStore::new(path.clone()).load().unwrap_err();
        assert!(err.to_string().contains("schema 2 is newer"));
        assert_eq!(std::fs::read_to_string(path).unwrap(), future);
    }

    #[test]
    fn malformed_store_is_rejected_without_rewrite() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pair-tokens.toml");
        let malformed = "schema_version = [not valid\n";
        std::fs::write(&path, malformed).unwrap();

        assert!(PairTokenStore::new(path.clone()).load().is_err());
        assert_eq!(std::fs::read_to_string(path).unwrap(), malformed);
    }

    #[cfg(unix)]
    #[test]
    fn read_only_empty_file_still_loads_as_empty_vec() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let store = PairTokenStore::new(dir.path().join("pair-tokens.toml"));
        std::fs::write(&store.path, "").unwrap();

        let original = std::fs::metadata(dir.path()).unwrap().permissions();
        let mut read_only = original.clone();
        read_only.set_mode(0o500);
        std::fs::set_permissions(dir.path(), read_only).unwrap();
        let loaded = store.load();
        std::fs::set_permissions(dir.path(), original).unwrap();

        assert_eq!(loaded.unwrap(), Vec::<PairToken>::new());
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
