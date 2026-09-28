//! Format-v2 signing state of the audit log: enabling v2, rotating the audit
//! key, and signing each new entry in the log's current format.

use std::sync::Arc;

use astrid_core::identity::PrincipalUid;
use astrid_core::{PrincipalId, SessionId, Timestamp};
use astrid_crypto::{ContentHash, KeyPair, PublicKey};

use super::{AuditError, AuditLog, AuditResult};
use crate::entry::{AuditAction, AuditEntry, AuditEntryFormat, AuditOutcome, AuthorizationProof};
use crate::entry_v2::{
    AuditActor, EntryV2Draft, KeyRegistry, KeyRegistryRecord, KeyRole, derive_chain_id,
};

/// Resolves a principal alias to its durable UID for v2 chain ids.
pub trait PrincipalUidResolver: Send + Sync {
    /// The durable UID currently bound to `principal`, if any.
    fn resolve_uid(&self, principal: &PrincipalId) -> Option<PrincipalUid>;
}

impl PrincipalUidResolver for astrid_storage::PrincipalDirectory {
    fn resolve_uid(&self, principal: &PrincipalId) -> Option<PrincipalUid> {
        self.uid_for(principal).ok()
    }
}

/// How to sign format-v2 entries.
pub struct EntryV2Config {
    /// The audit signing key. It must be the registry's active audit key,
    /// or become it when this call creates the registry.
    pub audit_key: Arc<KeyPair>,
    /// Keys registered for other roles when this call creates the registry,
    /// for example the runtime key as capability, build and audit-v1 key.
    /// Ignored when the registry already exists.
    pub genesis_roles: Vec<(KeyRole, Arc<KeyPair>)>,
    /// Resolves principal aliases to durable UIDs. Without it, and for an
    /// alias it cannot resolve, entries carry a `null` UID.
    pub principals: Option<Arc<dyn PrincipalUidResolver>>,
}

impl std::fmt::Debug for EntryV2Config {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EntryV2Config")
            .field("audit_key", &self.audit_key)
            .field("genesis_roles", &self.genesis_roles)
            .field("principals", &self.principals.is_some())
            .finish()
    }
}

/// The active v2 signer: the audit key and the registry it is valid in.
pub(crate) struct V2Signer {
    key: Arc<KeyPair>,
    registry: Arc<KeyRegistry>,
    principals: Option<Arc<dyn PrincipalUidResolver>>,
}

/// A v2 chain position, cached with a chain head.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct V2Position {
    chain_id: [u8; 32],
    seq: u64,
    key_epoch: u64,
}

impl V2Position {
    pub(crate) fn of(entry: &AuditEntry) -> Option<Self> {
        entry.v2.as_ref().map(|seal| Self {
            chain_id: seal.chain_id,
            seq: seal.seq,
            key_epoch: seal.key_epoch,
        })
    }
}

/// What to record, independent of the entry format.
#[derive(Clone)]
pub(crate) struct EntryRequest {
    pub(crate) session_id: SessionId,
    pub(crate) principal: Option<PrincipalId>,
    pub(crate) actor: Option<AuditActor>,
    pub(crate) action: AuditAction,
    pub(crate) authorization: AuthorizationProof,
    pub(crate) outcome: AuditOutcome,
}

const REGISTRY_CHANGED: &str = "the key registry changed concurrently; reopen the audit log";

impl AuditLog {
    /// The format new entries are written in.
    #[must_use]
    pub fn entry_format(&self) -> AuditEntryFormat {
        if self.v2_signer().is_some() {
            AuditEntryFormat::V2
        } else {
            AuditEntryFormat::V1
        }
    }

    /// The public key that signs new entries: the audit key under format v2,
    /// the runtime key under format v1.
    #[must_use]
    pub fn signing_public_key(&self) -> PublicKey {
        self.archive_signer().0.export_public_key()
    }

    /// The verified key registry of this store, if format v2 was ever enabled
    /// on it.
    ///
    /// # Errors
    ///
    /// Returns an error when the stored registry cannot be read or does not
    /// verify.
    pub async fn key_registry(&self) -> AuditResult<Option<KeyRegistry>> {
        if let Some(signer) = self.v2_signer() {
            return Ok(Some(signer.registry.as_ref().clone()));
        }
        self.load_key_registry().await
    }

    /// Switch new entries to format v2, signed by `config.audit_key`.
    ///
    /// On a store without a key registry this writes the genesis record,
    /// binding `config.audit_key` to the audit role and `config.genesis_roles`
    /// to theirs, signed by every one of those keys. On a store with a
    /// registry, `config.audit_key` must be the registry's active audit key.
    ///
    /// Enabling is one-way for the store: once a registry exists, format-v1
    /// appends are refused (see [`AuditError::V1Closed`]). Existing v1 entries
    /// are kept as they are; the next entry of each chain opens a v2 chain
    /// linked to the last v1 entry.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError::KeyNotRegistered`] when the key is not the
    /// registry's active audit key, or [`AuditError::KeyRegistry`] when the
    /// registry is invalid or cannot be written.
    pub async fn enable_entry_v2(&self, config: EntryV2Config) -> AuditResult<KeyRegistry> {
        let _guard = self.registry_lock.lock().await;
        let registry = match self.load_key_registry().await? {
            Some(registry) => registry,
            None => self.create_key_registry(&config).await?,
        };
        let audit_public = config.audit_key.export_public_key();
        if registry.active_key(KeyRole::Audit, registry.head_seq()) != Some(audit_public) {
            return Err(AuditError::KeyNotRegistered {
                key: audit_public.to_hex(),
            });
        }
        self.install_v2_signer(V2Signer {
            key: config.audit_key,
            registry: Arc::new(registry.clone()),
            principals: config.principals,
        });
        Ok(registry)
    }

    async fn create_key_registry(&self, config: &EntryV2Config) -> AuditResult<KeyRegistry> {
        let mut keys: Vec<(KeyRole, &KeyPair)> = vec![(KeyRole::Audit, config.audit_key.as_ref())];
        keys.extend(
            config
                .genesis_roles
                .iter()
                .map(|(role, key)| (*role, key.as_ref())),
        );
        let genesis = KeyRegistry::genesis_record(Timestamp::now(), &keys)?;
        if self.persist_registry_record(&genesis).await? {
            return KeyRegistry::from_records(vec![genesis]);
        }
        // Another opener of this store wrote a genesis first; use it.
        self.load_key_registry()
            .await?
            .ok_or_else(|| AuditError::KeyRegistry(REGISTRY_CHANGED.to_owned()))
    }

    /// Replace the audit key with `new_key`.
    ///
    /// Appends a registry record retiring the current audit key and adding
    /// `new_key`, signed by both, then signs new entries with `new_key` at the
    /// new key epoch. Entries already signed by the old key stay valid.
    ///
    /// The caller must store `new_key` durably before calling this and keep
    /// the old key until it returns: after the record is written only
    /// `new_key` can be enabled on this store.
    ///
    /// # Errors
    ///
    /// Returns an error when format v2 is not enabled, `new_key` was
    /// registered before, or the record cannot be written.
    pub async fn rotate_audit_key(&self, new_key: Arc<KeyPair>) -> AuditResult<KeyRegistryRecord> {
        let _guard = self.registry_lock.lock().await;
        let signer = self
            .v2_signer()
            .ok_or_else(|| AuditError::KeyRegistry("entry format v2 is not enabled".to_owned()))?;
        let record = signer.registry.rotation_record(
            KeyRole::Audit,
            &signer.key,
            &new_key,
            Timestamp::now(),
        )?;
        let mut registry = signer.registry.as_ref().clone();
        registry.push(record.clone())?;
        if !self.persist_registry_record(&record).await? {
            return Err(AuditError::KeyRegistry(REGISTRY_CHANGED.to_owned()));
        }
        self.install_v2_signer(V2Signer {
            key: new_key,
            registry: Arc::new(registry),
            principals: signer.principals.clone(),
        });
        Ok(record)
    }

    fn install_v2_signer(&self, signer: V2Signer) {
        *self
            .entry_v2
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Arc::new(signer));
    }

    pub(crate) fn v2_signer(&self) -> Option<Arc<V2Signer>> {
        self.entry_v2
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// The key that signs archive receipts and the registry epoch it holds
    /// the audit role in: the audit key under format v2, the runtime key
    /// (without an epoch) otherwise.
    pub(crate) fn archive_signer(&self) -> (Arc<KeyPair>, Option<u64>) {
        self.v2_signer().map_or_else(
            || (Arc::clone(&self.runtime_key), None),
            |signer| (Arc::clone(&signer.key), Some(signer.registry.head_seq())),
        )
    }

    /// The registry to verify v2 entries against: the active one, else the
    /// stored one.
    pub(crate) async fn verification_registry(&self) -> AuditResult<Option<Arc<KeyRegistry>>> {
        if let Some(signer) = self.v2_signer() {
            return Ok(Some(Arc::clone(&signer.registry)));
        }
        Ok(self.load_key_registry().await?.map(Arc::new))
    }

    async fn load_key_registry(&self) -> AuditResult<Option<KeyRegistry>> {
        let raw = self.storage.key_registry_records().await?;
        if raw.is_empty() {
            return Ok(None);
        }
        let records = raw
            .iter()
            .map(|bytes| serde_json::from_slice::<KeyRegistryRecord>(bytes))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| AuditError::KeyRegistry(error.to_string()))?;
        KeyRegistry::from_records(records).map(Some)
    }

    async fn persist_registry_record(&self, record: &KeyRegistryRecord) -> AuditResult<bool> {
        let bytes = serde_json::to_vec(record)
            .map_err(|error| AuditError::SerializationError(error.to_string()))?;
        self.storage
            .put_key_registry_record(record.seq, bytes)
            .await
    }

    /// Whether storage refused `entries` only because this log's signing state
    /// advanced after they were signed (v2 enabled, or the audit key rotated,
    /// in this log), so signing them again succeeds. A refusal caused by
    /// another writer of the store, whose new key this log does not hold, is
    /// final. Only a single-entry append re-signs: its commit is all or
    /// nothing.
    pub(crate) fn can_resign<'a>(
        &self,
        error: &AuditError,
        entries: impl IntoIterator<Item = &'a AuditEntry>,
    ) -> bool {
        if !matches!(
            error,
            AuditError::V1Closed { .. } | AuditError::StaleAuditKey { .. }
        ) {
            return false;
        }
        let Some(signer) = self.v2_signer() else {
            return false;
        };
        entries.into_iter().all(|entry| {
            entry
                .v2
                .as_ref()
                .is_none_or(|seal| seal.key_epoch < signer.registry.head_seq())
        })
    }

    /// Create and sign the next entry of a chain whose head hash is
    /// `previous_hash` and whose head v2 position is `previous`.
    pub(crate) fn sign_entry(
        &self,
        request: EntryRequest,
        previous_hash: ContentHash,
        previous: Option<V2Position>,
    ) -> AuditResult<AuditEntry> {
        let Some(signer) = self.v2_signer() else {
            // Storage refuses a v1 commit once the store holds a key registry;
            // a v2 chain head is refused here already.
            if previous.is_some() {
                return Err(AuditError::V1Closed {
                    reason: "the chain head is a format-v2 entry",
                });
            }
            return Ok(sign_v1(request, previous_hash, &self.runtime_key));
        };
        let principal_uid = request.principal.as_ref().and_then(|principal| {
            signer
                .principals
                .as_ref()
                .and_then(|resolver| resolver.resolve_uid(principal))
        });
        let chain_id = derive_chain_id(
            &signer.registry.registry_id(),
            &request.session_id,
            request.principal.as_ref(),
            principal_uid.as_ref(),
        );
        let key_epoch = signer.registry.head_seq();
        if previous.is_some_and(|head| head.key_epoch > key_epoch) {
            return Err(AuditError::KeyRegistry(
                "the chain head names a newer key epoch than the loaded registry".to_owned(),
            ));
        }
        let seq = match previous {
            Some(head) if head.chain_id == chain_id => {
                head.seq.checked_add(1).ok_or_else(|| {
                    AuditError::StorageError("audit chain sequence exhausted".to_owned())
                })?
            },
            _ => 1,
        };
        AuditEntry::create_v2(
            EntryV2Draft {
                session_id: request.session_id,
                principal: request.principal,
                principal_uid,
                actor: request.actor,
                action: request.action,
                authorization: request.authorization,
                outcome: request.outcome,
                previous_hash,
                chain_id,
                seq,
                key_epoch,
            },
            &signer.key,
        )
    }
}

/// Format-v1 entry; v1 has no actor field, so an actor is not recorded.
fn sign_v1(request: EntryRequest, previous_hash: ContentHash, key: &KeyPair) -> AuditEntry {
    match request.principal {
        Some(principal) => AuditEntry::create_with_principal(
            request.session_id,
            principal,
            request.action,
            request.authorization,
            request.outcome,
            previous_hash,
            key,
        ),
        None => AuditEntry::create(
            request.session_id,
            request.action,
            request.authorization,
            request.outcome,
            previous_hash,
            key,
        ),
    }
}
