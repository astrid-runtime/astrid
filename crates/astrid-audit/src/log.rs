//! Audit log - main interface for audit logging.
//!
//! Provides a high-level API for recording and verifying audit entries.

use crate::entry::{AuditAction, AuditEntry, AuditOutcome, AuthorizationProof};
use crate::error::{AuditError, AuditResult};
use crate::storage::{AuditStorage, KvAuditStorage};
use astrid_capabilities::AuditEntryId;
use astrid_core::SessionId;
use astrid_crypto::{ContentHash, KeyPair};
use astrid_storage::KvStore;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Supplies media-native free capacity for destructive legacy audit imports.
///
/// The provider is deliberately narrower than the generic KV API: migration
/// must account for the verified source bytes while the native source remains
/// present, but ordinary audit operation does not need a capacity oracle. A
/// provider that cannot observe the selected medium returns `Ok(None)`; a
/// non-empty legacy source then fails closed before the destination is
/// mutated.
pub trait AuditCapacityProvider: Send + Sync {
    /// Return currently available bytes on the destination medium.
    ///
    /// # Errors
    ///
    /// Returns a provider or media-capacity error.
    fn available_bytes(&self) -> AuditResult<Option<u64>>;
}
use tracing::{debug, error, warn};
#[path = "log_types.rs"]
mod types;
pub use types::{AuditGlobalStats, ChainIssue, ChainVerificationResult};
#[path = "prune.rs"]
mod prune;
pub use prune::{AuditPruneReceipt, AuditRetentionPolicy};
#[path = "log/append_batch.rs"]
mod append_batch;
#[path = "log/import_legacy.rs"]
mod import_legacy;
#[path = "migration.rs"]
mod migration;
#[path = "log/prune_oldest.rs"]
mod prune_oldest_impl;
#[path = "log/verify_chain.rs"]
mod verify_chain_impl;
#[path = "log/verify_legacy_chain.rs"]
mod verify_legacy_chain_impl;
use migration::{
    LegacyAuditChainReceipt, LegacyAuditReceipt, ReceiptAccumulator, chain_fragment_summary,
    digest_legacy_source, estimated_migration_bytes, validate_legacy_source_path,
};
#[cfg(test)]
#[path = "builder.rs"]
mod builder;
#[path = "log_debug.rs"]
mod log_debug;
#[cfg(test)]
pub(crate) use builder::AuditBuilder;
/// Result of importing a legacy principal-home audit database.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegacyAuditImportReport {
    /// Number of source entries admitted into the system projection.
    pub source_entries: u64,
    /// Number of entries newly written during this call.
    pub imported_entries: u64,
    /// Whether this call installed the durable migration receipt.
    pub marker_installed: bool,
    /// Content digest bound by the receipt.
    pub source_digest: String,
}
/// Bounded O(1) accounting for the active segment of one audit chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditChainStats {
    /// Monotonic segment number. A sealed segment increments this on append.
    pub segment: u64,
    /// Whether the active segment has been explicitly sealed.
    pub sealed: bool,
    /// Number of entries represented by the chain metadata.
    pub count: u64,
    /// Canonical serialized bytes represented by the chain metadata.
    pub bytes: u64,
    /// Entries in the current segment.
    pub segment_count: u64,
    /// Bytes in the current segment.
    pub segment_bytes: u64,
    /// Durable chain head, if the chain has entries.
    pub head: Option<AuditEntryId>,
    /// Content hash of [`head`](Self::head), or zero for an empty chain.
    pub head_hash: ContentHash,
}
/// Key for the per-chain head cache: (session, optional principal).
/// System entries use `(session_id, None)`; principal entries use
/// `(session_id, Some(principal))`.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ChainKey {
    session_id: SessionId,
    principal: Option<astrid_core::PrincipalId>,
}

#[derive(Clone, Debug)]
struct HeadState {
    id: AuditEntryId,
    hash: ContentHash,
}

type ChainHead = Arc<Mutex<Option<HeadState>>>;
/// Automatic cap enforcement retains the active segment; the selected oldest
/// descriptor supplies the exact sealed-prefix boundary.
const DEFAULT_AUTO_RETENTION_ENTRIES: usize = 1;

async fn update_verify_chain_fragment(
    storage: &dyn AuditStorage,
    entry: &AuditEntry,
) -> AuditResult<()> {
    let principal = entry
        .principal
        .as_ref()
        .map_or_else(|| "<system>".to_owned(), ToString::to_string);
    let key = format!("chain:{}:{principal}", entry.session_id);
    loop {
        let previous = storage.migration_temp_get(&key).await?;
        let mut fragment = if let Some(previous) = previous.as_deref() {
            serde_json::from_slice::<LegacyAuditChainReceipt>(previous)
                .map_err(|error| AuditError::SerializationError(error.to_string()))?
        } else {
            LegacyAuditChainReceipt {
                session: entry.session_id.to_string(),
                principal: entry.principal.as_ref().map(ToString::to_string),
                count: 0,
                terminal_hash: ContentHash::zero().to_hex(),
            }
        };
        fragment.count = fragment.count.saturating_add(1);
        fragment.terminal_hash = entry.content_hash().to_hex();
        let encoded = serde_json::to_vec(&fragment)
            .map_err(|error| AuditError::SerializationError(error.to_string()))?;
        if storage
            .migration_temp_cas(&key, previous.as_deref(), encoded)
            .await?
        {
            return Ok(());
        }
    }
}

/// Audit log for recording and verifying security events.
pub struct AuditLog {
    /// Storage backend.
    storage: Box<dyn AuditStorage>,
    /// Runtime signing key.
    ///
    /// Held behind an [`Arc`] so the single runtime key can also be shared
    /// onto the [`Kernel`](../../astrid_kernel/struct.Kernel.html) (issue
    /// #929) without loading the key from disk twice — the audit log and the
    /// kernel's admin token-mint path sign with the exact same key bytes.
    runtime_key: Arc<KeyPair>,
    /// Per-(session, principal) append locks and cached chain heads.
    ///
    /// Each principal maintains its own independent chain within a session.
    /// System entries (no principal) use `(session_id, None)`.
    ///
    /// The outer mutex protects map lookup/insertion only; per-chain mutexes
    /// serialize durable appends without blocking unrelated principals.
    chain_heads: std::sync::Mutex<std::collections::HashMap<ChainKey, ChainHead>>,
    /// Serializes grouped append attempts so one bounded commit can sign a
    /// complete batch against one authoritative snapshot.
    append_coordinator: Arc<Mutex<()>>,
    /// Optional media-capacity oracle used only by legacy migration.
    migration_capacity: Option<Arc<dyn AuditCapacityProvider>>,
}
impl AuditLog {
    /// Open a legacy native audit source for migration only.
    ///
    /// The key is stored behind an [`Arc`]: callers may pass an owned
    /// [`KeyPair`] (converted via `Arc::from`) or an existing `Arc<KeyPair>`.
    /// Passing the kernel's already-`Arc`-wrapped runtime key lets the audit
    /// log and the kernel's admin token-mint path (issue #929) sign with the
    /// exact same key without a second load from disk.
    ///
    /// # Errors
    ///
    /// Returns an error if the storage backend fails to open at the given path.
    #[cfg(test)]
    pub(crate) fn open_legacy_source(
        path: impl AsRef<Path>,
        runtime_key: impl Into<Arc<KeyPair>>,
    ) -> AuditResult<Self> {
        let storage = KvAuditStorage::open_legacy_source(path)?;
        Ok(Self {
            storage: Box::new(storage),
            runtime_key: runtime_key.into(),
            chain_heads: std::sync::Mutex::new(std::collections::HashMap::new()),
            append_coordinator: Arc::new(Mutex::new(())),
            migration_capacity: None,
        })
    }

    /// Open an audit log over the kernel-owned system storage projection.
    ///
    /// Unlike the test-only legacy-source opener, this constructor accepts no
    /// native path.
    /// The backend stamps every logical audit namespace into
    /// `system:control:audit`,
    /// which is inaccessible to principal home mounts.
    ///
    /// # Errors
    ///
    /// Returns an error when the system projection cannot be constructed.
    pub fn open_with_kv_store(
        store: Arc<dyn KvStore>,
        runtime_key: impl Into<Arc<KeyPair>>,
    ) -> AuditResult<Self> {
        Self::open_with_kv_store_and_capacity(store, runtime_key, None)
    }

    /// Open an audit log over kernel-owned system storage with a migration
    /// capacity oracle.
    ///
    /// The oracle is consulted only when a non-empty native legacy audit
    /// source is imported. Supplying no oracle preserves normal operation for
    /// fresh stores, but such a store refuses a non-empty migration because
    /// it cannot prove that the destination fits before writing scratch
    /// indexes or entries.
    ///
    /// # Errors
    ///
    /// Returns an error when the system projection cannot be constructed.
    pub fn open_with_kv_store_and_capacity(
        store: Arc<dyn KvStore>,
        runtime_key: impl Into<Arc<KeyPair>>,
        migration_capacity: Option<Arc<dyn AuditCapacityProvider>>,
    ) -> AuditResult<Self> {
        let storage = KvAuditStorage::from_kv_store(store)?;
        Ok(Self {
            storage: Box::new(storage),
            runtime_key: runtime_key.into(),
            chain_heads: std::sync::Mutex::new(std::collections::HashMap::new()),
            append_coordinator: Arc::new(Mutex::new(())),
            migration_capacity,
        })
    }

    pub(crate) fn storage(&self) -> &dyn AuditStorage {
        self.storage.as_ref()
    }

    /// Create an in-memory audit log (for testing).
    ///
    /// Accepts an owned [`KeyPair`] or an `Arc<KeyPair>`; the native path
    /// opener remains test-only and is not part of the production API.
    #[must_use]
    pub fn in_memory(runtime_key: impl Into<Arc<KeyPair>>) -> Self {
        let storage = KvAuditStorage::in_memory();
        Self {
            storage: Box::new(storage),
            runtime_key: runtime_key.into(),
            chain_heads: std::sync::Mutex::new(std::collections::HashMap::new()),
            append_coordinator: Arc::new(Mutex::new(())),
            migration_capacity: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_test_storage(
        storage: Box<dyn AuditStorage>,
        runtime_key: impl Into<Arc<KeyPair>>,
    ) -> Self {
        Self {
            storage,
            runtime_key: runtime_key.into(),
            chain_heads: std::sync::Mutex::new(std::collections::HashMap::new()),
            append_coordinator: Arc::new(Mutex::new(())),
            migration_capacity: None,
        }
    }

    /// Import a legacy `SurrealKV` audit directory into the system-owned
    /// projection and return a content-bound receipt.
    ///
    /// The source is opened read-only in the logical sense (the legacy engine
    /// itself is closed without mutation). Every source byte is required to be
    /// canonical JSON, every signature and chain link is verified, and every
    /// destination conflict fails closed. The operation is resumable: entries
    /// already committed with identical bytes are accepted, while a durable
    /// marker records the exact source digest, chain terminal hashes, counts,
    /// and destination identity before the caller retires the native source.
    ///
    /// # Errors
    ///
    /// Returns an error when source bytes, signatures, chain links, or the
    /// destination receipt are invalid or conflicting.
    pub async fn import_legacy_audit(
        &self,
        legacy_path: impl AsRef<Path>,
        destination_identity: &str,
    ) -> AuditResult<LegacyAuditImportReport> {
        self.import_legacy_audit_impl(legacy_path, destination_identity)
            .await
    }

    /// Re-read and verify the legacy source digest immediately before source
    /// retirement.
    ///
    /// The import itself performs source-only, preflight, and post-copy digest
    /// passes. The kernel calls this final read-back under its boot singleton
    /// barrier so a source mutation between import completion and native-tree
    /// retirement leaves the source in place and fails closed.
    ///
    /// # Errors
    ///
    /// Returns an error when the source is redirected, cannot be opened, or no
    /// longer has the digest returned by [`Self::import_legacy_audit`].
    pub async fn verify_legacy_source_digest(
        &self,
        legacy_path: impl AsRef<Path>,
        destination_identity: &str,
        expected_digest: &str,
    ) -> AuditResult<()> {
        let legacy_path = legacy_path.as_ref();
        if !validate_legacy_source_path(legacy_path)? {
            return Err(AuditError::StorageError(
                "legacy audit source disappeared before retirement".to_owned(),
            ));
        }
        let source = KvAuditStorage::open_legacy_source(legacy_path)?;
        let receipt = digest_legacy_source(&source, destination_identity).await?;
        if receipt.source_digest != expected_digest {
            return Err(AuditError::StorageError(
                "legacy audit source changed before retirement".to_owned(),
            ));
        }
        Ok(())
    }

    fn ensure_migration_capacity(&self, source: &LegacyAuditReceipt) -> AuditResult<()> {
        if source.source_entries == 0 {
            return Ok(());
        }
        let required = estimated_migration_bytes(source.source_bytes, source.source_entries)
            .ok_or_else(|| {
                AuditError::StorageError(
                    "legacy audit migration size estimate overflowed; refusing import".to_owned(),
                )
            })?;
        let Some(provider) = self.migration_capacity.as_ref() else {
            return Err(AuditError::StorageError(
                "legacy audit migration capacity is unobservable; refusing non-empty import"
                    .to_owned(),
            ));
        };
        let available = provider.available_bytes()?.ok_or_else(|| {
            AuditError::StorageError(
                "legacy audit migration capacity is unobservable; refusing non-empty import"
                    .to_owned(),
            )
        })?;
        if available < required {
            return Err(AuditError::StorageError(format!(
                "insufficient destination capacity for legacy audit migration: need {required} bytes, have {available} bytes"
            )));
        }
        Ok(())
    }

    async fn verify_receipted_destination(&self, receipt: &LegacyAuditReceipt) -> AuditResult<()> {
        let mut accumulator = ReceiptAccumulator::new();
        // Digest over the entry-record key order.  This is deliberately
        // independent from the legacy per-session index order: migration
        // source scans `audit:entries` directly, so read-back must use the
        // exact same bounded projection and never materialise a giant index.
        let mut after = None;
        loop {
            let page = self.storage.all_entries_page(after.as_deref(), 256).await?;
            if page.is_empty() {
                break;
            }
            let next_after = page.last().map(|(cursor, _)| cursor.clone());
            for (_, entry) in page {
                entry.verify_signature()?;
                let bytes = serde_json::to_vec(&entry)
                    .map_err(|e| AuditError::SerializationError(e.to_string()))?;
                accumulator.add(&entry, &bytes);
                update_verify_chain_fragment(self.storage.as_ref(), &entry).await?;
            }
            after = next_after;
        }

        migration::finalize_chain_fragments(self.storage.as_ref(), "chain:").await?;
        let (chain_count, chain_digest) =
            chain_fragment_summary(self.storage.as_ref(), "chain:").await?;
        let actual = accumulator.finish(&receipt.destination, chain_count, chain_digest);
        if actual != *receipt {
            return Err(AuditError::StorageError(format!(
                "system audit read-back does not match migration receipt: expected entries={} bytes={} digest={} chains={} chain_digest={}, found entries={} bytes={} digest={} chains={} chain_digest={}",
                receipt.source_entries,
                receipt.source_bytes,
                receipt.source_digest,
                receipt.chain_count,
                receipt.chain_digest,
                actual.source_entries,
                actual.source_bytes,
                actual.source_digest,
                actual.chain_count,
                actual.chain_digest,
            )));
        }
        for (session, chain) in &self.verify_all().await? {
            if !chain.valid {
                return Err(AuditError::IntegrityViolation {
                    entry_id: session.to_string(),
                    reason: chain
                        .issues
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", "),
                });
            }
        }
        self.storage.clear_migration_temp().await?;
        Ok(())
    }

    /// Append a new audit entry.
    ///
    /// # Errors
    ///
    /// Returns an error if the entry cannot be stored or the chain head cannot be updated.
    pub async fn append(
        &self,
        session_id: SessionId,
        action: AuditAction,
        authorization: AuthorizationProof,
        outcome: AuditOutcome,
    ) -> AuditResult<AuditEntryId> {
        self.append_inner(session_id, None, action, authorization, outcome)
            .await
    }

    /// Append a new audit entry tagged with the acting principal.
    ///
    /// Use this when the action was performed on behalf of a specific
    /// user (e.g., cross-principal KV write, tool execution). The
    /// principal is included in the cryptographic signing data.
    ///
    /// # Errors
    ///
    /// Returns an error if the entry cannot be stored or the chain head cannot be updated.
    pub async fn append_with_principal(
        &self,
        session_id: SessionId,
        principal: astrid_core::PrincipalId,
        action: AuditAction,
        authorization: AuthorizationProof,
        outcome: AuditOutcome,
    ) -> AuditResult<AuditEntryId> {
        self.append_inner(session_id, Some(principal), action, authorization, outcome)
            .await
    }

    /// Append a bounded group of principal-stamped entries in queue order.
    ///
    /// This is the narrow ingestion hook used by the kernel host-audit sink.
    /// The default implementation preserves correctness on every backend by
    /// appending each signed successor through the normal per-chain CAS; a
    /// backend with a native multi-key commit may override the storage seam in
    /// a later release without changing callers or chain semantics.
    pub async fn append_batch_with_principal(
        &self,
        entries: Vec<(
            SessionId,
            astrid_core::PrincipalId,
            AuditAction,
            AuthorizationProof,
            AuditOutcome,
        )>,
    ) -> Vec<AuditResult<AuditEntryId>> {
        self.append_batch_with_principal_impl(entries).await
    }

    /// Seal the current durable segment for one session/principal chain.
    ///
    /// The next append starts a new segment and links to this segment's head;
    /// no signed history is deleted. Calling this method repeatedly is
    /// idempotent.
    ///
    /// # Errors
    ///
    /// Returns an error if the chain metadata cannot be sealed durably.
    pub async fn seal_chain(
        &self,
        session_id: &SessionId,
        principal: Option<&astrid_core::PrincipalId>,
    ) -> AuditResult<()> {
        self.storage.seal_chain(session_id, principal).await
    }

    /// Read O(1) segment/head accounting for one chain.
    ///
    /// # Errors
    ///
    /// Returns an error if the metadata projection cannot be read.
    pub async fn chain_stats(
        &self,
        session_id: &SessionId,
        principal: Option<&astrid_core::PrincipalId>,
    ) -> AuditResult<Option<AuditChainStats>> {
        Ok(self
            .storage
            .chain_metadata(session_id, principal)
            .await?
            .map(|metadata| AuditChainStats {
                segment: metadata.segment,
                sealed: metadata.sealed,
                count: metadata.count,
                bytes: metadata.bytes,
                segment_count: metadata.segment_count,
                segment_bytes: metadata.segment_bytes,
                head: metadata.head,
                head_hash: metadata.head_hash,
            }))
    }

    /// Read O(1) system-wide audit totals, cap, and degraded state.
    ///
    /// # Errors
    ///
    /// Returns an error if the system accounting projection cannot be read.
    pub async fn global_stats(&self) -> AuditResult<AuditGlobalStats> {
        let metadata = self.storage.global_metadata().await?;
        Ok(AuditGlobalStats {
            total_count: metadata.total_count,
            total_bytes: metadata.total_bytes,
            sealed_segments: metadata.sealed_segments,
            segments: metadata.segments,
            eligible_segments: metadata.eligible_segments,
            cap_entries: metadata.cap_entries,
            cap_bytes: metadata.cap_bytes,
            degraded: metadata.degraded,
            last_error: metadata.last_error,
        })
    }

    /// Set operator-selected global retention caps for the system audit
    /// projection.
    ///
    /// # Errors
    ///
    /// Returns an error when either cap is zero or the projection CAS loses a
    /// concurrent update.
    pub async fn set_global_retention_caps(
        &self,
        max_entries: u64,
        max_bytes: u64,
    ) -> AuditResult<()> {
        self.storage.set_global_caps(max_entries, max_bytes).await
    }

    /// Prune one oldest sealed chain.
    ///
    /// # Errors
    /// Returns an error if the archive plan cannot be committed.
    pub async fn prune_oldest(
        &self,
        policy: AuditRetentionPolicy,
    ) -> AuditResult<Option<AuditPruneReceipt>> {
        self.prune_oldest_impl(policy).await
    }

    /// Prune a verified prefix while retaining a bounded suffix and writing a
    /// signed archive anchor before deleting any entry records.
    ///
    /// # Errors
    ///
    /// Returns an error when the retention policy or signed archive plan is
    /// invalid or cannot be committed.
    pub async fn prune_chain(
        &self,
        session_id: &SessionId,
        principal: Option<&astrid_core::PrincipalId>,
        policy: AuditRetentionPolicy,
    ) -> AuditResult<AuditPruneReceipt> {
        prune::prune_chain(self, session_id, principal, policy).await
    }

    pub(crate) fn sign_archive_receipt(&self, bytes: &[u8]) -> astrid_crypto::Signature {
        self.runtime_key.sign(bytes)
    }

    /// Shared implementation for `append` and `append_with_principal`.
    ///
    /// # Locking contract
    ///
    /// The entire append critical section — resolving this chain's current head,
    /// creating and signing the entry against that head, persisting it, and then
    /// advancing the cached head — runs while holding that chain's mutex.
    /// This serializes appends to the same `(session, principal)` chain so
    /// that `previous_hash` and the head move together atomically.
    ///
    /// Without this, two concurrent appends to the same chain both read the same
    /// parent hash before either stores, then sign two entries that claim the
    /// same predecessor — FORKING the signed chain. `verify_chain` then reports
    /// `valid = false` (`BrokenLink` / duplicate genesis) under nothing more than
    /// normal concurrent host-call load.
    ///
    /// Signing happens inside the per-chain lock. That serialization is
    /// intentional: a hash chain is inherently ordered. Independent chains use
    /// independent locks and may persist concurrently.
    async fn append_inner(
        &self,
        session_id: SessionId,
        principal: Option<astrid_core::PrincipalId>,
        action: AuditAction,
        authorization: AuthorizationProof,
        outcome: AuditOutcome,
    ) -> AuditResult<AuditEntryId> {
        let chain_key = ChainKey {
            session_id: session_id.clone(),
            principal: principal.clone(),
        };

        // Hold the lock across read-prev-hash -> create+sign -> store ->
        // head update so the whole append is atomic per chain (see the locking
        // contract above).
        let chain_head = {
            let mut heads = self
                .chain_heads
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            Arc::clone(
                heads
                    .entry(chain_key.clone())
                    .or_insert_with(|| Arc::new(Mutex::new(None))),
            )
        };
        let mut head = chain_head.lock().await;

        // Resolve the parent hash from the head cache we already hold (falling
        // back to storage), NOT via a fresh lock — re-locking would reopen the
        // fork window between the read and the head advance below.
        loop {
            let (expected_head, previous_hash) =
                self.previous_hash_locked(&chain_key, head.as_ref()).await?;

            // Create and sign the entry. session_id is moved into create,
            // chain_key retains the clone for the cache update below.
            let entry = if let Some(p) = principal.clone() {
                AuditEntry::create_with_principal(
                    session_id.clone(),
                    p,
                    action.clone(),
                    authorization.clone(),
                    outcome.clone(),
                    previous_hash,
                    &self.runtime_key,
                )
            } else {
                AuditEntry::create(
                    session_id.clone(),
                    action.clone(),
                    authorization.clone(),
                    outcome.clone(),
                    previous_hash,
                    &self.runtime_key,
                )
            };

            let entry_id = entry.id.clone();
            let entry_hash = entry.content_hash();

            debug!(
                entry_id = %entry_id,
                action = %entry.action.description(),
                "Appending audit entry"
            );

            // The storage future may be cancelled after its durable commit point but
            // before it reports success. Invalidate the cache before awaiting so an
            // error or cancellation leaves `None` behind and the next append recovers
            // the authoritative committed head from storage. Only a reported success
            // installs the new fast-path hash.
            *head = None;
            let append_results = match self
                .storage
                .append_batch_if_heads(&[(&entry, expected_head.as_ref())])
                .await
            {
                Ok(results) => results,
                Err(AuditError::RetentionCapReached) => {
                    *head = None;
                    if self
                        .prune_oldest(AuditRetentionPolicy {
                            retain_entries: DEFAULT_AUTO_RETENTION_ENTRIES,
                            retain_bytes: None,
                        })
                        .await?
                        .is_some()
                    {
                        continue;
                    }
                    return Err(AuditError::StorageError(
                        "audit retention cap reached with no eligible sealed segment".to_owned(),
                    ));
                },
                Err(error) => return Err(error),
            };
            if append_results.first().copied().unwrap_or(false) {
                *head = Some(HeadState {
                    id: entry_id.clone(),
                    hash: entry_hash,
                });
                return Ok(entry_id);
            }
            // Another durable writer advanced this chain between the cache miss
            // and the backend CAS. Re-read its head and sign a fresh successor.
        }
    }

    /// Resolve a chain's parent hash from the caller-held head cache, falling
    /// back to storage, then to genesis (`ContentHash::zero()`).
    ///
    /// `head` MUST belong to the per-chain mutex the caller holds. This method
    /// deliberately does not lock: resolving the parent and advancing the head
    /// must stay inside the same critical section.
    async fn previous_hash_locked(
        &self,
        chain_key: &ChainKey,
        head: Option<&HeadState>,
    ) -> AuditResult<(Option<AuditEntryId>, ContentHash)> {
        // Check the in-memory head cache first.
        if let Some(state) = head {
            return Ok((Some(state.id.clone()), state.hash));
        }

        // Fall back to storage (first append after a restart / cache miss).
        if let Some(head_id) = self
            .storage
            .get_chain_head(&chain_key.session_id, chain_key.principal.as_ref())
            .await?
            && let Some(entry) = self.storage.get(&head_id).await?
        {
            return Ok((Some(head_id), entry.content_hash()));
        }

        // Genesis - no previous entry for this chain.
        Ok((None, ContentHash::zero()))
    }

    /// Get an entry by ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the storage backend fails to retrieve the entry.
    pub async fn get(&self, id: &AuditEntryId) -> AuditResult<Option<AuditEntry>> {
        self.storage.get(id).await
    }

    /// Get all entries for a session.
    ///
    /// Entries are returned in durable insertion order, including across a
    /// legacy-index migration.
    ///
    /// # Errors
    ///
    /// Returns an error if the storage backend fails to retrieve entries.
    pub async fn get_session_entries(
        &self,
        session_id: &SessionId,
    ) -> AuditResult<Vec<AuditEntry>> {
        self.storage.get_session_entries(session_id).await
    }

    /// Verify the integrity of all audit chains in a session.
    ///
    /// Each principal (and the system chain) is verified independently.
    /// A session with entries from principals "alice" and "bob" plus system
    /// entries will verify three independent chains.
    ///
    /// # Errors
    ///
    /// Returns an error if entries cannot be retrieved from storage.
    pub async fn verify_chain(
        &self,
        session_id: &SessionId,
    ) -> AuditResult<ChainVerificationResult> {
        self.verify_chain_impl(session_id).await
    }

    /// Verify the integrity of a single principal's chain within a session.
    ///
    /// Pass `None` to verify the system chain (entries without a principal).
    ///
    /// # Errors
    ///
    /// Returns an error if entries cannot be retrieved from storage.
    pub async fn verify_principal_chain(
        &self,
        session_id: &SessionId,
        principal: Option<&astrid_core::PrincipalId>,
    ) -> AuditResult<ChainVerificationResult> {
        let entries = self.get_principal_entries(session_id, principal).await?;

        if entries.is_empty() {
            return Ok(ChainVerificationResult {
                valid: true,
                entries_verified: 0,
                issues: Vec::new(),
            });
        }

        let mut issues = Vec::new();
        let mut entries_verified: usize = 0;

        // Storage order is the durable append order. Wall-clock timestamps are
        // signed evidence, not an ordering primitive: clocks can move backward.
        let sorted = entries;

        if !self
            .verify_archive_anchor(
                &sorted[0].session_id,
                sorted[0].principal.as_ref(),
                &sorted[0].previous_hash,
            )
            .await?
        {
            issues.push(ChainIssue::InvalidGenesis {
                entry_id: sorted[0].id.clone(),
            });
        }

        for entry in &sorted {
            if let Err(e) = entry.verify_signature() {
                error!(entry_id = %entry.id, error = %e, "Invalid signature");
                issues.push(ChainIssue::InvalidSignature {
                    entry_id: entry.id.clone(),
                });
            }
            entries_verified = entries_verified.saturating_add(1);
        }

        for i in 1..sorted.len() {
            #[expect(clippy::arithmetic_side_effects)]
            let prev = &sorted[i - 1];
            let curr = &sorted[i];
            if !curr.follows(prev) {
                warn!(current = %curr.id, previous = %prev.id, "Chain link broken");
                issues.push(ChainIssue::BrokenLink {
                    entry_id: curr.id.clone(),
                    expected_previous: prev.content_hash(),
                    actual_previous: curr.previous_hash,
                });
            }
        }

        Ok(ChainVerificationResult {
            valid: issues.is_empty(),
            entries_verified,
            issues,
        })
    }

    async fn verify_archive_anchor(
        &self,
        session_id: &SessionId,
        principal: Option<&astrid_core::PrincipalId>,
        previous_hash: &ContentHash,
    ) -> AuditResult<bool> {
        if previous_hash.is_zero() {
            return Ok(true);
        }
        let Some(raw) = self.storage.prune_receipt(session_id, principal).await? else {
            return Ok(false);
        };
        let receipt: AuditPruneReceipt = serde_json::from_slice(&raw)
            .map_err(|error| AuditError::SerializationError(error.to_string()))?;
        let expected_principal = principal.map(ToString::to_string);
        if receipt.session != session_id.to_string()
            || receipt.principal.as_deref() != expected_principal.as_deref()
        {
            return Ok(false);
        }
        prune::verify_anchor(&receipt, previous_hash)
    }

    /// Get entries for a specific principal within a session.
    ///
    /// Pass `None` to get system entries (no principal).
    ///
    /// # Errors
    ///
    /// Returns an error if entries cannot be retrieved from storage.
    pub async fn get_principal_entries(
        &self,
        session_id: &SessionId,
        principal: Option<&astrid_core::PrincipalId>,
    ) -> AuditResult<Vec<AuditEntry>> {
        let all = self.storage.get_session_entries(session_id).await?;
        Ok(all
            .into_iter()
            .filter(|e| e.principal.as_ref() == principal)
            .collect())
    }

    /// Verify the entire audit log (all sessions).
    ///
    /// # Errors
    ///
    /// Returns an error if sessions cannot be listed or verified.
    pub async fn verify_all(&self) -> AuditResult<Vec<(SessionId, ChainVerificationResult)>> {
        let sessions = self.storage.list_sessions().await?;
        let mut results = Vec::new();

        for session_id in sessions {
            let result = self.verify_chain(&session_id).await?;
            results.push((session_id, result));
        }

        Ok(results)
    }

    /// Count total entries.
    ///
    /// # Errors
    ///
    /// Returns an error if the storage backend fails.
    pub async fn count(&self) -> AuditResult<usize> {
        self.storage.count().await
    }

    /// Count entries for a session.
    ///
    /// # Errors
    ///
    /// Returns an error if the storage backend fails.
    pub async fn count_session(&self, session_id: &SessionId) -> AuditResult<usize> {
        self.storage.count_session(session_id).await
    }

    /// List all sessions.
    ///
    /// # Errors
    ///
    /// Returns an error if the storage backend fails.
    pub async fn list_sessions(&self) -> AuditResult<Vec<SessionId>> {
        self.storage.list_sessions().await
    }

    /// Flush pending writes.
    ///
    /// # Errors
    ///
    /// Returns an error if the storage backend fails to flush.
    pub async fn flush(&self) -> AuditResult<()> {
        self.storage.flush().await
    }

    /// Flush and close the audit log, releasing the underlying storage lock.
    ///
    /// The kernel calls this on graceful shutdown so the persistent surrealkv
    /// `LOCK` is released on exit rather than only on process death — otherwise
    /// a wedged/terminating daemon holds the audit lock until `SIGKILL`, and a
    /// restart races the still-held lock. Callable through the kernel's shared
    /// `Arc<AuditLog>`: the storage backend closes through its own
    /// `Arc<dyn KvStore>`, so no exclusive ownership (`&mut self`) is required.
    ///
    /// # Errors
    ///
    /// Returns an error if the storage backend fails to close.
    pub async fn close(&self) -> AuditResult<()> {
        self.storage.close().await
    }

    /// Get the runtime public key.
    #[must_use]
    pub fn runtime_public_key(&self) -> astrid_crypto::PublicKey {
        self.runtime_key.export_public_key()
    }
}
#[cfg(test)]
#[path = "batch_tests.rs"]
mod batch_tests;
#[cfg(test)]
#[path = "migration_capacity_tests.rs"]
mod migration_capacity_tests;
#[cfg(test)]
#[path = "prune_tests.rs"]
mod prune_tests;
#[cfg(test)]
#[path = "log_tests.rs"]
mod tests;
