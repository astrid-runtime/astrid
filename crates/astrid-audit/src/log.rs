//! Audit log - main interface for audit logging.
//!
//! Provides a high-level API for recording and verifying audit entries.

use astrid_capabilities::AuditEntryId;
use astrid_core::SessionId;
use astrid_crypto::{ContentHash, KeyPair};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, error, warn};

use crate::entry::{AuditAction, AuditEntry, AuditOutcome, AuthorizationProof};
use crate::error::AuditResult;
use crate::storage::{AuditStorage, SurrealKvAuditStorage};

/// Key for the per-chain head cache: (session, optional principal).
///
/// System entries (no principal) use `(session_id, None)`.
/// Principal entries use `(session_id, Some(principal))`.
type ChainKey = (SessionId, Option<astrid_core::PrincipalId>);

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
    /// Current chain heads per (session, principal) pair.
    ///
    /// Each principal maintains its own independent chain within a session.
    /// System entries (no principal) use `(session_id, None)`.
    ///
    /// This is a [`tokio::sync::Mutex`] (not a `std` one) because
    /// [`append_inner`](Self::append_inner) holds the guard *across the
    /// persistent `store().await`* to keep read-prev-hash → sign → persist →
    /// advance-head atomic per chain — a `std` guard cannot legally live across
    /// an `.await`. Access is exclusive-only, so a plain mutex (not `RwLock`)
    /// is the honest primitive. See the locking contract on [`append_inner`].
    chain_heads: Mutex<std::collections::HashMap<ChainKey, ContentHash>>,
}

impl AuditLog {
    /// Create a new audit log with `SurrealKV` persistence.
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
    pub fn open(path: impl AsRef<Path>, runtime_key: impl Into<Arc<KeyPair>>) -> AuditResult<Self> {
        let storage = SurrealKvAuditStorage::open(path)?;
        Ok(Self {
            storage: Box::new(storage),
            runtime_key: runtime_key.into(),
            chain_heads: Mutex::new(std::collections::HashMap::new()),
        })
    }

    /// Create an in-memory audit log (for testing).
    ///
    /// Accepts an owned [`KeyPair`] or an `Arc<KeyPair>` — see [`open`](Self::open).
    #[must_use]
    pub fn in_memory(runtime_key: impl Into<Arc<KeyPair>>) -> Self {
        let storage = SurrealKvAuditStorage::in_memory();
        Self {
            storage: Box::new(storage),
            runtime_key: runtime_key.into(),
            chain_heads: Mutex::new(std::collections::HashMap::new()),
        }
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

    /// Shared implementation for `append` and `append_with_principal`.
    ///
    /// # Locking contract
    ///
    /// The entire append critical section — resolving the chain's current head,
    /// creating and signing the entry against that head, persisting it, and then
    /// advancing the cached head — runs while holding the `chain_heads` mutex.
    /// This serializes appends to the same `(session, principal)` chain so
    /// that `previous_hash` and the head move together atomically.
    ///
    /// Without this, two concurrent appends to the same chain both read the same
    /// parent hash before either stores, then sign two entries that claim the
    /// same predecessor — FORKING the signed chain. `verify_chain` then reports
    /// `valid = false` (`BrokenLink` / duplicate genesis) under nothing more than
    /// normal concurrent host-call load.
    ///
    /// Signing happens inside the lock. That serializes same-chain appends, which
    /// is intentional and correct: a hash chain is inherently ordered, so a
    /// well-defined append order IS the product. The lock spans every chain in
    /// this log (one mutex), so it also serializes appends across chains; that
    /// is a stronger guarantee than required and is acceptable — audit append is
    /// not a hot path relative to the signed-ordering invariant it protects.
    ///
    /// The lock is a [`tokio::sync::Mutex`]: the guard is held *across the
    /// persistent `store().await`*, which a `std` guard cannot legally do. An
    /// async-aware lock is what lets the whole critical section stay atomic on
    /// the now-genuinely-async persist path.
    async fn append_inner(
        &self,
        session_id: SessionId,
        principal: Option<astrid_core::PrincipalId>,
        action: AuditAction,
        authorization: AuthorizationProof,
        outcome: AuditOutcome,
    ) -> AuditResult<AuditEntryId> {
        let chain_key: ChainKey = (session_id.clone(), principal.clone());

        // Hold the lock across read-prev-hash -> create+sign -> store ->
        // head update so the whole append is atomic per chain (see the locking
        // contract above).
        let mut heads = self.chain_heads.lock().await;

        // Resolve the parent hash from the head cache we already hold (falling
        // back to storage), NOT via a fresh lock — re-locking would reopen the
        // fork window between the read and the head advance below.
        let previous_hash = self.previous_hash_locked(&chain_key, &heads).await?;

        // Create and sign the entry. session_id is moved into create,
        // chain_key retains the clone for the cache update below.
        let entry = if let Some(p) = principal {
            AuditEntry::create_with_principal(
                session_id,
                p,
                action,
                authorization,
                outcome,
                previous_hash,
                &self.runtime_key,
            )
        } else {
            AuditEntry::create(
                session_id,
                action,
                authorization,
                outcome,
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

        // Store the entry, then advance the head. Both happen under the lock, so
        // a concurrent same-chain append cannot observe the stored entry without
        // also observing the advanced head. On a store failure we return without
        // touching the head — nothing was persisted, so the chain is unchanged.
        self.storage.store(&entry).await?;
        heads.insert(chain_key, entry_hash);

        Ok(entry_id)
    }

    /// Resolve a chain's parent hash from the caller-held head cache, falling
    /// back to storage, then to genesis (`ContentHash::zero()`).
    ///
    /// `heads` MUST be the live `chain_heads` map the caller already holds the
    /// write lock on. This method deliberately does NOT lock: reading the parent
    /// hash and advancing the head must stay inside one critical section (see the
    /// locking contract on [`append_inner`]). Taking a fresh lock here would
    /// reopen the fork window this design closes.
    async fn previous_hash_locked(
        &self,
        chain_key: &ChainKey,
        heads: &std::collections::HashMap<ChainKey, ContentHash>,
    ) -> AuditResult<ContentHash> {
        // Check the in-memory head cache first.
        if let Some(hash) = heads.get(chain_key) {
            return Ok(*hash);
        }

        // Fall back to storage (first append after a restart / cache miss).
        if let Some(head_id) = self
            .storage
            .get_chain_head(&chain_key.0, chain_key.1.as_ref())
            .await?
            && let Some(entry) = self.storage.get(&head_id).await?
        {
            return Ok(entry.content_hash());
        }

        // Genesis - no previous entry for this chain.
        Ok(ContentHash::zero())
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
        let entries = self.storage.get_session_entries(session_id).await?;

        if entries.is_empty() {
            return Ok(ChainVerificationResult {
                valid: true,
                entries_verified: 0,
                issues: Vec::new(),
            });
        }

        // Group entries by principal (None = system chain).
        let mut chains: std::collections::HashMap<
            Option<astrid_core::PrincipalId>,
            Vec<&AuditEntry>,
        > = std::collections::HashMap::new();
        for entry in &entries {
            chains
                .entry(entry.principal.clone())
                .or_default()
                .push(entry);
        }

        let mut issues = Vec::new();
        let mut entries_verified: usize = 0;

        // Verify each chain independently.
        for chain_entries in chains.values_mut() {
            // Sort by timestamp within each chain.
            chain_entries.sort_by_key(|a| a.timestamp.0);

            // Verify genesis (first entry has zero previous hash).
            if !chain_entries[0].previous_hash.is_zero() {
                issues.push(ChainIssue::InvalidGenesis {
                    entry_id: chain_entries[0].id.clone(),
                });
            }

            // Verify signatures.
            for entry in chain_entries.iter() {
                if let Err(e) = entry.verify_signature() {
                    error!(entry_id = %entry.id, error = %e, "Invalid signature");
                    issues.push(ChainIssue::InvalidSignature {
                        entry_id: entry.id.clone(),
                    });
                }
                entries_verified = entries_verified.saturating_add(1);
            }

            // Verify chain linking within this principal's chain.
            for i in 1..chain_entries.len() {
                #[expect(clippy::arithmetic_side_effects)]
                let prev = chain_entries[i - 1];
                let curr = chain_entries[i];

                if !curr.follows(prev) {
                    warn!(
                        current = %curr.id,
                        previous = %prev.id,
                        "Chain link broken"
                    );
                    issues.push(ChainIssue::BrokenLink {
                        entry_id: curr.id.clone(),
                        expected_previous: prev.content_hash(),
                        actual_previous: curr.previous_hash,
                    });
                }
            }
        }

        Ok(ChainVerificationResult {
            valid: issues.is_empty(),
            entries_verified,
            issues,
        })
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

        let mut sorted = entries;
        sorted.sort_by_key(|a| a.timestamp.0);

        if !sorted[0].previous_hash.is_zero() {
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

    /// Get the runtime public key.
    #[must_use]
    pub fn runtime_public_key(&self) -> astrid_crypto::PublicKey {
        self.runtime_key.export_public_key()
    }
}

impl std::fmt::Debug for AuditLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditLog")
            .field("runtime_key_id", &self.runtime_key.key_id_hex())
            .finish_non_exhaustive()
    }
}

/// Result of chain verification.
#[derive(Debug, Clone)]
pub struct ChainVerificationResult {
    /// Whether the chain is valid.
    pub valid: bool,
    /// Number of entries verified.
    pub entries_verified: usize,
    /// Issues found (empty if valid).
    pub issues: Vec<ChainIssue>,
}

/// An issue found during chain verification.
#[derive(Debug, Clone)]
pub enum ChainIssue {
    /// First entry doesn't have zero previous hash.
    InvalidGenesis {
        /// The entry with invalid genesis.
        entry_id: AuditEntryId,
    },
    /// Entry has invalid signature.
    InvalidSignature {
        /// The entry with invalid signature.
        entry_id: AuditEntryId,
    },
    /// Chain link is broken.
    BrokenLink {
        /// The entry with broken link.
        entry_id: AuditEntryId,
        /// Expected previous hash.
        expected_previous: ContentHash,
        /// Actual previous hash in entry.
        actual_previous: ContentHash,
    },
}

impl std::fmt::Display for ChainIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidGenesis { entry_id } => {
                write!(f, "Invalid genesis at {entry_id}")
            },
            Self::InvalidSignature { entry_id } => {
                write!(f, "Invalid signature at {entry_id}")
            },
            Self::BrokenLink { entry_id, .. } => {
                write!(f, "Broken chain link at {entry_id}")
            },
        }
    }
}

/// Builder for audit entries with fluent API.
#[cfg(test)]
pub(crate) struct AuditBuilder<'a> {
    log: &'a AuditLog,
    session_id: SessionId,
    action: Option<AuditAction>,
    authorization: Option<AuthorizationProof>,
}

#[cfg(test)]
impl<'a> AuditBuilder<'a> {
    /// Create a new audit builder.
    pub(crate) fn new(log: &'a AuditLog, session_id: SessionId) -> Self {
        Self {
            log,
            session_id,
            action: None,
            authorization: None,
        }
    }

    /// Set the action.
    #[must_use]
    pub(crate) fn action(mut self, action: AuditAction) -> Self {
        self.action = Some(action);
        self
    }

    /// Set the authorization.
    #[must_use]
    pub(crate) fn authorization(mut self, auth: AuthorizationProof) -> Self {
        self.authorization = Some(auth);
        self
    }

    /// Record success.
    ///
    /// # Panics
    ///
    /// Panics if `action` was not set on the builder.
    ///
    /// # Errors
    ///
    /// Returns an error if the audit entry cannot be appended.
    pub(crate) async fn success(self) -> AuditResult<AuditEntryId> {
        self.log
            .append(
                self.session_id,
                self.action.expect("action required"),
                self.authorization
                    .unwrap_or(AuthorizationProof::NotRequired {
                        reason: "unspecified".to_string(),
                    }),
                AuditOutcome::success(),
            )
            .await
    }

    /// Record success with details.
    ///
    /// # Panics
    ///
    /// Panics if `action` was not set on the builder.
    ///
    /// # Errors
    ///
    /// Returns an error if the audit entry cannot be appended.
    pub(crate) async fn success_with(
        self,
        details: impl Into<String>,
    ) -> AuditResult<AuditEntryId> {
        self.log
            .append(
                self.session_id,
                self.action.expect("action required"),
                self.authorization
                    .unwrap_or(AuthorizationProof::NotRequired {
                        reason: "unspecified".to_string(),
                    }),
                AuditOutcome::success_with(details),
            )
            .await
    }

    /// Record failure.
    ///
    /// # Panics
    ///
    /// Panics if `action` was not set on the builder.
    ///
    /// # Errors
    ///
    /// Returns an error if the audit entry cannot be appended.
    pub(crate) async fn failure(self, error: impl Into<String>) -> AuditResult<AuditEntryId> {
        self.log
            .append(
                self.session_id,
                self.action.expect("action required"),
                self.authorization
                    .unwrap_or(AuthorizationProof::NotRequired {
                        reason: "unspecified".to_string(),
                    }),
                AuditOutcome::failure(error),
            )
            .await
    }
}

#[cfg(test)]
#[path = "log_tests.rs"]
mod tests;
