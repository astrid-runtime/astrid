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
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ChainKey {
    session_id: SessionId,
    principal: Option<astrid_core::PrincipalId>,
}

type ChainHead = Arc<Mutex<Option<ContentHash>>>;

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
    /// The outer standard mutex protects only map lookup/insertion and is never
    /// held across an await. Each value is its own async mutex, held across the
    /// durable append so one chain remains strictly ordered without blocking an
    /// unrelated principal's chain.
    chain_heads: std::sync::Mutex<std::collections::HashMap<ChainKey, ChainHead>>,
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
            chain_heads: std::sync::Mutex::new(std::collections::HashMap::new()),
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
            chain_heads: std::sync::Mutex::new(std::collections::HashMap::new()),
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
        let previous_hash = self.previous_hash_locked(&chain_key, head.as_ref()).await?;

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

        // The storage future may be cancelled after its durable commit point but
        // before it reports success. Invalidate the cache before awaiting so an
        // error or cancellation leaves `None` behind and the next append recovers
        // the authoritative committed head from storage. Only a reported success
        // installs the new fast-path hash.
        *head = None;
        self.storage.store(&entry).await?;
        *head = Some(entry_hash);

        Ok(entry_id)
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
        head: Option<&ContentHash>,
    ) -> AuditResult<ContentHash> {
        // Check the in-memory head cache first.
        if let Some(hash) = head {
            return Ok(*hash);
        }

        // Fall back to storage (first append after a restart / cache miss).
        if let Some(head_id) = self
            .storage
            .get_chain_head(&chain_key.session_id, chain_key.principal.as_ref())
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
        for chain_entries in chains.values() {
            // Verify genesis (first entry has zero previous hash).
            if !chain_entries[0].previous_hash.is_zero() {
                issues.push(ChainIssue::InvalidGenesis {
                    entry_id: chain_entries[0].id.clone(),
                });
            }

            // Verify signatures.
            for entry in chain_entries {
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

        // Storage order is the durable append order. Wall-clock timestamps are
        // signed evidence, not an ordering primitive: clocks can move backward.
        let sorted = entries;

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
