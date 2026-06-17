//! Audit log - main interface for audit logging.
//!
//! Provides a high-level API for recording and verifying audit entries.

use astrid_capabilities::AuditEntryId;
use astrid_core::SessionId;
use astrid_crypto::{ContentHash, KeyPair};
use std::path::Path;
use std::sync::{Arc, RwLock};
use tracing::{debug, error, warn};

use crate::entry::{AuditAction, AuditEntry, AuditOutcome, AuthorizationProof};
use crate::error::{AuditError, AuditResult};
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
    chain_heads: RwLock<std::collections::HashMap<ChainKey, ContentHash>>,
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
            chain_heads: RwLock::new(std::collections::HashMap::new()),
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
            chain_heads: RwLock::new(std::collections::HashMap::new()),
        }
    }

    /// Append a new audit entry.
    ///
    /// # Errors
    ///
    /// Returns an error if the entry cannot be stored or the chain head cannot be updated.
    pub fn append(
        &self,
        session_id: SessionId,
        action: AuditAction,
        authorization: AuthorizationProof,
        outcome: AuditOutcome,
    ) -> AuditResult<AuditEntryId> {
        self.append_inner(session_id, None, action, authorization, outcome)
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
    pub fn append_with_principal(
        &self,
        session_id: SessionId,
        principal: astrid_core::PrincipalId,
        action: AuditAction,
        authorization: AuthorizationProof,
        outcome: AuditOutcome,
    ) -> AuditResult<AuditEntryId> {
        self.append_inner(session_id, Some(principal), action, authorization, outcome)
    }

    /// Shared implementation for `append` and `append_with_principal`.
    fn append_inner(
        &self,
        session_id: SessionId,
        principal: Option<astrid_core::PrincipalId>,
        action: AuditAction,
        authorization: AuthorizationProof,
        outcome: AuditOutcome,
    ) -> AuditResult<AuditEntryId> {
        // Get the previous hash for this entry's chain (system or principal).
        let chain_key: ChainKey = (session_id.clone(), principal.clone());
        let previous_hash = self.get_previous_hash(&chain_key)?;

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

        // Store the entry
        self.storage.store(&entry)?;

        // Update cached chain head for this entry's chain.
        {
            let mut heads = self
                .chain_heads
                .write()
                .map_err(|e| AuditError::StorageError(e.to_string()))?;
            heads.insert(chain_key, entry_hash);
        }

        Ok(entry_id)
    }

    /// Get the previous hash for a chain (session + optional principal).
    fn get_previous_hash(&self, chain_key: &ChainKey) -> AuditResult<ContentHash> {
        // Check cache first
        {
            let heads = self
                .chain_heads
                .read()
                .map_err(|e| AuditError::StorageError(e.to_string()))?;
            if let Some(hash) = heads.get(chain_key) {
                return Ok(*hash);
            }
        }

        // Check storage
        if let Some(head_id) = self
            .storage
            .get_chain_head(&chain_key.0, chain_key.1.as_ref())?
            && let Some(entry) = self.storage.get(&head_id)?
        {
            return Ok(entry.content_hash());
        }

        // Genesis - no previous entry for this chain
        Ok(ContentHash::zero())
    }

    /// Get an entry by ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the storage backend fails to retrieve the entry.
    pub fn get(&self, id: &AuditEntryId) -> AuditResult<Option<AuditEntry>> {
        self.storage.get(id)
    }

    /// Get all entries for a session.
    ///
    /// # Errors
    ///
    /// Returns an error if the storage backend fails to retrieve entries.
    pub fn get_session_entries(&self, session_id: &SessionId) -> AuditResult<Vec<AuditEntry>> {
        self.storage.get_session_entries(session_id)
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
    pub fn verify_chain(&self, session_id: &SessionId) -> AuditResult<ChainVerificationResult> {
        let entries = self.storage.get_session_entries(session_id)?;

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
    pub fn verify_principal_chain(
        &self,
        session_id: &SessionId,
        principal: Option<&astrid_core::PrincipalId>,
    ) -> AuditResult<ChainVerificationResult> {
        let entries = self.get_principal_entries(session_id, principal)?;

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
    pub fn get_principal_entries(
        &self,
        session_id: &SessionId,
        principal: Option<&astrid_core::PrincipalId>,
    ) -> AuditResult<Vec<AuditEntry>> {
        let all = self.storage.get_session_entries(session_id)?;
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
    pub fn verify_all(&self) -> AuditResult<Vec<(SessionId, ChainVerificationResult)>> {
        let sessions = self.storage.list_sessions()?;
        let mut results = Vec::new();

        for session_id in sessions {
            let result = self.verify_chain(&session_id)?;
            results.push((session_id, result));
        }

        Ok(results)
    }

    /// Count total entries.
    ///
    /// # Errors
    ///
    /// Returns an error if the storage backend fails.
    pub fn count(&self) -> AuditResult<usize> {
        self.storage.count()
    }

    /// Count entries for a session.
    ///
    /// # Errors
    ///
    /// Returns an error if the storage backend fails.
    pub fn count_session(&self, session_id: &SessionId) -> AuditResult<usize> {
        self.storage.count_session(session_id)
    }

    /// List all sessions.
    ///
    /// # Errors
    ///
    /// Returns an error if the storage backend fails.
    pub fn list_sessions(&self) -> AuditResult<Vec<SessionId>> {
        self.storage.list_sessions()
    }

    /// Flush pending writes.
    ///
    /// # Errors
    ///
    /// Returns an error if the storage backend fails to flush.
    pub fn flush(&self) -> AuditResult<()> {
        self.storage.flush()
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
    pub(crate) fn success(self) -> AuditResult<AuditEntryId> {
        self.log.append(
            self.session_id,
            self.action.expect("action required"),
            self.authorization
                .unwrap_or(AuthorizationProof::NotRequired {
                    reason: "unspecified".to_string(),
                }),
            AuditOutcome::success(),
        )
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
    pub(crate) fn success_with(self, details: impl Into<String>) -> AuditResult<AuditEntryId> {
        self.log.append(
            self.session_id,
            self.action.expect("action required"),
            self.authorization
                .unwrap_or(AuthorizationProof::NotRequired {
                    reason: "unspecified".to_string(),
                }),
            AuditOutcome::success_with(details),
        )
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
    pub(crate) fn failure(self, error: impl Into<String>) -> AuditResult<AuditEntryId> {
        self.log.append(
            self.session_id,
            self.action.expect("action required"),
            self.authorization
                .unwrap_or(AuthorizationProof::NotRequired {
                    reason: "unspecified".to_string(),
                }),
            AuditOutcome::failure(error),
        )
    }
}

#[cfg(test)]
#[path = "log_tests.rs"]
mod tests;
