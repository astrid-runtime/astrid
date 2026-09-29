use super::{
    AuditEntry, AuditError, AuditLog, AuditPruneReceipt, AuditResult, ChainIssue,
    ChainVerificationResult, prune,
};
use crate::entry_v2::{ChainVerifier, KeyRegistry, KeyRole};
use astrid_core::{PrincipalId, SessionId};
use tracing::{error, warn};

const PAGE_SIZE: usize = 256;
const MAX_ISSUES: usize = 1024;

struct VerificationState {
    entries_verified: usize,
    issues: Vec<ChainIssue>,
}

impl VerificationState {
    fn new() -> Self {
        Self {
            entries_verified: 0,
            issues: Vec::new(),
        }
    }

    fn push_issue(&mut self, issue: ChainIssue) {
        if self.issues.len() < MAX_ISSUES {
            self.issues.push(issue);
        }
    }

    fn finish(self) -> ChainVerificationResult {
        ChainVerificationResult {
            valid: self.issues.is_empty(),
            entries_verified: self.entries_verified,
            issues: self.issues,
        }
    }
}

fn log_issue(issue: &ChainIssue) {
    match issue {
        ChainIssue::InvalidSignature { entry_id } => {
            error!(entry_id = %entry_id, "Invalid signature");
        },
        ChainIssue::BrokenLink { entry_id, .. } => {
            warn!(current = %entry_id, "Chain link broken");
        },
        other => warn!(issue = %other, "Audit chain issue"),
    }
}

impl AuditLog {
    pub(super) async fn verify_chain_impl(
        &self,
        session_id: &SessionId,
    ) -> AuditResult<ChainVerificationResult> {
        let registry = self.verification_registry().await?;
        let mut after = None;
        let mut state = VerificationState::new();
        loop {
            let chains = match self
                .storage
                .session_chains_page(session_id, after.as_deref(), PAGE_SIZE)
                .await
            {
                Ok(chains) => chains,
                Err(AuditError::UnsupportedOperation { .. }) => {
                    return self.verify_legacy_chain_impl(session_id).await;
                },
                Err(error) => return Err(error),
            };
            let chain_count = chains.len();
            let Some(last) = chains.last().map(|(key, _)| key.clone()) else {
                if after.is_none() && self.session_has_entries(session_id).await? {
                    return self.verify_legacy_chain_impl(session_id).await;
                }
                break;
            };
            for (_, principal) in chains {
                self.verify_indexed_chain(
                    session_id,
                    principal.as_ref(),
                    registry.as_deref(),
                    &mut state,
                )
                .await?;
            }
            after = Some(last);
            if chain_count < PAGE_SIZE {
                break;
            }
        }
        Ok(state.finish())
    }

    async fn session_has_entries(&self, session_id: &SessionId) -> AuditResult<bool> {
        Ok(!self
            .storage
            .get_session_entries_page(session_id, None, 1)
            .await?
            .is_empty())
    }

    async fn verify_indexed_chain(
        &self,
        session_id: &SessionId,
        principal: Option<&PrincipalId>,
        registry: Option<&KeyRegistry>,
        state: &mut VerificationState,
    ) -> AuditResult<()> {
        let mut cursor = None;
        let mut previous = None;
        loop {
            let entries = self
                .storage
                .principal_entries_page(session_id, principal, cursor.as_deref(), PAGE_SIZE)
                .await?;
            let Some(last_entry) = entries.last().map(|(key, _)| key.clone()) else {
                break;
            };
            for (_, entry) in entries {
                self.verify_stored_entry(&entry, previous.as_ref(), registry, &mut |issue| {
                    state.push_issue(issue);
                })
                .await?;
                state.entries_verified = state.entries_verified.saturating_add(1);
                previous = Some(entry);
            }
            cursor = Some(last_entry);
        }
        Ok(())
    }

    /// Check one stored entry of a chain: the first entry's anchoring (zero
    /// genesis hash or a signed archive receipt) and every format rule
    /// [`ChainVerifier`] applies against `previous`.
    pub(super) async fn verify_stored_entry(
        &self,
        entry: &AuditEntry,
        previous: Option<&AuditEntry>,
        registry: Option<&KeyRegistry>,
        report: &mut impl FnMut(ChainIssue),
    ) -> AuditResult<()> {
        if previous.is_none() && !self.verify_archive_anchor(entry, registry).await? {
            report(ChainIssue::InvalidGenesis {
                entry_id: entry.id.clone(),
            });
        }
        for issue in ChainVerifier::new(registry).check_entry(entry, previous) {
            log_issue(&issue);
            report(issue);
        }
        Ok(())
    }

    pub(super) async fn verify_principal_chain_impl(
        &self,
        session_id: &SessionId,
        principal: Option<&PrincipalId>,
    ) -> AuditResult<ChainVerificationResult> {
        let registry = self.verification_registry().await?;
        let entries = self.get_principal_entries(session_id, principal).await?;
        let mut issues = Vec::new();
        let mut previous: Option<&AuditEntry> = None;
        // Storage order is the durable append order. Wall-clock timestamps are
        // signed evidence, not an ordering primitive: clocks can move backward.
        for entry in &entries {
            self.verify_stored_entry(entry, previous, registry.as_deref(), &mut |issue| {
                issues.push(issue);
            })
            .await?;
            previous = Some(entry);
        }
        Ok(ChainVerificationResult {
            valid: issues.is_empty(),
            entries_verified: entries.len(),
            issues,
        })
    }

    /// Whether the first stored entry of a chain is anchored: its previous
    /// hash is zero, or a signed archive receipt for this chain names it.
    ///
    /// Once the store has a key registry, the receipt's key must be one it
    /// lists, like the keys of the entries themselves:
    ///
    /// - a receipt written before v2 was enabled carries no key epoch and must
    ///   be signed by the registered v1-audit key;
    /// - a receipt written under v2 must name a key epoch at which its key
    ///   held the audit role, and for a v2 first entry that epoch must be no
    ///   earlier than the entry's (a receipt is written after the entries it
    ///   keeps), so a retired key cannot anchor a suffix that starts after
    ///   its retirement.
    ///
    /// Without a registry, receipts are checked under their embedded key, as
    /// format v1 did.
    async fn verify_archive_anchor(
        &self,
        first: &AuditEntry,
        registry: Option<&KeyRegistry>,
    ) -> AuditResult<bool> {
        if first.previous_hash.is_zero() {
            return Ok(true);
        }
        let principal = first.principal.as_ref();
        let Some(raw) = self
            .storage
            .prune_receipt(&first.session_id, principal)
            .await?
        else {
            return Ok(false);
        };
        let receipt: AuditPruneReceipt = serde_json::from_slice(&raw)
            .map_err(|error| AuditError::SerializationError(error.to_string()))?;
        let expected_principal = principal.map(ToString::to_string);
        if receipt.session != first.session_id.to_string()
            || receipt.principal.as_deref() != expected_principal.as_deref()
        {
            return Ok(false);
        }
        if !receipt_key_registered(&receipt, first, registry) {
            return Ok(false);
        }
        prune::verify_anchor(&receipt, &first.previous_hash)
    }
}

/// Whether `receipt` is signed by a key the registry lists for it; see
/// `AuditLog::verify_archive_anchor`.
fn receipt_key_registered(
    receipt: &AuditPruneReceipt,
    first: &AuditEntry,
    registry: Option<&KeyRegistry>,
) -> bool {
    let Some(registry) = registry else {
        return first.v2.is_none();
    };
    let key = &receipt.public_key;
    match (receipt.key_epoch, &first.v2) {
        (Some(epoch), Some(seal)) => {
            epoch >= seal.key_epoch && registry.is_active(KeyRole::Audit, key, epoch)
        },
        (Some(epoch), None) => registry.is_active(KeyRole::Audit, key, epoch),
        (None, Some(_)) => false,
        (None, None) => registry.was_registered(KeyRole::AuditV1, key),
    }
}
