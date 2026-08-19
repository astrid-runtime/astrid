use super::{AuditEntry, AuditError, AuditLog, AuditResult, ChainIssue, ChainVerificationResult};
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

impl AuditLog {
    pub(super) async fn verify_chain_impl(
        &self,
        session_id: &SessionId,
    ) -> AuditResult<ChainVerificationResult> {
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
                self.verify_indexed_chain(session_id, principal.as_ref(), &mut state)
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
                self.verify_indexed_entry(&entry, previous.as_ref(), state)
                    .await?;
                previous = Some(entry);
            }
            cursor = Some(last_entry);
        }
        Ok(())
    }

    async fn verify_indexed_entry(
        &self,
        entry: &AuditEntry,
        previous: Option<&AuditEntry>,
        state: &mut VerificationState,
    ) -> AuditResult<()> {
        if previous.is_none()
            && !self
                .verify_archive_anchor(
                    &entry.session_id,
                    entry.principal.as_ref(),
                    &entry.previous_hash,
                )
                .await?
        {
            state.push_issue(ChainIssue::InvalidGenesis {
                entry_id: entry.id.clone(),
            });
        }
        if let Err(error) = entry.verify_signature()
            && state.issues.len() < MAX_ISSUES
        {
            error!(entry_id = %entry.id, error = %error, "Invalid signature");
            state.push_issue(ChainIssue::InvalidSignature {
                entry_id: entry.id.clone(),
            });
        }
        if let Some(previous_entry) = previous
            && !entry.follows(previous_entry)
            && state.issues.len() < MAX_ISSUES
        {
            warn!(current = %entry.id, previous = %previous_entry.id, "Chain link broken");
            state.push_issue(ChainIssue::BrokenLink {
                entry_id: entry.id.clone(),
                expected_previous: previous_entry.content_hash(),
                actual_previous: entry.previous_hash,
            });
        }
        state.entries_verified = state.entries_verified.saturating_add(1);
        Ok(())
    }
}
