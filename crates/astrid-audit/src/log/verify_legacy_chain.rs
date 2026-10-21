use super::{AuditEntry, AuditLog, AuditResult, ChainIssue, ChainVerificationResult};
use crate::entry_v2::KeyRegistry;
use astrid_core::{PrincipalId, SessionId};
use std::collections::HashMap;

impl AuditLog {
    pub(super) async fn verify_legacy_chain_impl(
        &self,
        session_id: &SessionId,
    ) -> AuditResult<ChainVerificationResult> {
        let registry = self.verification_registry().await?;
        let entries = self.storage.get_session_entries(session_id).await?;
        let mut chains: HashMap<Option<PrincipalId>, Vec<&AuditEntry>> = HashMap::new();
        for entry in &entries {
            chains
                .entry(entry.principal.clone())
                .or_default()
                .push(entry);
        }

        let mut issues = Vec::new();
        let mut entries_verified = 0usize;
        for chain_entries in chains.values() {
            entries_verified = entries_verified.saturating_add(
                self.verify_legacy_entries(chain_entries, registry.as_deref(), &mut issues)
                    .await?,
            );
        }
        Ok(ChainVerificationResult {
            valid: issues.is_empty(),
            entries_verified,
            issues,
        })
    }

    async fn verify_legacy_entries(
        &self,
        entries: &[&AuditEntry],
        registry: Option<&KeyRegistry>,
        issues: &mut Vec<ChainIssue>,
    ) -> AuditResult<usize> {
        let mut previous: Option<&AuditEntry> = None;
        for entry in entries {
            self.verify_stored_entry(entry, previous, registry, &mut |issue| {
                issues.push(issue);
            })
            .await?;
            previous = Some(entry);
        }
        Ok(entries.len())
    }
}
