use super::{AuditEntry, AuditLog, AuditResult, ChainIssue, ChainVerificationResult};
use astrid_core::{PrincipalId, SessionId};
use std::collections::HashMap;
use tracing::{error, warn};

impl AuditLog {
    pub(super) async fn verify_legacy_chain_impl(
        &self,
        session_id: &SessionId,
    ) -> AuditResult<ChainVerificationResult> {
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
                self.verify_legacy_entries(chain_entries, &mut issues)
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
        issues: &mut Vec<ChainIssue>,
    ) -> AuditResult<usize> {
        let Some(first) = entries.first() else {
            return Ok(0);
        };
        if !self
            .verify_archive_anchor(
                &first.session_id,
                first.principal.as_ref(),
                &first.previous_hash,
            )
            .await?
        {
            issues.push(ChainIssue::InvalidGenesis {
                entry_id: first.id.clone(),
            });
        }
        for entry in entries {
            if let Err(error) = entry.verify_signature() {
                error!(entry_id = %entry.id, error = %error, "Invalid signature");
                issues.push(ChainIssue::InvalidSignature {
                    entry_id: entry.id.clone(),
                });
            }
        }
        for pair in entries.windows(2) {
            let [previous, current] = pair else {
                continue;
            };
            if !current.follows(previous) {
                warn!(current = %current.id, previous = %previous.id, "Chain link broken");
                issues.push(ChainIssue::BrokenLink {
                    entry_id: current.id.clone(),
                    expected_previous: previous.content_hash(),
                    actual_previous: current.previous_hash,
                });
            }
        }
        Ok(entries.len())
    }
}
