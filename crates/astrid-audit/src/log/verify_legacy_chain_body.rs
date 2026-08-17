{
let entries = self.storage.get_session_entries(session_id).await?;
let mut chains: HashMap<Option<astrid_core::PrincipalId>, Vec<&AuditEntry>> = HashMap::new();
for entry in &entries {
    chains.entry(entry.principal.clone()).or_default().push(entry);
}
let mut issues = Vec::new();
let mut entries_verified = 0usize;
for chain_entries in chains.values() {
    let anchored = self
        .verify_archive_anchor(
            &chain_entries[0].session_id,
            chain_entries[0].principal.as_ref(),
            &chain_entries[0].previous_hash,
        )
        .await?;
    if !anchored {
        issues.push(ChainIssue::InvalidGenesis { entry_id: chain_entries[0].id.clone() });
    }
    for entry in chain_entries {
        if let Err(error) = entry.verify_signature() {
            error!(entry_id = %entry.id, error = %error, "Invalid signature");
            issues.push(ChainIssue::InvalidSignature { entry_id: entry.id.clone() });
        }
        entries_verified = entries_verified.saturating_add(1);
    }
    for pair in chain_entries.windows(2) {
        let [previous, current] = pair else { continue };
        if !current.follows(previous) {
            warn!(current = %current.id, previous = %previous.id, "Chain link broken");
            issues.push(ChainIssue::BrokenLink {
                entry_id: current.id.clone(),
                expected_previous: previous.content_hash(),
                actual_previous: current.previous_hash,
            });
        }
    }
}
Ok(ChainVerificationResult { valid: issues.is_empty(), entries_verified, issues })
}
