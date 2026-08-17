{
    const PAGE_SIZE: usize = 256;
    const MAX_ISSUES: usize = 1024;
    let mut after = None;
    let mut issues = Vec::new();
    let mut entries_verified = 0usize;
    loop {
        let chains = self
            .storage
            .session_chains_page(session_id, after.as_deref(), PAGE_SIZE)
            .await;
        let chains = match chains {
            Ok(chains) => chains,
            Err(AuditError::UnsupportedOperation { .. }) => {
                return self.verify_legacy_chain(session_id).await;
            },
            Err(error) => return Err(error),
        };
        let chain_count = chains.len();
        let Some(last) = chains.last().map(|(key, _)| key.clone()) else {
            if after.is_none()
                && !self
                    .storage
                    .get_session_entries_page(session_id, None, 1)
                    .await?
                    .is_empty()
            {
                return self.verify_legacy_chain(session_id).await;
            }
            break;
        };
        for (_, principal) in chains {
            let mut cursor = None;
            let mut previous = None;
            loop {
                let entries = self
                    .storage
                    .principal_entries_page(
                        session_id,
                        principal.as_ref(),
                        cursor.as_deref(),
                        PAGE_SIZE,
                    )
                    .await?;
                let Some(last_entry) = entries.last().map(|(key, _)| key.clone()) else { break };
                for (_, entry) in entries {
                    if previous.is_none()
                        && !self
                            .verify_archive_anchor(
                                &entry.session_id,
                                entry.principal.as_ref(),
                                &entry.previous_hash,
                            )
                            .await?
                        && issues.len() < MAX_ISSUES
                    {
                        issues.push(ChainIssue::InvalidGenesis { entry_id: entry.id.clone() });
                    }
                    if let Err(error) = entry.verify_signature()
                        && issues.len() < MAX_ISSUES
                    {
                        error!(entry_id = %entry.id, error = %error, "Invalid signature");
                        issues.push(ChainIssue::InvalidSignature { entry_id: entry.id.clone() });
                    }
                    if let Some(previous_entry) = previous.as_ref()
                        && !entry.follows(previous_entry)
                        && issues.len() < MAX_ISSUES
                    {
                        warn!(current = %entry.id, previous = %previous_entry.id, "Chain link broken");
                        issues.push(ChainIssue::BrokenLink {
                            entry_id: entry.id.clone(),
                            expected_previous: previous_entry.content_hash(),
                            actual_previous: entry.previous_hash,
                        });
                    }
                    entries_verified = entries_verified.saturating_add(1);
                    previous = Some(entry);
                }
                cursor = Some(last_entry);
            }
        }
        after = Some(last);
        if chain_count < PAGE_SIZE { break; }
    }
    Ok(ChainVerificationResult { valid: issues.is_empty(), entries_verified, issues })
}
