use super::{
    AuditError, AuditResult, AuditStorage, ChainMetadata, DURABLE_APPEND_LOCK, KvAuditStorage,
    NS_COMMITTED_ENTRIES, NS_ENTRIES, NS_PRUNE_PLANS, NS_PRUNE_RECEIPTS, NS_SEGMENT_INDEX,
    NS_SESSION_ENTRIES, NS_SESSION_SEQUENCE, PrunePlan, helpers::chain_head_key,
};
use astrid_core::{PrincipalId, SessionId};

struct ReceiptDetails {
    cutoff: Option<String>,
    omitted_count: u64,
    omitted_bytes: u64,
    omitted_terminal_hash: String,
}

impl ReceiptDetails {
    fn parse(receipt: &[u8]) -> AuditResult<Self> {
        let value: serde_json::Value = serde_json::from_slice(receipt)
            .map_err(|error| AuditError::SerializationError(error.to_string()))?;
        Ok(Self {
            cutoff: value
                .get("cutoff_cursor")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
            omitted_count: value
                .get("omitted_count")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0),
            omitted_bytes: value
                .get("omitted_bytes")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0),
            omitted_terminal_hash: value
                .get("omitted_terminal_hash")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_owned(),
        })
    }
}

impl KvAuditStorage {
    pub(super) async fn prune_chain_durable(
        &self,
        session_id: &SessionId,
        principal: Option<&PrincipalId>,
        keep_entries: usize,
        receipt: Vec<u8>,
    ) -> AuditResult<()> {
        let _guard = DURABLE_APPEND_LOCK.lock().await;
        self.require_paged_session_projection(session_id).await?;
        let plan_key = chain_head_key(session_id, principal);
        let mut plan = self
            .load_or_create_prune_plan(session_id, principal, &plan_key, keep_entries, receipt)
            .await?;
        if plan.complete {
            return self
                .finish_prune_plan_durable(session_id, principal, &plan_key, &plan)
                .await;
        }

        let cutoff = ReceiptDetails::parse(&plan.receipt)?.cutoff;
        if let Some(cutoff) = cutoff.as_deref() {
            self.delete_prune_page(session_id, principal, &plan_key, cutoff, &mut plan)
                .await?;
        } else {
            plan.complete = true;
            self.persist_prune_plan(
                &plan_key,
                &plan,
                "audit prune plan changed during finalization",
            )
            .await?;
        }

        if plan.complete {
            self.finish_prune_plan_durable(session_id, principal, &plan_key, &plan)
                .await
        } else {
            Ok(())
        }
    }

    async fn require_paged_session_projection(&self, session_id: &SessionId) -> AuditResult<()> {
        if self
            .store
            .exists(NS_SESSION_SEQUENCE, &session_id.0.to_string())
            .await
            .map_err(|error| AuditError::StorageError(error.to_string()))?
        {
            Ok(())
        } else {
            Err(AuditError::StorageError(
                "audit prune requires a paged session projection".to_owned(),
            ))
        }
    }

    async fn load_or_create_prune_plan(
        &self,
        session_id: &SessionId,
        principal: Option<&PrincipalId>,
        plan_key: &str,
        keep_entries: usize,
        receipt: Vec<u8>,
    ) -> AuditResult<PrunePlan> {
        if let Some(bytes) = self
            .store
            .get(NS_PRUNE_PLANS, plan_key)
            .await
            .map_err(|error| AuditError::StorageError(error.to_string()))?
        {
            return serde_json::from_slice(&bytes)
                .map_err(|error| AuditError::SerializationError(error.to_string()));
        }

        self.validate_receipt_generation(plan_key, &receipt).await?;
        let details = ReceiptDetails::parse(&receipt)?;
        let segment_key = self
            .find_pruned_segment(session_id, principal, &details)
            .await?;
        let plan = PrunePlan {
            receipt,
            keep_entries,
            after: None,
            complete: false,
            segment_key,
            segment_count: details.omitted_count,
            segment_bytes: details.omitted_bytes,
            segment_accounted: false,
        };
        let encoded = serde_json::to_vec(&plan)
            .map_err(|error| AuditError::SerializationError(error.to_string()))?;
        if !self
            .store
            .compare_and_swap(NS_PRUNE_PLANS, plan_key, None, encoded)
            .await
            .map_err(|error| AuditError::StorageError(error.to_string()))?
        {
            return Err(AuditError::StorageError(
                "audit prune plan was concurrently installed; retry".to_owned(),
            ));
        }
        Ok(plan)
    }

    async fn validate_receipt_generation(&self, plan_key: &str, receipt: &[u8]) -> AuditResult<()> {
        let Some(current) = self
            .store
            .get(NS_PRUNE_RECEIPTS, plan_key)
            .await
            .map_err(|error| AuditError::StorageError(error.to_string()))?
        else {
            return Ok(());
        };
        let old: serde_json::Value = serde_json::from_slice(&current)
            .map_err(|error| AuditError::SerializationError(error.to_string()))?;
        let next: serde_json::Value = serde_json::from_slice(receipt)
            .map_err(|error| AuditError::SerializationError(error.to_string()))?;
        let old_generation = receipt_generation(&old)?;
        let next_generation = receipt_generation(&next)?;
        let expected_prior = blake3::hash(&current).to_hex().to_string();
        let prior = next
            .get("prior_receipt_hash")
            .and_then(serde_json::Value::as_str);
        if next_generation == old_generation.saturating_add(1)
            && prior == Some(expected_prior.as_str())
        {
            Ok(())
        } else {
            Err(AuditError::StorageError(
                "audit prune receipt generation is not linked to the current anchor".to_owned(),
            ))
        }
    }

    async fn find_pruned_segment(
        &self,
        session_id: &SessionId,
        principal: Option<&PrincipalId>,
        details: &ReceiptDetails,
    ) -> AuditResult<Option<String>> {
        if details.omitted_count == 0 {
            return Ok(None);
        }
        let chain_marker = format!(":{}:", chain_head_key(session_id, principal));
        let mut after = None;
        loop {
            let page = self
                .store
                .list_keys_with_prefix_page(NS_SEGMENT_INDEX, "", after.as_deref(), 256)
                .await
                .map_err(|error| AuditError::StorageError(error.to_string()))?;
            if page.is_empty() {
                return Ok(None);
            }
            for candidate in &page {
                if candidate.contains(&chain_marker)
                    && self.segment_matches_receipt(candidate, details).await?
                {
                    return Ok(Some(candidate.clone()));
                }
            }
            after = page.last().cloned();
        }
    }

    async fn segment_matches_receipt(
        &self,
        candidate: &str,
        details: &ReceiptDetails,
    ) -> AuditResult<bool> {
        let Some(bytes) = self
            .store
            .get(NS_SEGMENT_INDEX, candidate)
            .await
            .map_err(|error| AuditError::StorageError(error.to_string()))?
        else {
            return Ok(false);
        };
        let metadata: ChainMetadata = serde_json::from_slice(&bytes)
            .map_err(|error| AuditError::SerializationError(error.to_string()))?;
        Ok(metadata.sealed
            && metadata.segment_count == details.omitted_count
            && metadata.segment_bytes == details.omitted_bytes
            && metadata.head_hash.to_hex() == details.omitted_terminal_hash)
    }

    async fn delete_prune_page(
        &self,
        session_id: &SessionId,
        principal: Option<&PrincipalId>,
        plan_key: &str,
        cutoff: &str,
        plan: &mut PrunePlan,
    ) -> AuditResult<()> {
        let page = self
            .get_session_entries_page(session_id, plan.after.as_deref(), 256)
            .await?;
        let page_empty = page.is_empty();
        let mut reached_cutoff = false;
        let mut last_cursor = plan.after.clone();
        for (cursor, entry) in page {
            if cursor.as_str() > cutoff {
                reached_cutoff = true;
                break;
            }
            last_cursor = Some(cursor.clone());
            if entry.principal.as_ref() != principal {
                continue;
            }
            self.delete_pruned_entry(&cursor, &entry.id).await?;
            if cursor == cutoff {
                reached_cutoff = true;
                break;
            }
        }
        plan.after = last_cursor;
        plan.complete = reached_cutoff || page_empty;
        self.persist_prune_plan(
            plan_key,
            plan,
            "audit prune plan changed during bounded deletion",
        )
        .await
    }

    async fn delete_pruned_entry(
        &self,
        cursor: &str,
        id: &astrid_capabilities::AuditEntryId,
    ) -> AuditResult<()> {
        let entry_key = id.0.to_string();
        self.store
            .delete(NS_ENTRIES, &entry_key)
            .await
            .map_err(|error| AuditError::StorageError(error.to_string()))?;
        self.store
            .delete(NS_COMMITTED_ENTRIES, &entry_key)
            .await
            .map_err(|error| AuditError::StorageError(error.to_string()))?;
        self.store
            .delete(NS_SESSION_ENTRIES, cursor)
            .await
            .map_err(|error| AuditError::StorageError(error.to_string()))?;
        Ok(())
    }

    async fn persist_prune_plan(
        &self,
        plan_key: &str,
        plan: &PrunePlan,
        conflict_message: &str,
    ) -> AuditResult<()> {
        let expected = self
            .store
            .get(NS_PRUNE_PLANS, plan_key)
            .await
            .map_err(|error| AuditError::StorageError(error.to_string()))?;
        let encoded = serde_json::to_vec(plan)
            .map_err(|error| AuditError::SerializationError(error.to_string()))?;
        if self
            .store
            .compare_and_swap(NS_PRUNE_PLANS, plan_key, expected.as_deref(), encoded)
            .await
            .map_err(|error| AuditError::StorageError(error.to_string()))?
        {
            Ok(())
        } else {
            Err(AuditError::StorageError(conflict_message.to_owned()))
        }
    }
}

fn receipt_generation(value: &serde_json::Value) -> AuditResult<u64> {
    value
        .get("generation")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| AuditError::StorageError("archive receipt lacks generation".to_owned()))
}
