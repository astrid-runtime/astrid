use super::{
    AuditError, AuditResult, AuditStorage, GlobalMetadata, KvAuditStorage, NS_GLOBAL_METADATA,
    NS_PRUNE_PLANS, NS_PRUNE_RECEIPTS, NS_SEGMENT_INDEX, PrunePlan, helpers::chain_head_key,
};
use crate::entry::AuditEntry;
use astrid_capabilities::AuditEntryId;
use astrid_core::{PrincipalId, SessionId};
use astrid_storage::{KvBatchCondition, KvBatchMutation, KvEntryKey, KvMutationBatch};

struct ReceiptAccounting {
    omitted_count: u64,
    omitted_bytes: u64,
    retained_head: Option<AuditEntryId>,
}

impl ReceiptAccounting {
    fn parse(receipt: &[u8]) -> AuditResult<Self> {
        let value: serde_json::Value = serde_json::from_slice(receipt)
            .map_err(|error| AuditError::SerializationError(error.to_string()))?;
        let retained_head = value
            .get("retained_head")
            .and_then(serde_json::Value::as_str)
            .map(str::parse::<uuid::Uuid>)
            .transpose()
            .map_err(|error| AuditError::StorageError(error.to_string()))?
            .map(AuditEntryId);
        Ok(Self {
            omitted_count: count_field(&value, "omitted_count"),
            omitted_bytes: count_field(&value, "omitted_bytes"),
            retained_head,
        })
    }
}

struct GlobalAccountingWrite {
    expected_global: Option<Vec<u8>>,
    global: GlobalMetadata,
    expected_plan: Option<Vec<u8>>,
    next_plan: Vec<u8>,
}

impl KvAuditStorage {
    pub(super) async fn finish_prune_plan_durable(
        &self,
        session_id: &SessionId,
        principal: Option<&PrincipalId>,
        plan_key: &str,
        plan: &PrunePlan,
    ) -> AuditResult<()> {
        let accounting = ReceiptAccounting::parse(&plan.receipt)?;
        self.update_retained_chain(session_id, principal, &accounting)
            .await?;
        self.account_pruned_entries(plan_key, plan, &accounting)
            .await?;
        self.remove_pruned_segment(plan).await?;
        self.install_prune_receipt(session_id, principal, plan_key, plan)
            .await
    }

    async fn update_retained_chain(
        &self,
        session_id: &SessionId,
        principal: Option<&PrincipalId>,
        accounting: &ReceiptAccounting,
    ) -> AuditResult<()> {
        // The retention receipt was planned before the bounded durable delete
        // pages ran.  Another append may have committed in that window, so
        // applying the receipt's planned head/count verbatim would roll the
        // chain back over the new successor.  Re-read the surviving projection
        // and derive the canonical head/accounting from it instead.
        let survivors = self
            .get_session_entries(session_id)
            .await?
            .into_iter()
            .filter(|entry| entry.principal.as_ref() == principal)
            .collect::<Vec<_>>();
        let retained_count = u64::try_from(survivors.len()).unwrap_or(u64::MAX);
        let retained_bytes = survivors.iter().try_fold(0_u64, |total, entry| {
            let encoded = serde_json::to_vec(entry)
                .map_err(|error| AuditError::SerializationError(error.to_string()))?;
            Ok::<_, AuditError>(
                total.saturating_add(u64::try_from(encoded.len()).unwrap_or(u64::MAX)),
            )
        })?;
        let retained_head = survivors.last().map(|entry| entry.id.clone());
        let head_hash = survivors
            .last()
            .map_or_else(astrid_crypto::ContentHash::zero, AuditEntry::content_hash);
        let (metadata_bytes, Some(mut metadata)) =
            self.load_chain_metadata(session_id, principal).await?
        else {
            return Ok(());
        };
        let planned_head_still_current = metadata.head == accounting.retained_head;
        metadata.count = retained_count;
        metadata.bytes = retained_bytes;
        metadata.head = retained_head;
        metadata.head_hash = head_hash;
        if planned_head_still_current {
            // With no concurrent successor, the retained suffix is the active
            // durable tail of the selected sealed segment.
            metadata.sealed = true;
            metadata.segment_count = retained_count;
            metadata.segment_bytes = retained_bytes;
            metadata.segment_first = survivors.first().map(|entry| entry.id.clone());
        }
        if self
            .persist_chain_metadata(session_id, principal, metadata_bytes.as_deref(), &metadata)
            .await?
        {
            Ok(())
        } else {
            Err(AuditError::StorageError(
                "audit chain metadata changed while pruning".to_owned(),
            ))
        }
    }

    async fn account_pruned_entries(
        &self,
        plan_key: &str,
        plan: &PrunePlan,
        accounting: &ReceiptAccounting,
    ) -> AuditResult<()> {
        let write = self
            .prepare_global_accounting(plan_key, plan, accounting)
            .await?;
        if self.store.supports_atomic_batch() {
            self.persist_global_accounting_atomic(plan_key, &write)
                .await
        } else {
            self.persist_global_accounting_cas(plan_key, &write).await
        }
    }

    async fn prepare_global_accounting(
        &self,
        plan_key: &str,
        plan: &PrunePlan,
        accounting: &ReceiptAccounting,
    ) -> AuditResult<GlobalAccountingWrite> {
        let (expected_global, mut global) = self.load_global_metadata().await?;
        global.total_count = global.total_count.saturating_sub(accounting.omitted_count);
        global.total_bytes = global.total_bytes.saturating_sub(accounting.omitted_bytes);
        if plan.segment_key.is_some() && !plan.segment_accounted {
            global.sealed_segments = global.sealed_segments.saturating_sub(1);
            global.eligible_segments = global.eligible_segments.saturating_sub(1);
            global.segments = global.segments.saturating_sub(1);
        }
        global.degraded =
            global.total_count > global.cap_entries || global.total_bytes > global.cap_bytes;
        let mut next_plan = plan.clone();
        next_plan.segment_accounted = true;
        let expected_plan = self
            .store
            .get(NS_PRUNE_PLANS, plan_key)
            .await
            .map_err(|error| AuditError::StorageError(error.to_string()))?;
        let next_plan = serde_json::to_vec(&next_plan)
            .map_err(|error| AuditError::SerializationError(error.to_string()))?;
        Ok(GlobalAccountingWrite {
            expected_global,
            global,
            expected_plan,
            next_plan,
        })
    }

    async fn persist_global_accounting_atomic(
        &self,
        plan_key: &str,
        write: &GlobalAccountingWrite,
    ) -> AuditResult<()> {
        let plan_key = KvEntryKey::new(NS_PRUNE_PLANS, plan_key)
            .map_err(|error| AuditError::StorageError(error.to_string()))?;
        let global_key = KvEntryKey::new(NS_GLOBAL_METADATA, "current")
            .map_err(|error| AuditError::StorageError(error.to_string()))?;
        let encoded_global = serde_json::to_vec(&write.global)
            .map_err(|error| AuditError::SerializationError(error.to_string()))?;
        let batch = KvMutationBatch::new(
            [
                KvBatchCondition::ValueEquals {
                    key: plan_key.clone(),
                    expected: write.expected_plan.clone(),
                },
                KvBatchCondition::ValueEquals {
                    key: global_key.clone(),
                    expected: write.expected_global.clone(),
                },
            ],
            [
                KvBatchMutation::Set {
                    key: plan_key,
                    value: write.next_plan.clone(),
                },
                KvBatchMutation::Set {
                    key: global_key,
                    value: encoded_global,
                },
            ],
        )
        .map_err(|error| AuditError::StorageError(error.to_string()))?;
        if self
            .store
            .apply_batch(&batch)
            .await
            .map_err(|error| AuditError::StorageError(error.to_string()))?
            .applied
        {
            Ok(())
        } else {
            Err(AuditError::StorageError(
                "audit prune plan or global metadata changed".to_owned(),
            ))
        }
    }

    async fn persist_global_accounting_cas(
        &self,
        plan_key: &str,
        write: &GlobalAccountingWrite,
    ) -> AuditResult<()> {
        if !self
            .persist_global_metadata(write.expected_global.as_deref(), &write.global)
            .await?
        {
            return Err(AuditError::StorageError(
                "audit global metadata changed while pruning".to_owned(),
            ));
        }
        if self
            .store
            .compare_and_swap(
                NS_PRUNE_PLANS,
                plan_key,
                write.expected_plan.as_deref(),
                write.next_plan.clone(),
            )
            .await
            .map_err(|error| AuditError::StorageError(error.to_string()))?
        {
            Ok(())
        } else {
            Err(AuditError::StorageError(
                "audit prune plan changed while accounting".to_owned(),
            ))
        }
    }

    async fn remove_pruned_segment(&self, plan: &PrunePlan) -> AuditResult<()> {
        let Some(segment_key) = plan.segment_key.as_deref() else {
            return Ok(());
        };
        self.store
            .delete(NS_SEGMENT_INDEX, segment_key)
            .await
            .map_err(|error| AuditError::StorageError(error.to_string()))?;
        Ok(())
    }

    async fn install_prune_receipt(
        &self,
        session_id: &SessionId,
        principal: Option<&PrincipalId>,
        plan_key: &str,
        plan: &PrunePlan,
    ) -> AuditResult<()> {
        let receipt_key = chain_head_key(session_id, principal);
        let current = self
            .store
            .get(NS_PRUNE_RECEIPTS, &receipt_key)
            .await
            .map_err(|error| AuditError::StorageError(error.to_string()))?;
        if current.as_deref() != Some(plan.receipt.as_slice())
            && !self
                .store
                .compare_and_swap(
                    NS_PRUNE_RECEIPTS,
                    &receipt_key,
                    current.as_deref(),
                    plan.receipt.clone(),
                )
                .await
                .map_err(|error| AuditError::StorageError(error.to_string()))?
        {
            return Err(AuditError::StorageError(
                "audit prune receipt pointer changed during finalization".to_owned(),
            ));
        }
        self.store
            .delete(NS_PRUNE_PLANS, plan_key)
            .await
            .map_err(|error| AuditError::StorageError(error.to_string()))?;
        Ok(())
    }
}

fn count_field(value: &serde_json::Value, field: &str) -> u64 {
    value
        .get(field)
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0)
}
