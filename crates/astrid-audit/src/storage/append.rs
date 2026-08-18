use super::{
    AuditStorage, ChainMetadata, DEFAULT_SEGMENT_MAX_BYTES, DEFAULT_SEGMENT_MAX_ENTRIES,
    DURABLE_APPEND_LOCK, GlobalMetadata, KvAuditStorage, NS_CHAIN_HEADS, NS_COMMITTED_ENTRIES,
    NS_SEGMENT_INDEX, chain_head_key,
};
use crate::entry::AuditEntry;
use crate::error::{AuditError, AuditResult};
use astrid_capabilities::AuditEntryId;

struct Preparation {
    head_key: String,
    expected_head_bytes: Option<Vec<u8>>,
    metadata_bytes: Option<Vec<u8>>,
    prior: ChainMetadata,
}

struct GlobalState {
    expected_bytes: Option<Vec<u8>>,
    metadata: GlobalMetadata,
}

struct ChainTransition {
    prior_count_zero: bool,
    prior_sealed: bool,
    next: ChainMetadata,
}

impl KvAuditStorage {
    pub(super) async fn append_if_head_durable(
        &self,
        entry: &AuditEntry,
        expected: Option<&AuditEntryId>,
    ) -> AuditResult<bool> {
        let _guard = DURABLE_APPEND_LOCK.lock().await;
        let Some(prepared) = self.prepare_append(entry, expected).await? else {
            return Ok(false);
        };
        let entry_bytes = serialized_len(entry)?;
        let mut global = self.admit_append(entry_bytes).await?;

        self.commit_entry_and_head(entry, &prepared).await?;
        let transition = advance_chain(entry, &prepared.prior, entry_bytes, &mut global.metadata);
        self.persist_chain_transition(entry, &prepared, &transition.next)
            .await?;
        self.persist_sealed_segment(&prepared.head_key, &transition.next, &global.metadata)
            .await?;
        account_global_append(&mut global.metadata, &transition, entry_bytes);
        self.persist_append_global(&global).await?;
        Ok(true)
    }

    async fn prepare_append(
        &self,
        entry: &AuditEntry,
        expected: Option<&AuditEntryId>,
    ) -> AuditResult<Option<Preparation>> {
        let current = self
            .get_chain_head(&entry.session_id, entry.principal.as_ref())
            .await?;
        if current.as_ref() != expected {
            return Ok(None);
        }
        let head_key = chain_head_key(&entry.session_id, entry.principal.as_ref());
        let stored_head = self
            .store
            .get(NS_CHAIN_HEADS, &head_key)
            .await
            .map_err(|error| AuditError::StorageError(error.to_string()))?;
        let (metadata_bytes, metadata) = self
            .load_chain_metadata(&entry.session_id, entry.principal.as_ref())
            .await?;
        if metadata
            .as_ref()
            .and_then(|value| value.head.as_ref())
            .is_some_and(|head| Some(head) != expected)
        {
            return Ok(None);
        }
        let expected_head_bytes = expected.map(|id| id.0.to_string().into_bytes());
        if !self
            .reconcile_stored_head(
                &head_key,
                stored_head.as_deref(),
                expected_head_bytes.as_deref(),
            )
            .await?
        {
            return Ok(None);
        }
        Ok(Some(Preparation {
            head_key,
            expected_head_bytes,
            metadata_bytes,
            prior: metadata.unwrap_or_default(),
        }))
    }

    async fn reconcile_stored_head(
        &self,
        head_key: &str,
        stored: Option<&[u8]>,
        expected: Option<&[u8]>,
    ) -> AuditResult<bool> {
        if stored == expected {
            return Ok(true);
        }
        let Some(expected) = expected else {
            return Ok(false);
        };
        self.store
            .compare_and_swap(NS_CHAIN_HEADS, head_key, stored, expected.to_vec())
            .await
            .map_err(|error| AuditError::StorageError(error.to_string()))
    }

    async fn admit_append(&self, entry_bytes: u64) -> AuditResult<GlobalState> {
        let (expected_bytes, mut metadata) = self.load_global_metadata().await?;
        if metadata.total_count >= metadata.cap_entries
            || metadata.total_bytes.saturating_add(entry_bytes) > metadata.cap_bytes
        {
            metadata.degraded = true;
            metadata.last_error =
                Some("system audit retention cap reached; prune sealed segments".to_owned());
            let _ = self
                .persist_global_metadata(expected_bytes.as_deref(), &metadata)
                .await?;
            return Err(AuditError::RetentionCapReached);
        }
        Ok(GlobalState {
            expected_bytes,
            metadata,
        })
    }

    async fn commit_entry_and_head(
        &self,
        entry: &AuditEntry,
        prepared: &Preparation,
    ) -> AuditResult<()> {
        self.store(entry).await?;
        let committed = self
            .store
            .compare_and_swap(
                NS_CHAIN_HEADS,
                &prepared.head_key,
                prepared.expected_head_bytes.as_deref(),
                entry.id.0.to_string().into_bytes(),
            )
            .await
            .map_err(|error| AuditError::StorageError(error.to_string()))?;
        if !committed {
            return Err(AuditError::StorageError(
                "audit chain head CAS lost after entry commit".to_owned(),
            ));
        }
        self.store
            .set(NS_COMMITTED_ENTRIES, &entry.id.0.to_string(), vec![1])
            .await
            .map_err(|error| AuditError::StorageError(error.to_string()))
    }

    async fn persist_chain_transition(
        &self,
        entry: &AuditEntry,
        prepared: &Preparation,
        next: &ChainMetadata,
    ) -> AuditResult<()> {
        if self
            .persist_chain_metadata(
                &entry.session_id,
                entry.principal.as_ref(),
                prepared.metadata_bytes.as_deref(),
                next,
            )
            .await?
        {
            return Ok(());
        }
        Err(AuditError::StorageError(
            "audit chain metadata CAS lost after head commit".to_owned(),
        ))
    }

    async fn persist_sealed_segment(
        &self,
        head_key: &str,
        next: &ChainMetadata,
        global: &GlobalMetadata,
    ) -> AuditResult<()> {
        if !next.sealed {
            return Ok(());
        }
        let segment_key = format!(
            "{:020}:{head_key}:{:020}",
            global.next_seal_ordinal, next.segment
        );
        let segment_bytes = serde_json::to_vec(next)
            .map_err(|error| AuditError::SerializationError(error.to_string()))?;
        self.store
            .set(NS_SEGMENT_INDEX, &segment_key, segment_bytes)
            .await
            .map_err(|error| AuditError::StorageError(error.to_string()))
    }

    async fn persist_append_global(&self, global: &GlobalState) -> AuditResult<()> {
        if self
            .persist_global_metadata(global.expected_bytes.as_deref(), &global.metadata)
            .await?
        {
            return Ok(());
        }
        Err(AuditError::StorageError(
            "audit global metadata CAS lost after append".to_owned(),
        ))
    }
}

fn serialized_len(entry: &AuditEntry) -> AuditResult<u64> {
    let bytes = serde_json::to_vec(entry)
        .map_err(|error| AuditError::SerializationError(error.to_string()))?;
    Ok(u64::try_from(bytes.len()).unwrap_or(u64::MAX))
}

fn advance_chain(
    entry: &AuditEntry,
    prior: &ChainMetadata,
    entry_bytes: u64,
    global: &mut GlobalMetadata,
) -> ChainTransition {
    let prior_segment_count = if prior.segment_count == 0 && prior.count > 0 {
        prior.count
    } else {
        prior.segment_count
    };
    let prior_segment_bytes = if prior.segment_bytes == 0 && prior.bytes > 0 {
        prior.bytes
    } else {
        prior.segment_bytes
    };
    let starts_new_segment = prior.sealed;
    let segment_count = if starts_new_segment {
        1
    } else {
        prior_segment_count.saturating_add(1)
    };
    let segment_bytes = if starts_new_segment {
        entry_bytes
    } else {
        prior_segment_bytes.saturating_add(entry_bytes)
    };
    let sealed =
        segment_count >= DEFAULT_SEGMENT_MAX_ENTRIES || segment_bytes >= DEFAULT_SEGMENT_MAX_BYTES;
    if sealed {
        global.next_seal_ordinal = global.next_seal_ordinal.saturating_add(1);
    }
    ChainTransition {
        prior_count_zero: prior.count == 0,
        prior_sealed: prior.sealed,
        next: ChainMetadata {
            schema: 1,
            segment: if starts_new_segment {
                prior.segment.saturating_add(1)
            } else {
                prior.segment
            },
            sealed,
            count: prior.count.saturating_add(1),
            bytes: prior.bytes.saturating_add(entry_bytes),
            head: Some(entry.id.clone()),
            head_hash: entry.content_hash(),
            segment_count,
            segment_bytes,
            segment_first: if starts_new_segment {
                Some(entry.id.clone())
            } else {
                prior
                    .segment_first
                    .clone()
                    .or_else(|| Some(entry.id.clone()))
            },
            seal_ordinal: if sealed {
                Some(global.next_seal_ordinal)
            } else if starts_new_segment {
                None
            } else {
                prior.seal_ordinal
            },
        },
    }
}

fn account_global_append(
    global: &mut GlobalMetadata,
    transition: &ChainTransition,
    entry_bytes: u64,
) {
    global.total_count = global.total_count.saturating_add(1);
    global.total_bytes = global.total_bytes.saturating_add(entry_bytes);
    if transition.prior_count_zero || transition.prior_sealed {
        global.segments = global.segments.saturating_add(1);
    }
    if transition.next.sealed && !transition.prior_sealed {
        global.sealed_segments = global.sealed_segments.saturating_add(1);
        global.eligible_segments = global.eligible_segments.saturating_add(1);
    }
    global.degraded =
        global.total_count > global.cap_entries || global.total_bytes > global.cap_bytes;
    if !global.degraded {
        global.last_error = None;
    }
}
