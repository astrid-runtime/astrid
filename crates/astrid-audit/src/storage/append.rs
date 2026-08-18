use super::{
    AuditStorage, ChainMetadata, DEFAULT_SEGMENT_MAX_BYTES, DEFAULT_SEGMENT_MAX_ENTRIES,
    DURABLE_APPEND_LOCK, GlobalMetadata, KvAuditStorage, NS_APPEND_INTENTS, NS_CHAIN_HEADS,
    NS_CHAIN_METADATA, NS_COMMITTED_ENTRIES, NS_ENTRIES, NS_GLOBAL_METADATA, NS_SEGMENT_INDEX,
    NS_SESSION_ENTRIES, NS_SESSION_SEQUENCE, chain_head_key,
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

#[derive(serde::Deserialize, serde::Serialize)]
struct AppendIntent {
    entry: AuditEntry,
    head_key: String,
    session_sequence_key: String,
    expected_session_sequence: Option<Vec<u8>>,
    next_session_sequence: Vec<u8>,
    session_index_key: String,
    expected_head: Option<Vec<u8>>,
    expected_metadata: Option<Vec<u8>>,
    next_metadata: ChainMetadata,
    expected_global: Option<Vec<u8>>,
    next_global: GlobalMetadata,
    segment_key: Option<String>,
}

struct SessionSequenceWrite {
    sequence_key: String,
    expected: Option<Vec<u8>>,
    next_sequence: Vec<u8>,
    index_key: String,
}

const APPEND_INTENT_KEY: &str = "current";

impl KvAuditStorage {
    pub(super) async fn append_if_head_durable(
        &self,
        entry: &AuditEntry,
        expected: Option<&AuditEntryId>,
    ) -> AuditResult<bool> {
        let guard = DURABLE_APPEND_LOCK.lock().await;
        let result = self.append_if_head_durable_locked(entry, expected).await;
        drop(guard);
        result
    }

    async fn append_if_head_durable_locked(
        &self,
        entry: &AuditEntry,
        expected: Option<&AuditEntryId>,
    ) -> AuditResult<bool> {
        self.recover_append_intents().await?;
        let Some(prepared) = self.prepare_append(entry, expected).await? else {
            return Ok(false);
        };
        let entry_bytes = serialized_len(entry)?;
        let mut global = self.admit_append(entry_bytes).await?;
        let transition = advance_chain(entry, &prepared.prior, entry_bytes, &mut global.metadata);
        account_global_append(&mut global.metadata, &transition, entry_bytes);
        let segment_key =
            sealed_segment_key(&prepared.head_key, &transition.next, &global.metadata);
        let sequence = self
            .prepare_session_sequence(&entry.session_id, &entry.id)
            .await?;
        let intent = self
            .install_append_intent(
                entry,
                &prepared,
                &transition.next,
                &global,
                segment_key.as_deref(),
                &sequence,
            )
            .await?;

        self.commit_entry_and_head(&prepared, &intent).await?;
        self.persist_chain_transition(entry, &prepared, &transition.next)
            .await?;
        self.persist_sealed_segment(segment_key.as_deref(), &transition.next)
            .await?;
        self.persist_append_global(&global).await?;
        self.remove_append_intent().await?;
        Ok(true)
    }

    pub(super) async fn recover_append_intents(&self) -> AuditResult<()> {
        let bytes = self
            .store
            .get(NS_APPEND_INTENTS, APPEND_INTENT_KEY)
            .await
            .map_err(|error| AuditError::StorageError(error.to_string()))?;
        let Some(bytes) = bytes else {
            return Ok(());
        };
        let intent: AppendIntent = serde_json::from_slice(&bytes)
            .map_err(|error| AuditError::SerializationError(error.to_string()))?;
        self.commit_entry_projection(&intent).await?;

        self.store
            .set(
                NS_COMMITTED_ENTRIES,
                &intent.entry.id.0.to_string(),
                vec![1],
            )
            .await
            .map_err(|error| AuditError::StorageError(error.to_string()))?;
        let next_head = intent
            .next_metadata
            .head
            .as_ref()
            .map(|head| head.0.to_string().into_bytes())
            .ok_or_else(|| {
                AuditError::StorageError("audit append intent lacks a head".to_owned())
            })?;
        self.recover_cas(
            NS_CHAIN_HEADS,
            &intent.head_key,
            intent.expected_head.as_deref(),
            &next_head,
        )
        .await?;
        let next_metadata = serde_json::to_vec(&intent.next_metadata)
            .map_err(|error| AuditError::SerializationError(error.to_string()))?;
        self.recover_cas(
            NS_CHAIN_METADATA,
            &intent.head_key,
            intent.expected_metadata.as_deref(),
            &next_metadata,
        )
        .await?;
        self.persist_sealed_segment(intent.segment_key.as_deref(), &intent.next_metadata)
            .await?;
        let next_global = serde_json::to_vec(&intent.next_global)
            .map_err(|error| AuditError::SerializationError(error.to_string()))?;
        self.recover_cas(
            NS_GLOBAL_METADATA,
            "current",
            intent.expected_global.as_deref(),
            &next_global,
        )
        .await?;
        self.remove_append_intent().await?;
        Ok(())
    }

    async fn recover_cas(
        &self,
        namespace: &str,
        key: &str,
        expected: Option<&[u8]>,
        next: &[u8],
    ) -> AuditResult<()> {
        if self
            .store
            .compare_and_swap(namespace, key, expected, next.to_vec())
            .await
            .map_err(|error| AuditError::StorageError(error.to_string()))?
        {
            return Ok(());
        }
        let current = self
            .store
            .get(namespace, key)
            .await
            .map_err(|error| AuditError::StorageError(error.to_string()))?;
        if current.as_deref() == Some(next) {
            return Ok(());
        }
        Err(AuditError::StorageError(
            "durable audit append intent conflicts with canonical state".to_owned(),
        ))
    }

    async fn install_append_intent(
        &self,
        entry: &AuditEntry,
        prepared: &Preparation,
        next_metadata: &ChainMetadata,
        global: &GlobalState,
        segment_key: Option<&str>,
        sequence: &SessionSequenceWrite,
    ) -> AuditResult<AppendIntent> {
        let intent = AppendIntent {
            entry: entry.clone(),
            head_key: prepared.head_key.clone(),
            session_sequence_key: sequence.sequence_key.clone(),
            expected_session_sequence: sequence.expected.clone(),
            next_session_sequence: sequence.next_sequence.clone(),
            session_index_key: sequence.index_key.clone(),
            expected_head: prepared.expected_head_bytes.clone(),
            expected_metadata: prepared.metadata_bytes.clone(),
            next_metadata: next_metadata.clone(),
            expected_global: global.expected_bytes.clone(),
            next_global: global.metadata.clone(),
            segment_key: segment_key.map(str::to_owned),
        };
        let bytes = serde_json::to_vec(&intent)
            .map_err(|error| AuditError::SerializationError(error.to_string()))?;
        self.store
            .set(NS_APPEND_INTENTS, APPEND_INTENT_KEY, bytes)
            .await
            .map_err(|error| AuditError::StorageError(error.to_string()))?;
        Ok(intent)
    }

    async fn prepare_session_sequence(
        &self,
        session_id: &astrid_core::SessionId,
        id: &AuditEntryId,
    ) -> AuditResult<SessionSequenceWrite> {
        let sequence_key = session_id.0.to_string();
        let expected = self
            .store
            .get(NS_SESSION_SEQUENCE, &sequence_key)
            .await
            .map_err(|error| AuditError::StorageError(error.to_string()))?;
        let current = expected.as_deref().map_or(Ok(0), super::parse_sequence)?;
        let next = current.checked_add(1).ok_or_else(|| {
            AuditError::StorageError("audit session sequence exhausted".to_owned())
        })?;
        let index_key = format!("{sequence_key}:{next:020}:{}", id.0);
        Ok(SessionSequenceWrite {
            sequence_key,
            expected,
            next_sequence: next.to_be_bytes().to_vec(),
            index_key,
        })
    }

    async fn remove_append_intent(&self) -> AuditResult<()> {
        self.store
            .delete(NS_APPEND_INTENTS, APPEND_INTENT_KEY)
            .await
            .map_err(|error| AuditError::StorageError(error.to_string()))
            .map(|_| ())
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
        prepared: &Preparation,
        intent: &AppendIntent,
    ) -> AuditResult<()> {
        self.commit_entry_projection(intent).await?;
        let committed = self
            .store
            .compare_and_swap(
                NS_CHAIN_HEADS,
                &prepared.head_key,
                prepared.expected_head_bytes.as_deref(),
                intent.entry.id.0.to_string().into_bytes(),
            )
            .await
            .map_err(|error| AuditError::StorageError(error.to_string()))?;
        if !committed {
            return Err(AuditError::StorageError(
                "audit chain head CAS lost after entry commit".to_owned(),
            ));
        }
        self.store
            .set(
                NS_COMMITTED_ENTRIES,
                &intent.entry.id.0.to_string(),
                vec![1],
            )
            .await
            .map_err(|error| AuditError::StorageError(error.to_string()))
    }

    async fn commit_entry_projection(&self, intent: &AppendIntent) -> AuditResult<()> {
        let entry_data = serde_json::to_vec(&intent.entry)
            .map_err(|error| AuditError::SerializationError(error.to_string()))?;
        self.store
            .set(NS_ENTRIES, &intent.entry.id.0.to_string(), entry_data)
            .await
            .map_err(|error| AuditError::StorageError(error.to_string()))?;

        let sequence_swapped = self
            .store
            .compare_and_swap(
                NS_SESSION_SEQUENCE,
                &intent.session_sequence_key,
                intent.expected_session_sequence.as_deref(),
                intent.next_session_sequence.clone(),
            )
            .await
            .map_err(|error| AuditError::StorageError(error.to_string()))?;
        if sequence_swapped {
            return self.write_session_index(intent).await;
        }
        let current = self
            .store
            .get(NS_SESSION_SEQUENCE, &intent.session_sequence_key)
            .await
            .map_err(|error| AuditError::StorageError(error.to_string()))?;
        if current.as_deref() == Some(intent.next_session_sequence.as_slice()) {
            return self.write_session_index(intent).await;
        }
        Err(AuditError::StorageError(
            "audit append intent conflicts with session sequence".to_owned(),
        ))
    }

    async fn write_session_index(&self, intent: &AppendIntent) -> AuditResult<()> {
        self.store
            .set(NS_SESSION_ENTRIES, &intent.session_index_key, vec![1])
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
        segment_key: Option<&str>,
        next: &ChainMetadata,
    ) -> AuditResult<()> {
        let Some(segment_key) = segment_key else {
            return Ok(());
        };
        let segment_bytes = serde_json::to_vec(next)
            .map_err(|error| AuditError::SerializationError(error.to_string()))?;
        self.store
            .set(NS_SEGMENT_INDEX, segment_key, segment_bytes)
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

fn sealed_segment_key(
    head_key: &str,
    next: &ChainMetadata,
    global: &GlobalMetadata,
) -> Option<String> {
    next.sealed.then(|| {
        format!(
            "{:020}:{head_key}:{:020}",
            global.next_seal_ordinal, next.segment
        )
    })
}
