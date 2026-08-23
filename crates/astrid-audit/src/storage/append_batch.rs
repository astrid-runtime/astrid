use super::key_types::SessionSequence;
use super::{
    AuditStorage, ChainMetadata, DEFAULT_SEGMENT_MAX_BYTES, DEFAULT_SEGMENT_MAX_ENTRIES,
    DURABLE_APPEND_LOCK, GlobalMetadata, KvAuditStorage, NS_CHAIN_HEADS, NS_CHAIN_METADATA,
    NS_COMMITTED_ENTRIES, NS_ENTRIES, NS_GLOBAL_METADATA, NS_SEGMENT_INDEX, NS_SESSION_ENTRIES,
    NS_SESSION_SEQUENCE, chain_head_key, parse_sequence,
};
use crate::entry::AuditEntry;
use crate::error::{AuditError, AuditResult};
use astrid_capabilities::AuditEntryId;
use astrid_storage::{KvBatchCondition, KvBatchMutation, KvEntryKey, KvMutationBatch};
use std::collections::{HashMap, HashSet};

const MAX_ATOMIC_BATCH_ENTRIES: usize = 128;

type StoredValue = (String, Vec<u8>);

struct ChainState {
    /// Raw `audit:chain_heads` bytes currently stored, or `None` if absent.
    /// Conditions must match these bytes, not a re-serialized UUID, or a
    /// MOVE leftover encoding never commits and retries until CAS exhausts.
    head_expected: Option<Vec<u8>>,
    metadata_expected: Option<Vec<u8>>,
    metadata: ChainMetadata,
    segment_index: Vec<StoredValue>,
}

struct SequenceState {
    expected: Option<Vec<u8>>,
    next: SessionSequence,
}

struct PreparedBatch {
    chains: HashMap<String, ChainState>,
    sequences: HashMap<String, SequenceState>,
    entries: Vec<StoredValue>,
    session_indexes: Vec<StoredValue>,
    committed_entries: Vec<StoredValue>,
    global_expected: Option<Vec<u8>>,
    global: GlobalMetadata,
}

impl PreparedBatch {
    fn new(global_expected: Option<Vec<u8>>, global: GlobalMetadata, capacity: usize) -> Self {
        Self {
            chains: HashMap::new(),
            sequences: HashMap::new(),
            entries: Vec::with_capacity(capacity),
            session_indexes: Vec::with_capacity(capacity),
            committed_entries: Vec::with_capacity(capacity),
            global_expected,
            global,
        }
    }

    fn into_mutation_batch(self) -> AuditResult<KvMutationBatch> {
        let Self {
            chains,
            sequences,
            entries,
            session_indexes,
            committed_entries,
            global_expected,
            global,
        } = self;
        let mut conditions = Vec::new();
        let mut mutations = Vec::new();
        append_chain_changes(&mut conditions, &mut mutations, chains)?;
        append_sequence_changes(&mut conditions, &mut mutations, sequences)?;
        append_stored_values(&mut mutations, NS_ENTRIES, entries)?;
        append_stored_values(&mut mutations, NS_SESSION_ENTRIES, session_indexes)?;
        append_stored_values(&mut mutations, NS_COMMITTED_ENTRIES, committed_entries)?;
        append_global_change(&mut conditions, &mut mutations, global_expected, &global)?;
        KvMutationBatch::new(conditions, mutations)
            .map_err(|error| AuditError::StorageError(error.to_string()))
    }
}

impl KvAuditStorage {
    pub(super) async fn append_batch_if_heads_durable(
        &self,
        entries: &[(&AuditEntry, Option<&AuditEntryId>)],
    ) -> AuditResult<Vec<bool>> {
        if entries.is_empty() {
            return Ok(Vec::new());
        }
        // Keep one root commit comfortably below the backend's 1,024-operation
        // limit. Larger caller batches still use the per-entry CAS fallback.
        if entries.len() > MAX_ATOMIC_BATCH_ENTRIES {
            let guard = DURABLE_APPEND_LOCK.lock().await;
            self.recover_append_intents().await?;
            drop(guard);
            return self.append_batch_with_cas(entries).await;
        }
        if !self.store.supports_atomic_batch() {
            let guard = DURABLE_APPEND_LOCK.lock().await;
            self.recover_append_intents().await?;
            drop(guard);
            return self.append_batch_with_cas(entries).await;
        }
        let _guard = DURABLE_APPEND_LOCK.lock().await;
        self.recover_append_intents().await?;
        let Some(prepared) = self.prepare_batch(entries).await? else {
            return Ok(vec![false; entries.len()]);
        };
        let batch = prepared.into_mutation_batch()?;
        let outcome = self
            .store
            .apply_batch(&batch)
            .await
            .map_err(|error| AuditError::StorageError(error.to_string()))?;
        Ok(vec![outcome.applied; entries.len()])
    }

    async fn append_batch_with_cas(
        &self,
        entries: &[(&AuditEntry, Option<&AuditEntryId>)],
    ) -> AuditResult<Vec<bool>> {
        let mut results = Vec::with_capacity(entries.len());
        for (entry, expected) in entries {
            results.push(self.append_if_head_durable(entry, *expected).await?);
        }
        Ok(results)
    }

    async fn prepare_batch(
        &self,
        entries: &[(&AuditEntry, Option<&AuditEntryId>)],
    ) -> AuditResult<Option<PreparedBatch>> {
        let (global_expected, global) = self.load_global_metadata().await?;
        let mut prepared = PreparedBatch::new(global_expected, global, entries.len());
        let mut seen_entries = HashSet::with_capacity(entries.len());
        for (entry, expected) in entries {
            validate_unique_entry(&mut seen_entries, entry)?;
            let chain_key = chain_head_key(&entry.session_id, entry.principal.as_ref());
            if !self
                .ensure_chain_state(&mut prepared, &chain_key, entry, *expected)
                .await?
            {
                return Ok(None);
            }
            if !self
                .accumulate_entry(&mut prepared, &chain_key, entry)
                .await?
            {
                return Ok(None);
            }
        }
        if prepared.global.total_count > prepared.global.cap_entries
            || prepared.global.total_bytes > prepared.global.cap_bytes
        {
            return Err(AuditError::RetentionCapReached);
        }
        Ok(Some(prepared))
    }

    async fn ensure_chain_state(
        &self,
        prepared: &mut PreparedBatch,
        chain_key: &str,
        entry: &AuditEntry,
        expected: Option<&AuditEntryId>,
    ) -> AuditResult<bool> {
        if let Some(state) = prepared.chains.get(chain_key) {
            return Ok(state
                .metadata
                .head
                .as_ref()
                .is_some_and(|head| expected == Some(head)));
        }
        let stored_head_bytes = self
            .store
            .get(NS_CHAIN_HEADS, chain_key)
            .await
            .map_err(|error| AuditError::StorageError(error.to_string()))?;
        let stored_head = parse_stored_head(stored_head_bytes.as_deref())?;
        let (metadata_expected, metadata) = self
            .load_chain_metadata(&entry.session_id, entry.principal.as_ref())
            .await?;
        let Some(metadata) = self
            .parent_metadata_for_append(metadata, expected, stored_head.as_ref())
            .await?
        else {
            return Ok(false);
        };
        prepared.chains.insert(
            chain_key.to_owned(),
            ChainState {
                head_expected: stored_head_bytes,
                metadata_expected,
                metadata,
                segment_index: Vec::new(),
            },
        );
        Ok(true)
    }

    /// Align chain metadata with the parent `append_batch_if_heads` signed.
    ///
    /// `get_chain_head` prefers `metadata.head`. A missing heads key is
    /// created in this batch. A stored heads value that disagrees in ID or
    /// encoding is overwritten in the same commit using the raw stored
    /// bytes as the CAS expected value. Missing metadata with a live stored
    /// head is reconstructed from that parent entry so retries do not mill.
    async fn parent_metadata_for_append(
        &self,
        metadata: Option<ChainMetadata>,
        expected: Option<&AuditEntryId>,
        stored_head: Option<&AuditEntryId>,
    ) -> AuditResult<Option<ChainMetadata>> {
        let mut metadata = metadata.unwrap_or_default();
        if metadata.head.as_ref() != expected {
            return self
                .metadata_from_stored_parent(metadata, expected, stored_head)
                .await;
        }
        if let Some(head) = expected
            && let Some(parent) = self.get(head).await?
            && metadata.head_hash != parent.content_hash()
        {
            metadata.head_hash = parent.content_hash();
        }
        Ok(Some(metadata))
    }

    async fn metadata_from_stored_parent(
        &self,
        mut metadata: ChainMetadata,
        expected: Option<&AuditEntryId>,
        stored_head: Option<&AuditEntryId>,
    ) -> AuditResult<Option<ChainMetadata>> {
        if metadata.head.is_some() || stored_head != expected {
            return Ok(None);
        }
        let Some(head) = expected else {
            return Ok(Some(metadata));
        };
        let Some(parent) = self.get(head).await? else {
            return Ok(None);
        };
        metadata.head = Some(head.clone());
        metadata.head_hash = parent.content_hash();
        if metadata.count == 0 {
            metadata.count = 1;
            metadata.bytes = entry_byte_len(&parent)?;
        }
        Ok(Some(metadata))
    }

    async fn accumulate_entry(
        &self,
        prepared: &mut PreparedBatch,
        chain_key: &str,
        entry: &AuditEntry,
    ) -> AuditResult<bool> {
        let entry_data = serde_json::to_vec(entry)
            .map_err(|error| AuditError::SerializationError(error.to_string()))?;
        let entry_bytes = u64::try_from(entry_data.len()).unwrap_or(u64::MAX);
        prepared.entries.push((entry.id.0.to_string(), entry_data));
        let session_key = entry.session_id.0.to_string();
        let sequence = self
            .allocate_session_sequence(&mut prepared.sequences, &session_key)
            .await?;
        prepared.session_indexes.push((
            format!("{session_key}:{:020}:{}", sequence.value(), entry.id.0),
            vec![1],
        ));
        prepared
            .committed_entries
            .push((entry.id.0.to_string(), vec![1]));
        let state = prepared.chains.get_mut(chain_key).ok_or_else(|| {
            AuditError::StorageError("audit batch chain state disappeared".to_owned())
        })?;
        advance_chain(state, &mut prepared.global, entry, entry_bytes)
    }

    async fn allocate_session_sequence(
        &self,
        sequences: &mut HashMap<String, SequenceState>,
        session_key: &str,
    ) -> AuditResult<SessionSequence> {
        if let Some(state) = sequences.get_mut(session_key) {
            let sequence = state.next;
            state.next = sequence.checked_next().map_err(|error| {
                AuditError::StorageError(format!("{error} for session index key {session_key}"))
            })?;
            return Ok(sequence);
        }
        let expected = self
            .store
            .get(NS_SESSION_SEQUENCE, session_key)
            .await
            .map_err(|error| AuditError::StorageError(error.to_string()))?;
        let sequence = expected
            .as_deref()
            .map(parse_sequence)
            .transpose()?
            .unwrap_or(SessionSequence::ZERO);
        let next = sequence.checked_next().map_err(|error| {
            AuditError::StorageError(format!("{error} for session index key {session_key}"))
        })?;
        sequences.insert(session_key.to_owned(), SequenceState { expected, next });
        Ok(sequence)
    }

    #[cfg(test)]
    async fn test_zero_chain_head_hash(
        &self,
        session_id: &astrid_core::SessionId,
        principal: Option<&astrid_core::PrincipalId>,
    ) -> AuditResult<()> {
        let key = chain_head_key(session_id, principal);
        let (_, metadata) = self.load_chain_metadata(session_id, principal).await?;
        let mut metadata = metadata.ok_or_else(|| {
            AuditError::StorageError("missing chain metadata to zero head_hash".to_owned())
        })?;
        metadata.head_hash = astrid_crypto::ContentHash::zero();
        let bytes = serde_json::to_vec(&metadata)
            .map_err(|error| AuditError::SerializationError(error.to_string()))?;
        self.store
            .set(NS_CHAIN_METADATA, &key, bytes)
            .await
            .map_err(|error| AuditError::StorageError(error.to_string()))
    }
}

fn validate_unique_entry(seen: &mut HashSet<uuid::Uuid>, entry: &AuditEntry) -> AuditResult<()> {
    if !seen.insert(entry.id.0) {
        return Err(AuditError::StorageError(
            "audit batch contains duplicate entry IDs".to_owned(),
        ));
    }
    Ok(())
}

fn parse_stored_head(bytes: Option<&[u8]>) -> AuditResult<Option<AuditEntryId>> {
    bytes
        .map(std::str::from_utf8)
        .transpose()
        .map_err(|error| AuditError::StorageError(error.to_string()))?
        .map(uuid::Uuid::parse_str)
        .transpose()
        .map_err(|error| AuditError::StorageError(error.to_string()))
        .map(|head| head.map(AuditEntryId))
}

fn advance_chain(
    state: &mut ChainState,
    global: &mut GlobalMetadata,
    entry: &AuditEntry,
    entry_bytes: u64,
) -> AuditResult<bool> {
    let prior = state.metadata.clone();
    let expected_previous = if prior.count == 0 {
        astrid_crypto::ContentHash::zero()
    } else {
        prior.head_hash
    };
    if entry.previous_hash != expected_previous {
        return Ok(false);
    }
    let next = next_chain_metadata(&prior, global, entry, entry_bytes);
    if next.sealed {
        let key = format!(
            "{:020}:{}:{:020}",
            global.next_seal_ordinal,
            chain_head_key(&entry.session_id, entry.principal.as_ref()),
            next.segment
        );
        let value = serde_json::to_vec(&next)
            .map_err(|error| AuditError::SerializationError(error.to_string()))?;
        state.segment_index.push((key, value));
    }
    update_global_metadata(global, &prior, &next, entry_bytes);
    state.metadata = next;
    Ok(true)
}

fn next_chain_metadata(
    prior: &ChainMetadata,
    global: &mut GlobalMetadata,
    entry: &AuditEntry,
    entry_bytes: u64,
) -> ChainMetadata {
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
    ChainMetadata {
        schema: 1,
        segment: prior.segment.saturating_add(u64::from(starts_new_segment)),
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
    }
}

fn update_global_metadata(
    global: &mut GlobalMetadata,
    prior: &ChainMetadata,
    next: &ChainMetadata,
    entry_bytes: u64,
) {
    global.total_count = global.total_count.saturating_add(1);
    global.total_bytes = global.total_bytes.saturating_add(entry_bytes);
    if prior.count == 0 || prior.sealed {
        global.segments = global.segments.saturating_add(1);
    }
    if next.sealed {
        global.sealed_segments = global.sealed_segments.saturating_add(1);
        global.eligible_segments = global.eligible_segments.saturating_add(1);
    }
}

fn append_chain_changes(
    conditions: &mut Vec<KvBatchCondition>,
    mutations: &mut Vec<KvBatchMutation>,
    chains: HashMap<String, ChainState>,
) -> AuditResult<()> {
    for (chain_key, state) in chains {
        conditions.push(KvBatchCondition::ValueEquals {
            key: kv_key(NS_CHAIN_HEADS, &chain_key)?,
            expected: state.head_expected,
        });
        conditions.push(KvBatchCondition::ValueEquals {
            key: kv_key(NS_CHAIN_METADATA, &chain_key)?,
            expected: state.metadata_expected,
        });
        let metadata = serde_json::to_vec(&state.metadata)
            .map_err(|error| AuditError::SerializationError(error.to_string()))?;
        let head =
            state.metadata.head.as_ref().ok_or_else(|| {
                AuditError::StorageError("audit batch has no chain head".to_owned())
            })?;
        mutations.push(KvBatchMutation::Set {
            key: kv_key(NS_CHAIN_HEADS, &chain_key)?,
            value: head.0.to_string().into_bytes(),
        });
        mutations.push(KvBatchMutation::Set {
            key: kv_key(NS_CHAIN_METADATA, &chain_key)?,
            value: metadata,
        });
        append_stored_values(mutations, NS_SEGMENT_INDEX, state.segment_index)?;
    }
    Ok(())
}

fn append_sequence_changes(
    conditions: &mut Vec<KvBatchCondition>,
    mutations: &mut Vec<KvBatchMutation>,
    sequences: HashMap<String, SequenceState>,
) -> AuditResult<()> {
    for (session_key, sequence) in sequences {
        conditions.push(KvBatchCondition::ValueEquals {
            key: kv_key(NS_SESSION_SEQUENCE, &session_key)?,
            expected: sequence.expected,
        });
        mutations.push(KvBatchMutation::Set {
            key: kv_key(NS_SESSION_SEQUENCE, &session_key)?,
            value: sequence.next.bytes().to_vec(),
        });
    }
    Ok(())
}

fn append_stored_values(
    mutations: &mut Vec<KvBatchMutation>,
    namespace: &str,
    values: Vec<StoredValue>,
) -> AuditResult<()> {
    for (key, value) in values {
        mutations.push(KvBatchMutation::Set {
            key: kv_key(namespace, &key)?,
            value,
        });
    }
    Ok(())
}

fn append_global_change(
    conditions: &mut Vec<KvBatchCondition>,
    mutations: &mut Vec<KvBatchMutation>,
    expected: Option<Vec<u8>>,
    global: &GlobalMetadata,
) -> AuditResult<()> {
    conditions.push(KvBatchCondition::ValueEquals {
        key: kv_key(NS_GLOBAL_METADATA, "current")?,
        expected,
    });
    let value = serde_json::to_vec(global)
        .map_err(|error| AuditError::SerializationError(error.to_string()))?;
    mutations.push(KvBatchMutation::Set {
        key: kv_key(NS_GLOBAL_METADATA, "current")?,
        value,
    });
    Ok(())
}

fn kv_key(namespace: &str, value: &str) -> AuditResult<KvEntryKey> {
    KvEntryKey::new(namespace, value).map_err(|error| AuditError::StorageError(error.to_string()))
}

fn entry_byte_len(entry: &AuditEntry) -> AuditResult<u64> {
    let bytes = serde_json::to_vec(entry)
        .map_err(|error| AuditError::SerializationError(error.to_string()))?;
    Ok(u64::try_from(bytes.len()).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use super::super::{AuditStorage, KvAuditStorage};
    use crate::entry::{AuditAction, AuditEntry, AuditOutcome, AuthorizationProof};
    use astrid_core::{PrincipalId, SessionId};
    use astrid_crypto::{ContentHash, KeyPair};

    #[tokio::test]
    async fn append_heals_missing_chain_heads_after_metadata_move() {
        let storage = KvAuditStorage::in_memory();
        let keypair = KeyPair::generate();
        let session = SessionId::new();
        let principal = PrincipalId::new("alice").expect("principal");
        let first = AuditEntry::create_with_principal(
            session.clone(),
            principal.clone(),
            AuditAction::FileRead {
                path: "/a".to_owned(),
            },
            AuthorizationProof::System {
                reason: "test".to_owned(),
            },
            AuditOutcome::success(),
            ContentHash::zero(),
            &keypair,
        );
        let committed = storage
            .append_batch_if_heads(&[(&first, None)])
            .await
            .expect("first append");
        assert_eq!(committed, vec![true]);

        storage
            .test_drop_chain_head(&session, Some(&principal))
            .await
            .expect("drop heads key");
        assert!(
            storage
                .get_chain_head(&session, Some(&principal))
                .await
                .expect("head via metadata")
                .is_some(),
            "metadata still names the parent"
        );

        let second = AuditEntry::create_with_principal(
            session.clone(),
            principal.clone(),
            AuditAction::FileRead {
                path: "/b".to_owned(),
            },
            AuthorizationProof::System {
                reason: "test".to_owned(),
            },
            AuditOutcome::success(),
            first.content_hash(),
            &keypair,
        );
        let committed = storage
            .append_batch_if_heads(&[(&second, Some(&first.id))])
            .await
            .expect("healed append");
        assert_eq!(
            committed,
            vec![true],
            "missing heads key must not fail closed as a CAS miss"
        );
        assert_eq!(
            storage
                .get_chain_head(&session, Some(&principal))
                .await
                .expect("restored head"),
            Some(second.id)
        );
    }

    fn sample_entry(
        session: &SessionId,
        principal: &PrincipalId,
        path: &str,
        previous: ContentHash,
        keypair: &KeyPair,
    ) -> AuditEntry {
        AuditEntry::create_with_principal(
            session.clone(),
            principal.clone(),
            AuditAction::FileRead {
                path: path.to_owned(),
            },
            AuthorizationProof::System {
                reason: "test".to_owned(),
            },
            AuditOutcome::success(),
            previous,
            keypair,
        )
    }

    #[tokio::test]
    async fn append_heals_noncanonical_chain_heads_bytes() {
        let storage = KvAuditStorage::in_memory();
        let keypair = KeyPair::generate();
        let session = SessionId::new();
        let principal = PrincipalId::new("alice").expect("principal");
        let first = sample_entry(&session, &principal, "/a", ContentHash::zero(), &keypair);
        assert_eq!(
            storage
                .append_batch_if_heads(&[(&first, None)])
                .await
                .expect("first append"),
            vec![true]
        );

        storage
            .test_set_chain_head(
                &session,
                Some(&principal),
                first.id.0.to_string().to_ascii_uppercase().into_bytes(),
            )
            .await
            .expect("overwrite heads encoding");

        let second = sample_entry(&session, &principal, "/b", first.content_hash(), &keypair);
        let committed = storage
            .append_batch_if_heads(&[(&second, Some(&first.id))])
            .await
            .expect("healed encoding");
        assert_eq!(
            committed,
            vec![true],
            "canonical UUID CAS expected must not miss leftover heads bytes"
        );
        assert_eq!(
            storage
                .get_chain_head(&session, Some(&principal))
                .await
                .expect("restored head"),
            Some(second.id)
        );
    }

    #[tokio::test]
    async fn append_heals_stale_chain_heads_id_when_metadata_matches() {
        let storage = KvAuditStorage::in_memory();
        let keypair = KeyPair::generate();
        let session = SessionId::new();
        let principal = PrincipalId::new("alice").expect("principal");
        let first = sample_entry(&session, &principal, "/a", ContentHash::zero(), &keypair);
        assert_eq!(
            storage
                .append_batch_if_heads(&[(&first, None)])
                .await
                .expect("first append"),
            vec![true]
        );

        storage
            .test_set_chain_head(
                &session,
                Some(&principal),
                uuid::Uuid::new_v4().to_string().into_bytes(),
            )
            .await
            .expect("stale heads id");

        let second = sample_entry(&session, &principal, "/b", first.content_hash(), &keypair);
        let committed = storage
            .append_batch_if_heads(&[(&second, Some(&first.id))])
            .await
            .expect("healed stale id");
        assert_eq!(
            committed,
            vec![true],
            "metadata-matching parent must overwrite a leftover heads id"
        );
        assert_eq!(
            storage
                .get_chain_head(&session, Some(&principal))
                .await
                .expect("restored head"),
            Some(second.id)
        );
    }

    #[tokio::test]
    async fn append_heals_missing_metadata_from_stored_head() {
        let storage = KvAuditStorage::in_memory();
        let keypair = KeyPair::generate();
        let session = SessionId::new();
        let principal = PrincipalId::new("alice").expect("principal");
        let first = sample_entry(&session, &principal, "/a", ContentHash::zero(), &keypair);
        assert_eq!(
            storage
                .append_batch_if_heads(&[(&first, None)])
                .await
                .expect("first append"),
            vec![true]
        );

        storage
            .test_drop_chain_metadata(&session, Some(&principal))
            .await
            .expect("drop metadata");

        let second = sample_entry(&session, &principal, "/b", first.content_hash(), &keypair);
        let committed = storage
            .append_batch_if_heads(&[(&second, Some(&first.id))])
            .await
            .expect("healed metadata");
        assert_eq!(
            committed,
            vec![true],
            "stored head must reconstruct missing chain metadata"
        );
        assert_eq!(
            storage
                .get_chain_head(&session, Some(&principal))
                .await
                .expect("restored head"),
            Some(second.id)
        );
    }

    #[tokio::test]
    async fn append_heals_zeroed_metadata_head_hash() {
        let storage = KvAuditStorage::in_memory();
        let keypair = KeyPair::generate();
        let session = SessionId::new();
        let principal = PrincipalId::new("alice").expect("principal");
        let first = sample_entry(&session, &principal, "/a", ContentHash::zero(), &keypair);
        assert_eq!(
            storage
                .append_batch_if_heads(&[(&first, None)])
                .await
                .expect("first append"),
            vec![true]
        );

        storage
            .test_zero_chain_head_hash(&session, Some(&principal))
            .await
            .expect("zero stored head_hash");
        let metadata = storage
            .chain_metadata(&session, Some(&principal))
            .await
            .expect("load zeroed metadata");
        assert_eq!(
            metadata.expect("chain metadata").head_hash,
            ContentHash::zero(),
            "falsifier requires a committed parent with a zeroed head_hash"
        );

        let second = sample_entry(&session, &principal, "/b", first.content_hash(), &keypair);
        let committed = storage
            .append_batch_if_heads(&[(&second, Some(&first.id))])
            .await
            .expect("healed zeroed head_hash");
        assert_eq!(
            committed,
            vec![true],
            "zeroed metadata.head_hash must not fail closed as a CAS miss"
        );
        assert_eq!(
            storage
                .get_chain_head(&session, Some(&principal))
                .await
                .expect("restored head"),
            Some(second.id)
        );
    }
}
