{
    struct ChainState {
        head_expected: Option<AuditEntryId>,
        metadata_expected: Option<Vec<u8>>,
        metadata: ChainMetadata,
        segment_index: Vec<(String, Vec<u8>)>,
    }
    struct SequenceState {
        expected: Option<Vec<u8>>,
        next: u64,
    }

    if entries.is_empty() {
        return Ok(Vec::new());
    }
    // Keep one root commit comfortably below the backend's 1,024-operation
    // limit. Larger caller batches are still accepted, but use the CAS
    // fallback rather than constructing an unbounded mutation vector.
    if entries.len() > 128 {
        let mut results = Vec::with_capacity(entries.len());
        for (entry, expected) in entries {
            results.push(self.append_if_head(entry, *expected).await?);
        }
        return Ok(results);
    }

    let mut chains: std::collections::HashMap<String, ChainState> =
        std::collections::HashMap::new();
    let mut sequences: std::collections::HashMap<String, SequenceState> =
        std::collections::HashMap::new();
    let mut entry_mutations = Vec::with_capacity(entries.len());
    let mut session_index_mutations = Vec::with_capacity(entries.len());
    let mut committed_mutations = Vec::with_capacity(entries.len());
    let mut seen_entries = HashSet::with_capacity(entries.len());
    let (global_expected, mut global) = self.load_global_metadata().await?;

    for (entry, expected) in entries {
        if !seen_entries.insert(entry.id.0) {
            return Err(AuditError::StorageError(
                "audit batch contains duplicate entry IDs".to_owned(),
            ));
        }
        let chain_key = chain_head_key(&entry.session_id, entry.principal.as_ref());
        if chains.contains_key(&chain_key) {
            let Some(state) = chains.get(&chain_key) else {
                return Err(AuditError::StorageError(
                    "audit batch chain state disappeared".to_owned(),
                ));
            };
            let Some(current_head) = state.metadata.head.as_ref() else {
                return Ok(vec![false; entries.len()]);
            };
            if *expected != Some(current_head) {
                return Ok(vec![false; entries.len()]);
            }
        } else {
            let stored_head = self
                .store
                .get(NS_CHAIN_HEADS, &chain_key)
                .await
                .map_err(|error| AuditError::StorageError(error.to_string()))?;
            let stored_head_id = stored_head
                .as_deref()
                .map(std::str::from_utf8)
                .transpose()
                .map_err(|error| AuditError::StorageError(error.to_string()))?
                .map(uuid::Uuid::parse_str)
                .transpose()
                .map_err(|error| AuditError::StorageError(error.to_string()))?
                .map(AuditEntryId);
            if stored_head_id.as_ref() != *expected {
                return Ok(vec![false; entries.len()]);
            }
            let (metadata_expected, metadata) =
                self.load_chain_metadata(&entry.session_id, entry.principal.as_ref()).await?;
            let metadata = metadata.unwrap_or_default();
            if metadata.head.as_ref() != *expected {
                return Ok(vec![false; entries.len()]);
            }
            chains.insert(
                chain_key.clone(),
                ChainState {
                    head_expected: (*expected).cloned(),
                    metadata_expected,
                    metadata,
                    segment_index: Vec::new(),
                },
            );
        }
        let Some(state) = chains.get_mut(&chain_key) else {
            return Err(AuditError::StorageError(
                "audit batch chain state disappeared".to_owned(),
            ));
        };
        let prior = state.metadata.clone();
        let expected_previous = if prior.count == 0 {
            astrid_crypto::ContentHash::zero()
        } else {
            prior.head_hash
        };
        if entry.previous_hash != expected_previous {
            return Ok(vec![false; entries.len()]);
        }
        let entry_data = serde_json::to_vec(entry)
            .map_err(|error| AuditError::SerializationError(error.to_string()))?;
        let entry_bytes = u64::try_from(entry_data.len()).unwrap_or(u64::MAX);
        entry_mutations.push((entry.id.0.to_string(), entry_data));

        let session_key = entry.session_id.0.to_string();
        let sequence_state = if let Some(sequence) = sequences.get_mut(&session_key) {
            sequence
        } else {
            let expected_sequence = self
                .store
                .get(NS_SESSION_SEQUENCE, &session_key)
                .await
                .map_err(|error| AuditError::StorageError(error.to_string()))?;
            let next = expected_sequence.as_deref().map_or(Ok(0), parse_sequence)?;
            sequences.insert(
                session_key.clone(),
                SequenceState {
                    expected: expected_sequence,
                    next,
                },
            );
            let Some(sequence) = sequences.get_mut(&session_key) else {
                return Err(AuditError::StorageError(
                    "audit batch sequence state disappeared".to_owned(),
                ));
            };
            sequence
        };
        let sequence = sequence_state.next;
        sequence_state.next = sequence.saturating_add(1);
        session_index_mutations.push((
            format!("{session_key}:{sequence:020}:{}", entry.id.0),
            vec![1],
        ));
        committed_mutations.push((entry.id.0.to_string(), vec![1]));

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
        let next_sealed = segment_count >= DEFAULT_SEGMENT_MAX_ENTRIES
            || segment_bytes >= DEFAULT_SEGMENT_MAX_BYTES;
        if next_sealed {
            global.next_seal_ordinal = global.next_seal_ordinal.saturating_add(1);
        }
        let next = ChainMetadata {
            schema: 1,
            segment: if starts_new_segment {
                prior.segment.saturating_add(1)
            } else {
                prior.segment
            },
            sealed: next_sealed,
            count: prior.count.saturating_add(1),
            bytes: prior.bytes.saturating_add(entry_bytes),
            head: Some(entry.id.clone()),
            head_hash: entry.content_hash(),
            segment_count,
            segment_bytes,
            segment_first: if starts_new_segment {
                Some(entry.id.clone())
            } else {
                prior.segment_first.or_else(|| Some(entry.id.clone()))
            },
            seal_ordinal: if next_sealed {
                Some(global.next_seal_ordinal)
            } else if starts_new_segment {
                None
            } else {
                prior.seal_ordinal
            },
        };
        if next_sealed {
            let key = format!(
                "{:020}:{}:{:020}",
                global.next_seal_ordinal, chain_key, next.segment
            );
            let value = serde_json::to_vec(&next)
                .map_err(|error| AuditError::SerializationError(error.to_string()))?;
            state.segment_index.push((key, value));
        }
        global.total_count = global.total_count.saturating_add(1);
        global.total_bytes = global.total_bytes.saturating_add(entry_bytes);
        if prior.count == 0 || prior.sealed {
            global.segments = global.segments.saturating_add(1);
        }
        if next_sealed {
            global.sealed_segments = global.sealed_segments.saturating_add(1);
            global.eligible_segments = global.eligible_segments.saturating_add(1);
        }
        state.metadata = next;
    }

    if global.total_count > global.cap_entries || global.total_bytes > global.cap_bytes {
        return Err(AuditError::RetentionCapReached);
    }

    let key = |namespace: &str, value: &str| {
        KvEntryKey::new(namespace, value)
            .map_err(|error| AuditError::StorageError(error.to_string()))
    };
    let mut conditions = Vec::new();
    let mut mutations = Vec::new();
    for (chain_key, state) in &chains {
        conditions.push(KvBatchCondition::ValueEquals {
            key: key(NS_CHAIN_HEADS, chain_key)?,
            expected: state
                .head_expected
                .as_ref()
                .map(|head| head.0.to_string().into_bytes()),
        });
        conditions.push(KvBatchCondition::ValueEquals {
            key: key(NS_CHAIN_METADATA, chain_key)?,
            expected: state.metadata_expected.clone(),
        });
        let metadata = serde_json::to_vec(&state.metadata)
            .map_err(|error| AuditError::SerializationError(error.to_string()))?;
        let head = state
            .metadata
            .head
            .as_ref()
            .ok_or_else(|| AuditError::StorageError("audit batch has no chain head".to_owned()))?;
        mutations.push(KvBatchMutation::Set {
            key: key(NS_CHAIN_HEADS, chain_key)?,
            value: head.0.to_string().into_bytes(),
        });
        mutations.push(KvBatchMutation::Set {
            key: key(NS_CHAIN_METADATA, chain_key)?,
            value: metadata,
        });
        for (segment_key, value) in &state.segment_index {
            mutations.push(KvBatchMutation::Set {
                key: key(NS_SEGMENT_INDEX, segment_key)?,
                value: value.clone(),
            });
        }
    }
    for (session_key, sequence) in &sequences {
        conditions.push(KvBatchCondition::ValueEquals {
            key: key(NS_SESSION_SEQUENCE, session_key)?,
            expected: sequence.expected.clone(),
        });
        mutations.push(KvBatchMutation::Set {
            key: key(NS_SESSION_SEQUENCE, session_key)?,
            value: sequence.next.to_be_bytes().to_vec(),
        });
    }
    for (entry_key, value) in entry_mutations {
        mutations.push(KvBatchMutation::Set {
            key: key(NS_ENTRIES, &entry_key)?,
            value,
        });
    }
    for (index_key, value) in session_index_mutations {
        mutations.push(KvBatchMutation::Set {
            key: key(NS_SESSION_ENTRIES, &index_key)?,
            value,
        });
    }
    for (entry_key, value) in committed_mutations {
        mutations.push(KvBatchMutation::Set {
            key: key(NS_COMMITTED_ENTRIES, &entry_key)?,
            value,
        });
    }
    conditions.push(KvBatchCondition::ValueEquals {
        key: key(NS_GLOBAL_METADATA, "current")?,
        expected: global_expected,
    });
    let global_data = serde_json::to_vec(&global)
        .map_err(|error| AuditError::SerializationError(error.to_string()))?;
    mutations.push(KvBatchMutation::Set {
        key: key(NS_GLOBAL_METADATA, "current")?,
        value: global_data,
    });
    let batch = KvMutationBatch::new(conditions, mutations)
        .map_err(|error| AuditError::StorageError(error.to_string()))?;
    if !self.store.supports_atomic_batch() {
        let mut results = Vec::with_capacity(entries.len());
        for (entry, expected) in entries {
            results.push(self.append_if_head(entry, *expected).await?);
        }
        return Ok(results);
    }
    let outcome = self
        .store
        .apply_batch(&batch)
        .await
        .map_err(|error| AuditError::StorageError(error.to_string()))?;
    Ok(vec![outcome.applied; entries.len()])
}
