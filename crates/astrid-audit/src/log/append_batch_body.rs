{
    if entries.is_empty() {
        return Vec::new();
    }
    let _append_guard = self.append_coordinator.lock().await;
    let mut handles: HashMap<ChainKey, ChainHead> = HashMap::new();
    let mut results: Vec<Option<AuditResult<AuditEntryId>>> =
        (0..entries.len()).map(|_| None).collect();

    // A bounded queue batch is intentionally committed as one logical unit.
    // The storage backend validates the same head conditions and publishes
    // entries, indexes, and projections in one root transaction.
    loop {
        let mut working: HashMap<ChainKey, Option<HeadState>> = HashMap::new();
        let mut signed: Vec<(usize, AuditEntry, Option<AuditEntryId>)> =
            Vec::with_capacity(entries.len());
        let mut build_error = None;

        for (index, (session_id, principal, action, authorization, outcome)) in
            entries.iter().enumerate()
        {
            let chain_key = ChainKey {
                session_id: session_id.clone(),
                principal: Some(principal.clone()),
            };
            if !handles.contains_key(&chain_key) {
                let handle = {
                    let mut heads = self
                        .chain_heads
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    Arc::clone(
                        heads
                            .entry(chain_key.clone())
                            .or_insert_with(|| Arc::new(Mutex::new(None))),
                    )
                };
                handles.insert(chain_key.clone(), handle);
            }
            if !working.contains_key(&chain_key) {
                let Some(handle) = handles.get(&chain_key) else {
                    build_error = Some("audit chain handle disappeared".to_owned());
                    break;
                };
                let initial = handle.lock().await.clone();
                working.insert(chain_key.clone(), initial);
            }
            let previous = working.get(&chain_key).and_then(Option::as_ref);
            let (expected, previous_hash) = match self
                .previous_hash_locked(&chain_key, previous)
                .await
            {
                Ok(value) => value,
                Err(error) => {
                    build_error = Some(error.to_string());
                    break;
                },
            };
            let entry = AuditEntry::create_with_principal(
                session_id.clone(),
                principal.clone(),
                action.clone(),
                authorization.clone(),
                outcome.clone(),
                previous_hash,
                &self.runtime_key,
            );
            working.insert(
                chain_key,
                Some(HeadState {
                    id: entry.id.clone(),
                    hash: entry.content_hash(),
                }),
            );
            signed.push((index, entry, expected));
        }

        if let Some(error) = build_error {
            for slot in &mut results {
                *slot = Some(Err(AuditError::StorageError(error.clone())));
            }
            break;
        }

        let requests: Vec<(&AuditEntry, Option<&AuditEntryId>)> = signed
            .iter()
            .map(|(_, entry, expected)| (entry, expected.as_ref()))
            .collect();
        let append_results = match self.storage.append_batch_if_heads(&requests).await {
            Ok(values) => values,
            Err(AuditError::RetentionCapReached) => {
                for handle in handles.values() {
                    *handle.lock().await = None;
                }
                match self
                    .prune_oldest(AuditRetentionPolicy {
                        retain_entries: DEFAULT_AUTO_RETENTION_ENTRIES,
                        retain_bytes: None,
                    })
                    .await
                {
                    Ok(Some(_)) => continue,
                    Ok(None) => {},
                    Err(error) => {
                        for slot in &mut results {
                            *slot = Some(Err(AuditError::StorageError(error.to_string())));
                        }
                        break;
                    },
                }
                for slot in &mut results {
                    *slot = Some(Err(AuditError::StorageError(
                        "audit retention cap reached with no eligible sealed segment".to_owned(),
                    )));
                }
                break;
            },
            Err(error) => {
                for slot in &mut results {
                    *slot = Some(Err(AuditError::StorageError(error.to_string())));
                }
                for handle in handles.values() {
                    *handle.lock().await = None;
                }
                break;
            },
        };
        if append_results.len() != signed.len()
            || append_results.iter().any(|committed| !committed)
        {
            // A different AuditLog handle may have advanced one of the same
            // system chains.  No mutation was published for an atomic batch;
            // discard the speculative entries, reload every head, and sign
            // the entire logical batch again before retrying.
            working.clear();
            for handle in handles.values() {
                *handle.lock().await = None;
            }
            continue;
        }

        for ((index, entry, _), committed) in signed.iter().zip(append_results) {
            if committed {
                results[*index] = Some(Ok(entry.id.clone()));
            }
        }
        for (chain_key, state) in working {
            if let Some(handle) = handles.get(&chain_key) {
                *handle.lock().await = state;
            }
        }
        break;
    }

    results
        .into_iter()
        .map(|result| result.unwrap_or_else(|| {
            Err(AuditError::StorageError(
                "audit batch did not produce a result".to_owned(),
            ))
        }))
        .collect()
}
