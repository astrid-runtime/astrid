//! Batched principal audit append implementation.

use super::prune::AuditRetentionPolicy;
use super::{
    AuditAction, AuditEntry, AuditEntryId, AuditError, AuditLog, AuditOutcome, AuditResult,
    AuthorizationProof, ChainHead, ChainKey, DEFAULT_AUTO_RETENTION_ENTRIES, HeadState,
};
use astrid_core::{PrincipalId, SessionId};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

type PrincipalEntry = (
    SessionId,
    PrincipalId,
    AuditAction,
    AuthorizationProof,
    AuditOutcome,
);
type SignedEntry = (usize, AuditEntry, Option<AuditEntryId>);

struct SignedBatch {
    heads: HashMap<ChainKey, Option<HeadState>>,
    entries: Vec<SignedEntry>,
}

impl AuditLog {
    pub(super) async fn append_batch_with_principal_impl(
        &self,
        entries: Vec<PrincipalEntry>,
    ) -> Vec<AuditResult<AuditEntryId>> {
        if entries.is_empty() {
            return Vec::new();
        }
        let _append_guard = self.append_coordinator.lock().await;
        let mut handles = HashMap::new();

        loop {
            let signed = match self.build_signed_batch(&entries, &mut handles).await {
                Ok(signed) => signed,
                Err(error) => return batch_error(entries.len(), &error),
            };
            let requests: Vec<_> = signed
                .entries
                .iter()
                .map(|(_, entry, expected)| (entry, expected.as_ref()))
                .collect();
            let append_results = match self.storage.append_batch_if_heads(&requests).await {
                Ok(results) => results,
                Err(AuditError::RetentionCapReached) => {
                    self.invalidate_batch_heads(&handles).await;
                    match self.prune_for_batch_retry().await {
                        Ok(true) => continue,
                        Ok(false) => {
                            return batch_error(
                                entries.len(),
                                "audit retention cap reached with no eligible sealed segment",
                            );
                        },
                        Err(error) => return batch_error(entries.len(), &error),
                    }
                },
                Err(error) => {
                    self.invalidate_batch_heads(&handles).await;
                    return batch_error(entries.len(), &error);
                },
            };
            if append_results.len() != signed.entries.len()
                || append_results.iter().any(|committed| !committed)
            {
                self.invalidate_batch_heads(&handles).await;
                continue;
            }
            self.publish_batch_heads(&handles, signed.heads).await;
            return signed
                .entries
                .into_iter()
                .map(|(_, entry, _)| Ok(entry.id))
                .collect();
        }
    }

    async fn build_signed_batch(
        &self,
        entries: &[PrincipalEntry],
        handles: &mut HashMap<ChainKey, ChainHead>,
    ) -> AuditResult<SignedBatch> {
        let mut heads = HashMap::new();
        let mut signed = Vec::with_capacity(entries.len());

        for (index, (session_id, principal, action, authorization, outcome)) in
            entries.iter().enumerate()
        {
            let chain_key = ChainKey {
                session_id: session_id.clone(),
                principal: Some(principal.clone()),
            };
            let handle = self.batch_chain_handle(handles, &chain_key);
            if !heads.contains_key(&chain_key) {
                heads.insert(chain_key.clone(), handle.lock().await.clone());
            }
            let previous = heads.get(&chain_key).and_then(Option::as_ref);
            let (expected, previous_hash) = self.previous_hash_locked(&chain_key, previous).await?;
            let entry = AuditEntry::create_with_principal(
                session_id.clone(),
                principal.clone(),
                action.clone(),
                authorization.clone(),
                outcome.clone(),
                previous_hash,
                &self.runtime_key,
            );
            heads.insert(
                chain_key,
                Some(HeadState {
                    id: entry.id.clone(),
                    hash: entry.content_hash(),
                }),
            );
            signed.push((index, entry, expected));
        }
        Ok(SignedBatch {
            heads,
            entries: signed,
        })
    }

    fn batch_chain_handle(
        &self,
        handles: &mut HashMap<ChainKey, ChainHead>,
        chain_key: &ChainKey,
    ) -> ChainHead {
        Arc::clone(handles.entry(chain_key.clone()).or_insert_with(|| {
            let mut heads = self
                .chain_heads
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            Arc::clone(
                heads
                    .entry(chain_key.clone())
                    .or_insert_with(|| Arc::new(Mutex::new(None))),
            )
        }))
    }

    async fn prune_for_batch_retry(&self) -> AuditResult<bool> {
        Ok(self
            .prune_oldest(AuditRetentionPolicy {
                retain_entries: DEFAULT_AUTO_RETENTION_ENTRIES,
                retain_bytes: None,
            })
            .await?
            .is_some())
    }

    async fn invalidate_batch_heads(&self, handles: &HashMap<ChainKey, ChainHead>) {
        for handle in handles.values() {
            *handle.lock().await = None;
        }
    }

    async fn publish_batch_heads(
        &self,
        handles: &HashMap<ChainKey, ChainHead>,
        heads: HashMap<ChainKey, Option<HeadState>>,
    ) {
        for (chain_key, state) in heads {
            if let Some(handle) = handles.get(&chain_key) {
                *handle.lock().await = state;
            }
        }
    }
}

fn batch_error(count: usize, error: &(impl ToString + ?Sized)) -> Vec<AuditResult<AuditEntryId>> {
    let message = error.to_string();
    (0..count)
        .map(|_| Err(AuditError::StorageError(message.clone())))
        .collect()
}
