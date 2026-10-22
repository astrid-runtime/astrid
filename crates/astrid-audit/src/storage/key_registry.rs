//! Persistence of the format-v2 key registry records.
//!
//! Records live under `record:{seq:020}` so a prefix listing returns them in
//! registry order. Each record is written once, by compare-and-swap against
//! absence, so two writers can never both extend the registry at one `seq`.
//!
//! Record writes take the process-wide durable append lock, and every append
//! checks the registry under that lock before it commits
//! (`check_registry_state`). No writer of this store can therefore commit a
//! format-v1 entry once a registry exists, or a v2 entry signed at an epoch
//! the registry has moved past. A new prune plan is checked the same way
//! against the key that signed its receipt (`check_receipt_signer`), so a
//! stale log handle cannot delete entries under a receipt the registry no
//! longer accepts.

use super::{AuditError, AuditResult, DURABLE_APPEND_LOCK, KvAuditStorage, NS_KEY_REGISTRY};
use crate::entry::AuditEntry;

const RECORD_PREFIX: &str = "record:";

fn record_key(seq: u64) -> String {
    format!("{RECORD_PREFIX}{seq:020}")
}

impl KvAuditStorage {
    pub(super) async fn load_key_registry_records(&self) -> AuditResult<Vec<Vec<u8>>> {
        let mut keys = self
            .store
            .list_keys_with_prefix(NS_KEY_REGISTRY, RECORD_PREFIX)
            .await
            .map_err(|error| AuditError::StorageError(error.to_string()))?;
        keys.sort_unstable();
        let mut records = Vec::with_capacity(keys.len());
        for key in keys {
            let bytes = self
                .store
                .get(NS_KEY_REGISTRY, &key)
                .await
                .map_err(|error| AuditError::StorageError(error.to_string()))?
                .ok_or_else(|| {
                    AuditError::StorageError("audit key registry record disappeared".to_owned())
                })?;
            records.push(bytes);
        }
        Ok(records)
    }

    pub(super) async fn insert_key_registry_record(
        &self,
        seq: u64,
        bytes: Vec<u8>,
    ) -> AuditResult<bool> {
        let _guard = DURABLE_APPEND_LOCK.lock().await;
        self.store
            .compare_and_swap(NS_KEY_REGISTRY, &record_key(seq), None, bytes)
            .await
            .map_err(|error| AuditError::StorageError(error.to_string()))
    }

    async fn registry_record_exists(&self, seq: u64) -> AuditResult<bool> {
        self.store
            .exists(NS_KEY_REGISTRY, &record_key(seq))
            .await
            .map_err(|error| AuditError::StorageError(error.to_string()))
    }

    /// Refuse a new prune plan whose receipt was signed by a key the stored
    /// registry does not accept now: a format-v1 receipt (runtime key, no
    /// epoch) once any registry record exists, or a v2 receipt whose key
    /// epoch is not the registry head. Callers hold the durable append lock.
    pub(super) async fn check_receipt_signer(&self, key_epoch: Option<u64>) -> AuditResult<()> {
        let Some(key_epoch) = key_epoch else {
            if self.registry_record_exists(0).await? {
                return Err(AuditError::V1Closed {
                    reason: "the store holds a format-v2 key registry",
                });
            }
            return Ok(());
        };
        if !self.registry_record_exists(key_epoch).await? {
            return Err(AuditError::KeyRegistry(format!(
                "audit prune receipt names key epoch {key_epoch}, which the registry does not hold"
            )));
        }
        let next = key_epoch
            .checked_add(1)
            .ok_or_else(|| AuditError::StorageError("audit key epoch exhausted".to_owned()))?;
        if self.registry_record_exists(next).await? {
            return Err(AuditError::StaleAuditKey { key_epoch });
        }
        Ok(())
    }

    /// Refuse to commit `entries` against the stored key registry: a v1
    /// entry once any registry record exists, or a v2 entry whose key epoch
    /// is no longer the registry head. Callers hold the durable append lock.
    pub(super) async fn check_registry_state<'a>(
        &self,
        entries: impl IntoIterator<Item = &'a AuditEntry>,
    ) -> AuditResult<()> {
        let mut v1 = false;
        let mut epochs = std::collections::BTreeSet::new();
        for entry in entries {
            match &entry.v2 {
                None => v1 = true,
                Some(seal) => {
                    epochs.insert(seal.key_epoch);
                },
            }
        }
        if v1 && self.registry_record_exists(0).await? {
            return Err(AuditError::V1Closed {
                reason: "the store holds a format-v2 key registry",
            });
        }
        for key_epoch in epochs {
            let next = key_epoch
                .checked_add(1)
                .ok_or_else(|| AuditError::StorageError("audit key epoch exhausted".to_owned()))?;
            if self.registry_record_exists(next).await? {
                return Err(AuditError::StaleAuditKey { key_epoch });
            }
        }
        Ok(())
    }
}
