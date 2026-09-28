//! Persistence of the format-v2 key registry records.
//!
//! Records live under `record:{seq:020}` so a prefix listing returns them in
//! registry order. Each record is written once, by compare-and-swap against
//! absence, so two writers can never both extend the registry at one `seq`.

use super::{AuditError, AuditResult, KvAuditStorage, NS_KEY_REGISTRY};

const RECORD_PREFIX: &str = "record:";

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
        self.store
            .compare_and_swap(
                NS_KEY_REGISTRY,
                &format!("{RECORD_PREFIX}{seq:020}"),
                None,
                bytes,
            )
            .await
            .map_err(|error| AuditError::StorageError(error.to_string()))
    }
}
