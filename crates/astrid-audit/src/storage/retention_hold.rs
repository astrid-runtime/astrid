//! The global retention hold: the state in which the audit log keeps
//! entries over its global cap because every prune candidate would remove
//! history that is not anchored.

use super::{AuditError, AuditResult, DURABLE_APPEND_LOCK, KvAuditStorage};

impl KvAuditStorage {
    /// Set (`Some(reason)`) or clear (`None`) the retention hold. Returns
    /// whether the stored state changed.
    ///
    /// While the hold is set, appends at the global cap are admitted over it
    /// and the global state reports degraded with `reason`. Appends write the
    /// global metadata under the durable append lock and fail when it changed
    /// under them, so the hold is written under the same lock, after any
    /// interrupted append is recovered.
    pub(crate) async fn set_retention_hold(&self, reason: Option<String>) -> AuditResult<bool> {
        let _guard = DURABLE_APPEND_LOCK.lock().await;
        self.recover_append_intents().await?;
        let (expected, mut global) = self.load_global_metadata().await?;
        if global.retention_hold == reason {
            return Ok(false);
        }
        let over_cap =
            global.total_count > global.cap_entries || global.total_bytes > global.cap_bytes;
        global.degraded = over_cap || reason.is_some();
        global.last_error = match &reason {
            Some(reason) => Some(reason.clone()),
            None if over_cap => {
                Some("system audit retention cap exceeded; prune sealed segments".to_owned())
            },
            None => None,
        };
        global.retention_hold = reason;
        if self
            .persist_global_metadata(expected.as_deref(), &global)
            .await?
        {
            Ok(true)
        } else {
            Err(AuditError::StorageError(
                "audit global metadata changed while updating the retention hold".to_owned(),
            ))
        }
    }
}
