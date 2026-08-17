use crate::log::AuditLog;

impl std::fmt::Debug for AuditLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditLog")
            .field("runtime_key_id", &self.runtime_key.key_id_hex())
            .finish_non_exhaustive()
    }
}
