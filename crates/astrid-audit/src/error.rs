//! Audit-related error types.

use thiserror::Error;

/// Errors that can occur with audit logging.
#[derive(Debug, Error)]
pub enum AuditError {
    /// Storage error.
    #[error("storage error: {0}")]
    StorageError(String),

    /// The configured global retention cap requires pruning before appending.
    #[error("audit retention cap reached")]
    RetentionCapReached,

    /// The selected backend does not expose a bounded operation.
    #[error("audit backend does not support {operation}")]
    UnsupportedOperation {
        /// Stable operation name for callers that need a capability fallback.
        operation: &'static str,
    },

    /// Serialization error.
    #[error("serialization error: {0}")]
    SerializationError(String),

    /// Entry not found.
    #[error("audit entry not found: {entry_id}")]
    EntryNotFound {
        /// The entry ID that was not found.
        entry_id: String,
    },

    /// Chain integrity violation.
    #[error("chain integrity violation at entry {entry_id}: {reason}")]
    IntegrityViolation {
        /// The entry where violation was detected.
        entry_id: String,
        /// Why the chain is invalid.
        reason: String,
    },

    /// Invalid signature on entry.
    #[error("invalid signature on entry {entry_id}")]
    InvalidSignature {
        /// The entry with invalid signature.
        entry_id: String,
    },

    /// Session not found.
    #[error("session not found: {session_id}")]
    SessionNotFound {
        /// The session ID that was not found.
        session_id: String,
    },

    /// Crypto error.
    #[error("crypto error: {0}")]
    CryptoError(#[from] astrid_crypto::CryptoError),

    /// The key registry is missing, malformed, or refuses a change.
    #[error("audit key registry: {0}")]
    KeyRegistry(String),

    /// The configured audit key is not the registry's active audit key.
    #[error("audit key {key} is not the active audit key of the key registry")]
    KeyNotRegistered {
        /// Hex of the refused public key.
        key: String,
    },

    /// A format-v2 entry was signed at a key epoch the stored key registry
    /// has moved past (the audit key was rotated after it was signed).
    #[error(
        "audit entry signed at key epoch {key_epoch}, but the key registry has moved past it; \
         the audit key was rotated, reopen the audit log with the current key"
    )]
    StaleAuditKey {
        /// The epoch the refused entry was signed at.
        key_epoch: u64,
    },

    /// A format-v1 append was refused because the log has moved to format v2.
    #[error(
        "audit log is closed to format-v1 entries ({reason}); enable entry format v2 to append"
    )]
    V1Closed {
        /// Why v1 is closed: a v2 chain head or a key registry in the store.
        reason: &'static str,
    },
}

/// Result type for audit operations.
pub type AuditResult<T> = Result<T, AuditError>;
