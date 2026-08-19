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
}

/// Result type for audit operations.
pub type AuditResult<T> = Result<T, AuditError>;
