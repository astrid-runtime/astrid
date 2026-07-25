//! Storage error types.

/// Errors from storage operations.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    /// The requested key or item was not found.
    #[error("not found: {0}")]
    NotFound(String),

    /// A storage operation failed.
    #[error("storage error: {0}")]
    Internal(String),

    /// Connection to the storage backend failed.
    #[error("connection error: {0}")]
    Connection(String),

    /// Serialization or deserialization failed.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// The namespace or key is invalid.
    #[error("invalid key: {0}")]
    InvalidKey(String),
}

impl StorageError {
    /// Preserve the existing public error variants while reporting a
    /// fail-closed quota rejection.
    pub(crate) fn quota_exceeded(used: u64, limit: u64) -> Self {
        Self::Internal(format!(
            "storage quota exceeded: mutation would use {used} bytes (limit {limit})"
        ))
    }
}

/// Result type for storage operations.
pub type StorageResult<T> = Result<T, StorageError>;
