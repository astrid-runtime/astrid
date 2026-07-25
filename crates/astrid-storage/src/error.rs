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

    /// A mutation would increase logical principal state beyond its configured
    /// storage budget.
    #[error("storage quota exceeded: mutation would use {used} bytes (limit {limit})")]
    QuotaExceeded {
        /// Logical bytes after the rejected mutation.
        used: u64,
        /// Configured logical-byte ceiling.
        limit: u64,
    },
}

/// Result type for storage operations.
pub type StorageResult<T> = Result<T, StorageError>;
