use std::path::PathBuf;
use thiserror::Error;

/// Errors that can occur during capsule operations.
#[derive(Debug, Error)]
pub enum CapsuleError {
    /// Failed to parse the `Capsule.toml` manifest.
    #[error("Failed to parse manifest at {path}: {message}")]
    ManifestParseError {
        /// Path to the invalid manifest.
        path: PathBuf,
        /// The parse error message.
        message: String,
    },
    /// The capsule requests an unsupported entry point or feature.
    #[error("Unsupported entry point: {0}")]
    UnsupportedEntryPoint(String),
    /// A WASM host call or tool execution failed.
    #[error("Execution failed: {0}")]
    ExecutionFailed(String),
    /// An error originated inside the WASM VM runtime.
    #[error("WASM error: {0}")]
    WasmError(String),
    /// The requested capsule was not found in the registry.
    #[error("Not found: {0}")]
    NotFound(String),
    /// The engine does not support the requested operation.
    #[error("Not supported: {0}")]
    NotSupported(String),
}

/// A specialized Result type for capsule operations.
pub type CapsuleResult<T> = Result<T, CapsuleError>;
