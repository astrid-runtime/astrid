//! Support for the astrid index command.
//!
//! The command namespace is index; the configured noun shown to operators
//! is source. This module owns the source file and its locking/validation
//! rules, while dispatch supplies clap arguments, a real TUF verifier, and a
//! refresh transport.

mod handlers;
mod model;
mod storage;
mod transport;
mod tuf;
mod usage;

#[allow(unused_imports)]
pub(crate) use handlers::{
    add_source, list_sources, remove_source, rotate_source_root, update_source,
};
#[allow(unused_imports)]
pub(crate) use model::{
    BUILTIN_INDEX_ID, CONFIG_SCHEMA_VERSION, IndexConfig, IndexSource, MetadataSnapshot,
    PinnedRoot, normalize_fingerprint, normalize_root_fingerprint, validate_base_url,
    validate_index_id, validate_root_path,
};
#[allow(unused_imports)]
pub(crate) use storage::{
    AddArgs, AddOutcome, BuiltinSource, IndexListFormat, IndexPaths, IndexStore, ListArgs,
    MetadataVerifier, RefreshResponse, RefreshTransport, RemoveArgs, RemoveOutcome, RootInput,
    RootRotation, UpdateArgs, UpdateOutcome, UsageChecker, VerifiedMetadata,
};
#[allow(unused_imports)]
pub(crate) use transport::{DEFAULT_MAX_RESPONSE_BYTES, ReqwestTufTransport};
#[allow(unused_imports)]
pub(crate) use tuf::{TufIndexAdapter, TufStatePaths};
#[allow(unused_imports)]
pub(crate) use usage::{
    DEFAULT_MAX_LOCK_BYTES, DEFAULT_MAX_LOCK_DEPTH, DEFAULT_MAX_LOCK_FILES, LockUsageScanner,
};

use std::path::PathBuf;

use thiserror::Error;

/// Errors raised while configuring or refreshing Capsule Index sources.
#[derive(Debug, Error)]
pub(crate) enum IndexError {
    /// An underlying filesystem operation failed.
    #[error("index storage I/O at {path}: {source}")]
    Io {
        /// Path involved in the operation.
        path: PathBuf,
        /// Operating-system error.
        #[source]
        source: std::io::Error,
    },
    /// The persisted config could not be parsed.
    #[error("corrupt index source config {path}: {source}")]
    CorruptConfig {
        /// Config path.
        path: PathBuf,
        /// TOML parse error.
        #[source]
        source: toml::de::Error,
    },
    /// The persisted config could not be serialized.
    #[error("failed to serialize index source config: {source}")]
    Serialize {
        /// TOML serialization error.
        #[source]
        source: toml::ser::Error,
    },
    /// Config schema is newer than this CLI understands.
    #[error("unsupported index config schema {found}; this CLI supports {supported}")]
    UnsupportedSchema {
        /// Found schema version.
        found: u32,
        /// Supported schema version.
        supported: u32,
    },
    /// A source ID is malformed.
    #[error("invalid index source ID {0:?}")]
    InvalidId(String),
    /// A source ID is syntactically valid but ambiguous.
    #[error("ambiguous index source ID {0:?}; use lowercase path-free ASCII")]
    AmbiguousId(String),
    /// A source URL is malformed.
    #[error("invalid index base URL {0:?}")]
    InvalidUrl(String),
    /// URL parsing failed.
    #[error("failed to parse index URL {value:?}: {source}")]
    UrlParse {
        /// Supplied URL.
        value: String,
        /// URL parser error.
        #[source]
        source: url::ParseError,
    },
    /// URL scheme is not HTTPS or a loopback HTTP endpoint.
    #[error("index URL must use HTTPS (HTTP is allowed only for loopback tests): {0}")]
    InsecureUrl(String),
    /// URL contains credentials.
    #[error("index URL must not contain credentials: {0}")]
    UrlCredentials(String),
    /// URL contains query or fragment components.
    #[error("index URL must not contain a query or fragment: {0}")]
    UrlQueryOrFragment(String),
    /// URL path contains traversal or encoded separators.
    #[error("index URL contains path traversal or encoded separators: {0}")]
    UrlPathTraversal(String),
    /// URL is valid but not in canonical form.
    #[error("index URL is not canonical; use {canonical:?} instead of {supplied:?}")]
    NonCanonicalUrl {
        /// Supplied URL.
        supplied: String,
        /// Canonical URL.
        canonical: String,
    },
    /// A trust-root path contains traversal components.
    #[error("index trust-root path contains traversal: {0}")]
    PathTraversal(PathBuf),
    /// Reading a trust root failed.
    #[error("failed to read trust root {path}: {source}")]
    RootRead {
        /// Root path.
        path: PathBuf,
        /// Operating-system error.
        #[source]
        source: std::io::Error,
    },
    /// Root bytes are not valid base64.
    #[error("invalid base64 encoding in pinned TUF root: {source}")]
    CorruptRootEncoding {
        /// Base64 decoder error.
        #[source]
        source: base64::DecodeError,
    },
    /// Metadata bytes are not valid base64.
    #[error("invalid base64 encoding in verified metadata: {source}")]
    CorruptMetadataEncoding {
        /// Base64 decoder error.
        #[source]
        source: base64::DecodeError,
    },
    /// A supplied digest string is malformed or uses an unsupported algorithm.
    #[error("invalid index fingerprint {0:?}; expected tagged sha256:<64 lowercase hex>")]
    InvalidFingerprint(String),
    /// A supplied digest did not match exact bytes.
    #[error("index fingerprint mismatch: expected {expected}, supplied {supplied}")]
    FingerprintMismatch {
        /// Computed digest.
        expected: String,
        /// Caller-supplied digest.
        supplied: String,
    },
    /// A metadata digest did not match exact bytes.
    #[error("verified metadata digest mismatch: expected {expected}, supplied {supplied}")]
    MetadataDigestMismatch {
        /// Computed digest.
        expected: String,
        /// Caller-supplied digest.
        supplied: String,
    },
    /// A source ID already exists.
    #[error("index source ID already exists: {0}")]
    DuplicateId(String),
    /// Two source IDs claim one trust root.
    #[error("trust root {fingerprint} is already owned by {first}; cannot assign it to {second}")]
    DuplicateTrustRoot {
        /// Root fingerprint.
        fingerprint: String,
        /// Existing owner.
        first: String,
        /// Conflicting owner.
        second: String,
    },
    /// Two source IDs claim one URL.
    #[error("base URL {url} is already owned by {first}; cannot assign it to {second}")]
    DuplicateUrl {
        /// URL.
        url: String,
        /// Existing owner.
        first: String,
        /// Conflicting owner.
        second: String,
    },
    /// The built-in source cannot be changed by regular commands.
    #[error("the built-in Astrid Index source cannot be removed or repointed")]
    BuiltinProtected,
    /// The built-in source in storage differs from the compiled identity.
    #[error("stored built-in Astrid Index source does not match the compiled identity")]
    BuiltinRepointed,
    /// The official source was requested without a compiled trust anchor.
    #[error("the official Astrid Index trust root is not compiled into this build")]
    BuiltinRootUnavailable,
    /// Source does not exist.
    #[error("index source not found: {0}")]
    NotFound(String),
    /// Remove was refused because a lock/index references the source.
    #[error("index source {id} is still in use")]
    InUse {
        /// Source ID.
        id: String,
        /// References reported by the usage checker.
        references: Vec<String>,
    },
    /// Refresh returned a different root than the pinned one.
    #[error("refresh returned a different TUF root for {id}; explicit root rotation is required")]
    RootMismatch {
        /// Source ID.
        id: String,
    },
    /// Explicit root rotation was not authorized by the verifier.
    #[error("TUF root rotation for {id} was not verified")]
    RootRotationRefused {
        /// Source ID.
        id: String,
    },
    /// Refresh transport failed.
    #[error("failed to refresh index source {id}: {message}")]
    Refresh {
        /// Source ID.
        id: String,
        /// Transport error text.
        message: String,
    },
    /// A production network/TUF adapter could not complete an operation.
    #[error("index adapter {operation} failed: {message}")]
    Network {
        /// Operation being performed.
        operation: String,
        /// Failure detail.
        message: String,
    },
    /// Metadata verifier rejected a snapshot.
    #[error("TUF verifier rejected metadata for {id}: {message}")]
    Verification {
        /// Source ID.
        id: String,
        /// Verifier error text.
        message: String,
    },
    /// A lock file could not be acquired.
    #[error("failed to lock index source config {path}: {source}")]
    Lock {
        /// Lock path.
        path: PathBuf,
        /// Operating-system error.
        #[source]
        source: std::io::Error,
    },
    /// Usage checker failed.
    #[error("failed to inspect index usage: {0}")]
    Usage(String),
    /// The requested output format is unsupported.
    #[error("unsupported index list format {0:?}")]
    Format(String),
    /// JSON rendering failed.
    #[error("failed to serialize index list as JSON: {source}")]
    JsonSerialize {
        /// JSON serialization error.
        #[source]
        source: serde_json::Error,
    },
}

/// Tagged SHA-256 digest of the exact trust-root bytes.
pub(crate) fn root_fingerprint(bytes: &[u8]) -> String {
    use sha2::{Digest as _, Sha256};

    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

/// BLAKE3 digest used for verified metadata identity.
pub(crate) fn metadata_digest(bytes: &[u8]) -> String {
    format!("blake3:{}", blake3::hash(bytes).to_hex())
}

#[cfg(test)]
mod tests;
