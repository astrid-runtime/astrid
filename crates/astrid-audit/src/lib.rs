//! Astrid Audit - Chain-linked cryptographic audit logging.
//!
//! This crate provides:
//! - Cryptographically signed audit entries
//! - Chain-linked entries (each contains hash of previous)
//! - Persistent storage with `SurrealKV`
//! - Chain integrity verification
//!
//! # Security Model
//!
//! Every audit entry is:
//! - Signed by an ed25519 key
//! - Linked to the previous entry via content hash
//! - Timestamped
//! - Indexed by session
//!
//! The chain linking provides tamper evidence - any modification
//! to historical entries breaks the chain and is detectable.
//!
//! # Entry formats
//!
//! Format v1 (the default) signs a mixed binary/JSON layout with the runtime
//! key and is verified against the key embedded in each entry. Format v2
//! ([`entry_v2`]) signs a canonical CBOR body covering every field with a
//! dedicated audit key, carries a per-chain sequence number, and is verified
//! against a cross-signed key registry, so a rewritten chain signed under
//! some other key no longer verifies. [`AuditLog::enable_entry_v2`] switches
//! a log to v2; v1 history stays as it is and is hash-linked into the v2
//! chains that follow it.
//!
//! # Example
//!
//! ```
//! use astrid_audit::{AuditLog, AuditAction, AuditOutcome, AuthorizationProof};
//! use astrid_core::SessionId;
//! use astrid_crypto::KeyPair;
//!
//! // Create an in-memory audit log
//! let runtime_key = KeyPair::generate();
//! let user_id = runtime_key.key_id();
//! let log = AuditLog::in_memory(runtime_key);
//!
//! // Start a session
//! let session_id = SessionId::new();
//!
//! // The read/write surface is async; drive it on a current-thread runtime.
//! # let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
//! # rt.block_on(async {
//! // Record an action
//! let entry_id = log.append(
//!     session_id.clone(),
//!     AuditAction::SessionStarted {
//!         user_id,
//!         platform: "cli".to_string(),
//!     },
//!     AuthorizationProof::System {
//!         reason: "session start".to_string(),
//!     },
//!     AuditOutcome::success(),
//! ).await.unwrap();
//!
//! // Verify chain integrity
//! let result = log.verify_chain(&session_id).await.unwrap();
//! assert!(result.valid);
//! # });
//! ```

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![deny(unreachable_pub)]
#![deny(clippy::unwrap_used)]
#![cfg_attr(test, allow(clippy::unwrap_used))]

pub mod entry_v2;
pub mod host_call;
pub mod prelude;

mod entry;
mod error;
mod log;
mod storage;

pub use entry::{
    ApprovalScope, AuditAction, AuditEntry, AuditEntryFormat, AuditOutcome, AuthorizationProof,
    CapsuleActor, ProviderRequestId,
};
pub use entry_v2::{
    AuditActor, ChainStart, ChainVerifier, EntryV2Seal, KeyRegistry, KeyRegistryRecord, KeyRole,
};
pub use error::{AuditError, AuditResult};
pub use log::{
    AuditAnchorMarkResult, AuditAnchorWatermark, AuditArchiveWriter, AuditArchiver,
    AuditCapacityProvider, AuditChainAnchorStatus, AuditChainHead, AuditChainPruneState,
    AuditChainStats, AuditGlobalStats, AuditLog, AuditPruneReceipt, AuditRetentionPolicy,
    ChainIssue, ChainVerificationResult, EntryV2Config, LegacyAuditImportReport,
    PrincipalUidResolver,
};

// Re-export AuditEntryId from capabilities for convenience
pub use astrid_capabilities::AuditEntryId;
