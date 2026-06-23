//! Astrid Capabilities - Cryptographically signed authorization tokens.
//!
//! This crate provides:
//! - Capability tokens with ed25519 signatures
//! - Resource patterns with glob matching
//! - Session and persistent token storage
//! - Token validation and authorization checking
//!
//! # Security Model
//!
//! Every capability token is:
//! - Signed by the runtime's ed25519 key
//! - Linked to the approval audit entry that created it
//! - Time-bounded (optional expiration)
//! - Scoped (session or persistent)
//!
//! # Example
//!
//! ```
//! use astrid_capabilities::{
//!     CapabilityToken, CapabilityStore, ResourcePattern, TokenScope, AuditEntryId,
//! };
//! use astrid_core::Permission;
//! use astrid_core::principal::PrincipalId;
//! use astrid_crypto::KeyPair;
//!
//! // Create a capability store
//! let store = CapabilityStore::in_memory();
//!
//! // Runtime key for signing
//! let runtime_key = KeyPair::generate();
//!
//! // Create a capability token for a specific principal (Layer 4, issue #668).
//! let principal = PrincipalId::default();
//! let token = CapabilityToken::create(
//!     ResourcePattern::new("mcp://filesystem:*").unwrap(),
//!     vec![Permission::Invoke],
//!     TokenScope::Session,
//!     runtime_key.key_id(),
//!     AuditEntryId::new(),
//!     &runtime_key,
//!     None,
//!     principal.clone(),
//! );
//!
//! // Add to store
//! store.add(token).unwrap();
//!
//! // Check capability (scoped by principal)
//! assert!(store.has_capability(&principal, "mcp://filesystem:read_file", Permission::Invoke));
//! ```

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![deny(unreachable_pub)]
#![deny(clippy::unwrap_used)]
#![cfg_attr(test, allow(clippy::unwrap_used))]

pub mod prelude;

mod error;
mod handle;
mod pattern;
mod policy;
mod store;
mod token;
mod validator;

pub use error::{CapabilityError, CapabilityResult};
pub use handle::{DirHandle, FileHandle};
pub use pattern::ResourcePattern;
pub use policy::{CapabilityCheck, PermissionError, device_scope_within};
pub use store::CapabilityStore;
pub use token::{AuditEntryId, CapabilityToken, TokenScope};
pub use validator::{AuthorizationResult, CapabilityValidator};
