//! Prelude module - commonly used types for convenient import.
//!
//! Use `use astrid_capabilities::prelude::*;` to import all essential types.
//!
//! # Example
//!
//! ```rust
//! use astrid_capabilities::prelude::*;
//! use astrid_crypto::KeyPair;
//! use astrid_core::Permission;
//! use astrid_core::principal::PrincipalId;
//!
//! # #[tokio::main(flavor = "current_thread")]
//! # async fn main() {
//! // Create a capability store
//! let store = CapabilityStore::in_memory();
//!
//! // Create a token for a specific principal (Layer 4, issue #668).
//! let runtime_key = KeyPair::generate();
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
//! // Add and check capability (scoped by principal).
//! store.add(token).await.unwrap();
//! assert!(
//!     store
//!         .has_capability(&principal, "mcp://filesystem:read_file", Permission::Invoke)
//!         .await
//! );
//! # }
//! ```

// Errors
pub use crate::{CapabilityError, CapabilityResult};

// Token types
pub use crate::{AuditEntryId, CapabilityToken, TokenScope};

// Resource patterns
pub use crate::ResourcePattern;

// Store and validation
pub use crate::CapabilityStore;
pub use crate::{AuthorizationResult, CapabilityValidator};
