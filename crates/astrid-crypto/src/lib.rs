//! Astrid Crypto - Cryptographic primitives for the secure agent runtime.
//!
//! This crate provides:
//! - Ed25519 key pairs with secure memory handling
//! - Signatures for capability tokens and audit entries
//! - BLAKE3 content hashing for audit chains and verification
//!
//! # Security Philosophy
//!
//! **Cryptography over prompts.** Authorization comes from ed25519 signatures
//! and capability tokens, not from hoping the LLM follows instructions.
//!
//! # Example
//!
//! ```
//! use astrid_crypto::{KeyPair, ContentHash};
//!
//! // Generate a new key pair
//! let keypair = KeyPair::generate();
//!
//! // Sign a message
//! let message = b"important data";
//! let signature = keypair.sign(message);
//!
//! // Verify the signature
//! assert!(keypair.verify(message, &signature).is_ok());
//!
//! // Hash content
//! let hash = ContentHash::hash(message);
//! println!("Hash: {}", hash.to_hex());
//! ```

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![deny(unreachable_pub)]
#![deny(clippy::unwrap_used)]
#![cfg_attr(test, allow(clippy::unwrap_used))]

pub mod prelude;

mod error;
mod hash;
mod identifier;
mod keypair;
mod signature;

pub use error::{CryptoError, CryptoResult};
pub use hash::ContentHash;
pub use identifier::{IdentifierHash, PublicKeyFingerprint};
pub use keypair::{KeyPair, PublicKey};
pub use signature::Signature;
