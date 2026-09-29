//! Supporting types for the host-observed audit actions: the code identity a
//! host-call entry is attributed to, and provider request ids on HTTP
//! completions.

use astrid_crypto::ContentHash;
use serde::{Deserialize, Serialize};

/// Code identity of the capsule a host-observed entry is attributed to.
///
/// Stamped by the host from the capsule it loaded, never taken from the
/// guest: `capsule_id` is the manifest package name and `wasm_hash` is the
/// BLAKE3 hash of the wasm component the host verified before loading it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapsuleActor {
    /// Capsule id (manifest package name).
    pub capsule_id: String,
    /// BLAKE3 of the verified wasm component. `None` for capsules without a
    /// wasm component.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wasm_hash: Option<ContentHash>,
}

/// A provider request id taken from an HTTP response header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderRequestId {
    /// Lower-case response header name (for example `x-request-id`).
    pub header: String,
    /// Header value, truncated to a bounded length.
    pub value: String,
}
