//! Typed capsule metadata shared by authenticated kernel clients.

use serde::{Deserialize, Serialize};

/// Dynamic option-discovery metadata for a capsule environment field.
///
/// This mirrors the non-secret portion of a verified manifest's
/// `options_from` declaration without exposing any configured values.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapsuleEnvOptionsFromMetadata {
    /// HTTP endpoint template used for option discovery.
    pub http: String,
    /// Optional bearer-token template.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bearer: Option<String>,
    /// JSON shape identifying the option list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub select: Option<String>,
    /// Environment keys that must be collected first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub after: Vec<String>,
}
