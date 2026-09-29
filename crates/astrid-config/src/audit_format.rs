//! `audit.entry_format`: the signed layout of new audit entries.

use serde::{Deserialize, Serialize};

/// Signed layout of new audit entries (`audit.entry_format`).
///
/// `v2` signs a canonical CBOR body covering every field with a dedicated
/// audit key (`keys/audit.key`) and verifies entries against a cross-signed
/// key registry. Enabling it is one-way for a node: once the registry exists
/// the kernel keeps writing v2 even if this is set back to `v1`, because a
/// v1 entry after a v2 entry would reopen a chain under the weaker format.
/// Existing v1 entries are kept as they are. Only the operator's own
/// configuration can set this; a workspace layer cannot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditEntryFormat {
    /// The original entry format (default).
    #[default]
    V1,
    /// Canonical, fully signed entries verified against the key registry.
    V2,
}

#[cfg(test)]
mod tests {
    use super::AuditEntryFormat;
    use crate::Config;
    use crate::merge::{deep_merge, enforce_restrictions};

    #[test]
    fn v1_is_the_default() {
        assert_eq!(Config::default().audit.entry_format, AuditEntryFormat::V1);
        let defaults: Config = toml::from_str(include_str!("defaults.toml")).unwrap();
        assert_eq!(defaults.audit.entry_format, AuditEntryFormat::V1);
    }

    #[test]
    fn only_v1_and_v2_parse() {
        let config: Config = toml::from_str("[audit]\nentry_format = \"v2\"").unwrap();
        assert_eq!(config.audit.entry_format, AuditEntryFormat::V2);
        assert!(toml::from_str::<Config>("[audit]\nentry_format = \"v3\"").is_err());
        assert!(toml::from_str::<Config>("[audit]\nentry_format = \"V2\"").is_err());
    }

    #[test]
    fn a_workspace_layer_cannot_switch_the_format() {
        let baseline: toml::Value = toml::from_str("[audit]\nentry_format = \"v1\"").unwrap();
        let workspace: toml::Value = toml::from_str("[audit]\nentry_format = \"v2\"").unwrap();
        let mut merged = baseline.clone();
        deep_merge(&mut merged, &workspace);
        enforce_restrictions(&mut merged, &baseline, &workspace);
        assert_eq!(merged["audit"]["entry_format"].as_str(), Some("v1"));

        // An operator's own v2 survives a workspace that tries to reset it.
        let operator: toml::Value = toml::from_str("[audit]\nentry_format = \"v2\"").unwrap();
        let reset: toml::Value = toml::from_str("[audit]\nentry_format = \"v1\"").unwrap();
        let mut merged = operator.clone();
        deep_merge(&mut merged, &reset);
        enforce_restrictions(&mut merged, &operator, &reset);
        assert_eq!(merged["audit"]["entry_format"].as_str(), Some("v2"));
    }
}
