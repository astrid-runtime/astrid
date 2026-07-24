//! Static group-to-capability configuration (issue #670).
//!
//! A [`GroupConfig`] names a small set of built-in groups
//! ([`BUILTIN_ADMIN`], [`BUILTIN_AGENT`], [`BUILTIN_RESTRICTED`]) and
//! optionally merges operator-defined custom groups from
//! `$ASTRID_HOME/etc/groups.toml`. Each group confers a set of capability
//! patterns, evaluated left-to-right against the colon-delimited grammar
//! in [`crate::capability_grammar`].
//!
//! # Design contract
//!
//! - Built-in groups are baked in. Attempting to redefine them in
//!   `groups.toml` is a hard error at load time.
//! - Custom groups go through [`validate_capability`] for every entry.
//! - The universal `*` pattern is reserved for the built-in `admin`
//!   group. Custom groups may grant it only by explicitly opting in via
//!   `unsafe_admin = true` on that group; otherwise it's rejected at load.
//! - Missing `groups.toml` → built-ins only (the single-tenant default).
//! - Malformed TOML, unknown fields, or duplicate group names are hard
//!   errors — this fails the kernel boot, which is intentional.
//! - `GroupConfig::get` returning `None` for a name referenced by a
//!   principal profile is **not** an error here; the caller
//!   ([`CapabilityCheck`](../../../astrid-capabilities/src/policy.rs))
//!   treats it as fail-closed and logs a `warn!`.

mod io_impl;

use std::collections::{HashMap, HashSet};
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::capability_grammar::CapabilityGrammarError;
use crate::dirs::AstridHome;
use crate::profile::{CapabilityPattern, GroupName, ProfileFieldError};

/// Canonical name of the built-in administrator group.
pub const BUILTIN_ADMIN: &str = "admin";
/// Canonical name of the built-in agent group (self-scoped capabilities).
pub const BUILTIN_AGENT: &str = "agent";
/// Canonical name of the built-in restricted group (no capabilities).
pub const BUILTIN_RESTRICTED: &str = "restricted";

const BUILTIN_NAMES: [&str; 3] = [BUILTIN_ADMIN, BUILTIN_AGENT, BUILTIN_RESTRICTED];

/// Errors raised when loading or validating a [`GroupConfig`].
#[derive(Debug, Error)]
pub enum GroupConfigError {
    /// Filesystem IO failed while reading `groups.toml`.
    #[error("groups config io error: {0}")]
    Io(#[from] io::Error),
    /// `groups.toml` failed to parse as TOML, or contains unknown fields.
    #[error("groups config parse error: {0}")]
    Parse(#[from] toml::de::Error),
    /// A group entry attempts to redefine a reserved built-in group name.
    #[error("built-in group {name:?} may not be redefined in groups.toml")]
    RedefinedBuiltin {
        /// Name of the built-in group the config tried to overwrite.
        name: String,
    },
    /// Two different group entries share the same name.
    ///
    /// Note: the TOML parser itself rejects duplicate keys in a single
    /// table, but this variant covers the future case where multiple
    /// sources are merged.
    #[error("groups config declares {name:?} more than once")]
    DuplicateName {
        /// Duplicated group name.
        name: String,
    },
    /// A group entry uses a name outside the profile group-name grammar.
    #[error("groups config: group name {name:?} rejected: {reason}")]
    InvalidName {
        /// Raw group name that failed validation.
        name: String,
        /// Underlying group-name validation error.
        reason: ProfileFieldError,
    },
    /// A group entry contains a capability that fails the grammar
    /// validator.
    #[error("groups config: group {group:?} capability {cap:?} rejected: {reason}")]
    InvalidCapability {
        /// Name of the offending group.
        group: String,
        /// Raw capability string that failed validation.
        cap: String,
        /// Underlying grammar error.
        reason: CapabilityGrammarError,
    },
    /// A custom group grants the universal `*` capability without
    /// opting in to the `unsafe_admin` flag.
    #[error(
        "groups config: custom group {group:?} grants '*' (universal admin); \
         set `unsafe_admin = true` to confirm this elevation"
    )]
    UnsafeUniversalGrant {
        /// Name of the offending custom group.
        group: String,
    },
    /// A runtime admin mutation targets a group name that does not
    /// exist in the current config. Returned by
    /// [`GroupConfig::modify_custom_group`] and
    /// [`GroupConfig::remove_group`].
    #[error("groups config: unknown group {name:?}")]
    UnknownGroup {
        /// Name of the group that could not be located.
        name: String,
    },
}

/// Result alias for [`GroupConfig`] operations.
pub type GroupConfigResult<T> = Result<T, GroupConfigError>;

/// A named set of capability patterns.
///
/// Custom groups can opt-in to granting the universal `*` capability by
/// setting [`Group::unsafe_admin`] — intended as a safeguard against
/// typo-driven privilege escalation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Group {
    /// Capability patterns this group confers. Each pattern is validated
    /// by [`validate_capability`] at load time.
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Human-readable description surfaced in CLI and audit log views.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Opt-in flag: custom groups must set this to grant the universal
    /// `*` capability, making the elevation deliberate and visible in
    /// the config.
    #[serde(default)]
    pub unsafe_admin: bool,
}

/// The frozen group-to-capability map consumed by
/// [`CapabilityCheck`](../../../astrid-capabilities/src/policy.rs).
///
/// Built at kernel boot from built-ins merged with any operator-provided
/// `groups.toml`. Treat the resulting value as immutable — hot reload is
/// deferred to Layer 6.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupConfig {
    /// Group name → group definition.
    pub groups: HashMap<String, Group>,
}

/// Borrowed typed view over a string-shaped [`Group`].
///
/// `Group` remains the public/wire shape for TOML, JSON, and admin APIs.
/// Internal authorization code can use this view to keep group capability
/// patterns distinct from other string domains without cloning group config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedGroup<'a> {
    /// Validated capability patterns conferred by this group.
    pub capabilities: Vec<CapabilityPattern<&'a str>>,
}

/// Borrowed typed view over a string-shaped [`GroupConfig`].
///
/// The map keys are validated group names and each group contains validated
/// capability patterns. Construction fails closed if a public caller has built
/// an invalid in-memory [`GroupConfig`] without going through the loader or
/// mutation helpers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedGroupConfig<'a> {
    groups: HashMap<GroupName<&'a str>, ValidatedGroup<'a>>,
}

/// TOML wrapper: the on-disk representation uses a top-level `[groups.*]`
/// table so operators write `[groups.ops]` rather than a nested
/// `[[groups]]` array.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct GroupsFile {
    #[serde(default)]
    groups: HashMap<String, Group>,
}

impl GroupConfig {
    /// Canonical on-disk path for the system-wide groups config.
    #[must_use]
    pub fn path_for(home: &AstridHome) -> PathBuf {
        home.etc_dir().join("groups.toml")
    }

    /// Return a [`GroupConfig`] containing only the built-in groups.
    #[must_use]
    pub fn builtin_only() -> Self {
        let mut groups = HashMap::with_capacity(BUILTIN_NAMES.len());
        for (name, group) in builtin_entries() {
            groups.insert(name.to_string(), group);
        }
        Self { groups }
    }

    /// Load the group config from `home`'s `etc/groups.toml`, falling
    /// back to [`Self::builtin_only`] if the file is absent.
    ///
    /// # Errors
    ///
    /// See [`GroupConfigError`].
    pub fn load(home: &AstridHome) -> GroupConfigResult<Self> {
        Self::load_from_path(&Self::path_for(home))
    }

    /// Load the group config from an explicit path.
    ///
    /// # Errors
    ///
    /// See [`GroupConfigError`].
    pub fn load_from_path(path: &Path) -> GroupConfigResult<Self> {
        let contents = match crate::platform_fs::read_private_file_to_string(path) {
            Ok(c) => c,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Ok(Self::builtin_only());
            },
            Err(e) => return Err(GroupConfigError::Io(e)),
        };
        Self::from_toml_str(&contents)
    }

    /// Parse a [`GroupConfig`] from raw TOML, merging with the built-ins.
    ///
    /// # Errors
    ///
    /// See [`GroupConfigError`].
    pub fn from_toml_str(contents: &str) -> GroupConfigResult<Self> {
        let file: GroupsFile = toml::from_str(contents)?;
        Self::from_custom_groups(file.groups)
    }

    fn from_custom_groups(custom: HashMap<String, Group>) -> GroupConfigResult<Self> {
        // Reject redefinition of any built-in group.
        for name in custom.keys() {
            if is_builtin(name) {
                return Err(GroupConfigError::RedefinedBuiltin { name: name.clone() });
            }
            validate_group_name(name)?;
        }

        // Validate each custom group's capability entries.
        let mut seen: HashSet<&str> = HashSet::new();
        for (name, group) in &custom {
            if !seen.insert(name.as_str()) {
                return Err(GroupConfigError::DuplicateName { name: name.clone() });
            }
            validate_custom_group(name, group)?;
        }

        let mut groups = HashMap::with_capacity(BUILTIN_NAMES.len().saturating_add(custom.len()));
        for (name, group) in builtin_entries() {
            groups.insert(name.to_string(), group);
        }
        for (name, group) in custom {
            groups.insert(name, group);
        }

        let config = Self { groups };
        config.typed()?;
        Ok(config)
    }

    /// Look up a group by name, if present.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Group> {
        self.groups.get(name)
    }

    /// Number of groups in the resolved config (built-ins + custom).
    #[must_use]
    pub fn len(&self) -> usize {
        self.groups.len()
    }

    /// Whether the config contains no groups. Always `false` in practice
    /// because built-ins are baked in.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }

    /// Iterator over `(group_name, &Group)`.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &Group)> {
        self.groups.iter()
    }

    /// Return `true` if `name` refers to one of the reserved built-in
    /// groups ([`BUILTIN_ADMIN`], [`BUILTIN_AGENT`], [`BUILTIN_RESTRICTED`]).
    #[must_use]
    pub fn is_builtin_name(name: &str) -> bool {
        is_builtin(name)
    }

    /// Return a new [`GroupConfig`] with a custom group inserted.
    ///
    /// Validates the group with the same rules the boot loader applies
    /// to `groups.toml`: built-in names are rejected, every capability
    /// passes [`validate_capability`], and the universal `*` pattern
    /// requires `unsafe_admin = true`.
    ///
    /// # Errors
    ///
    /// - [`GroupConfigError::RedefinedBuiltin`] if `name` is a built-in.
    /// - [`GroupConfigError::DuplicateName`] if `name` already exists in
    ///   the custom set (an existing custom group must be removed or
    ///   modified, not re-inserted).
    /// - [`GroupConfigError::InvalidCapability`] on a bad capability
    ///   string.
    /// - [`GroupConfigError::UnsafeUniversalGrant`] if `group.capabilities`
    ///   contains `*` without `unsafe_admin = true`.
    pub fn insert_custom_group(&self, name: String, group: Group) -> GroupConfigResult<Self> {
        if is_builtin(&name) {
            return Err(GroupConfigError::RedefinedBuiltin { name });
        }
        validate_group_name(&name)?;
        if self.groups.contains_key(&name) {
            return Err(GroupConfigError::DuplicateName { name });
        }
        validate_custom_group(&name, &group)?;

        let mut next = self.groups.clone();
        next.insert(name, group);
        let config = Self { groups: next };
        config.typed()?;
        Ok(config)
    }

    /// Return a new [`GroupConfig`] with a partial update applied to a
    /// custom group. Any field left as `None` is preserved.
    ///
    /// # Errors
    ///
    /// - [`GroupConfigError::RedefinedBuiltin`] if `name` is a built-in.
    /// - [`GroupConfigError::DuplicateName`] if `name` is unknown — modify
    ///   is strictly an update, not an upsert.
    /// - [`GroupConfigError::InvalidCapability`] /
    ///   [`GroupConfigError::UnsafeUniversalGrant`] from revalidation.
    pub fn modify_custom_group(
        &self,
        name: &str,
        capabilities: Option<Vec<String>>,
        description: Option<Option<String>>,
        unsafe_admin: Option<bool>,
    ) -> GroupConfigResult<Self> {
        if is_builtin(name) {
            return Err(GroupConfigError::RedefinedBuiltin {
                name: name.to_string(),
            });
        }
        validate_group_name(name)?;
        let existing = self
            .groups
            .get(name)
            .ok_or_else(|| GroupConfigError::UnknownGroup {
                name: name.to_string(),
            })?;
        let mut updated = existing.clone();
        if let Some(caps) = capabilities {
            updated.capabilities = caps;
        }
        if let Some(desc) = description {
            updated.description = desc;
        }
        if let Some(flag) = unsafe_admin {
            updated.unsafe_admin = flag;
        }
        validate_custom_group(name, &updated)?;

        let mut next = self.groups.clone();
        next.insert(name.to_string(), updated);
        let config = Self { groups: next };
        config.typed()?;
        Ok(config)
    }

    /// Return a new [`GroupConfig`] with `name` removed.
    ///
    /// Built-in groups cannot be removed and produce
    /// [`GroupConfigError::RedefinedBuiltin`]. Removing an unknown custom
    /// group produces [`GroupConfigError::DuplicateName`] (reused as the
    /// "not a custom group I know about" sentinel).
    ///
    /// # Errors
    ///
    /// See above.
    pub fn remove_group(&self, name: &str) -> GroupConfigResult<Self> {
        if is_builtin(name) {
            return Err(GroupConfigError::RedefinedBuiltin {
                name: name.to_string(),
            });
        }
        validate_group_name(name)?;
        if !self.groups.contains_key(name) {
            return Err(GroupConfigError::UnknownGroup {
                name: name.to_string(),
            });
        }
        let mut next = self.groups.clone();
        next.remove(name);
        Ok(Self { groups: next })
    }

    /// Convert this public string-shaped config into a borrowed typed view.
    ///
    /// # Errors
    ///
    /// Returns [`GroupConfigError`] if any group name or capability pattern
    /// violates the same grammar enforced by load and mutation helpers.
    pub fn typed(&self) -> GroupConfigResult<ValidatedGroupConfig<'_>> {
        ValidatedGroupConfig::try_from(self)
    }
}

impl<'a> ValidatedGroupConfig<'a> {
    /// Look up a validated group by validated group name.
    #[must_use]
    pub fn get(&self, name: &GroupName<&'a str>) -> Option<&ValidatedGroup<'a>> {
        self.groups.get(name)
    }
}

impl<'a> TryFrom<&'a GroupConfig> for ValidatedGroupConfig<'a> {
    type Error = GroupConfigError;

    fn try_from(config: &'a GroupConfig) -> Result<Self, Self::Error> {
        let mut groups = HashMap::with_capacity(config.groups.len());
        for (name, group) in &config.groups {
            let name =
                GroupName::new(name.as_str()).map_err(|reason| GroupConfigError::InvalidName {
                    name: name.clone(),
                    reason,
                })?;
            let group = validate_group_view(name.as_str(), group)?;
            if groups.insert(name, group).is_some() {
                return Err(GroupConfigError::DuplicateName {
                    name: name.as_str().to_string(),
                });
            }
        }
        Ok(Self { groups })
    }
}

impl Default for GroupConfig {
    fn default() -> Self {
        Self::builtin_only()
    }
}

fn is_builtin(name: &str) -> bool {
    BUILTIN_NAMES.contains(&name)
}

fn validate_group_name(name: &str) -> GroupConfigResult<GroupName<&str>> {
    GroupName::new(name).map_err(|reason| GroupConfigError::InvalidName {
        name: name.to_string(),
        reason,
    })
}

fn builtin_entries() -> [(&'static str, Group); 3] {
    [
        (
            BUILTIN_ADMIN,
            Group {
                capabilities: vec!["*".to_string()],
                description: Some("Built-in administrator — universal capability grant".into()),
                // `admin` is the one group the universal `*` is reserved for;
                // the `unsafe_admin` flag is a custom-group concern.
                unsafe_admin: false,
            },
        ),
        (
            BUILTIN_AGENT,
            Group {
                // `self:*` already subsumes self:quota:get / self:agent:list,
                // but they are listed explicitly so operators reading the
                // built-ins can see that agents have self-service visibility
                // into their own quota and agent row (issue #672 Layer 6).
                capabilities: vec![
                    "self:*".to_string(),
                    "self:quota:get".to_string(),
                    "self:agent:list".to_string(),
                    "delegate:self:*".to_string(),
                ],
                description: Some(
                    "Built-in agent — self-scoped capability grants for routine agent workflows"
                        .into(),
                ),
                unsafe_admin: false,
            },
        ),
        (
            BUILTIN_RESTRICTED,
            Group {
                capabilities: Vec::new(),
                description: Some(
                    "Built-in restricted — no implicit capabilities; grants must be explicit"
                        .into(),
                ),
                unsafe_admin: false,
            },
        ),
    ]
}

fn validate_custom_group(name: &str, group: &Group) -> GroupConfigResult<()> {
    validate_group_name(name)?;
    for cap in &group.capabilities {
        validate_group_capability(name, cap)?;
        if cap == "*" && !group.unsafe_admin {
            return Err(GroupConfigError::UnsafeUniversalGrant {
                group: name.to_string(),
            });
        }
    }
    Ok(())
}

fn validate_group_view<'a>(name: &str, group: &'a Group) -> GroupConfigResult<ValidatedGroup<'a>> {
    let capabilities = group
        .capabilities
        .iter()
        .map(|cap| {
            let pattern = validate_group_capability(name, cap.as_str())?;
            if pattern == "*" && !group.unsafe_admin && name != BUILTIN_ADMIN {
                return Err(GroupConfigError::UnsafeUniversalGrant {
                    group: name.to_string(),
                });
            }
            Ok(pattern)
        })
        .collect::<GroupConfigResult<_>>()?;
    Ok(ValidatedGroup { capabilities })
}

fn validate_group_capability<'a>(
    group: &str,
    cap: &'a str,
) -> GroupConfigResult<CapabilityPattern<&'a str>> {
    match CapabilityPattern::new(cap) {
        Ok(pattern) => Ok(pattern),
        Err(ProfileFieldError::InvalidCapabilityPattern(reason)) => {
            Err(GroupConfigError::InvalidCapability {
                group: group.to_string(),
                cap: cap.to_string(),
                reason,
            })
        },
        Err(other) => unreachable!("CapabilityPattern only returns capability errors: {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    use tempfile::tempdir;

    #[test]
    fn builtin_only_contains_admin_agent_restricted() {
        let cfg = GroupConfig::builtin_only();
        assert_eq!(cfg.len(), 3);
        assert_eq!(
            cfg.get(BUILTIN_ADMIN).unwrap().capabilities,
            vec!["*".to_string()]
        );
        // Agent gets self:* plus explicit self-service visibility caps
        // (self:quota:get, self:agent:list) added in Layer 6 / issue #672.
        let agent_caps = &cfg.get(BUILTIN_AGENT).unwrap().capabilities;
        assert!(agent_caps.contains(&"self:*".to_string()));
        assert!(agent_caps.contains(&"self:quota:get".to_string()));
        assert!(agent_caps.contains(&"self:agent:list".to_string()));
        assert!(agent_caps.contains(&"delegate:self:*".to_string()));
        assert!(cfg.get(BUILTIN_RESTRICTED).unwrap().capabilities.is_empty());
    }

    #[test]
    fn load_missing_file_returns_builtins() {
        let dir = tempdir().unwrap();
        let home = AstridHome::from_path(dir.path());
        assert!(!GroupConfig::path_for(&home).exists());
        let cfg = GroupConfig::load(&home).unwrap();
        assert_eq!(cfg.len(), 3);
    }

    #[test]
    fn load_merges_custom_groups_with_builtins() {
        let toml_doc = r#"
            [groups.ops]
            description = "Deployment operators"
            capabilities = ["capsule:install", "capsule:remove"]

            [groups.auditor]
            capabilities = ["audit:read", "agent:list"]
        "#;
        let cfg = GroupConfig::from_toml_str(toml_doc).unwrap();
        assert_eq!(cfg.len(), 5);
        assert_eq!(
            cfg.get("ops").unwrap().capabilities,
            vec!["capsule:install".to_string(), "capsule:remove".to_string()]
        );
        assert_eq!(cfg.get("auditor").unwrap().capabilities.len(), 2);
        // Built-ins remain intact.
        assert_eq!(
            cfg.get(BUILTIN_ADMIN).unwrap().capabilities,
            vec!["*".to_string()]
        );
    }

    #[test]
    fn rejects_redefined_builtin() {
        let toml_doc = r#"
            [groups.admin]
            capabilities = ["custom:garbage"]
        "#;
        let err = GroupConfig::from_toml_str(toml_doc).unwrap_err();
        match err {
            GroupConfigError::RedefinedBuiltin { name } => assert_eq!(name, BUILTIN_ADMIN),
            other => panic!("expected RedefinedBuiltin, got: {other:?}"),
        }
    }

    #[test]
    fn rejects_redefined_agent_builtin() {
        let toml_doc = r#"
            [groups.agent]
            capabilities = ["self:capsule:install"]
        "#;
        assert!(matches!(
            GroupConfig::from_toml_str(toml_doc),
            Err(GroupConfigError::RedefinedBuiltin { .. })
        ));
    }

    #[test]
    fn rejects_unknown_top_level_field() {
        let toml_doc = r#"
            typo_field = true
            [groups.ops]
            capabilities = ["capsule:install"]
        "#;
        assert!(matches!(
            GroupConfig::from_toml_str(toml_doc),
            Err(GroupConfigError::Parse(_))
        ));
    }

    #[test]
    fn rejects_unknown_group_field() {
        let toml_doc = "
            [groups.ops]
            priviledges = []
        ";
        assert!(matches!(
            GroupConfig::from_toml_str(toml_doc),
            Err(GroupConfigError::Parse(_))
        ));
    }

    #[test]
    fn rejects_invalid_group_name_key() {
        let toml_doc = r#"
            [groups."ops/team"]
            capabilities = ["capsule:install"]
        "#;
        let err = GroupConfig::from_toml_str(toml_doc).unwrap_err();
        match err {
            GroupConfigError::InvalidName { name, .. } => assert_eq!(name, "ops/team"),
            other => panic!("expected InvalidName, got: {other:?}"),
        }
    }

    #[test]
    fn rejects_invalid_capability_grammar() {
        let toml_doc = r#"
            [groups.ops]
            capabilities = ["system:shut down"]
        "#;
        let err = GroupConfig::from_toml_str(toml_doc).unwrap_err();
        match err {
            GroupConfigError::InvalidCapability { group, cap, .. } => {
                assert_eq!(group, "ops");
                assert_eq!(cap, "system:shut down");
            },
            other => panic!("expected InvalidCapability, got: {other:?}"),
        }
    }

    #[test]
    fn rejects_custom_group_with_universal_star_without_opt_in() {
        let toml_doc = r#"
            [groups.privileged]
            capabilities = ["*"]
        "#;
        let err = GroupConfig::from_toml_str(toml_doc).unwrap_err();
        assert!(matches!(err, GroupConfigError::UnsafeUniversalGrant { .. }));
    }

    #[test]
    fn accepts_custom_group_with_universal_star_and_opt_in() {
        let toml_doc = r#"
            [groups.privileged]
            unsafe_admin = true
            capabilities = ["*"]
        "#;
        let cfg = GroupConfig::from_toml_str(toml_doc).unwrap();
        assert_eq!(
            cfg.get("privileged").unwrap().capabilities,
            vec!["*".to_string()]
        );
        assert!(cfg.get("privileged").unwrap().unsafe_admin);
    }

    #[test]
    fn rejects_double_glob_capability() {
        let toml_doc = r#"
            [groups.ops]
            capabilities = ["capsule:**"]
        "#;
        let err = GroupConfig::from_toml_str(toml_doc).unwrap_err();
        match err {
            GroupConfigError::InvalidCapability { reason, .. } => {
                assert_eq!(reason, CapabilityGrammarError::DoubleStar);
            },
            other => panic!("expected InvalidCapability(DoubleStar), got: {other:?}"),
        }
    }

    #[test]
    fn load_from_path_parses_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("groups.toml");
        fs::write(
            &path,
            "[groups.ops]\ncapabilities = [\"capsule:install\"]\n",
        )
        .unwrap();
        let cfg = GroupConfig::load_from_path(&path).unwrap();
        assert!(cfg.get("ops").is_some());
    }

    #[test]
    fn get_returns_none_for_unknown_name() {
        let cfg = GroupConfig::builtin_only();
        assert!(cfg.get("not-a-real-group").is_none());
    }

    // ── Runtime mutation helpers (issue #672) ─────────────────────────

    fn custom(caps: &[&str]) -> Group {
        Group {
            capabilities: caps.iter().map(|s| (*s).to_string()).collect(),
            description: None,
            unsafe_admin: false,
        }
    }

    #[test]
    fn insert_custom_group_adds_and_validates() {
        let cfg = GroupConfig::builtin_only();
        let next = cfg
            .insert_custom_group("ops".to_string(), custom(&["capsule:install"]))
            .unwrap();
        assert!(next.get("ops").is_some());
        // Original untouched (returned by value, immutable).
        assert!(cfg.get("ops").is_none());
    }

    #[test]
    fn insert_custom_group_rejects_builtin_name() {
        let cfg = GroupConfig::builtin_only();
        let err = cfg
            .insert_custom_group(BUILTIN_ADMIN.to_string(), custom(&["system:shutdown"]))
            .unwrap_err();
        assert!(matches!(err, GroupConfigError::RedefinedBuiltin { .. }));
    }

    #[test]
    fn insert_custom_group_rejects_duplicate_name() {
        let cfg = GroupConfig::builtin_only()
            .insert_custom_group("ops".to_string(), custom(&["capsule:install"]))
            .unwrap();
        let err = cfg
            .insert_custom_group("ops".to_string(), custom(&["audit:read"]))
            .unwrap_err();
        assert!(matches!(err, GroupConfigError::DuplicateName { .. }));
    }

    #[test]
    fn insert_custom_group_rejects_invalid_group_name() {
        let err = GroupConfig::builtin_only()
            .insert_custom_group("ops/team".to_string(), custom(&["capsule:install"]))
            .unwrap_err();
        assert!(matches!(err, GroupConfigError::InvalidName { .. }));
    }

    #[test]
    fn insert_custom_group_rejects_unsafe_star_without_opt_in() {
        let err = GroupConfig::builtin_only()
            .insert_custom_group("privileged".to_string(), custom(&["*"]))
            .unwrap_err();
        assert!(matches!(err, GroupConfigError::UnsafeUniversalGrant { .. }));
    }

    #[test]
    fn typed_view_rejects_manual_unsafe_star_without_opt_in() {
        let cfg = GroupConfig {
            groups: HashMap::from([(
                "privileged".to_string(),
                Group {
                    capabilities: vec!["*".to_string()],
                    description: None,
                    unsafe_admin: false,
                },
            )]),
        };
        let err = cfg.typed().unwrap_err();
        assert!(matches!(err, GroupConfigError::UnsafeUniversalGrant { .. }));
    }

    #[test]
    fn typed_view_accepts_builtin_admin_star() {
        let cfg = GroupConfig::builtin_only();
        let typed = cfg.typed().unwrap();
        assert!(
            typed.get(&GroupName::new(BUILTIN_ADMIN).unwrap()).is_some(),
            "built-in admin must remain valid despite unsafe_admin=false"
        );
    }

    #[test]
    fn insert_custom_group_rejects_invalid_capability_grammar() {
        let err = GroupConfig::builtin_only()
            .insert_custom_group("bad".to_string(), custom(&["system:shut down"]))
            .unwrap_err();
        assert!(matches!(err, GroupConfigError::InvalidCapability { .. }));
    }

    #[test]
    fn modify_custom_group_updates_capabilities() {
        let cfg = GroupConfig::builtin_only()
            .insert_custom_group("ops".to_string(), custom(&["capsule:install"]))
            .unwrap();
        let next = cfg
            .modify_custom_group(
                "ops",
                Some(vec!["capsule:install".into(), "capsule:remove".into()]),
                None,
                None,
            )
            .unwrap();
        assert_eq!(next.get("ops").unwrap().capabilities.len(), 2);
    }

    #[test]
    fn modify_custom_group_partial_update_preserves_other_fields() {
        let cfg = GroupConfig::builtin_only()
            .insert_custom_group(
                "ops".to_string(),
                Group {
                    capabilities: vec!["capsule:install".into()],
                    description: Some("original".into()),
                    unsafe_admin: false,
                },
            )
            .unwrap();
        let next = cfg
            .modify_custom_group("ops", None, Some(Some("updated".into())), None)
            .unwrap();
        let g = next.get("ops").unwrap();
        assert_eq!(g.description.as_deref(), Some("updated"));
        assert_eq!(g.capabilities, vec!["capsule:install".to_string()]);
    }

    #[test]
    fn modify_custom_group_rejects_builtin() {
        let cfg = GroupConfig::builtin_only();
        let err = cfg
            .modify_custom_group(BUILTIN_ADMIN, Some(vec!["audit:read".into()]), None, None)
            .unwrap_err();
        assert!(matches!(err, GroupConfigError::RedefinedBuiltin { .. }));
    }

    #[test]
    fn modify_custom_group_rejects_unknown_name() {
        let cfg = GroupConfig::builtin_only();
        let err = cfg
            .modify_custom_group("never-defined", Some(vec![]), None, None)
            .unwrap_err();
        assert!(matches!(err, GroupConfigError::UnknownGroup { .. }));
    }

    #[test]
    fn modify_custom_group_revalidates_new_capabilities() {
        let cfg = GroupConfig::builtin_only()
            .insert_custom_group("ops".to_string(), custom(&["capsule:install"]))
            .unwrap();
        let err = cfg
            .modify_custom_group(
                "ops",
                Some(vec!["system:shut down".into()]), // bad grammar
                None,
                None,
            )
            .unwrap_err();
        assert!(matches!(err, GroupConfigError::InvalidCapability { .. }));
    }

    #[test]
    fn remove_group_drops_custom_group() {
        let cfg = GroupConfig::builtin_only()
            .insert_custom_group("ops".to_string(), custom(&["capsule:install"]))
            .unwrap();
        assert!(cfg.get("ops").is_some());
        let next = cfg.remove_group("ops").unwrap();
        assert!(next.get("ops").is_none());
        // Built-ins survive.
        assert!(next.get(BUILTIN_ADMIN).is_some());
    }

    #[test]
    fn remove_group_rejects_every_builtin() {
        let cfg = GroupConfig::builtin_only();
        for name in [BUILTIN_ADMIN, BUILTIN_AGENT, BUILTIN_RESTRICTED] {
            let err = cfg.remove_group(name).unwrap_err();
            assert!(
                matches!(err, GroupConfigError::RedefinedBuiltin { .. }),
                "expected RedefinedBuiltin for {name}, got {err:?}"
            );
        }
    }

    #[test]
    fn remove_group_rejects_unknown_name() {
        let cfg = GroupConfig::builtin_only();
        let err = cfg.remove_group("never-defined").unwrap_err();
        assert!(matches!(err, GroupConfigError::UnknownGroup { .. }));
    }

    #[test]
    fn is_builtin_name_covers_every_builtin() {
        assert!(GroupConfig::is_builtin_name(BUILTIN_ADMIN));
        assert!(GroupConfig::is_builtin_name(BUILTIN_AGENT));
        assert!(GroupConfig::is_builtin_name(BUILTIN_RESTRICTED));
        assert!(!GroupConfig::is_builtin_name("ops"));
    }
}
