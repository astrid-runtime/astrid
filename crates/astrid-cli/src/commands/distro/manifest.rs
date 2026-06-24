//! Distro manifest types and parsing.
//!
//! Parses `Distro.toml` into strongly-typed [`DistroManifest`] with validation
//! for schema version, semver, identifier formats, and variable references.

use std::collections::HashMap;
use std::path::Path;

use anyhow::Context;
use serde::{Deserialize, Serialize};

/// Current supported schema version.
pub(crate) const SCHEMA_VERSION: u32 = 1;

/// A parsed distro manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct DistroManifest {
    /// Schema version for forward compatibility.
    pub(crate) schema_version: u32,
    /// Distro metadata.
    pub(crate) distro: DistroMeta,
    /// Shared variables for capsule env configuration.
    #[serde(default)]
    pub(crate) variables: HashMap<String, VariableDef>,
    /// Capsule entries in the distro.
    #[serde(default, rename = "capsule")]
    pub(crate) capsules: Vec<DistroCapsule>,
    /// Invite policy — when `Some`, the deployment ships with the
    /// `astrid-gateway` HTTP surface configured to accept new
    /// principals via invite redemption. `None` (the default) keeps
    /// the distro single-tenant: no public registration UI.
    ///
    /// The kernel never reads this directly — `astrid init` /
    /// `astrid distro apply` surfaces it to the operator and the
    /// gateway reads it through `/api/distribution`.
    #[serde(default)]
    pub(crate) invites: Option<InviteConfig>,
    /// Optional visual branding for the dashboard. The kernel and
    /// admin API ignore this entirely; only the gateway returns it
    /// through `/api/distribution`.
    #[serde(default)]
    pub(crate) branding: Option<BrandingConfig>,
}

/// Invite policy from `[invites]`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct InviteConfig {
    /// Group(s) allowed to issue invite tokens. An empty `issuers`
    /// list disables registration (single-tenant deployment). All
    /// names must be defined groups (built-in or custom).
    #[serde(default)]
    pub(crate) issuers: Vec<String>,
    /// Default group new redeemers join. Required when `issuers` is
    /// non-empty.
    #[serde(default)]
    pub(crate) default_group: Option<String>,
    /// Default token lifetime (e.g. `"24h"`, `"7d"`, `"30s"`).
    /// `None` falls back to the gateway's compiled-in default
    /// (24 hours).
    #[serde(default)]
    pub(crate) default_expires: Option<String>,
    /// Total-principal cap for the deployment. `"unlimited"` (the
    /// default) skips the check; integer strings cap the count.
    #[serde(default)]
    pub(crate) max_principals: Option<String>,
}

/// Visual branding from `[branding]`. Operator-controlled hints for
/// the dashboard.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) struct BrandingConfig {
    /// Icon — either a data URL (`data:image/svg+xml,...`) or a path
    /// relative to the distro root. Capped at 64 `KiB` on parse to
    /// keep malformed `Distro.toml` from ballooning memory.
    #[serde(default)]
    pub(crate) icon: Option<String>,
    /// Primary brand colour as a CSS hex string (`#RRGGBB`). The
    /// parser validates the shape; the dashboard interprets it.
    #[serde(default)]
    pub(crate) primary_color: Option<String>,
    /// Optional accent colour. Same shape constraints as
    /// [`Self::primary_color`].
    #[serde(default)]
    pub(crate) accent_color: Option<String>,
}

/// Distro identity and metadata (os-release style).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct DistroMeta {
    /// Machine-readable identifier (e.g. `astralis`).
    pub(crate) id: String,
    /// Display name (e.g. `Astralis`).
    pub(crate) name: String,
    /// Full human-readable string (e.g. `Astralis 0.1.0 (Genesis)`).
    #[serde(default)]
    pub(crate) pretty_name: Option<String>,
    /// Semantic version.
    pub(crate) version: String,
    /// Release codename (e.g. `genesis`).
    #[serde(default)]
    pub(crate) codename: Option<String>,
    /// Release date (YYYY-MM-DD).
    #[serde(default)]
    pub(crate) release_date: Option<String>,
    /// Short description.
    #[serde(default)]
    pub(crate) description: Option<String>,
    /// Original authors.
    #[serde(default)]
    pub(crate) authors: Vec<String>,
    /// Current maintainers.
    #[serde(default)]
    pub(crate) maintainers: Vec<String>,
    /// Homepage URL.
    #[serde(default)]
    pub(crate) homepage: Option<String>,
    /// Support URL.
    #[serde(default)]
    pub(crate) support: Option<String>,
    /// Bug tracker URL.
    #[serde(default)]
    pub(crate) bug_tracker: Option<String>,
    /// Source repository URL.
    #[serde(default)]
    pub(crate) repository: Option<String>,
    /// SPDX license identifier.
    #[serde(default)]
    pub(crate) license: Option<String>,
    /// Minimum Astrid runtime version required.
    #[serde(default)]
    pub(crate) astrid_version: Option<String>,
    /// Namespaced interface requirements.
    ///
    /// Outer key = namespace, inner key = interface name, value = semver requirement.
    /// Example: `[distro.requires.astrid] llm = "^1.0"`
    #[serde(default)]
    pub(crate) requires: HashMap<String, HashMap<String, String>>,
    /// Optional signing configuration. When present, declares the
    /// ed25519 public key the distro's maintainer signs `.shuttle`
    /// archives with. Drives trust-store pinning at install time.
    #[serde(default)]
    pub(crate) signing: Option<SigningConfig>,
}

/// Signing configuration from `[distro.signing]`.
///
/// The `pubkey` is the maintainer's ed25519 verification key in
/// `ed25519:<base64>` wire form. `endorses` carries a successor key for
/// future key-rotation chains — it is parsed and recorded but chain
/// verification is deferred (the field is wire-stable so older clients
/// don't reject manifests that carry it).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct SigningConfig {
    /// Maintainer verification key as `ed25519:<base64>`.
    pub(crate) pubkey: String,
    /// Successor key for rotation (wire field; chain verify deferred).
    #[serde(default)]
    pub(crate) endorses: Option<String>,
}

/// A shared variable defined at the distro level.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct VariableDef {
    /// Whether this variable holds a secret (masked during input).
    #[serde(default)]
    pub(crate) secret: bool,
    /// Human-readable description shown during prompts.
    #[serde(default)]
    pub(crate) description: Option<String>,
    /// Default value.
    #[serde(default)]
    pub(crate) default: Option<String>,
}

/// A capsule entry in the distro manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct DistroCapsule {
    /// Capsule package name (e.g. `astrid-capsule-session`).
    pub(crate) name: String,
    /// Source location (e.g. `@unicity-astrid/capsule-session`).
    pub(crate) source: String,
    /// Exact version to install (resolved to a git tag).
    pub(crate) version: String,
    /// Explicit git tag to install. Highest-priority ref selector —
    /// overrides `version` when both are set.
    #[serde(default)]
    pub(crate) tag: Option<String>,
    /// Git branch to track. Used when no tag/version pins a release.
    #[serde(default)]
    pub(crate) branch: Option<String>,
    /// Exact git revision (commit SHA) to install.
    #[serde(default)]
    pub(crate) rev: Option<String>,
    /// Whether this capsule is the default choice within its
    /// [`Self::group`] for non-interactive (`--yes`) selection.
    #[serde(default)]
    pub(crate) default: bool,
    /// Provider group for multi-select during init (e.g. `llm`).
    #[serde(default)]
    pub(crate) group: Option<String>,
    /// Deployment role (e.g. `uplink`).
    #[serde(default)]
    pub(crate) role: Option<String>,
    /// Environment variable mappings with `{{ var }}` template references.
    #[serde(default)]
    pub(crate) env: HashMap<String, String>,
}

/// Parse a `Distro.toml` string into a [`DistroManifest`].
pub(crate) fn parse_manifest(content: &str) -> anyhow::Result<DistroManifest> {
    let manifest: DistroManifest =
        toml::from_str(content).context("failed to parse Distro.toml")?;
    super::validate::validate_manifest(&manifest)?;
    Ok(manifest)
}

/// Load and parse a `Distro.toml` from disk.
pub(crate) fn load_manifest(path: &Path) -> anyhow::Result<DistroManifest> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    parse_manifest(&content)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
schema-version = 1

[distro]
id = "test"
name = "Test"
version = "0.1.0"

[[capsule]]
name = "astrid-capsule-cli"
source = "@unicity-astrid/capsule-cli"
version = "0.1.0"
role = "uplink"
"#;

    #[test]
    fn parse_minimal_manifest() {
        let m = parse_manifest(MINIMAL).unwrap();
        assert_eq!(m.schema_version, 1);
        assert_eq!(m.distro.id, "test");
        assert_eq!(m.distro.name, "Test");
        assert_eq!(m.distro.version, "0.1.0");
        assert_eq!(m.capsules.len(), 1);
        assert_eq!(m.capsules[0].name, "astrid-capsule-cli");
        assert_eq!(m.capsules[0].role.as_deref(), Some("uplink"));
    }

    #[test]
    fn parse_full_manifest() {
        let toml = r#"
schema-version = 1

[distro]
id = "astralis"
name = "Astralis"
pretty-name = "Astralis 0.1.0 (Genesis)"
version = "0.1.0"
codename = "genesis"
release-date = "2026-03-21"
description = "The complete Astrid AI assistant experience"
authors = ["Astrid Core Team"]
maintainers = ["Joshua J. Bouw <josh@unicity-labs.com>"]
homepage = "https://github.com/unicity-astrid/astralis"
support = "https://github.com/unicity-astrid/astrid/discussions"
bug-tracker = "https://github.com/unicity-astrid/astralis/issues"
repository = "https://github.com/unicity-astrid/astralis"
license = "MIT OR Apache-2.0"
astrid-version = ">=0.5.0"

[distro.requires.astrid]
llm = "^1.0"
session = "^1.0"

[variables]
api_key = { secret = true, description = "API key" }
base_url = { description = "Base URL", default = "https://api.openai.com" }

[[capsule]]
name = "astrid-capsule-cli"
source = "@unicity-astrid/capsule-cli"
version = "0.1.0"
role = "uplink"

[[capsule]]
name = "astrid-capsule-openai-compat"
source = "@unicity-astrid/capsule-openai-compat"
version = "0.1.0"
group = "llm"

[capsule.env]
api_key = "{{ api_key }}"
base_url = "{{ base_url }}"
"#;
        let m = parse_manifest(toml).unwrap();
        assert_eq!(m.distro.codename.as_deref(), Some("genesis"));
        assert_eq!(m.distro.maintainers.len(), 1);
        assert_eq!(m.variables.len(), 2);
        assert!(m.variables["api_key"].secret);
        assert_eq!(
            m.variables["base_url"].default.as_deref(),
            Some("https://api.openai.com")
        );
        assert_eq!(m.capsules.len(), 2);
        assert_eq!(m.capsules[1].group.as_deref(), Some("llm"));
        assert_eq!(m.capsules[1].env["api_key"], "{{ api_key }}");
        let requires = &m.distro.requires;
        assert_eq!(requires["astrid"]["llm"], "^1.0");
    }

    #[test]
    fn parse_capsule_ref_and_default_fields() {
        // Release selectors (`tag`, `default`, `group`) parse and
        // validate. `version`/`tag` are the only ref selectors allowed
        // in a distro manifest.
        let toml = r#"
schema-version = 1

[distro]
id = "test"
name = "Test"
version = "0.1.0"

[distro.signing]
pubkey = "ed25519:AAAA"

[[capsule]]
name = "astrid-capsule-cli"
source = "@org/cli"
version = "0.1.0"
role = "uplink"

[[capsule]]
name = "astrid-capsule-a"
source = "@org/a"
version = "0.2.0"
tag = "v0.2.0-rc1"
group = "llm"
default = true

[[capsule]]
name = "astrid-capsule-b"
source = "@org/b"
version = "0.3.0"
group = "llm"
"#;
        let m = parse_manifest(toml).unwrap();
        assert_eq!(m.distro.signing.as_ref().unwrap().pubkey, "ed25519:AAAA");
        let a = m
            .capsules
            .iter()
            .find(|c| c.name == "astrid-capsule-a")
            .unwrap();
        assert_eq!(a.tag.as_deref(), Some("v0.2.0-rc1"));
        assert!(a.default);
        let b = m
            .capsules
            .iter()
            .find(|c| c.name == "astrid-capsule-b")
            .unwrap();
        assert!(!b.default);
        assert_eq!(b.group.as_deref(), Some("llm"));
    }

    #[test]
    fn branch_and_rev_fields_still_deserialize_on_struct() {
        // The `branch`/`rev` fields stay ON `DistroCapsule` so validation
        // can name them in a friendly error (rather than serde producing
        // an opaque unknown-field failure). They parse syntactically; the
        // semantic rejection happens in `validate_manifest`, exercised in
        // the validate.rs tests. Bypass `parse_manifest` (which validates)
        // and deserialize the struct directly.
        let toml = r#"
schema-version = 1

[distro]
id = "test"
name = "Test"
version = "0.1.0"

[[capsule]]
name = "astrid-capsule-b"
source = "@org/b"
version = "0.3.0"
branch = "main"
rev = "abc123"
role = "uplink"
"#;
        let m: DistroManifest = toml::from_str(toml).unwrap();
        let b = &m.capsules[0];
        assert_eq!(b.branch.as_deref(), Some("main"));
        assert_eq!(b.rev.as_deref(), Some("abc123"));
        // And it is rejected once validated.
        assert!(parse_manifest(toml).is_err());
    }

    #[test]
    fn parse_rejects_wrong_schema_version() {
        let toml = r#"
schema-version = 99

[distro]
id = "test"
name = "Test"
version = "0.1.0"

[[capsule]]
name = "cli"
source = "@org/cli"
version = "0.1.0"
role = "uplink"
"#;
        let err = parse_manifest(toml).unwrap_err();
        assert!(err.to_string().contains("schema-version"), "got: {err}");
    }

    #[test]
    fn parse_rejects_invalid_distro_id() {
        let toml = r#"
schema-version = 1

[distro]
id = "INVALID"
name = "Test"
version = "0.1.0"

[[capsule]]
name = "cli"
source = "@org/cli"
version = "0.1.0"
role = "uplink"
"#;
        let err = parse_manifest(toml).unwrap_err();
        assert!(err.to_string().contains("distro.id"), "got: {err}");
    }

    #[test]
    fn parse_rejects_no_capsules() {
        let toml = r#"
schema-version = 1

[distro]
id = "test"
name = "Test"
version = "0.1.0"
"#;
        let err = parse_manifest(toml).unwrap_err();
        assert!(
            err.to_string().contains("at least one capsule"),
            "got: {err}"
        );
    }

    #[test]
    fn parse_rejects_no_uplink() {
        let toml = r#"
schema-version = 1

[distro]
id = "test"
name = "Test"
version = "0.1.0"

[[capsule]]
name = "astrid-capsule-session"
source = "@org/session"
version = "0.1.0"
"#;
        let err = parse_manifest(toml).unwrap_err();
        assert!(err.to_string().contains("uplink"), "got: {err}");
    }

    #[test]
    fn parse_rejects_duplicate_capsule_names() {
        let toml = r#"
schema-version = 1

[distro]
id = "test"
name = "Test"
version = "0.1.0"

[[capsule]]
name = "astrid-capsule-cli"
source = "@org/cli"
version = "0.1.0"
role = "uplink"

[[capsule]]
name = "astrid-capsule-cli"
source = "@org/cli2"
version = "0.2.0"
role = "uplink"
"#;
        let err = parse_manifest(toml).unwrap_err();
        assert!(err.to_string().contains("duplicate"), "got: {err}");
    }

    #[test]
    fn parse_rejects_undefined_variable_ref() {
        let toml = r#"
schema-version = 1

[distro]
id = "test"
name = "Test"
version = "0.1.0"

[[capsule]]
name = "astrid-capsule-cli"
source = "@org/cli"
version = "0.1.0"
role = "uplink"

[[capsule]]
name = "astrid-capsule-llm"
source = "@org/llm"
version = "0.1.0"

[capsule.env]
key = "{{ undefined_var }}"
"#;
        let err = parse_manifest(toml).unwrap_err();
        assert!(err.to_string().contains("undefined_var"), "got: {err}");
    }

    #[test]
    fn parse_rejects_invalid_distro_version() {
        let toml = r#"
schema-version = 1

[distro]
id = "test"
name = "Test"
version = "not_semver"

[[capsule]]
name = "cli"
source = "@org/cli"
version = "0.1.0"
role = "uplink"
"#;
        let err = parse_manifest(toml).unwrap_err();
        assert!(err.to_string().contains("version"), "got: {err}");
    }
}
