//! Distro manifest validation.
//!
//! Validates structural constraints that TOML deserialization alone cannot
//! enforce: schema version, identifier formats, semver, variable references,
//! role presence, and duplicate names.

use std::collections::HashSet;

use super::manifest::{DistroManifest, SCHEMA_VERSION};

/// Check if a string is a valid identifier: `^[a-z][a-z0-9-]*$`.
fn is_valid_id(s: &str) -> bool {
    let mut chars = s.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_lowercase()
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// Extract `{{ var_name }}` references from a template string.
fn extract_variable_refs(template: &str) -> Vec<&str> {
    template
        .split("{{")
        .skip(1)
        .filter_map(|s| s.split_once("}}"))
        .map(|(var, _)| var.trim())
        .filter(|var| !var.is_empty())
        .collect()
}

/// Validate a parsed distro manifest.
///
/// Checks that cannot be expressed in serde alone:
/// - Schema version is supported
/// - Distro ID format
/// - Distro version is valid semver
/// - astrid-version (if set) is valid semver requirement
/// - No duplicate capsule names
/// - At least one capsule
/// - At least one capsule with role = "uplink"
/// - Variable references in capsule env resolve to defined variables
/// - Requires version strings are valid semver requirements
#[allow(
    clippy::too_many_lines,
    reason = "flat sequence of independent validation checks; \
              inlining keeps the full ruleset auditable in one place"
)]
pub(crate) fn validate_manifest(manifest: &DistroManifest) -> anyhow::Result<()> {
    // Schema version.
    if manifest.schema_version != SCHEMA_VERSION {
        anyhow::bail!(
            "unsupported schema-version {} (expected {SCHEMA_VERSION})",
            manifest.schema_version,
        );
    }

    // Distro ID format.
    if !is_valid_id(&manifest.distro.id) {
        anyhow::bail!(
            "distro.id '{}' is invalid (must match ^[a-z][a-z0-9-]*$)",
            manifest.distro.id,
        );
    }

    // Distro version is valid semver.
    if semver::Version::parse(&manifest.distro.version).is_err() {
        anyhow::bail!(
            "distro.version '{}' is not valid semver",
            manifest.distro.version,
        );
    }

    // astrid-version is valid semver requirement (if set).
    if let Some(ref av) = manifest.distro.astrid_version
        && semver::VersionReq::parse(av).is_err()
    {
        anyhow::bail!("distro.astrid-version '{av}' is not a valid semver requirement");
    }

    // Requires version strings are valid semver requirements.
    for (ns, ifaces) in &manifest.distro.requires {
        for (name, req) in ifaces {
            if semver::VersionReq::parse(req).is_err() {
                anyhow::bail!(
                    "distro.requires.{ns}.{name} '{req}' is not a valid semver requirement",
                );
            }
        }
    }

    // At least one capsule.
    if manifest.capsules.is_empty() {
        anyhow::bail!("distro must contain at least one capsule");
    }

    // No duplicate capsule names, and each name must be a valid
    // identifier. Names become path components in the `.shuttle` layout
    // (`capsules/<name>.capsule`) and on disk under the capsule store;
    // constraining them to `^[a-z][a-z0-9-]*$` keeps a manifest from
    // introducing `/`, `..`, or other path-hostile characters there.
    let mut seen_names = HashSet::new();
    for cap in &manifest.capsules {
        if !is_valid_id(&cap.name) {
            anyhow::bail!(
                "capsule name '{}' is invalid (must match ^[a-z][a-z0-9-]*$)",
                cap.name,
            );
        }
        if !seen_names.insert(&cap.name) {
            anyhow::bail!("duplicate capsule name '{}'", cap.name);
        }
        // Distros compose *released* capsules. `branch`/`rev` selectors
        // can only be honored by compiling from a git ref — the exact
        // toolchain dependency offline/headless distro seeding exists to
        // remove. Reject them: a distro must pin a released `version` or
        // `tag`. (Git-ref installs remain available via the standalone
        // `astrid capsule install` command.)
        if cap.branch.is_some() || cap.rev.is_some() {
            anyhow::bail!(
                "capsule '{}': branch/rev require building from source and are not allowed in a \
                 distro manifest — pin a released `version` or `tag` (git-ref installs are \
                 available via `astrid capsule install`).",
                cap.name,
            );
        }
    }

    // At least one uplink.
    let has_uplink = manifest
        .capsules
        .iter()
        .any(|c| c.role.as_deref() == Some("uplink"));
    if !has_uplink {
        anyhow::bail!("distro must have at least one capsule with role = \"uplink\" (a frontend)");
    }

    // Variable references in capsule env.
    let defined_vars: HashSet<&str> = manifest.variables.keys().map(String::as_str).collect();
    for cap in &manifest.capsules {
        for (key, value) in &cap.env {
            for var_ref in extract_variable_refs(value) {
                if !defined_vars.contains(var_ref) {
                    anyhow::bail!(
                        "capsule '{}' env.{key} references undefined variable '{{{{ {var_ref} }}}}'",
                        cap.name,
                    );
                }
            }
        }
    }

    // Invite policy — additive, so the rule is "if any field is set,
    // the shape must be coherent". The kernel still cap-gates issuance
    // at runtime; this is fail-fast for typos.
    if let Some(invites) = &manifest.invites {
        if !invites.issuers.is_empty() && invites.default_group.is_none() {
            anyhow::bail!(
                "invites.issuers is non-empty but invites.default-group is unset — \
                 either configure both or remove the [invites] section"
            );
        }
        if let Some(exp) = &invites.default_expires {
            parse_invite_duration(exp).map_err(|e| anyhow::anyhow!(e))?;
        }
        if let Some(cap) = &invites.max_principals
            && cap != "unlimited"
            && cap.parse::<u32>().is_err()
        {
            anyhow::bail!(
                "invites.max-principals must be \"unlimited\" or a non-negative integer (got {cap:?})",
            );
        }
    }

    // Branding — only structural rails. The dashboard interprets the
    // values; the parser just refuses obvious garbage.
    if let Some(branding) = &manifest.branding {
        if let Some(icon) = &branding.icon
            && icon.len() > 64 * 1024
        {
            anyhow::bail!(
                "branding.icon is {} bytes — distros must not embed assets larger than 64 KiB",
                icon.len()
            );
        }
        if let Some(color) = &branding.primary_color {
            validate_hex_color(color)
                .map_err(|e| anyhow::anyhow!("branding.primary-color: {e}"))?;
        }
        if let Some(color) = &branding.accent_color {
            validate_hex_color(color).map_err(|e| anyhow::anyhow!("branding.accent-color: {e}"))?;
        }
    }

    Ok(())
}

/// Parse the operator-friendly duration form (`24h`, `7d`, `30m`, `30s`)
/// into seconds. The kernel caps at 30 days regardless.
pub(crate) fn parse_invite_duration(input: &str) -> Result<u64, String> {
    let trimmed = input.trim();
    let (num_str, multiplier_secs) = if let Some(s) = trimmed.strip_suffix('s') {
        (s, 1_u64)
    } else if let Some(s) = trimmed.strip_suffix('m') {
        (s, 60)
    } else if let Some(s) = trimmed.strip_suffix('h') {
        (s, 3_600)
    } else if let Some(s) = trimmed.strip_suffix('d') {
        (s, 86_400)
    } else {
        return Err(format!(
            "invalid duration {input:?} — must end with s/m/h/d (e.g. 24h, 7d, 30m, 30s)"
        ));
    };
    let n: u64 = num_str
        .parse()
        .map_err(|e| format!("invalid duration number in {input:?}: {e}"))?;
    n.checked_mul(multiplier_secs)
        .ok_or_else(|| format!("duration {input:?} overflows u64 seconds"))
}

/// Validate `#RRGGBB` or `#RGB` style hex colours.
fn validate_hex_color(input: &str) -> Result<(), String> {
    let Some(rest) = input.strip_prefix('#') else {
        return Err(format!("expected leading '#'; got {input:?}"));
    };
    if !matches!(rest.len(), 3 | 6) {
        return Err(format!("{input:?} must be 3 or 6 hex digits after '#'"));
    }
    if !rest.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("{input:?} contains non-hex characters"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_valid_id_accepts_lowercase() {
        assert!(is_valid_id("astralis"));
        assert!(is_valid_id("my-distro"));
        assert!(is_valid_id("a1b2c3"));
    }

    #[test]
    fn is_valid_id_rejects_invalid() {
        assert!(!is_valid_id(""));
        assert!(!is_valid_id("UPPER"));
        assert!(!is_valid_id("1starts-with-digit"));
        assert!(!is_valid_id("has space"));
        assert!(!is_valid_id("under_score"));
    }

    #[test]
    fn extract_refs_finds_variables() {
        assert_eq!(extract_variable_refs("{{ foo }}"), vec!["foo"]);
        assert_eq!(
            extract_variable_refs("prefix-{{ bar }}-{{ baz }}-suffix"),
            vec!["bar", "baz"]
        );
        assert_eq!(extract_variable_refs("no refs here"), Vec::<&str>::new());
        assert_eq!(extract_variable_refs("{{}}"), Vec::<&str>::new());
    }

    #[test]
    fn extract_refs_handles_whitespace() {
        assert_eq!(extract_variable_refs("{{  spaced  }}"), vec!["spaced"]);
        assert_eq!(extract_variable_refs("{{no_space}}"), vec!["no_space"]);
    }

    #[test]
    fn parse_invite_duration_accepts_units() {
        assert_eq!(parse_invite_duration("30s"), Ok(30));
        assert_eq!(parse_invite_duration("5m"), Ok(300));
        assert_eq!(parse_invite_duration("24h"), Ok(86_400));
        assert_eq!(parse_invite_duration("7d"), Ok(604_800));
        assert_eq!(parse_invite_duration(" 12h "), Ok(43_200));
    }

    #[test]
    fn parse_invite_duration_rejects_garbage() {
        assert!(parse_invite_duration("").is_err());
        assert!(parse_invite_duration("24").is_err());
        assert!(parse_invite_duration("ten h").is_err());
        assert!(parse_invite_duration("forever").is_err());
    }

    #[test]
    fn hex_color_accepts_standard_forms() {
        assert!(validate_hex_color("#abc").is_ok());
        assert!(validate_hex_color("#ABCDEF").is_ok());
        assert!(validate_hex_color("#123456").is_ok());
    }

    #[test]
    fn hex_color_rejects_garbage() {
        assert!(validate_hex_color("abc").is_err());
        assert!(validate_hex_color("#abcd").is_err());
        assert!(validate_hex_color("#xyz").is_err());
        assert!(validate_hex_color("rgb(1,2,3)").is_err());
    }

    #[test]
    fn invites_block_validates_coherence() {
        let toml_src = r##"
schema-version = 1

[distro]
id = "tenancy-demo"
name = "Tenancy"
version = "0.1.0"

[[capsule]]
name = "astrid-capsule-cli"
source = "@unicity-astrid/capsule-cli"
version = "0.7.0"
role = "uplink"

[invites]
issuers = ["admin"]
"##;
        let manifest: DistroManifest =
            toml::from_str(toml_src).expect("manifest should parse syntactically");
        let err = validate_manifest(&manifest).expect_err("missing default-group must reject");
        assert!(
            err.to_string().contains("default-group is unset"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_path_hostile_capsule_name() {
        let toml_src = r#"
schema-version = 1

[distro]
id = "test"
name = "Test"
version = "0.1.0"

[[capsule]]
name = "evil/../escape"
source = "@org/cli"
version = "0.1.0"
role = "uplink"
"#;
        let manifest: DistroManifest = toml::from_str(toml_src).unwrap();
        let err = validate_manifest(&manifest).expect_err("slash name must be rejected");
        assert!(err.to_string().contains("capsule name"), "got: {err}");
    }

    #[test]
    fn rejects_branch_selector_in_distro() {
        let toml_src = r#"
schema-version = 1

[distro]
id = "test"
name = "Test"
version = "0.1.0"

[[capsule]]
name = "astrid-capsule-cli"
source = "@org/cli"
version = "0.1.0"
branch = "main"
role = "uplink"
"#;
        let manifest: DistroManifest = toml::from_str(toml_src).unwrap();
        let err = validate_manifest(&manifest).expect_err("branch must be rejected");
        let msg = err.to_string();
        assert!(msg.contains("branch/rev"), "got: {msg}");
        assert!(msg.contains("astrid-capsule-cli"), "got: {msg}");
    }

    #[test]
    fn rejects_rev_selector_in_distro() {
        let toml_src = r#"
schema-version = 1

[distro]
id = "test"
name = "Test"
version = "0.1.0"

[[capsule]]
name = "astrid-capsule-cli"
source = "@org/cli"
version = "0.1.0"
rev = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
role = "uplink"
"#;
        let manifest: DistroManifest = toml::from_str(toml_src).unwrap();
        let err = validate_manifest(&manifest).expect_err("rev must be rejected");
        assert!(err.to_string().contains("branch/rev"), "got: {err}");
    }

    #[test]
    fn accepts_version_and_tag_release_selectors() {
        let toml_src = r#"
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
name = "astrid-capsule-a"
source = "@org/a"
version = "0.2.0"
tag = "v0.2.0-rc1"
"#;
        let manifest: DistroManifest = toml::from_str(toml_src).unwrap();
        validate_manifest(&manifest).expect("version/tag release selectors are allowed");
    }

    #[test]
    fn branding_accepts_well_formed_colors() {
        let toml_src = r##"
schema-version = 1

[distro]
id = "branded"
name = "Branded"
version = "0.1.0"

[[capsule]]
name = "astrid-capsule-cli"
source = "@unicity-astrid/capsule-cli"
version = "0.7.0"
role = "uplink"

[branding]
primary-color = "#ff8800"
accent-color = "#abc"
"##;
        let manifest: DistroManifest = toml::from_str(toml_src).unwrap();
        validate_manifest(&manifest).expect("branding accepts hex colours");
    }
}
