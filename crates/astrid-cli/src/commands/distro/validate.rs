//! Distro manifest validation.
//!
//! Validates structural constraints that TOML deserialization alone cannot
//! enforce: schema version, identifier formats, semver, variable references,
//! role presence, and duplicate names.

use std::collections::HashSet;

use semver::{Version, VersionReq};

use super::manifest::{DistroManifest, SCHEMA_VERSION};

/// The running CLI version, taken from the astrid-cli binary crate
/// (`CARGO_PKG_VERSION`) — the same source `astrid version` prints.
pub(crate) const RUNNING_ASTRID_VERSION: &str = env!("CARGO_PKG_VERSION");

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

    // No duplicate capsule names.
    let mut seen_names = HashSet::new();
    for cap in &manifest.capsules {
        if !seen_names.insert(&cap.name) {
            anyhow::bail!("duplicate capsule name '{}'", cap.name);
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

/// Enforce a manifest's `[distro].astrid-version` floor against the running CLI.
///
/// Called on the init / `distro apply` path *after* the manifest is fetched and
/// parsed but *before* any prompting or install, so a distro whose `Distro.toml`
/// (fetched from the repo `main` tip) bumps its CLI floor fails fast with an
/// actionable message instead of breaking onboarding mid-flight on an older CLI.
///
/// A manifest with no `astrid-version` floor imposes no requirement.
pub(crate) fn enforce_astrid_version(manifest: &DistroManifest) -> anyhow::Result<()> {
    let Some(req) = manifest.distro.astrid_version.as_deref() else {
        return Ok(());
    };
    let running = Version::parse(RUNNING_ASTRID_VERSION).map_err(|e| {
        // The binary's own version should always be valid semver; if it isn't,
        // that's a build-time defect, not a distro problem.
        anyhow::anyhow!("running astrid version {RUNNING_ASTRID_VERSION:?} is not valid semver: {e}")
    })?;
    distro_astrid_version_satisfied(req, &running)
}

/// Decide whether the running CLI `running` satisfies a distro's
/// `[distro].astrid-version` requirement `req`.
///
/// Pure (no fetch, no env) so it is unit-testable in isolation.
///
/// **Prerelease policy.** By default `semver::VersionReq::matches` refuses a
/// prerelease running version (e.g. `0.6.0-dev.3` does *not* satisfy `>=0.6.0`),
/// which would falsely reject a locally-built / dev CLI that is, by release
/// triple, at or above the floor. That is the classic semver footgun. We compare
/// on the **release triple only** — the running version's `(major, minor, patch)`
/// with the prerelease and build metadata stripped — so a dev build of a
/// sufficiently-new astrid is accepted, while still rejecting a CLI whose release
/// triple genuinely falls below the floor. A clean (non-prerelease) running
/// version compares unchanged.
pub(crate) fn distro_astrid_version_satisfied(
    req: &str,
    running: &Version,
) -> anyhow::Result<()> {
    let version_req = VersionReq::parse(req)
        .map_err(|e| anyhow::anyhow!("distro.astrid-version {req:?} is not a valid requirement: {e}"))?;

    // Strip prerelease / build metadata: compare on the release triple so a
    // dev / prerelease CLI at or above the floor is not falsely rejected.
    let release_triple = Version::new(running.major, running.minor, running.patch);

    if version_req.matches(&release_triple) {
        return Ok(());
    }

    anyhow::bail!(
        "This distro requires astrid {req}, but you are running {running}. \
         Run `astrid update` to upgrade.",
    );
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
    fn astrid_version_rejects_running_below_floor() {
        // Running CLI is older than the distro's floor — must reject with the
        // actionable upgrade message.
        let running = Version::parse("0.5.0").unwrap();
        let err = distro_astrid_version_satisfied(">=0.6.0", &running)
            .expect_err("0.5.0 must not satisfy >=0.6.0");
        let msg = err.to_string();
        assert!(
            msg.contains("This distro requires astrid >=0.6.0")
                && msg.contains("you are running 0.5.0")
                && msg.contains("astrid update"),
            "expected actionable upgrade message, got: {msg}"
        );
    }

    #[test]
    fn astrid_version_accepts_running_at_or_above_floor() {
        // Exactly at the floor.
        let at = Version::parse("0.6.0").unwrap();
        distro_astrid_version_satisfied(">=0.6.0", &at).expect("0.6.0 satisfies >=0.6.0");

        // Above the floor (same minor and a newer minor).
        let above_patch = Version::parse("0.6.3").unwrap();
        distro_astrid_version_satisfied(">=0.6.0", &above_patch).expect("0.6.3 satisfies >=0.6.0");
        let above_minor = Version::parse("0.7.0").unwrap();
        distro_astrid_version_satisfied(">=0.6.0", &above_minor).expect("0.7.0 satisfies >=0.6.0");
    }

    #[test]
    fn astrid_version_accepts_prerelease_at_or_above_floor() {
        // The footgun: a locally-built / dev CLI whose release triple is at or
        // above the floor must be ACCEPTED, even though raw `VersionReq::matches`
        // refuses a prerelease against `>=0.6.0`. We compare on the release triple.
        let dev_at_floor = Version::parse("0.6.0-dev.3").unwrap();
        // Sanity: prove the naive comparison would have falsely rejected it.
        assert!(
            !VersionReq::parse(">=0.6.0")
                .unwrap()
                .matches(&dev_at_floor),
            "guard: naive matches must reject the prerelease, else the test proves nothing"
        );
        distro_astrid_version_satisfied(">=0.6.0", &dev_at_floor)
            .expect("0.6.0-dev.3 (release triple 0.6.0) satisfies >=0.6.0");

        // A dev build of a newer release is likewise accepted.
        let dev_above = Version::parse("0.7.0-rc.1").unwrap();
        distro_astrid_version_satisfied(">=0.6.0", &dev_above)
            .expect("0.7.0-rc.1 (release triple 0.7.0) satisfies >=0.6.0");
    }

    #[test]
    fn astrid_version_rejects_prerelease_below_floor() {
        // The triple-strip must not over-accept: a prerelease whose release
        // triple is genuinely below the floor still fails.
        let dev_below = Version::parse("0.5.0-dev.9").unwrap();
        distro_astrid_version_satisfied(">=0.6.0", &dev_below)
            .expect_err("0.5.0-dev.9 (release triple 0.5.0) must not satisfy >=0.6.0");
    }

    #[test]
    fn astrid_version_malformed_requirement_is_an_error() {
        // A malformed requirement is still rejected (distinct from "no floor").
        let running = Version::parse("0.6.0").unwrap();
        let err = distro_astrid_version_satisfied("not-a-version", &running)
            .expect_err("a malformed astrid-version requirement must error");
        assert!(
            err.to_string().contains("is not a valid requirement"),
            "got: {err}"
        );
    }

    #[test]
    fn enforce_astrid_version_no_floor_is_ok() {
        // A manifest with no astrid-version imposes no requirement.
        let toml_src = r##"
schema-version = 1

[distro]
id = "no-floor"
name = "No Floor"
version = "0.1.0"

[[capsule]]
name = "astrid-capsule-cli"
source = "@unicity-astrid/capsule-cli"
version = "0.7.0"
role = "uplink"
"##;
        let manifest: DistroManifest = toml::from_str(toml_src).unwrap();
        assert!(manifest.distro.astrid_version.is_none());
        enforce_astrid_version(&manifest).expect("no floor → no requirement");
    }

    #[test]
    fn running_astrid_version_is_valid_semver() {
        // The enforcement reads RUNNING_ASTRID_VERSION as semver; guard against a
        // build whose CARGO_PKG_VERSION cannot parse (would break every init).
        Version::parse(RUNNING_ASTRID_VERSION)
            .expect("the CLI's own version must be valid semver");
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
