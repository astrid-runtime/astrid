//! Capsule manifest discovery from standard locations.
//!
//! Scans well-known directories for `Capsule.toml` files, providing
//! the entry point for the Manifest-First architecture.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use astrid_core::dirs::WorkspaceLayout;
use tracing::{debug, info, warn};

use crate::error::{CapsuleError, CapsuleResult};
use crate::manifest::CapsuleManifest;

/// Standard capsule manifest file name.
pub(crate) const MANIFEST_FILE_NAME: &str = "Capsule.toml";

/// Check if a string is a valid namespace or interface name: `^[a-z][a-z0-9-]*$`.
fn is_valid_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_lowercase()
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// Validate namespace and interface name identifiers for a manifest section.
fn validate_interface_identifiers<'a>(
    path: &Path,
    section: &str,
    namespace: &str,
    names: impl Iterator<Item = &'a String>,
) -> CapsuleResult<()> {
    if !is_valid_identifier(namespace) {
        return Err(CapsuleError::ManifestParseError {
            path: path.to_path_buf(),
            message: format!(
                "[{section}].{namespace}: invalid namespace \
                 (must match ^[a-z][a-z0-9-]*$)"
            ),
        });
    }
    for name in names {
        if !is_valid_identifier(name) {
            return Err(CapsuleError::ManifestParseError {
                path: path.to_path_buf(),
                message: format!(
                    "[{section}.{namespace}].{name}: invalid interface name \
                     (must match ^[a-z][a-z0-9-]*$)"
                ),
            });
        }
    }
    Ok(())
}

/// Validate a `kind = "cli"` command name (a top-level
/// `astrid capsule <verb>` subcommand).
///
/// Rules (fail closed): the name must match `[a-z][a-z0-9-]*`, be 1-32
/// characters, and must not collide with a built-in `astrid capsule`
/// subcommand ([`astrid_core::kernel_api::RESERVED_CAPSULE_VERBS`]).
fn validate_cli_verb_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("must not be empty".into());
    }
    if name.len() > 32 {
        return Err("must be at most 32 characters".into());
    }
    let mut chars = name.chars();
    let first = chars.next().expect("non-empty checked above");
    if !first.is_ascii_lowercase() {
        return Err("must start with a lowercase ASCII letter (a-z)".into());
    }
    for c in chars {
        if !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
            return Err(format!(
                "contains invalid character '{c}' (allowed: a-z, 0-9, '-')"
            ));
        }
    }
    if astrid_core::kernel_api::RESERVED_CAPSULE_VERBS.contains(&name) {
        return Err(format!(
            "'{name}' is a reserved built-in `astrid capsule` subcommand"
        ));
    }
    Ok(())
}

/// Discover capsule manifests from standard locations with precedence.
///
/// Scans directories in priority order:
/// 1. `extra_paths` (system and principal capsule dirs, passed by kernel)
/// 2. Capsules under the selected project state directory
///
/// **Deduplication:** When the same `package.name` appears in multiple
/// sources, the first occurrence wins (highest priority). Lower-priority
/// duplicates are logged as warnings and skipped. The kernel passes paths
/// in order: system (`~/.astrid/capsules/`), principal
/// (`~/.astrid/home/{id}/.local/capsules/`), then workspace is scanned
/// last.
///
/// Returns `(manifest, capsule_dir)` pairs where `capsule_dir` is the
/// directory containing the manifest.
pub fn discover_manifests(extra_paths: Option<&[PathBuf]>) -> Vec<(CapsuleManifest, PathBuf)> {
    discover_manifests_with_layout(extra_paths, &WorkspaceLayout::default())
}

/// Discover capsule manifests using an explicit workspace layout.
pub fn discover_manifests_with_layout(
    extra_paths: Option<&[PathBuf]>,
    workspace_layout: &WorkspaceLayout,
) -> Vec<(CapsuleManifest, PathBuf)> {
    let workspace_root = std::env::current_dir().ok();
    discover_manifests_in_workspace(extra_paths, workspace_root.as_deref(), workspace_layout)
}

/// Discover capsule manifests with an explicit workspace root and layout.
pub fn discover_manifests_in_workspace(
    extra_paths: Option<&[PathBuf]>,
    workspace_root: Option<&Path>,
    workspace_layout: &WorkspaceLayout,
) -> Vec<(CapsuleManifest, PathBuf)> {
    let mut manifests = Vec::new();
    let mut seen_names: HashSet<String> = HashSet::new();

    // Helper: load from a directory and deduplicate by name.
    let mut load_dedup = |dir: &Path, source: &str| {
        if !dir.exists() {
            return;
        }
        info!(path = %dir.display(), source, "Discovering capsules");
        match load_manifests_from_dir(dir) {
            Ok(found) => {
                for (manifest, path) in found {
                    if seen_names.contains(&manifest.package.name) {
                        warn!(
                            capsule = %manifest.package.name,
                            source,
                            skipped_path = %path.display(),
                            "Skipping duplicate capsule (higher-priority version already loaded)"
                        );
                    } else {
                        seen_names.insert(manifest.package.name.clone());
                        manifests.push((manifest, path));
                    }
                }
            },
            Err(e) => warn!(source, error = %e, "Failed to load capsules"),
        }
    };

    // 1. Extra paths in priority order (system, then principal).
    if let Some(paths) = extra_paths {
        for path in paths {
            load_dedup(path, "extra");
        }
    }

    // 2. Workspace-level capsules (lowest priority).
    if let Some(workspace_root) = workspace_root {
        match workspace_layout
            .resolve(workspace_root)
            .and_then(|selection| {
                selection
                    .verify_tree("capsules")
                    .map(|dir| (selection, dir))
            }) {
            Ok((selection, dir)) => {
                load_dedup(&dir, "workspace");
                if let Err(error) = selection.verify_tree("capsules") {
                    warn!(%error, "Workspace changed during capsule discovery; discarding results");
                    manifests.retain(|(_, path)| !path.starts_with(&dir));
                }
            },
            Err(error) => {
                warn!(%error, "Unsafe workspace capsule path; skipping workspace capsules")
            },
        }
    }

    info!(count = manifests.len(), "Discovered capsule manifests");
    manifests
}

/// Load all capsule manifests from a directory.
///
/// Looks for subdirectories containing `Capsule.toml` files, as well as
/// `Capsule.toml` files directly in the directory.
pub(crate) fn load_manifests_from_dir(
    dir: &Path,
) -> CapsuleResult<Vec<(CapsuleManifest, PathBuf)>> {
    let mut manifests = Vec::new();

    let entries = std::fs::read_dir(dir).map_err(|e| CapsuleError::ManifestParseError {
        path: dir.to_path_buf(),
        message: e.to_string(),
    })?;

    for entry in entries {
        let entry = entry.map_err(|e| CapsuleError::ManifestParseError {
            path: dir.to_path_buf(),
            message: e.to_string(),
        })?;
        let path = entry.path();

        if path.is_dir() {
            // Look for Capsule.toml in subdirectory
            let manifest_path = path.join(MANIFEST_FILE_NAME);
            if manifest_path.exists() {
                match load_manifest(&manifest_path) {
                    Ok(manifest) => {
                        debug!(
                            path = %manifest_path.display(),
                            capsule_name = %manifest.package.name,
                            "Loaded capsule manifest"
                        );
                        manifests.push((manifest, path));
                    },
                    Err(e) => {
                        warn!(
                            path = %manifest_path.display(),
                            error = %e,
                            "Failed to load capsule manifest"
                        );
                    },
                }
            }
        } else if path.is_file()
            && path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n == MANIFEST_FILE_NAME)
        {
            let capsule_dir = path.parent().unwrap_or(dir).to_path_buf();
            match load_manifest(&path) {
                Ok(manifest) => {
                    debug!(
                        path = %path.display(),
                        capsule_name = %manifest.package.name,
                        "Loaded capsule manifest"
                    );
                    manifests.push((manifest, capsule_dir));
                },
                Err(e) => {
                    warn!(path = %path.display(), error = %e, "Failed to load capsule manifest");
                },
            }
        }
    }

    Ok(manifests)
}

/// Load a single capsule manifest from a TOML file.
pub fn load_manifest(path: &Path) -> CapsuleResult<CapsuleManifest> {
    let content = std::fs::read_to_string(path).map_err(|e| CapsuleError::ManifestParseError {
        path: path.to_path_buf(),
        message: e.to_string(),
    })?;

    let mut manifest: CapsuleManifest =
        toml::from_str(&content).map_err(|e| CapsuleError::ManifestParseError {
            path: path.to_path_buf(),
            message: e.to_string(),
        })?;

    // Merge component-level capabilities into the root capabilities.
    // [[component]].capabilities can declare fs_read, fs_write, host_process,
    // etc. These must be visible in the root `manifest.capabilities` because
    // the security gate reads from there.
    for component in &manifest.components {
        if let Some(ref caps) = component.capabilities {
            manifest.capabilities.fs_read.extend(caps.fs_read.clone());
            manifest.capabilities.fs_write.extend(caps.fs_write.clone());
            manifest
                .capabilities
                .host_process
                .extend(caps.host_process.clone());
            manifest.capabilities.net.extend(caps.net.clone());
            manifest.capabilities.net_bind.extend(caps.net_bind.clone());
            // Scalar (not a list): a component declaring bind_workers wins over
            // the root default. Single-component capsules (the common case) just
            // promote it up so the run-loop worker count is honored.
            if caps.bind_workers.is_some() {
                manifest.capabilities.bind_workers = caps.bind_workers;
            }
        }
    }

    // Enforce astrid-version (MSRV for Astrid, like rust-version in Cargo.toml).
    // If the capsule requires a newer runtime than we are, reject it.
    // CARGO_PKG_VERSION is a compile-time constant; parse is trivially cheap.
    if let Some(ref constraint) = manifest.package.astrid_version {
        let runtime = semver::Version::parse(env!("CARGO_PKG_VERSION")).expect("valid semver");
        let req = semver::VersionReq::parse(constraint).map_err(|e| {
            CapsuleError::ManifestParseError {
                path: path.to_path_buf(),
                message: format!("invalid astrid-version '{constraint}' - {e}"),
            }
        })?;

        if !req.matches(&runtime) {
            return Err(CapsuleError::ManifestParseError {
                path: path.to_path_buf(),
                message: format!(
                    "capsule requires astrid-version {constraint}, \
                     but this runtime is {runtime}"
                ),
            });
        }
    }

    // Validate version is valid semver (same as Cargo.toml).
    if semver::Version::parse(&manifest.package.version).is_err() {
        return Err(CapsuleError::ManifestParseError {
            path: path.to_path_buf(),
            message: format!(
                "invalid version '{}' in [package] - must be valid semver (MAJOR.MINOR.PATCH)",
                manifest.package.version
            ),
        });
    }

    // Validate publish + subscribe patterns for empty segments. Both are the
    // keys of the `[publish]` / `[subscribe]` tables. The subscribe set is ALL
    // `[subscribe]` keys (handler-less ACL-only entries included), since every
    // key installs a `check_subscribe_acl` pattern; interceptor event patterns
    // are a subset of these keys, so they are covered here too. Borrow the keys
    // directly — no `effective_*` Vec allocation, the loop only reads them.
    let publish_patterns = manifest
        .publishes
        .keys()
        .map(|p| ("publish pattern", p.as_str()));
    let subscribe_patterns = manifest
        .subscribes
        .keys()
        .map(|p| ("subscribe pattern", p.as_str()));

    for (kind, pattern) in publish_patterns.chain(subscribe_patterns) {
        if !crate::topic::has_valid_segments(pattern) {
            return Err(CapsuleError::ManifestParseError {
                path: path.to_path_buf(),
                message: format!(
                    "{kind} '{pattern}' contains empty segments \
                     (consecutive dots, leading/trailing dots, or is empty)"
                ),
            });
        }
    }

    // Validate [imports] and [exports] namespace/name format.
    // Semver parsing is already handled by the custom Deserialize impls.
    for (namespace, ifaces) in &manifest.imports {
        validate_interface_identifiers(path, "imports", namespace, ifaces.keys())?;
    }
    for (namespace, ifaces) in &manifest.exports {
        validate_interface_identifiers(path, "exports", namespace, ifaces.keys())?;
    }

    // Validate `kind = "cli"` command names. A CLI verb becomes a
    // top-level `astrid capsule <verb>` subcommand, so a hostile manifest
    // could otherwise shadow a built-in verb or smuggle shell-unsafe
    // characters into the dispatch path. Fail closed at parse time. Slash
    // commands (the default) are deliberately untouched — zero behaviour
    // change for the existing fleet.
    for cmd in &manifest.commands {
        if cmd.kind != astrid_core::kernel_api::CommandKind::Cli {
            continue;
        }
        if let Err(reason) = validate_cli_verb_name(&cmd.name) {
            return Err(CapsuleError::ManifestParseError {
                path: path.to_path_buf(),
                message: format!("invalid CLI command name '{}': {reason}", cmd.name),
            });
        }
    }

    // Uplink capsules load in a partition before non-uplinks.
    // Declaring [imports] on an uplink would violate this ordering.
    if manifest.capabilities.uplink && manifest.has_imports() {
        return Err(CapsuleError::ManifestParseError {
            path: path.to_path_buf(),
            message: "[imports] is not allowed on uplink capsules \
                      (uplinks load before non-uplinks and cannot depend on them)"
                .into(),
        });
    }

    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Write a TOML string to a temp file and call `load_manifest`.
    fn load_from_toml(toml: &str) -> CapsuleResult<crate::manifest::CapsuleManifest> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Capsule.toml");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(toml.as_bytes()).unwrap();
        load_manifest(&path)
    }

    const VALID_HEADER: &str = r#"
[package]
name = "test-capsule"
version = "0.1.0"
"#;

    #[test]
    fn discovery_uses_only_the_injected_workspace_layout() {
        let workspace = tempfile::tempdir().unwrap();
        let default_capsule = workspace.path().join(".astrid/capsules/default-capsule");
        let alternate_capsule = workspace
            .path()
            .join(".alternate-runtime/capsules/alternate-capsule");
        std::fs::create_dir_all(&default_capsule).unwrap();
        std::fs::create_dir_all(&alternate_capsule).unwrap();
        std::fs::write(
            default_capsule.join("Capsule.toml"),
            "[package]\nname = \"default-capsule\"\nversion = \"1.0.0\"\n",
        )
        .unwrap();
        std::fs::write(
            alternate_capsule.join("Capsule.toml"),
            "[package]\nname = \"alternate-capsule\"\nversion = \"1.0.0\"\n",
        )
        .unwrap();

        let layout = WorkspaceLayout::new(".alternate-runtime").unwrap();
        let found = discover_manifests_in_workspace(None, Some(workspace.path()), &layout);

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0.package.name, "alternate-capsule");
    }

    #[cfg(unix)]
    #[test]
    fn discovery_skips_workspace_with_symlinked_manifest() {
        use std::os::unix::fs::symlink;

        let workspace = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let capsule = workspace.path().join(".astrid/capsules/redirected");
        std::fs::create_dir_all(&capsule).unwrap();
        let manifest = outside.path().join("Capsule.toml");
        std::fs::write(&manifest, "[package]\nname='outside'\nversion='1.0.0'\n").unwrap();
        symlink(manifest, capsule.join("Capsule.toml")).unwrap();

        assert!(
            discover_manifests_in_workspace(
                None,
                Some(workspace.path()),
                &WorkspaceLayout::default()
            )
            .is_empty()
        );
    }

    #[test]
    fn load_manifest_accepts_valid_ipc_publish() {
        let toml = format!(
            "{VALID_HEADER}\n[capabilities]\nipc_publish = [\"registry.*\", \"llm.stream.anthropic\"]"
        );
        assert!(load_from_toml(&toml).is_ok());
    }

    #[test]
    fn load_manifest_rejects_empty_segment_in_publish_pattern() {
        for bad in &["a..b", ".a.b", "a.b.", "", ".", "a...b"] {
            let toml = format!("{VALID_HEADER}\n[publish]\n\"{bad}\" = {{ wit = \"opaque\" }}");
            let err = load_from_toml(&toml).unwrap_err();
            let msg = err.to_string();
            assert!(
                msg.contains("empty segments"),
                "expected 'empty segments' error for pattern '{bad}', got: {msg}"
            );
        }
    }

    #[test]
    fn load_manifest_rejects_empty_segment_in_subscribe_handler_event() {
        for bad in &["a..b", ".event", "event.", "", ".", "a...b"] {
            let toml = format!(
                "{VALID_HEADER}\n[subscribe]\n\"{bad}\" = {{ wit = \"x\", handler = \"handle\" }}"
            );
            let err = load_from_toml(&toml).unwrap_err();
            let msg = err.to_string();
            assert!(
                msg.contains("empty segments"),
                "expected 'empty segments' error for event '{bad}', got: {msg}"
            );
        }
    }

    #[test]
    fn load_manifest_accepts_valid_subscribe_handler_event() {
        let toml = format!(
            "{VALID_HEADER}\n[subscribe]\n\"user.prompt\" = {{ wit = \"x\", handler = \"handle\" }}"
        );
        assert!(load_from_toml(&toml).is_ok());
    }

    #[test]
    fn load_manifest_rejects_empty_segment_in_handlerless_subscribe() {
        // ACL-only `[subscribe]` entries (no handler) still install
        // `ipc_subscribe_patterns` matched by `check_subscribe_acl`, so their
        // keys must be validated for empty segments too — not just the
        // handler-bearing (interceptor) ones.
        for bad in &["a..b", ".event", "event.", "", ".", "a...b"] {
            let toml = format!("{VALID_HEADER}\n[subscribe]\n\"{bad}\" = {{ wit = \"opaque\" }}");
            let err = load_from_toml(&toml).unwrap_err();
            let msg = err.to_string();
            assert!(
                msg.contains("empty segments"),
                "expected 'empty segments' error for subscribe key '{bad}', got: {msg}"
            );
        }
    }

    #[test]
    fn load_manifest_accepts_valid_semver() {
        let toml = "[package]\nname = \"test\"\nversion = \"1.2.3\"\n";
        assert!(load_from_toml(toml).is_ok());
    }

    #[test]
    fn command_kind_defaults_to_slash_when_absent() {
        // An existing fleet manifest with no `kind` field parses unchanged
        // and the command is a slash command (zero behaviour change).
        let toml =
            format!("{VALID_HEADER}\n[[command]]\nname = \"git\"\ndescription = \"git ops\"\n");
        let m = load_from_toml(&toml).unwrap();
        assert_eq!(m.commands.len(), 1);
        assert_eq!(
            m.commands[0].kind,
            astrid_core::kernel_api::CommandKind::Slash
        );
    }

    #[test]
    fn command_kind_cli_valid_name_parses() {
        for good in &["deploy", "a", "x-y", "v2", "a1-b2-c3", "abcdefghijklmnop"] {
            let toml = format!("{VALID_HEADER}\n[[command]]\nname = \"{good}\"\nkind = \"cli\"\n");
            let m = load_from_toml(&toml)
                .unwrap_or_else(|e| panic!("expected CLI verb '{good}' to parse, got: {e}"));
            assert_eq!(
                m.commands[0].kind,
                astrid_core::kernel_api::CommandKind::Cli
            );
        }
    }

    #[test]
    fn command_kind_cli_invalid_pattern_rejected() {
        // Uppercase, leading digit, leading dash, illegal chars, unicode,
        // empty, and over-length names must all fail the parse (fail closed).
        let long = "a".repeat(33);
        let bad: Vec<String> = vec![
            "Deploy".into(),
            "1deploy".into(),
            "-deploy".into(),
            "de_ploy".into(),
            "de ploy".into(),
            "déploy".into(),
            "deploy!".into(),
            String::new(),
            long,
        ];
        for name in &bad {
            let toml = format!("{VALID_HEADER}\n[[command]]\nname = \"{name}\"\nkind = \"cli\"\n");
            let err = load_from_toml(&toml).unwrap_err();
            assert!(
                err.to_string().contains("invalid CLI command name"),
                "expected rejection for CLI verb '{name}', got: {err}"
            );
        }
    }

    #[test]
    fn command_kind_cli_reserved_name_rejected() {
        for reserved in astrid_core::kernel_api::RESERVED_CAPSULE_VERBS {
            let toml =
                format!("{VALID_HEADER}\n[[command]]\nname = \"{reserved}\"\nkind = \"cli\"\n");
            let err = load_from_toml(&toml).unwrap_err();
            assert!(
                err.to_string().contains("reserved"),
                "expected reserved-name rejection for '{reserved}', got: {err}"
            );
        }
    }

    #[test]
    fn slash_command_names_unaffected_by_cli_validation() {
        // Names that would be illegal as CLI verbs (uppercase, reserved,
        // long, unicode) are perfectly fine as slash commands — the new
        // validation must not touch them.
        for name in &["Install", "remove", "1abc", "MyCommand", "déjà"] {
            let toml = format!("{VALID_HEADER}\n[[command]]\nname = \"{name}\"\n");
            assert!(
                load_from_toml(&toml).is_ok(),
                "slash command '{name}' should parse without CLI validation"
            );
        }
    }

    #[test]
    fn load_manifest_accepts_prerelease_semver() {
        let toml = "[package]\nname = \"test\"\nversion = \"1.0.0-alpha.1\"\n";
        assert!(load_from_toml(toml).is_ok());
    }

    #[test]
    fn load_manifest_rejects_incomplete_semver() {
        let toml = "[package]\nname = \"test\"\nversion = \"1.0\"\n";
        let err = load_from_toml(toml).unwrap_err();
        assert!(
            err.to_string().contains("invalid version"),
            "expected 'invalid version' error, got: {err}"
        );
    }

    #[test]
    fn load_manifest_rejects_non_semver_version() {
        let toml = "[package]\nname = \"test\"\nversion = \"latest\"\n";
        let err = load_from_toml(toml).unwrap_err();
        assert!(
            err.to_string().contains("invalid version"),
            "expected 'invalid version' error, got: {err}"
        );
    }

    #[test]
    fn load_manifest_parses_imports_and_exports() {
        let toml = format!(
            "{VALID_HEADER}\n\
             [imports.astrid]\n\
             llm = \"^1.0\"\n\
             session = {{ version = \"^1.0\", optional = true }}\n\n\
             [exports.astrid]\n\
             identity = \"1.0.0\"\n"
        );
        let m = load_from_toml(&toml).unwrap();
        let astrid_imports = m.imports.get("astrid").unwrap();
        assert_eq!(astrid_imports.len(), 2);
        assert!(!astrid_imports["llm"].optional);
        assert!(astrid_imports["session"].optional);
        let astrid_exports = m.exports.get("astrid").unwrap();
        assert_eq!(astrid_exports.len(), 1);
        assert_eq!(
            astrid_exports["identity"].version,
            semver::Version::new(1, 0, 0)
        );
    }

    #[test]
    fn load_manifest_defaults_empty_imports_exports() {
        let m = load_from_toml(VALID_HEADER).unwrap();
        assert!(m.imports.is_empty());
        assert!(m.exports.is_empty());
        assert!(!m.has_imports());
    }

    #[test]
    fn load_manifest_parses_exports_only() {
        let toml = format!(
            "{VALID_HEADER}\n\
             [exports.astrid]\n\
             session = \"1.0.0\"\n\
             context = {{ version = \"1.0.0\" }}\n"
        );
        let m = load_from_toml(&toml).unwrap();
        assert!(m.imports.is_empty());
        let astrid = m.exports.get("astrid").unwrap();
        assert_eq!(astrid.len(), 2);
    }

    #[test]
    fn load_manifest_rejects_invalid_namespace() {
        let toml = format!("{VALID_HEADER}\n[exports.INVALID]\nfoo = \"1.0.0\"");
        let err = load_from_toml(&toml).unwrap_err();
        assert!(
            err.to_string().contains("invalid namespace"),
            "expected 'invalid namespace' error, got: {err}"
        );
    }

    #[test]
    fn load_manifest_rejects_invalid_interface_name() {
        let toml = format!("{VALID_HEADER}\n[exports.astrid]\n\"BAD_NAME\" = \"1.0.0\"");
        let err = load_from_toml(&toml).unwrap_err();
        assert!(
            err.to_string().contains("invalid interface name"),
            "expected 'invalid interface name' error, got: {err}"
        );
    }

    #[test]
    fn load_manifest_rejects_invalid_import_version() {
        let toml = format!("{VALID_HEADER}\n[imports.astrid]\nllm = \"not_semver\"");
        let err = load_from_toml(&toml).unwrap_err();
        assert!(
            err.to_string().contains("invalid semver"),
            "expected semver error, got: {err}"
        );
    }

    #[test]
    fn load_manifest_rejects_invalid_export_version() {
        let toml = format!("{VALID_HEADER}\n[exports.astrid]\nllm = \"not_semver\"");
        let err = load_from_toml(&toml).unwrap_err();
        assert!(
            err.to_string().contains("invalid semver"),
            "expected semver error, got: {err}"
        );
    }

    #[test]
    fn load_manifest_rejects_uplink_with_imports() {
        let toml = format!(
            "{VALID_HEADER}\n[capabilities]\nuplink = true\n\n[imports.astrid]\nllm = \"^1.0\""
        );
        let err = load_from_toml(&toml).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("not allowed on uplink"),
            "expected uplink+imports rejection, got: {msg}"
        );
    }

    #[test]
    fn load_manifest_allows_uplink_without_imports() {
        let toml = format!("{VALID_HEADER}\n[capabilities]\nuplink = true");
        assert!(
            load_from_toml(&toml).is_ok(),
            "uplink without imports should be valid"
        );
    }

    #[test]
    fn load_manifest_accepts_satisfied_astrid_version() {
        let toml = "[package]\nname = \"test\"\nversion = \"0.1.0\"\nastrid-version = \">=0.1.0\"";
        assert!(load_from_toml(toml).is_ok());
    }

    #[test]
    fn load_manifest_rejects_unsatisfied_astrid_version() {
        let toml = "[package]\nname = \"test\"\nversion = \"0.1.0\"\nastrid-version = \">=99.0.0\"";
        let err = load_from_toml(toml).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("astrid-version") && msg.contains("99.0.0"),
            "expected astrid-version rejection, got: {msg}"
        );
    }

    #[test]
    fn load_manifest_rejects_invalid_astrid_version() {
        let toml =
            "[package]\nname = \"test\"\nversion = \"0.1.0\"\nastrid-version = \"not-semver\"";
        let err = load_from_toml(toml).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("invalid astrid-version"),
            "expected parse error, got: {msg}"
        );
    }

    #[test]
    fn load_manifest_accepts_missing_astrid_version() {
        // No astrid-version field at all - should load fine.
        assert!(load_from_toml(VALID_HEADER).is_ok());
    }
}
