//! Persisted capsule installation metadata.
//!
//! `meta.json` lives alongside each installed capsule's `Capsule.toml`
//! and records the installed version, source, timestamps, content
//! hashes for the WASM/WIT blobs in the shared stores. Reads are
//! non-fatal — a missing or corrupt
//! `meta.json` is logged and treated as "no metadata", so an installer
//! can still upgrade over a partially-broken capsule. Writes are
//! atomic (temp file + rename) so a crash mid-write never leaves a
//! truncated JSON blob on disk.

use std::collections::HashMap;
use std::fmt;
use std::path::Path;

use anyhow::Context;
use astrid_core::dirs::AstridHome;
use serde::{Deserialize, Serialize};

/// Capsule installation metadata, persisted as `meta.json` alongside `Capsule.toml`.
#[derive(Debug, Serialize, Deserialize)]
pub struct CapsuleMeta {
    /// The currently installed version.
    pub version: String,
    /// When the capsule was first installed.
    pub installed_at: String,
    /// When the capsule was last updated.
    pub updated_at: String,
    /// The original install source (local path, GitHub URL, etc.).
    /// Used by `astrid capsule update` to re-fetch from the same source.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Namespaced interface imports — what this capsule needs from others.
    /// Outer key = namespace, inner key = interface name, value = version string.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub imports: HashMap<String, HashMap<String, String>>,
    /// Namespaced interface exports — what this capsule provides.
    /// Outer key = namespace, inner key = interface name, value = version string.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub exports: HashMap<String, HashMap<String, String>>,
    /// BLAKE3 hash of the WASM binary, stored content-addressed in `bin/`.
    /// `None` for non-WASM capsules (MCP).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wasm_hash: Option<String>,
    /// Content-addressed WIT files stored in `wit/`.
    /// Maps original filename to BLAKE3 hash (e.g. `"my-analytics.wit" → "abc123"`).
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub wit_files: HashMap<String, String>,
}

/// Read existing `meta.json` from a capsule's install directory (if present).
pub fn read_meta(target_dir: &Path) -> Option<CapsuleMeta> {
    let meta_path = target_dir.join("meta.json");
    let data = match std::fs::read_to_string(&meta_path) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            tracing::warn!(
                path = %meta_path.display(),
                error = %e,
                "failed to read meta.json, treating as missing"
            );
            return None;
        },
    };
    match serde_json::from_str::<CapsuleMeta>(&data) {
        Ok(m) => Some(m),
        Err(e) => {
            tracing::warn!(
                path = %meta_path.display(),
                error = %e,
                "meta.json is corrupt, treating as missing"
            );
            None
        },
    }
}

/// Write `meta.json` to the capsule's install directory.
///
/// Uses atomic write (temp file + rename) to avoid corruption from
/// crashes or power loss during write.
pub fn write_meta(target_dir: &Path, meta: &CapsuleMeta) -> anyhow::Result<()> {
    let meta_path = target_dir.join("meta.json");
    let json = serde_json::to_string_pretty(meta).context("failed to serialize meta.json")?;
    let mut tmp = tempfile::NamedTempFile::new_in(target_dir)
        .context("failed to create temp file for meta.json")?;
    std::io::Write::write_all(&mut tmp, json.as_bytes())
        .context("failed to write meta.json staging")?;
    tmp.persist(&meta_path)
        .map_err(|e| anyhow::anyhow!("failed to persist {}: {e}", meta_path.display()))?;
    Ok(())
}

/// Where an installed capsule lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapsuleLocation {
    /// User-level: `~/.astrid/capsules/`
    User,
    /// Workspace-level: `.astrid/capsules/` relative to CWD
    Workspace,
}

impl fmt::Display for CapsuleLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::User => f.write_str("user"),
            Self::Workspace => f.write_str("workspace"),
        }
    }
}

/// An installed capsule discovered on disk.
pub struct InstalledCapsule {
    /// Directory name (capsule ID).
    pub name: String,
    /// Parsed `meta.json`, if present.
    pub meta: Option<CapsuleMeta>,
    /// Where this capsule was found.
    pub location: CapsuleLocation,
}

/// Scan user-level and workspace capsule directories, returning all installed
/// capsules sorted alphabetically by name.
pub fn scan_installed_capsules() -> anyhow::Result<Vec<InstalledCapsule>> {
    let home = AstridHome::resolve().context("failed to resolve Astrid home directory")?;
    let mut capsules = Vec::new();

    let principal = astrid_core::PrincipalId::default();
    let principal_dir = home.principal_home(&principal).capsules_dir();
    if principal_dir.is_dir() {
        scan_dir(&principal_dir, CapsuleLocation::User, &mut capsules)?;
    }

    if let Ok(cwd) = std::env::current_dir() {
        let ws_dir = cwd.join(".astrid").join("capsules");
        if ws_dir.is_dir() {
            scan_dir(&ws_dir, CapsuleLocation::Workspace, &mut capsules)?;
        }
    }

    capsules.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(capsules)
}

fn scan_dir(
    dir: &Path,
    location: CapsuleLocation,
    out: &mut Vec<InstalledCapsule>,
) -> anyhow::Result<()> {
    let entries = std::fs::read_dir(dir)
        .with_context(|| format!("failed to read directory {}", dir.display()))?;

    for entry_result in entries {
        let entry = match entry_result {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!(dir = %dir.display(), error = %e, "failed to read directory entry, skipping");
                continue;
            },
        };
        let path = entry.path();
        let ft = match entry.file_type() {
            Ok(ft) => ft,
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "failed to get file type, skipping");
                continue;
            },
        };
        if !ft.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        let meta = read_meta(&path);
        out.push(InstalledCapsule {
            name,
            meta,
            location,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_installed_capsules_with_meta() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let capsules_dir = tmp.path().join("capsules");
        std::fs::create_dir_all(&capsules_dir).expect("mkdir");

        let cap_a = capsules_dir.join("alpha");
        std::fs::create_dir_all(&cap_a).expect("mkdir");
        std::fs::write(
            cap_a.join("meta.json"),
            r#"{"version":"1.0.0","installed_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z","provides":["topic:foo"],"requires":["topic:bar"]}"#,
        )
        .expect("write");

        let cap_b = capsules_dir.join("bravo");
        std::fs::create_dir_all(&cap_b).expect("mkdir");
        std::fs::write(
            cap_b.join("meta.json"),
            r#"{"version":"2.0.0","installed_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"}"#,
        )
        .expect("write");

        let mut results = Vec::new();
        scan_dir(&capsules_dir, CapsuleLocation::User, &mut results).expect("scan");

        results.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(results.len(), 2);

        assert_eq!(results[0].name, "alpha");
        let meta_a = results[0].meta.as_ref().expect("alpha has meta");
        assert_eq!(meta_a.version, "1.0.0");
        assert!(meta_a.exports.is_empty());

        assert_eq!(results[1].name, "bravo");
        let meta_b = results[1].meta.as_ref().expect("bravo has meta");
        assert_eq!(meta_b.version, "2.0.0");
    }

    #[test]
    fn test_scan_empty_directory() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let capsules_dir = tmp.path().join("capsules");
        std::fs::create_dir_all(&capsules_dir).expect("mkdir");

        let mut results = Vec::new();
        scan_dir(&capsules_dir, CapsuleLocation::User, &mut results).expect("scan");
        assert!(results.is_empty());
    }

    #[test]
    fn test_scan_missing_meta() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let capsules_dir = tmp.path().join("capsules");
        let cap = capsules_dir.join("no-meta-capsule");
        std::fs::create_dir_all(&cap).expect("mkdir");

        let mut results = Vec::new();
        scan_dir(&capsules_dir, CapsuleLocation::User, &mut results).expect("scan");

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "no-meta-capsule");
        assert!(results[0].meta.is_none());
    }

    #[test]
    fn test_scan_corrupt_meta_returns_none() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let capsules_dir = tmp.path().join("capsules");
        let cap = capsules_dir.join("corrupt-capsule");
        std::fs::create_dir_all(&cap).expect("mkdir");
        std::fs::write(cap.join("meta.json"), "{{not valid json").expect("write");

        let mut results = Vec::new();
        scan_dir(&capsules_dir, CapsuleLocation::User, &mut results).expect("scan");

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "corrupt-capsule");
        assert!(
            results[0].meta.is_none(),
            "corrupt meta.json should be treated as missing"
        );
    }
}
