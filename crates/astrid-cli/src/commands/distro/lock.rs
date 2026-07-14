//! Distro lockfile types and management.
//!
//! The lockfile (`Distro.lock`) pins exact resolved versions and BLAKE3 hashes
//! for reproducible installs. Lives at `home/{principal}/.config/distro.lock`.

use std::path::Path;

use anyhow::Context;
use serde::{Deserialize, Serialize};

use super::manifest::DistroManifest;

/// A resolved distro lockfile.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct DistroLock {
    /// Schema version (must match the manifest).
    pub(crate) schema_version: u32,
    /// Distro identity from the manifest.
    pub(crate) distro: DistroLockMeta,
    /// Resolved capsule entries.
    #[serde(default, rename = "capsule")]
    pub(crate) capsules: Vec<LockedCapsule>,
    /// BLAKE3 hash of the canonical `Distro.toml` bytes this lock was
    /// resolved from (`blake3:{hex}`). Lets `.shuttle` consumers detect
    /// a manifest that was tampered with after sealing. `None` for
    /// locks generated before this field existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) manifest_hash: Option<String>,
}

/// Distro identity in the lockfile.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) struct DistroLockMeta {
    /// Distro ID (must match `distro.id` in the manifest).
    pub(crate) id: String,
    /// Distro version (must match the manifest).
    pub(crate) version: String,
    /// ISO 8601 UTC timestamp of when the lock was generated.
    pub(crate) resolved_at: String,
}

/// A resolved capsule entry in the lockfile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct LockedCapsule {
    /// Capsule package name.
    pub(crate) name: String,
    /// Exact resolved version.
    pub(crate) version: String,
    /// Fully resolved source.
    pub(crate) source: String,
    /// BLAKE3 hash of the installed WASM binary (`blake3:{hex}`).
    pub(crate) hash: String,
    /// The concrete ref this capsule resolved to (e.g. `v0.3.2`, a
    /// branch name, or a commit SHA). Distinct from `version` because
    /// the manifest may pin a tag/branch/rev that doesn't equal the
    /// semver string. `None` for legacy locks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) resolved_ref: Option<String>,
}

/// Load a lockfile from disk. Returns `Ok(None)` if the file does not exist.
pub(crate) fn load_lock(path: &Path) -> anyhow::Result<Option<DistroLock>> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("failed to read {}", path.display())),
    };
    let lock: DistroLock = toml::from_str(&content).context("failed to parse Distro.lock")?;
    Ok(Some(lock))
}

/// Write a lockfile to disk. Uses atomic write (temp + rename) to avoid
/// partial writes on crash.
pub(crate) fn write_lock(path: &Path, lock: &DistroLock) -> anyhow::Result<()> {
    let content = toml::to_string_pretty(lock).context("failed to serialize Distro.lock")?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let mut tmp = tempfile::NamedTempFile::new_in(path.parent().unwrap_or(Path::new(".")))
        .context("failed to create temp file for Distro.lock")?;
    std::io::Write::write_all(&mut tmp, content.as_bytes())
        .context("failed to write Distro.lock staging")?;
    tmp.persist(path)
        .map_err(|e| anyhow::anyhow!("failed to persist {}: {e}", path.display()))?;
    Ok(())
}

/// Check if a lockfile is fresh (name and version match the manifest).
pub(crate) fn is_lock_fresh(lock: &DistroLock, manifest: &DistroManifest) -> bool {
    lock.distro.id == manifest.distro.id && lock.distro.version == manifest.distro.version
}

/// Create a new lockfile from resolved capsule data.
pub(crate) fn create_lock(manifest: &DistroManifest, capsules: Vec<LockedCapsule>) -> DistroLock {
    DistroLock {
        schema_version: manifest.schema_version,
        distro: DistroLockMeta {
            id: manifest.distro.id.clone(),
            version: manifest.distro.version.clone(),
            resolved_at: chrono::Utc::now().to_rfc3339(),
        },
        capsules,
        manifest_hash: None,
    }
}

/// Compute the canonical BLAKE3 hash of a raw `Distro.toml` byte stream,
/// formatted as `blake3:{hex}`.
///
/// "Canonical" here means the exact bytes the manifest was sealed from —
/// no re-serialization. Re-emitting TOML would not round-trip
/// deterministically (key ordering, comments, whitespace), so the seal
/// pipeline and the consumer both hash the original file bytes.
pub(crate) fn manifest_hash(toml_bytes: &[u8]) -> String {
    format!("blake3:{}", blake3::hash(toml_bytes).to_hex())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_and_load_lock_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("distro.lock");

        let lock = DistroLock {
            schema_version: 1,
            distro: DistroLockMeta {
                id: "test".into(),
                version: "0.1.0".into(),
                resolved_at: "2026-03-21T14:30:00Z".into(),
            },
            capsules: vec![LockedCapsule {
                name: "astrid-capsule-cli".into(),
                version: "0.1.0".into(),
                source: "@example-org/capsule-cli".into(),
                hash: "blake3:abc123".into(),
                resolved_ref: Some("v0.1.0".into()),
            }],
            manifest_hash: Some("blake3:deadbeef".into()),
        };

        write_lock(&path, &lock).unwrap();
        let loaded = load_lock(&path).unwrap().expect("lock should exist");

        assert_eq!(loaded.schema_version, 1);
        assert_eq!(loaded.distro.id, "test");
        assert_eq!(loaded.distro.version, "0.1.0");
        assert_eq!(loaded.capsules.len(), 1);
        assert_eq!(loaded.capsules[0].hash, "blake3:abc123");
        assert_eq!(loaded.capsules[0].resolved_ref.as_deref(), Some("v0.1.0"));
        assert_eq!(loaded.manifest_hash.as_deref(), Some("blake3:deadbeef"));
    }

    #[test]
    fn manifest_hash_is_stable_and_prefixed() {
        let bytes = b"schema-version = 1\n";
        let h1 = manifest_hash(bytes);
        let h2 = manifest_hash(bytes);
        assert_eq!(h1, h2);
        assert!(h1.starts_with("blake3:"));
        // Differs for different bytes.
        assert_ne!(manifest_hash(bytes), manifest_hash(b"different"));
    }

    #[test]
    fn load_lock_returns_none_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nonexistent.lock");
        assert!(load_lock(&path).unwrap().is_none());
    }

    #[test]
    fn is_lock_fresh_matches() {
        let manifest = super::super::manifest::parse_manifest(
            r#"
schema-version = 1

[distro]
id = "test"
name = "Test"
version = "0.1.0"

[[capsule]]
name = "cli"
source = "@org/cli"
version = "0.1.0"
role = "uplink"
"#,
        )
        .unwrap();

        let lock = DistroLock {
            schema_version: 1,
            distro: DistroLockMeta {
                id: "test".into(),
                version: "0.1.0".into(),
                resolved_at: "2026-01-01T00:00:00Z".into(),
            },
            capsules: vec![],
            manifest_hash: None,
        };
        assert!(is_lock_fresh(&lock, &manifest));
    }

    #[test]
    fn is_lock_stale_on_version_mismatch() {
        let manifest = super::super::manifest::parse_manifest(
            r#"
schema-version = 1

[distro]
id = "test"
name = "Test"
version = "0.2.0"

[[capsule]]
name = "cli"
source = "@org/cli"
version = "0.1.0"
role = "uplink"
"#,
        )
        .unwrap();

        let lock = DistroLock {
            schema_version: 1,
            distro: DistroLockMeta {
                id: "test".into(),
                version: "0.1.0".into(),
                resolved_at: "2026-01-01T00:00:00Z".into(),
            },
            capsules: vec![],
            manifest_hash: None,
        };
        assert!(!is_lock_fresh(&lock, &manifest));
    }
}
