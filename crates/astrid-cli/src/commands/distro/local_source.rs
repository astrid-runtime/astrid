//! Manifest-relative capsule archive resolution.

use std::path::{Component, Path, PathBuf};

use anyhow::{Context, bail};
use astrid_capsule_install::github_source::parse_github_source;

/// Whether a capsule source is resolved from the authenticated manifest's
/// filesystem root rather than GitHub.
pub(crate) fn is_local_capsule_source(source: &str) -> bool {
    source.ends_with(".capsule") && !source.contains("://") && parse_github_source(source).is_none()
}

/// Root a local authenticated manifest in the caller's current directory.
///
/// A bare `Distro.toml` has an empty parent, so resolve the authenticated
/// path once before any sibling or member resolution.
pub(crate) fn normalize_authenticated_manifest_path(
    manifest_path: &Path,
) -> anyhow::Result<PathBuf> {
    if manifest_path.is_absolute() {
        return Ok(manifest_path.to_path_buf());
    }

    let current_dir = std::env::current_dir().with_context(|| {
        format!(
            "failed to resolve current directory for authenticated manifest {}",
            manifest_path.display()
        )
    })?;
    Ok(current_dir.join(manifest_path))
}

/// Resolve a local `.capsule` member against the authenticated manifest.
///
/// `Ok(None)` means the source belongs to the caller's remote resolver.
/// The returned path is canonicalized so the subsequent copy and hash cover
/// the same filesystem object that passed containment checks.
pub(crate) fn resolve_local_capsule_archive(
    source: &str,
    manifest_path: Option<&Path>,
) -> anyhow::Result<Option<PathBuf>> {
    if !is_local_capsule_source(source) {
        return Ok(None);
    }
    let Some(manifest_path) = manifest_path else {
        bail!(
            "local capsule source {source:?} requires a local authenticated Distro.toml; \
             remote manifests cannot resolve relative members"
        );
    };

    let root = manifest_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Distro.toml has no parent directory"))?;
    let source_path = Path::new(source);
    let candidate = if source_path.is_absolute() {
        source_path.to_path_buf()
    } else {
        root.join(source_path)
    };
    if candidate
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        bail!("local capsule source {source:?} escapes the authenticated Distro.toml directory");
    }

    let canonical_root = root
        .canonicalize()
        .with_context(|| format!("failed to resolve Distro.toml directory {}", root.display()))?;
    let canonical_path = candidate
        .canonicalize()
        .with_context(|| format!("failed to resolve local capsule source {source:?}"))?;
    if !canonical_path.starts_with(&canonical_root) {
        bail!("local capsule source {source:?} escapes the authenticated Distro.toml directory");
    }
    let metadata = std::fs::metadata(&canonical_path)
        .with_context(|| format!("failed to stat local capsule source {source:?}"))?;
    if !metadata.is_file() {
        bail!("local capsule source {source:?} is not a regular file");
    }

    Ok(Some(canonical_path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_relative_member_from_manifest_parent() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("Distro.toml");
        std::fs::create_dir_all(dir.path().join("capsules")).unwrap();
        std::fs::write(dir.path().join("capsules/member.capsule"), b"member").unwrap();

        let resolved = resolve_local_capsule_archive("capsules/member.capsule", Some(&manifest))
            .unwrap()
            .unwrap();
        let expected = dir
            .path()
            .canonicalize()
            .unwrap()
            .join("capsules/member.capsule");
        assert_eq!(resolved, expected);
    }

    #[test]
    fn normalizes_bare_manifest_path_to_current_directory() {
        let current_dir = std::env::current_dir().unwrap();
        let manifest_path =
            normalize_authenticated_manifest_path(Path::new("Distro.toml")).unwrap();
        assert_eq!(manifest_path, current_dir.join("Distro.toml"));
    }

    #[test]
    fn missing_relative_member_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("Distro.toml");
        std::fs::write(&manifest, "schema-version = 1\n").unwrap();

        let err =
            resolve_local_capsule_archive("capsules/missing.capsule", Some(&manifest)).unwrap_err();
        assert!(err.to_string().contains("missing.capsule"));
    }

    #[test]
    fn traversal_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("nested/Distro.toml");
        std::fs::create_dir_all(manifest.parent().unwrap()).unwrap();
        std::fs::write(&manifest, "schema-version = 1\n").unwrap();
        std::fs::write(outside.path().join("outside.capsule"), b"outside").unwrap();

        let err = resolve_local_capsule_archive("../outside.capsule", Some(&manifest)).unwrap_err();
        assert!(err.to_string().contains("escapes"));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_escape_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("Distro.toml");
        std::fs::write(&manifest, "schema-version = 1\n").unwrap();
        std::fs::create_dir_all(dir.path().join("capsules")).unwrap();
        std::fs::write(outside.path().join("outside.capsule"), b"outside").unwrap();
        std::os::unix::fs::symlink(
            outside.path().join("outside.capsule"),
            dir.path().join("capsules/member.capsule"),
        )
        .unwrap();

        let err =
            resolve_local_capsule_archive("capsules/member.capsule", Some(&manifest)).unwrap_err();
        assert!(err.to_string().contains("escapes"));
    }

    #[test]
    fn non_regular_archive_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("Distro.toml");
        std::fs::write(&manifest, "schema-version = 1\n").unwrap();
        std::fs::create_dir_all(dir.path().join("capsules/member.capsule")).unwrap();

        let err =
            resolve_local_capsule_archive("capsules/member.capsule", Some(&manifest)).unwrap_err();
        assert!(err.to_string().contains("not a regular file"));
    }

    #[test]
    fn github_source_remains_remote() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("Distro.toml");

        let resolved = resolve_local_capsule_archive("@org/repo", Some(&manifest)).unwrap();
        assert_eq!(resolved, None);
    }

    #[test]
    fn local_member_on_remote_manifest_fails_closed() {
        let err = resolve_local_capsule_archive("capsules/member.capsule", None).unwrap_err();
        assert!(err.to_string().contains("local authenticated Distro.toml"));
    }
}
