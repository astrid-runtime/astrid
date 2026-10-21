//! Temporary lifecycle files must not become unadmitted runtime contents.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use astrid_core::dirs::AstridHome;

pub(super) fn outside_home(home: &AstridHome) -> Result<PathBuf> {
    validate_directory(home, &std::env::temp_dir())
}

fn validate_directory(home: &AstridHome, directory: &Path) -> Result<PathBuf> {
    let directory = directory
        .canonicalize()
        .context("failed to resolve daemon temporary directory")?;
    let root = physical_root(home.root())?;
    if directory.starts_with(&root) {
        bail!("daemon temporary directory must be outside Astrid home");
    }
    Ok(directory)
}

// A fresh home may not exist yet. Resolve its existing ancestor without
// creating it, then append only missing ordinary path components. Ambiguous
// missing paths (including unresolved parent traversal) fail closed.
fn physical_root(path: &Path) -> Result<PathBuf> {
    let mut ancestor = path;
    let mut missing = Vec::new();
    loop {
        match ancestor.canonicalize() {
            Ok(mut root) => {
                for name in missing.into_iter().rev() {
                    root.push(name);
                }
                return Ok(root);
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if std::fs::symlink_metadata(ancestor).is_ok() {
                    bail!("Astrid home contains an unresolved existing path");
                }
                let name = ancestor
                    .file_name()
                    .context("ambiguous missing Astrid home")?;
                missing.push(name.to_os_string());
                ancestor = ancestor
                    .parent()
                    .context("Astrid home has no existing ancestor")?;
            },
            Err(error) => return Err(error).context("failed to resolve physical Astrid home"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_inside_and_equal_without_creating_files() {
        let root = tempfile::tempdir().expect("owned root");
        let nested = root.path().join("temporary");
        std::fs::create_dir(&nested).expect("temporary directory");
        let home = AstridHome::from_path(root.path());
        assert!(validate_directory(&home, root.path()).is_err());
        assert!(validate_directory(&home, &nested).is_err());
        assert_eq!(std::fs::read_dir(&nested).expect("entries").count(), 0);
    }

    #[test]
    fn accepts_outside_missing_home_without_provisioning_it() {
        let root = tempfile::tempdir().expect("owned root");
        let home = AstridHome::from_path(root.path().join("missing/nested"));
        assert!(validate_directory(&home, root.path()).is_ok());
        assert!(!home.root().exists());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_alias_into_home() {
        let root = tempfile::tempdir().expect("owned root");
        let home_path = root.path().join("home");
        std::fs::create_dir(&home_path).expect("home");
        let alias = root.path().join("alias");
        std::os::unix::fs::symlink(&home_path, &alias).expect("alias");
        let home = AstridHome::from_path(&home_path);
        assert!(validate_directory(&home, &alias).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_dangling_home_alias_without_creating_target() {
        let root = tempfile::tempdir().expect("owned root");
        let target = root.path().join("missing");
        let alias = root.path().join("home-alias");
        std::os::unix::fs::symlink(&target, &alias).expect("alias");
        let home = AstridHome::from_path(alias.join("nested"));
        assert!(validate_directory(&home, root.path()).is_err());
        assert!(!target.exists());
    }
}
