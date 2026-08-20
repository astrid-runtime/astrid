//! Layout-1 tightening of dedicated `.local/{kv,tokens,tmp}` directories.
//!
//! Released 0.10.4 allowed `0755` dedicated children under an otherwise
//! private principal home. Layout-2 inventory still requires owner-only
//! directories, so first cut-over chmods owner-owned kv/tokens/tmp trees to
//! `0700` rather than aborting. Non-empty kv/tokens still have no importer
//! and remain fail-closed after the mode repair. Layout-2 serving stays
//! fail-closed.

use std::fs;
use std::io;
use std::path::Path;

use astrid_core::dirs::AstridHome;
use astrid_storage::PrincipalDirectory;

/// Tighten admitted principals' layout-1 dedicated local trees before snapshot.
pub(crate) fn tighten_legacy_dedicated_directories(
    home: &AstridHome,
    directory: &PrincipalDirectory,
) -> io::Result<()> {
    for (alias, _) in directory.bindings() {
        let principal = home.principal_home(&alias);
        for path in [
            principal.kv_dir(),
            principal.tokens_dir(),
            principal.tmp_dir(),
        ] {
            tighten_dedicated_tree(&path)?;
        }
    }
    Ok(())
}

fn tighten_dedicated_tree(path: &Path) -> io::Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "legacy dedicated source is not a regular directory: {}",
                path.display()
            ),
        ));
    }
    astrid_core::platform_fs::verify_no_redirects(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if metadata.uid() != nix::unistd::getuid().as_raw() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "legacy dedicated source is not owned by the current user: {}",
                    path.display()
                ),
            ));
        }
    }
    astrid_core::platform_fs::ensure_private_directory(path)?;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let child = entry.path();
        let child_metadata = fs::symlink_metadata(&child)?;
        if child_metadata.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "legacy dedicated source contains a redirect: {}",
                    child.display()
                ),
            ));
        }
        if child_metadata.is_dir() {
            tighten_dedicated_tree(&child)?;
        }
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use astrid_core::PrincipalId;
    use astrid_core::identity::PrincipalUid;
    use std::collections::BTreeMap;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::PathBuf;

    fn fixture_extra_principal() -> (
        tempfile::TempDir,
        AstridHome,
        PrincipalDirectory,
        PrincipalId,
    ) {
        let root = tempfile::tempdir().expect("temporary home");
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private root");
        let home = AstridHome::from_path(root.path());
        std::fs::create_dir_all(home.etc_dir()).expect("etc");
        std::fs::create_dir_all(home.migrations_dir()).expect("migrations");
        let extra = PrincipalId::new("legacy-agent").expect("extra alias");
        let directory = PrincipalDirectory::default();
        directory
            .register(PrincipalId::default(), PrincipalUid::from_bytes([0x71; 32]))
            .expect("default binding");
        directory
            .register(extra.clone(), PrincipalUid::from_bytes([0x72; 32]))
            .expect("extra binding");
        let principal_root = home.principal_home(&extra).root().to_path_buf();
        astrid_core::platform_fs::ensure_private_directory(&principal_root)
            .expect("private principal home");
        (root, home, directory, extra)
    }

    fn make_0755_dir(path: &PathBuf) {
        std::fs::create_dir_all(path).expect("dedicated dir");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).expect("0755");
    }

    #[test]
    fn layout1_empty_kv_and_tokens_dirs_are_tightened_instead_of_failing_snapshot() {
        let (_root, home, directory, extra) = fixture_extra_principal();
        let principal = home.principal_home(&extra);
        for path in [principal.kv_dir(), principal.tokens_dir()] {
            make_0755_dir(&path);
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o755
            );
        }
        tighten_legacy_dedicated_directories(&home, &directory).expect("tighten");
        for path in [principal.kv_dir(), principal.tokens_dir()] {
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o700
            );
            super::super::snapshot_path(&path).expect("private snapshot after tighten");
        }
        super::super::reject_unsupported_sources(&home, &directory, &BTreeMap::new())
            .expect("empty kv/tokens must not refuse cutover after tighten");
    }

    #[test]
    fn layout1_non_empty_kv_and_tokens_stay_fail_closed_after_tighten() {
        let (_root, home, directory, extra) = fixture_extra_principal();
        let principal = home.principal_home(&extra);
        for (path, name) in [
            (principal.kv_dir(), "kv"),
            (principal.tokens_dir(), "tokens"),
        ] {
            make_0755_dir(&path);
            let file = path.join("entry");
            std::fs::write(&file, b"keep-me").expect("bytes");
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).expect("0600");
            tighten_legacy_dedicated_directories(&home, &directory).expect("tighten");
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o700
            );
            let error =
                super::super::reject_unsupported_sources(&home, &directory, &BTreeMap::new())
                    .expect_err("non-empty dedicated state has no importer");
            assert!(
                error
                    .to_string()
                    .contains(&format!("unsupported {name} state")),
                "{error}"
            );
            assert_eq!(std::fs::read(&file).expect("preserved"), b"keep-me");
            std::fs::remove_file(&file).expect("reset file");
            std::fs::remove_dir_all(&path).expect("reset dir");
        }
    }
}
