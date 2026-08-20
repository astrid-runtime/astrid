//! Layout-1 tightening of disposable principal tmp/scratch directories.
//!
//! Released 0.10.4 allowed `0755` children under an otherwise private
//! `.local/tmp`. Layout-2 inventory still requires owner-only directories.
//! On first cut-over, chmod owner-owned tmp trees to `0700` rather than
//! aborting the kernel. Layout-2 serving remains fail-closed.

use std::fs;
use std::io;
use std::path::Path;

use astrid_core::dirs::AstridHome;
use astrid_storage::PrincipalDirectory;

/// Tighten admitted principals' layout-1 tmp trees before private snapshot.
pub(crate) fn tighten_legacy_tmp_directories(
    home: &AstridHome,
    directory: &PrincipalDirectory,
) -> io::Result<()> {
    for (alias, _) in directory.bindings() {
        tighten_tmp_tree(&home.principal_home(&alias).tmp_dir())?;
    }
    Ok(())
}

fn tighten_tmp_tree(path: &Path) -> io::Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "legacy tmp source is not a regular directory: {}",
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
                    "legacy tmp source is not owned by the current user: {}",
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
                format!("legacy tmp source contains a redirect: {}", child.display()),
            ));
        }
        if child_metadata.is_dir() {
            tighten_tmp_tree(&child)?;
        }
    }
    Ok(())
}
