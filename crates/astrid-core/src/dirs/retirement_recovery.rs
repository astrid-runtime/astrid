//! Structural preflight only; storage must prove volume recovery authority.

use std::io;

use super::AstridHome;

impl AstridHome {
    /// Validate a sentinel-free existing volume for singleton-owned recovery.
    ///
    /// This does not admit host bytes or authorize identity provisioning. The
    /// caller must open existing media and prove bootstrap-only authority or
    /// authenticated existing projection recovery before reading host policy.
    /// Ordinary fresh-root admission through [`Self::ensure`] remains strict.
    ///
    /// # Errors
    /// Returns an error for an existing sentinel, missing or unsafe media,
    /// redirects, special entries, or an unsafe durable root or runtime path.
    pub fn validate_volume_recovery_candidate(&self) -> io::Result<()> {
        self.validate_run_dir()?;
        if self.layout_version()?.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "volume recovery requires an absent layout sentinel",
            ));
        }
        self.validate_existing_volume_projection()
    }

    /// Validate structure for retrying interrupted bootstrap before its ledger.
    ///
    /// This grants no authority: storage must separately prove both the empty
    /// birth receipt and current bootstrap-only roots under the boot singleton.
    ///
    /// # Errors
    /// Rejects legacy/unknown layouts, unsafe media and redirected/special entries.
    pub fn validate_fresh_admission_candidate(&self) -> io::Result<()> {
        self.validate_run_dir()?;
        if !matches!(
            self.layout_version()?.as_deref(),
            None | Some(super::LAYOUT_VERSION)
        ) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "fresh admission retry requires a fresh or layout-two projection",
            ));
        }
        self.validate_existing_volume_projection()
    }

    /// Read-only recognition of ordinary sentinel-free root structure.
    ///
    /// This permits no host import or identity provisioning. Storage must still
    /// prove volume authority and recover stopped-key residue before use.
    ///
    /// # Errors
    /// Rejects a present sentinel or any unadmitted fresh-root entry.
    pub fn validate_unsentinelled_root(&self) -> io::Result<()> {
        self.validate_run_dir()?;
        if self.layout_version()?.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ordinary stopped root requires an absent sentinel",
            ));
        }
        self.validate_fresh_root_entries().map(|_| ())
    }

    fn validate_existing_volume_projection(&self) -> io::Result<()> {
        crate::platform_fs::validate_private_directory(self.root())?;
        crate::platform_fs::validate_private_file(&self.storage_volume_path())?;
        validate_projection_entry(self.root(), self.root())
    }
}

/// Whether a normalized relative projection name is disposable runtime state.
/// Capsule artifacts beneath `run/capsules` remain durable projection content.
#[must_use]
pub fn is_transient_runtime_projection_path(relative: &str) -> bool {
    relative
        .strip_prefix("run/")
        .is_some_and(|path| path != "capsules" && !path.starts_with("capsules/"))
}

fn validate_projection_entry(root: &std::path::Path, path: &std::path::Path) -> io::Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "runtime recovery projection is redirected: {}",
                path.display()
            ),
        ));
    }
    if metadata.is_dir() {
        for entry in std::fs::read_dir(path)? {
            validate_projection_entry(root, &entry?.path())?;
        }
    } else if !metadata.is_file() {
        let relative = path
            .strip_prefix(root)
            .ok()
            .and_then(std::path::Path::to_str)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid runtime recovery projection path",
                )
            })?;
        let relative = relative.replace(std::path::MAIN_SEPARATOR, "/");
        if !is_transient_runtime_projection_path(&relative) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "runtime recovery projection contains a special entry: {}",
                    path.display()
                ),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_preflight_does_not_admit_host_files_or_identity_provisioning() {
        let root = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(root.path());
        crate::platform_fs::ensure_private_directory(home.root()).unwrap();
        crate::platform_fs::atomic_write_private_file(&home.storage_volume_path(), b"volume")
            .unwrap();
        std::fs::create_dir(home.log_dir()).unwrap();
        std::fs::write(home.log_dir().join("audit"), b"surviving projection").unwrap();
        home.validate_volume_recovery_candidate().unwrap();
        assert!(home.ensure().is_err());
        assert!(home.validate_runtime_identity_provisioning().is_err());
        assert_eq!(
            std::fs::read(home.log_dir().join("audit")).unwrap(),
            b"surviving projection"
        );
        std::fs::remove_file(home.storage_volume_path()).unwrap();
        assert!(home.validate_volume_recovery_candidate().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn recovery_preflight_rejects_redirects_before_opening_media() {
        let root = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(root.path());
        crate::platform_fs::ensure_private_directory(home.root()).unwrap();
        crate::platform_fs::atomic_write_private_file(&home.storage_volume_path(), b"volume")
            .unwrap();
        std::os::unix::fs::symlink(root.path(), home.log_dir()).unwrap();
        assert!(home.validate_volume_recovery_candidate().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn only_disposable_runtime_specials_are_allowed_and_redirects_still_fail() {
        let root = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(root.path());
        crate::platform_fs::ensure_private_directory(home.root()).unwrap();
        crate::platform_fs::atomic_write_private_file(&home.storage_volume_path(), b"volume")
            .unwrap();
        std::fs::create_dir_all(home.root().join("run/principals/example")).unwrap();
        let _socket =
            std::os::unix::net::UnixListener::bind(home.root().join("run/principals/example/sock"))
                .unwrap();
        home.validate_volume_recovery_candidate().unwrap();
        std::fs::create_dir_all(home.root().join("run/capsules")).unwrap();
        let capsule_socket = home.root().join("run/capsules/sock");
        let socket = std::os::unix::net::UnixListener::bind(&capsule_socket).unwrap();
        assert!(home.validate_volume_recovery_candidate().is_err());
        drop(socket);
        std::fs::remove_file(capsule_socket).unwrap();
        std::os::unix::fs::symlink(root.path(), home.root().join("run/principals/redirect"))
            .unwrap();
        assert!(home.validate_volume_recovery_candidate().is_err());
    }
}
