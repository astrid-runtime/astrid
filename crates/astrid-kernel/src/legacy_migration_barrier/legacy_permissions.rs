//! Permission normalization for released owner-controlled migration sources.

use std::fs;
use std::io;
use std::path::Path;

use super::host_fs::{active_mountpoint, device_id};

/// Tighten one released strict-private migration source to `0700`/`0600`.
///
/// Layout one created some security-sensitive sources through ordinary
/// `create_dir_all` and file writes, so their modes inherited the caller's
/// umask. A common `0002` umask therefore produced `0775` directories and
/// `0664` files that layout two correctly refuses to snapshot. Normalize only
/// the exact sources named by the migration manifest. Redirects, mounts,
/// device crossings, foreign ownership, ACLs, and special entries remain hard
/// failures, and file contents are never changed.
pub(super) fn tighten_private_path(path: &Path) -> io::Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    astrid_core::platform_fs::verify_no_redirects(path)?;
    let device = device_id(&metadata);
    tighten_private_entry(path, device)
}

fn tighten_private_entry(path: &Path, device: u64) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || (!metadata.is_dir() && !metadata.is_file()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("legacy source contains a special entry: {}", path.display()),
        ));
    }
    if device_id(&metadata) != device {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "legacy source crosses a device boundary: {}",
                path.display()
            ),
        ));
    }
    if active_mountpoint(path)? {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("legacy source is an active mount: {}", path.display()),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;

        if metadata.uid() != nix::unistd::getuid().as_raw() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "legacy source entry is not owned by the current user: {}",
                    path.display()
                ),
            ));
        }
        astrid_core::platform_fs::validate_no_extended_acl(path)?;
    }
    if metadata.is_dir() {
        astrid_core::platform_fs::ensure_private_directory(path)?;
        for entry in fs::read_dir(path)? {
            tighten_private_entry(&entry?.path(), device)?;
        }
    } else {
        astrid_core::platform_fs::restrict_private_file(path)?;
    }
    Ok(())
}

/// Remove only group/world write bits from a released owner-controlled source.
///
/// Layout-one inherited the caller's umask, so common `0002` environments
/// produced `0775` directories and `0664` files. Tighten those exact,
/// current-user-owned trees before snapshotting them. Redirects, mounts,
/// device crossings, ACLs, and special entries remain hard failures.
pub(super) fn tighten_owner_controlled_path(path: &Path) -> io::Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    astrid_core::platform_fs::verify_no_redirects(path)?;
    let device = device_id(&metadata);
    tighten_owner_controlled_entry(path, device)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn strict_private_tree_repairs_umask_modes_without_changing_bytes() {
        let root = tempfile::tempdir().expect("temporary root");
        let source = root.path().join("secrets/default");
        fs::create_dir_all(&source).expect("source tree");
        let secret = source.join("provider.key");
        fs::write(&secret, b"preserve-me").expect("secret bytes");
        fs::set_permissions(&source, fs::Permissions::from_mode(0o775)).expect("0775 source");
        fs::set_permissions(&secret, fs::Permissions::from_mode(0o664)).expect("0664 secret");

        assert!(super::super::snapshot_path(&source).is_err());
        tighten_private_path(&source).expect("tighten strict-private source");

        assert_eq!(
            fs::metadata(&source).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(&secret).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(fs::read(&secret).unwrap(), b"preserve-me");
        super::super::snapshot_path(&source).expect("private snapshot after repair");
    }

    #[test]
    fn strict_private_tree_rejects_redirects_without_following_them() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().expect("temporary root");
        let outside = root.path().join("outside");
        fs::write(&outside, b"outside").expect("outside bytes");
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o664)).expect("outside mode");
        let source = root.path().join("secrets");
        fs::create_dir(&source).expect("source");
        symlink(&outside, source.join("redirect")).expect("redirect");

        let error = tighten_private_path(&source).expect_err("redirect must fail closed");
        assert!(error.to_string().contains("special entry"), "{error}");
        assert_eq!(
            fs::metadata(&outside).unwrap().permissions().mode() & 0o777,
            0o664
        );
        assert_eq!(fs::read(&outside).unwrap(), b"outside");
    }
}

fn tighten_owner_controlled_entry(path: &Path, device: u64) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || (!metadata.is_dir() && !metadata.is_file()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("legacy source contains a special entry: {}", path.display()),
        ));
    }
    if device_id(&metadata) != device {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "legacy source crosses a device boundary: {}",
                path.display()
            ),
        ));
    }
    if active_mountpoint(path)? {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("legacy source is an active mount: {}", path.display()),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        if metadata.uid() != nix::unistd::getuid().as_raw() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "legacy source entry is not owned by the current user: {}",
                    path.display()
                ),
            ));
        }
        astrid_core::platform_fs::validate_no_extended_acl(path)?;
        let mode = metadata.permissions().mode();
        if mode & 0o022 != 0 {
            let mut permissions = metadata.permissions();
            permissions.set_mode(mode & !0o022);
            fs::set_permissions(path, permissions)?;
        }
    }
    if metadata.is_dir() {
        for entry in fs::read_dir(path)? {
            tighten_owner_controlled_entry(&entry?.path(), device)?;
        }
    }
    Ok(())
}
