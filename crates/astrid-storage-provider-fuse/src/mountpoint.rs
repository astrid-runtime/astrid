//! Mountpoint admission and stale-mount checks.

use std::fs::Permissions;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use astrid_core::storage_provider::StorageProviderViewV1;
use nix::unistd::{getgid, getuid};

/// Prepare a canonical, private, empty, non-redirected Linux mountpoint.
pub(crate) fn prepare_mountpoint(
    requested: Option<PathBuf>,
    view: &StorageProviderViewV1,
) -> Result<(PathBuf, bool)> {
    let requested = requested.unwrap_or_else(|| {
        let leaf = match view {
            StorageProviderViewV1::Principal(principal) => principal.to_string(),
            StorageProviderViewV1::Fleet(fleet) => fleet.to_string(),
            StorageProviderViewV1::Admin => "system".to_owned(),
        };
        std::env::var_os("HOME")
            .map_or_else(|| PathBuf::from("/tmp"), PathBuf::from)
            .join("Astrid")
            .join(leaf)
    });
    if !requested.is_absolute() {
        bail!("mountpoint must be absolute");
    }
    let existed = requested.symlink_metadata().is_ok();
    if !existed {
        std::fs::create_dir_all(&requested)
            .with_context(|| format!("create mountpoint {}", requested.display()))?;
    }
    astrid_core::platform_fs::verify_no_redirects(&requested)
        .with_context(|| format!("reject redirected mountpoint {}", requested.display()))?;
    let metadata = std::fs::symlink_metadata(&requested)?;
    if !metadata.is_dir() {
        bail!("mountpoint is not a directory: {}", requested.display());
    }
    let expected_uid = u32::from(getuid());
    if metadata.uid() != expected_uid {
        bail!(
            "mountpoint must be owned by the current OS user: {}",
            requested.display()
        );
    }
    let mode = metadata.permissions().mode();
    if !existed {
        std::fs::set_permissions(&requested, Permissions::from_mode(0o700))?;
    } else if mode & 0o077 != 0 {
        bail!("mountpoint must be owner-private: {}", requested.display());
    }
    if std::fs::read_dir(&requested)?.next().is_some() {
        bail!("mountpoint is not empty: {}", requested.display());
    }
    let canonical = requested
        .canonicalize()
        .with_context(|| format!("canonicalize mountpoint {}", requested.display()))?;
    if mountinfo_contains(&canonical)? {
        bail!("mountpoint is already mounted: {}", canonical.display());
    }
    Ok((canonical, !existed))
}

/// Return current owner identity for synthetic inode metadata.
pub(crate) fn owner_ids() -> (u32, u32) {
    (getuid().into(), getgid().into())
}

/// Remove a dead FUSE mount if one remains at an exact canonical path.
pub(crate) fn lazy_unmount(mountpoint: &Path) -> Result<()> {
    use nix::mount::MntFlags;

    if !mountpoint.is_absolute() {
        bail!("cannot unmount a relative mountpoint");
    }
    match nix::mount::umount2(mountpoint, MntFlags::MNT_DETACH) {
        Ok(()) | Err(nix::errno::Errno::EINVAL) => Ok(()),
        Err(error) => Err(anyhow::anyhow!(
            "lazy unmount {}: {error}",
            mountpoint.display()
        )),
    }
}

/// Whether `/proc/self/mountinfo` has a mount at this exact path.
pub(crate) fn mountinfo_contains(mountpoint: &Path) -> Result<bool> {
    let expected = mountpoint
        .to_str()
        .context("mountpoint must be canonical Unicode text")?
        .as_bytes();
    let mounts = std::fs::read("/proc/self/mountinfo").context("read Linux mount table")?;
    Ok(mounts
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .any(|line| {
            line.split(|byte| *byte == b' ')
                .nth(4)
                .is_some_and(|field| unescape_mountinfo(field) == expected)
        }))
}

fn unescape_mountinfo(value: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(value.len());
    let mut index = 0;
    while index < value.len() {
        if let Some([b'\\', first, second, third]) = value.get(index..index.saturating_add(4))
            && matches!(first, b'0'..=b'7')
            && matches!(second, b'0'..=b'7')
            && matches!(third, b'0'..=b'7')
        {
            let first = first.checked_sub(b'0').unwrap_or_default();
            let second = second.checked_sub(b'0').unwrap_or_default();
            let third = third.checked_sub(b'0').unwrap_or_default();
            let octal = (u16::from(first) << 6) | (u16::from(second) << 3) | u16::from(third);
            if let Ok(byte) = u8::try_from(octal) {
                result.push(byte);
                index = index.saturating_add(4);
                continue;
            }
        }
        if let Some(byte) = value.get(index) {
            result.push(*byte);
        }
        index = index.saturating_add(1);
    }
    result
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn prepare_mountpoint_creates_canonical_private_directory() {
        let root = tempfile::tempdir().unwrap();
        let view = StorageProviderViewV1::Admin;
        let (mountpoint, created) =
            prepare_mountpoint(Some(root.path().join("mount")), &view).unwrap();

        assert!(created);
        assert_eq!(mountpoint, mountpoint.canonicalize().unwrap());
        assert_eq!(
            std::fs::metadata(&mountpoint).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    #[test]
    fn prepare_mountpoint_rejects_relative_nonempty_or_shared_directories() {
        let root = tempfile::tempdir().unwrap();
        let view = StorageProviderViewV1::Admin;
        assert!(prepare_mountpoint(Some(PathBuf::from("relative")), &view).is_err());

        let nonempty = root.path().join("nonempty");
        std::fs::create_dir(&nonempty).unwrap();
        std::fs::write(nonempty.join("entry"), b"x").unwrap();
        assert!(prepare_mountpoint(Some(nonempty), &view).is_err());

        let shared = root.path().join("shared");
        std::fs::create_dir(&shared).unwrap();
        std::fs::set_permissions(&shared, Permissions::from_mode(0o750)).unwrap();
        assert!(prepare_mountpoint(Some(shared), &view).is_err());
    }

    #[test]
    #[cfg(unix)]
    fn prepare_mountpoint_rejects_redirected_targets() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("target");
        let redirected = root.path().join("redirected");
        std::fs::create_dir(&target).unwrap();
        std::os::unix::fs::symlink(&target, &redirected).unwrap();
        let view = StorageProviderViewV1::Admin;

        assert!(prepare_mountpoint(Some(redirected), &view).is_err());
    }

    #[test]
    fn mountinfo_escaping_handles_spaces_tabs_and_newlines() {
        assert_eq!(
            unescape_mountinfo(br"/tmp/astrid\040new\011tab\012line"),
            b"/tmp/astrid new\ttab\nline".to_vec()
        );
    }
}
