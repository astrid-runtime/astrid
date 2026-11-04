//! Real same-device/inode bind mounts in a caller-owned private mount namespace.

use crate::platform_fs::mount_fixtures::{BindMount, require_private_namespace};

use super::retire_with_hooks;
use crate::dirs::retire_projection_root;

#[test]
#[ignore = "requires CAP_SYS_ADMIN in a caller-owned private mount namespace; run by native Linux CI"]
fn bind_mount_preflight_preserves_all_projection_bytes() {
    require_private_namespace();
    for directory in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("z-mounted");
        if directory {
            std::fs::create_dir(&target).unwrap();
        } else {
            std::fs::write(&target, b"packed").unwrap();
        }
        std::fs::write(temp.path().join("a"), b"untouched").unwrap();
        let mut mount = BindMount::attach(&target).unwrap();

        let error = retire_projection_root(temp.path()).unwrap_err();

        assert!(
            error.to_string().contains("Linux mount boundary"),
            "{error}"
        );
        assert_eq!(std::fs::read(temp.path().join("a")).unwrap(), b"untouched");
        mount.unmount().unwrap();
    }
}

#[test]
#[ignore = "requires CAP_SYS_ADMIN in a caller-owned private mount namespace; run by native Linux CI"]
fn bind_mount_added_after_open_is_rejected_before_unlink() {
    require_private_namespace();
    for directory in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("mounted");
        if directory {
            std::fs::create_dir(&target).unwrap();
        } else {
            std::fs::write(&target, b"packed").unwrap();
        }
        let mut mounted = None;
        let error = retire_with_hooks(
            temp.path(),
            || Ok(()),
            |path| {
                assert_eq!(path, target);
                mounted = Some(BindMount::attach(path)?);
                Ok(())
            },
        )
        .unwrap_err();

        assert!(
            error.to_string().contains("Linux mount boundary"),
            "{error}"
        );
        assert!(target.exists());
        mounted.as_mut().unwrap().unmount().unwrap();
    }
}
