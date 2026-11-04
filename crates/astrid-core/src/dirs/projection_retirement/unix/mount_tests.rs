//! Real same-device/inode bind mounts in a caller-owned private mount namespace.

use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::retire_with_hooks;
use crate::dirs::retire_projection_root;

struct BindMount(Option<PathBuf>);

impl BindMount {
    fn attach(path: &Path) -> io::Result<Self> {
        let result = Command::new("mount")
            .arg("--bind")
            .arg(path)
            .arg(path)
            .status()?;
        if !result.success() {
            return Err(io::Error::other(
                "bind-mount fixture requires CAP_SYS_ADMIN",
            ));
        }
        Ok(Self(Some(path.to_path_buf())))
    }

    fn unmount(&mut self) -> io::Result<()> {
        if let Some(path) = &self.0 {
            let result = Command::new("umount").arg(path).status()?;
            if !result.success() {
                return Err(io::Error::other("could not unmount owned bind fixture"));
            }
            self.0 = None;
        }
        Ok(())
    }
}

impl Drop for BindMount {
    fn drop(&mut self) {
        // The entire private namespace is discarded by the test launcher even
        // on panic. Still unmount our fixture before temporary-directory cleanup.
        if let Err(error) = self.unmount() {
            eprintln!("owned bind fixture cleanup: {error}");
        }
    }
}

fn require_private_namespace() {
    assert_ne!(
        std::fs::read_link("/proc/self/ns/mnt").unwrap(),
        std::fs::read_link("/proc/1/ns/mnt").unwrap(),
        "run this test binary through unshare --mount --propagation private"
    );
}

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
