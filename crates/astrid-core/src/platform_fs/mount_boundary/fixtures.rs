//! Owned bind fixtures shared by projection restoration and retirement tests.

use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

/// An owned bind mount in the test runner's private mount namespace.
pub struct BindMount(Option<PathBuf>);

impl BindMount {
    /// Bind the fixture directory onto itself.
    pub fn attach(path: &Path) -> io::Result<Self> {
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

    /// Remove only this fixture's owned mount.
    pub fn unmount(&mut self) -> io::Result<()> {
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

/// Reject execution in the host mount namespace.
pub fn require_private_namespace() {
    assert_ne!(
        std::fs::read_link("/proc/self/ns/mnt")
            .expect("read the owned test process mount namespace"),
        std::fs::read_link("/proc/1/ns/mnt")
            .expect("read the host init mount namespace for the fixture safety guard"),
        "run this test binary through unshare --mount --propagation private"
    );
}
