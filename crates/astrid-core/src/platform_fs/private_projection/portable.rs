//! Other platforms retain the existing per-file private replacement policy.

use std::io;
use std::path::{Path, PathBuf};

use super::RelativePath;

pub(super) struct Projection {
    root: PathBuf,
}

impl Projection {
    pub(super) fn open(root: &Path) -> io::Result<Self> {
        crate::platform_fs::verify_no_redirects(root)?;
        if !std::fs::symlink_metadata(root)?.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "projection root is not a directory",
            ));
        }
        crate::platform_fs::ensure_private_directory(root)?;
        Ok(Self {
            root: root.to_path_buf(),
        })
    }

    fn path(&self, relative: &RelativePath) -> PathBuf {
        self.root.join(relative.0.iter().collect::<PathBuf>())
    }

    pub(super) fn snapshot(&self, relative: &RelativePath) -> io::Result<Option<Vec<u8>>> {
        let path = self.path(relative);
        crate::platform_fs::verify_no_redirects(&path)?;
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_file() => std::fs::read(path).map(Some),
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "projection destination is not a regular file",
            )),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub(super) fn write(&self, relative: &RelativePath, bytes: &[u8]) -> io::Result<()> {
        let path = self.path(relative);
        let parent = path.parent().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "projection path has no parent")
        })?;
        crate::platform_fs::ensure_private_directory(parent)?;
        crate::platform_fs::atomic_write_private_file(&path, bytes)
    }

    pub(super) fn remove(&self, relative: &RelativePath) -> io::Result<()> {
        let path = self.path(relative);
        crate::platform_fs::verify_no_redirects(&path)?;
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_file() => std::fs::remove_file(path),
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "projection destination is not a regular file",
            )),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }

    pub(super) fn ensure_directory(&self, relative: &RelativePath) -> io::Result<()> {
        crate::platform_fs::ensure_private_directory(&self.path(relative))
    }

    pub(super) fn sync(&self) -> io::Result<()> {
        // Windows replacements already use its write-through policy. Preserve
        // that contract rather than attempting unsupported directory File opens.
        crate::platform_fs::verify_no_redirects(&self.root)
    }
}
