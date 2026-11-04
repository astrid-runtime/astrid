//! Other platforms retain the existing per-file private replacement policy.

use std::io;
use std::path::{Path, PathBuf};

use super::RelativePath;
use crate::platform_fs::StagingScope;

pub(super) struct Projection {
    root: PathBuf,
}

impl Projection {
    pub(super) fn open(root: &Path) -> io::Result<Self> {
        Self::open_with_optional_staging(root, None)
    }

    pub(super) fn open_with_staging(root: &Path, scope: StagingScope) -> io::Result<Self> {
        // Portable backends do not create Unix scoped temps; accept the scope
        // so restoration can use one open API across targets.
        Self::open_with_optional_staging(root, Some(scope))
    }

    fn open_with_optional_staging(root: &Path, _scope: Option<StagingScope>) -> io::Result<Self> {
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

    pub(super) fn remove_staging(
        &self,
        relative: &RelativePath,
        scope: StagingScope,
    ) -> io::Result<()> {
        let path = self.path(relative);
        let name = path.file_name().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "staging path has no basename")
        })?;
        if !scope.matches_temporary_basename(name) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "staging removal name is outside the durable restoration scope",
            ));
        }
        self.remove_authorized_private_leaf(relative)
    }

    pub(super) fn remove_authorized_private_leaf(&self, relative: &RelativePath) -> io::Result<()> {
        let path = self.path(relative);
        crate::platform_fs::verify_no_redirects(&path)?;
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_file() => {
                crate::platform_fs::validate_private_file(&path)?;
                std::fs::remove_file(path)
            },
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

pub(super) struct Inspection {
    root: PathBuf,
}

impl Inspection {
    pub(super) fn try_open(root: &Path) -> io::Result<Self> {
        crate::platform_fs::verify_no_redirects(root)?;
        if !std::fs::symlink_metadata(root)?.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "projection root is not a directory",
            ));
        }
        // Never repair before durable restoration intent.
        crate::platform_fs::validate_private_directory(root)?;
        Ok(Self {
            root: root.to_path_buf(),
        })
    }

    fn path(&self, relative: &RelativePath) -> PathBuf {
        self.root.join(relative.0.iter().collect::<PathBuf>())
    }

    pub(super) fn matches_private_directory(&self, relative: &RelativePath) -> io::Result<bool> {
        let path = self.path(relative);
        if !path.starts_with(&self.root) {
            return Ok(false);
        }
        match self.validate_private_ancestors(&path) {
            Ok(()) => Ok(true),
            Err(error) if is_non_match(&error) => Ok(false),
            Err(error) => Err(error),
        }
    }

    pub(super) fn matches_private_file(
        &self,
        relative: &RelativePath,
        expected: &[u8],
    ) -> io::Result<bool> {
        let path = self.path(relative);
        let Some(parent) = path.parent() else {
            return Ok(false);
        };
        match (|| {
            self.validate_private_ancestors(parent)?;
            crate::platform_fs::verify_no_redirects(&path)?;
            crate::platform_fs::validate_private_file(&path)?;
            let mut file = std::fs::File::open(&path)?;
            super::compare::matches_file(&mut file, expected)
        })() {
            Ok(matched) => Ok(matched),
            Err(error) if is_non_match(&error) => Ok(false),
            Err(error) => Err(error),
        }
    }

    pub(super) fn confirm_absolute_root(&self) -> io::Result<()> {
        crate::platform_fs::verify_no_redirects(&self.root)?;
        crate::platform_fs::validate_private_directory(&self.root)
    }

    fn validate_private_ancestors(&self, path: &Path) -> io::Result<()> {
        crate::platform_fs::verify_no_redirects(path)?;
        for ancestor in path.ancestors() {
            if !ancestor.starts_with(&self.root) {
                break;
            }
            crate::platform_fs::validate_private_directory(ancestor)?;
            if ancestor == self.root {
                break;
            }
        }
        Ok(())
    }
}

fn is_non_match(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::NotFound
            | io::ErrorKind::PermissionDenied
            | io::ErrorKind::InvalidData
            | io::ErrorKind::InvalidInput
    )
}
